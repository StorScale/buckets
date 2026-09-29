/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc support inspect: GET|POST /inspect-data?volume=&file=[&public-key=].
 * The raw files matching a pattern on every drive, each drive's
 * format.json, the command line and a script to start a server on them, in
 * a zip. With a public key the answer is an estream: cluster.info under a
 * key only MinIO's support can read (SUBNET's), inspect.zip under a key
 * the caller's private key opens. Without one (the legacy form) it is a
 * version byte, the key, and the zip sealed with sio-go's STREAM. Replaces
 * MinIO's InspectDataHandler (cmd/admin-handlers.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "core/zipwrite.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/estream.h"
#include "scanner/usage.h"
#include "storage/drive.h"
#include "object/sysconfig.h"

/* subnetAdminPublicKey and subnetAdminPublicKeyDev (MINIO_CI_CD) */
static const char k_subnet_key[] =
    "-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEAyC+ol5v0FP+QcsR6d1KypR/063FInmNEFsFzbEwlHQyEQN3O7kNI\n"
    "wVDN1vqp1wDmJYmv4VZGRGzfFw1q+QV7K1TnysrEjrqpVxfxzDQCoUadAp8IxLLc\n"
    "s2fjyDNxnZjoC6fTID9C0khKnEa5fPZZc3Ihci9SiCGkPmyUyCGVSxWXIKqL2Lrj\n"
    "yDc0pGeEhWeEPqw6q8X2jvTC246tlzqpDeNsPbcv2KblXRcKniQNbBrizT37CKHQ\n"
    "M6hc9kugrZbFuo8U5/4RQvZPJnx/DVjLDyoKo2uzuVQs4s+iBrA5sSSLp8rPED/3\n"
    "6DgWw3e244Dxtrg972dIT1IOqgn7KUJzVQIDAQAB\n-----END PUBLIC KEY-----";
static const char k_subnet_key_dev[] =
    "-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEArhQYXQd6zI4uagtVfthAPOt6i4AYHnEWCoNeAovM4MNl42I9uQFh\n"
    "3VHkbWj9Gpx9ghf6PgRgK+8FcFvy+StmGcXpDCiFywXX24uNhcZjscX1C4Esk0BW\n"
    "idfI2eXYkOlymD4lcK70SVgJvC693Qa7Z3FE1KU8Nfv2bkxEE4bzOkojX9t6a3+J\n"
    "R8X6Z2U8EMlH1qxJPgiPogELhWP0qf2Lq7GwSAflo1Tj/ytxvD12WrnE0Rrj/8yP\n"
    "Snp7TbYm91KocKMExlmvx3l2XPLxeU8nf9U0U+KOmorejD3MDMEPF+tlk9LB3JWP\n"
    "ZqYYe38rfALVTn4RVJriUcNOoEpEyC0WEwIDAQAB\n-----END PUBLIC KEY-----";

static bool env_on(const char *name) {
  const char *v = getenv(name);
  return v && (strcmp(v, "on") == 0 || strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0);
}

/* hasBadPathComponent */
static bool bad_path(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
  for (;;) {
    const char *e = strchr(p, '/');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    const char *a = p, *z = p + n;
    while (a < z && (*a == ' ' || *a == '\t' || *a == '\n' || *a == '\r')) a++;
    while (z > a && (z[-1] == ' ' || z[-1] == '\t' || z[-1] == '\n' || z[-1] == '\r')) z--;
    if ((z - a == 1 && a[0] == '.') || (z - a == 2 && a[0] == '.' && a[1] == '.')) return true;
    if (!e) return false;
    p = e + 1;
  }
}

/* path.Join */
static char *path_join3(const char *a, const char *b, const char *c) {
  buckets_buf j = BUCKETS_BUF_INIT;
  const char *parts[3] = {a, b, c};
  for (int i = 0; i < 3; i++) {
    if (!*parts[i]) continue;
    if (j.len) buckets_buf_append_char(&j, '/');
    buckets_buf_append_c(&j, parts[i]);
  }
  buckets_buf_append_char(&j, '\0');
  /* Clean: collapse slashes, drop "." elements and a trailing slash */
  char *s = j.data, *w = s;
  bool rooted = *s == '/';
  for (char *r = s; *r;) {
    if (*r == '/') {
      r++;
      continue;
    }
    char *e = strchr(r, '/');
    size_t n = e ? (size_t)(e - r) : strlen(r);
    if (!(n == 1 && r[0] == '.')) {
      if (w > s || rooted) *w++ = '/';
      memmove(w, r, n);
      w += n;
    }
    r += n;
  }
  *w = '\0';
  if (!*s) strcpy(s, rooted ? "/" : ".");
  return s;
}

/* getClusterMetaInfo: madmin.ClusterRegistrationInfo, indented */
void buckets_admin_cluster_info_json(buckets_s3_server *s, buckets_buf *out) {
  const buckets_cluster_info *ci = s->cluster;
  uint64_t total = 0, used = 0;
  size_t ndrives = ci ? ci->neps : 0;
  for (size_t i = 0; s->layer && i < s->layer->nall; i++) {
    uint64_t t = 0, f = 0;
    if (s->layer->all[i] && buckets_drive_disk_info(s->layer->all[i], &t, &f) == BUCKETS_DRIVE_OK) total += t, used += t - f;
  }
  buckets_data_usage u;
  memset(&u, 0, sizeof(u));
  buckets_buf raw = BUCKETS_BUF_INIT;
  bool have = buckets_sysconfig_read(s->layer, BUCKETS_USAGE_PATH, &raw, NULL) == BUCKETS_OBJ_OK &&
              buckets_data_usage_parse(raw.data, raw.len, &u);
  buckets_buf_free(&raw);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "deployment_id", s->layer ? s->layer->deployment_id_str : "");
  char name[128];
  size_t nservers = ci && ci->nnodes ? ci->nnodes : 1;
  snprintf(name, sizeof(name), "%zu-servers-%zu-disks-%s", nservers, ndrives, BUCKETS_VERSION);
  yyjson_mut_obj_add_strcpy(d, root, "cluster_name", name);
  yyjson_mut_obj_add_uint(d, root, "used_capacity", have ? u.total_size : 0);
  yyjson_mut_val *info = yyjson_mut_obj_add_obj(d, root, "info");
  yyjson_mut_obj_add_str(d, info, "minio_version", BUCKETS_VERSION);
  yyjson_mut_obj_add_uint(d, info, "no_of_server_pools", s->layer ? s->layer->npools : 0);
  yyjson_mut_obj_add_uint(d, info, "no_of_servers", nservers);
  yyjson_mut_obj_add_uint(d, info, "no_of_drives", ndrives);
  yyjson_mut_obj_add_uint(d, info, "no_of_buckets", have ? u.buckets_count : 0);
  yyjson_mut_obj_add_uint(d, info, "no_of_objects", have ? u.objects : 0);
  yyjson_mut_obj_add_uint(d, info, "total_drive_space", total);
  yyjson_mut_obj_add_uint(d, info, "used_drive_space", used);
  yyjson_mut_obj_add_str(d, info, "edition", "");
  size_t len;
  char *json = yyjson_mut_write(d, YYJSON_WRITE_PRETTY_TWO_SPACES, &len);
  buckets_buf_append(out, json, len);
  free(json);
  yyjson_mut_doc_free(d);
  if (have) buckets_data_usage_free(&u);
}

/* The drive of a pool's slot, named as the command line did. */
static const buckets_info_endpoint *slot_endpoint(const buckets_cluster_info *ci, size_t pool, size_t slot) {
  size_t k = 0;
  for (size_t i = 0; ci && i < ci->neps; i++) {
    if (ci->eps[i].pool != pool) continue;
    if (k++ == slot) return &ci->eps[i];
  }
  return NULL;
}

/* GetRawData: every online drive's matches; false when there were none. */
static bool raw_data(buckets_s3_server *s, buckets_zipw *z, const char *volume, const char *file) {
  buckets_objlayer *L = s->layer;
  const buckets_cluster_info *ci = s->cluster;
  size_t found = 0;
  for (size_t i = 0; i < L->nall; i++) {
    buckets_drive *d = L->all[i];
    if (!d) continue;
    buckets_drive_place pl;
    buckets_objlayer_place(L, i, &pl);
    const buckets_info_endpoint *ep = slot_endpoint(ci, pl.pool, i - pl.pool_first);
    if (!ep) continue;
    buckets_stat_info *si;
    size_t n;
    if (buckets_drive_stat_info(d, volume, file, &si, &n) != BUCKETS_DRIVE_OK) continue;
    for (size_t k = 0; k < n; k++) {
      buckets_buf data = BUCKETS_BUF_INIT;
      buckets_buf rel = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&rel, "%s/%s", volume, si[k].name);
      if (!si[k].dir && buckets_drive_read_all(d, volume, si[k].name, &data) != BUCKETS_DRIVE_OK) {
        buckets_buf_free(&data);
        buckets_buf_free(&rel);
        continue;
      }
      found++;
      /* host (none for a local path), the drive's path, the file */
      char *name = path_join3(ci && ci->distributed ? ep->node : "", ep->path, rel.data);
      if (si[k].dir) {
        size_t nl = strlen(name);
        name = buckets_xrealloc(name, nl + 2);
        strcpy(name + nl, "/");
      }
      uint32_t perm = si[k].mode ? si[k].mode : 0600;
      time_t mtime = si[k].mtime_ns ? (time_t)(si[k].mtime_ns / 1000000000LL) : time(NULL);
      buckets_zipw_add_mode(z, name, si[k].dir ? "" : data.data, si[k].dir ? 0 : data.len, mtime, perm, si[k].dir);
      free(name);
      buckets_buf_free(&data);
      buckets_buf_free(&rel);
    }
    buckets_stat_info_free(si, n);
  }
  return found > 0;
}

static const char k_start_script[] =
    "#!/usr/bin/env bash\n"
    "\n"
    "function main() {\n"
    "\tfor file in $(ls -1); do\n"
    "\t\tdest_file=$(echo \"$file\" | cut -d \":\" -f1)\n"
    "\t\tmv \"$file\" \"$dest_file\"\n"
    "\tdone\n"
    "\n"
    "\t# Read content of inspect-input.txt\n"
    "\tMINIO_OPTS=$(grep \"Server command line args\" <./inspect-input.txt | sed \"s/Server command line args: //g\" | sed -r \"s#%s:\\/\\/#\\.\\/#g\")\n"
    "\n"
    "\t# Start MinIO instance using the options\n"
    "\tSTART_CMD=\"CI=on _MINIO_AUTO_DRIVE_HEALING=off minio server ${MINIO_OPTS} &\"\n"
    "\techo\n"
    "\techo \"Starting MinIO instance: ${START_CMD}\"\n"
    "\techo\n"
    "\teval \"$START_CMD\"\n"
    "\tMINIO_SRVR_PID=\"$!\"\n"
    "\techo \"MinIO Server PID: ${MINIO_SRVR_PID}\"\n"
    "\techo\n"
    "\techo \"Waiting for MinIO instance to get ready!\"\n"
    "\tsleep 10\n"
    "}\n"
    "\n"
    "main \"$@\"";

void buckets_admin_inspect_data(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:InspectData")) return;
  buckets_s3_server *s = c->s;
  const char *volume = buckets_query_get(&c->q, "volume");
  const char *file = buckets_query_get(&c->q, "file");
  if (!volume || !*volume) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_BUCKET_NAME);
    return;
  }
  if (!file || !*file) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  if (bad_path(volume) || bad_path(file)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_RESOURCE_NAME); /* an XML error, as MinIO writes it here */
    return;
  }
  buckets_buf client_key = BUCKETS_BUF_INIT;
  const char *pk = buckets_query_get(&c->q, "public-key");
  if (pk && *pk) {
    size_t n = strlen(pk);
    uint8_t *raw = buckets_xmalloc(n + 4);
    long dn = buckets_base64_decode(pk, n, raw);
    if (dn < 0) {
      free(raw);
      /* base64.StdEncoding: the first byte it could not take */
      size_t bad = strspn(pk, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
      char msg[256];
      snprintf(msg, sizeof(msg), "We encountered an internal error, please try again. (illegal base64 data at input byte %zu)",
               bad < n ? bad : n);
      buckets_admin_custom_error(c, 500, "InternalError", msg);
      return;
    }
    bool ok = buckets_rsa_public_key_der(raw, (size_t)dn, &client_key);
    free(raw);
    if (!ok) {
      buckets_buf_free(&client_key);
      buckets_admin_custom_error(c, 500, "InternalError",
                                 "We encountered an internal error, please try again. (x509: invalid RSA public key)");
      return;
    }
  }

  /* the zip */
  buckets_buf zip = BUCKETS_BUF_INIT, info = BUCKETS_BUF_INIT;
  buckets_zipw *z = buckets_zipw_new(&zip);
  time_t now = time(NULL);
  buckets_admin_cluster_info_json(s, &info);
  if (!client_key.len) buckets_zipw_add(z, "cluster.info", info.data, info.len, now);
  buckets_buf input = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&input, "Inspect path: %s/%s\nServer command line args:", volume, file);
  for (size_t p = 0; p < s->layer->npools; p++) {
    const char *cl = buckets_objlayer_pool_cmdline(s->layer, p);
    buckets_buf_appendf(&input, " %s", cl ? cl : "");
  }
  buckets_buf_append_char(&input, '\n');
  buckets_zipw_add(z, "inspect-input.txt", input.data, input.len, now);
  buckets_buf_free(&input);
  const char *err = NULL;
  if (!raw_data(s, z, volume, file)) {
    err = "GetRawData: No files matched the given pattern";
  } else {
    if (strcmp(volume, BUCKETS_META_BUCKET) != 0 || strcmp(file, "format.json") != 0)
      raw_data(s, z, BUCKETS_META_BUCKET, "format.json");
    char *script = buckets_xmalloc(sizeof(k_start_script) + 16);
    snprintf(script, sizeof(k_start_script) + 16, k_start_script, s->cluster && s->cluster->secure ? "https" : "http");
    buckets_zipw_add_mode(z, "start-minio.sh", script, strlen(script), now, 0755, false);
    free(script);
  }
  buckets_zipw_finish(z);

  buckets_buf *out = &c->resp->body;
  buckets_buf_reset(out);
  if (client_key.len) {
    buckets_estream *e = buckets_estream_new(out);
    buckets_buf subnet = BUCKETS_BUF_INIT;
    const char *sk = env_on("MINIO_CI_CD") || env_on("CI") ? k_subnet_key_dev : k_subnet_key;
    buckets_rsa_public_key_der(sk, strlen(sk), &subnet);
    if (buckets_estream_add_key_encrypted(e, subnet.data, subnet.len))
      buckets_estream_add_encrypted(e, "cluster.info", info.data, info.len);
    buckets_buf_free(&subnet);
    buckets_estream_add_key_encrypted(e, client_key.data, client_key.len);
    buckets_estream_add_encrypted(e, "inspect.zip", zip.data, zip.len);
    if (err) buckets_estream_add_error(e, err);
    buckets_estream_close(e);
  } else {
    /* version 1, the key, then the sealed zip (a zero nonce: the key is used once) */
    uint8_t key[32], nonce[8] = {0};
    buckets_random(key, sizeof(key));
    buckets_buf_append_char(out, 1);
    buckets_buf_append(out, key, sizeof(key));
    buckets_sio_stream_seal(key, nonce, zip.data ? zip.data : "", zip.len, out);
  }
  buckets_buf_free(&zip);
  buckets_buf_free(&info);
  buckets_buf_free(&client_key);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/octet-stream");
}
