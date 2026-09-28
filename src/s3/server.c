/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/server.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/log.h"
#include "core/query.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "admin/admin.h"
#include "admin/info.h"
#include "config/sys.h"
#include "iam/openid.h"
#include "iam/plugins.h"
#include "bucket/metadata.h"
#include "bucket/metasys.h"
#include "dist/peer.h"
#include "s3/bucketname.h"
#include "s3/errors.h"
#include "s3/sigv4.h"
#include "s3/internal.h"
#include "s3/sigv2.h"
#include "s3/xml.h"

#define DEFAULT_REGION "us-east-1"


static void notify_iam(void *ud, const char *kind, const char *name) {
  buckets_s3_server *s = ud;
  if (s->peers) buckets_peer_notify_iam(s->peers, kind, name);
}

static void notify_bucket(void *ud, const char *bucket) {
  buckets_s3_server *s = ud;
  if (s->peers) buckets_peer_notify_bucket(s->peers, bucket);
}

void buckets_s3_peer_iam(void *server, const char *kind, const char *name) {
  buckets_s3_server *s = server;
  if (strcmp(kind, "config") == 0) {
    if (s->config) buckets_config_sys_reload(s->config);
    return;
  }
  buckets_iam_on_notify(s->iam, kind, name);
}

/* ---- OpenID providers ---- */

static const char *g_region = ""; /* for role ARNs built while validating a config */

buckets_openid *buckets_s3_openid(buckets_s3_server *s) {
  pthread_mutex_lock(&s->oidc_mu);
  buckets_openid *o = buckets_openid_ref(s->openid);
  pthread_mutex_unlock(&s->oidc_mu);
  return o;
}

buckets_plugins *buckets_s3_plugins(buckets_s3_server *s) {
  pthread_mutex_lock(&s->oidc_mu);
  buckets_plugins *p = buckets_plugins_ref(s->plugins);
  pthread_mutex_unlock(&s->oidc_mu);
  return p;
}

static void rebuild_plugins(buckets_s3_server *s) {
  buckets_config *cfg = buckets_config_sys_snapshot(s->config);
  char err[512];
  buckets_plugins *p = buckets_plugins_build(cfg, s->region, false, err, sizeof(err));
  buckets_config_free(cfg);
  if (!p) {
    buckets_log_error("plugins: %s", err);
    return;
  }
  if (buckets_authz_plugin_enabled(p)) buckets_log_info("policy_plugin: authorization is delegated to the plugin");
  if (buckets_idp_plugin_enabled(p)) buckets_log_info("identity_plugin: AssumeRoleWithCustomToken enabled");
  pthread_mutex_lock(&s->oidc_mu);
  buckets_plugins *old = s->plugins;
  s->plugins = p;
  pthread_mutex_unlock(&s->oidc_mu);
  buckets_plugins_release(old);
}

static bool validate_plugins(const buckets_config *cfg, char *err, size_t errlen) {
  buckets_plugins *p = buckets_plugins_build(cfg, g_region, true, err, errlen);
  buckets_plugins_release(p);
  return p != NULL;
}

static bool authz_hook(void *ud, const buckets_iam_ident *id, bool owner, const buckets_policy_args *a, bool *allowed) {
  buckets_plugins *p = buckets_s3_plugins(ud);
  bool handled = buckets_authz_plugin_enabled(p);
  if (handled) {
    char *claims = id && id->claims ? yyjson_write(id->claims, 0, NULL) : NULL;
    *allowed = buckets_authz_plugin_allowed(p, id ? id->access_key : "", id ? id->groups : NULL,
                                            id ? id->ngroups : 0, owner, a, claims);
    free(claims);
  }
  buckets_plugins_release(p);
  return handled;
}

static void rebuild_openid(buckets_s3_server *s) {
  buckets_config *cfg = buckets_config_sys_snapshot(s->config);
  char err[512];
  buckets_openid *o = buckets_openid_build(cfg, s->region, err, sizeof(err));
  buckets_config_free(cfg);
  if (!o) {
    buckets_log_error("identity_openid: %s", err);
    return;
  }
  if (buckets_openid_enabled(o)) buckets_log_info("identity_openid: OpenID configured");
  pthread_mutex_lock(&s->oidc_mu);
  buckets_openid *old = s->openid;
  s->openid = o;
  pthread_mutex_unlock(&s->oidc_mu);
  buckets_openid_release(old);
}

/* mc admin config set identity_openid: the providers must be reachable. */
static bool validate_openid(const buckets_config *cfg, char *err, size_t errlen) {
  buckets_openid *o = buckets_openid_build(cfg, g_region, err, errlen);
  buckets_openid_release(o);
  return o != NULL;
}

static char *oidc_claim_name(void *ud) {
  buckets_openid *o = buckets_s3_openid(ud);
  char *n = buckets_xstrdup(buckets_openid_claim_name(o));
  buckets_openid_release(o);
  return n;
}

static char *oidc_role_policy(void *ud, const char *arn) {
  buckets_openid *o = buckets_s3_openid(ud);
  const char *p = o ? buckets_openid_role_policy(o, arn) : NULL;
  char *r = p ? buckets_xstrdup(p) : NULL;
  buckets_openid_release(o);
  if (!r) { /* the identity plugin's role */
    buckets_plugins *pl = buckets_s3_plugins(ud);
    const char *parn = buckets_idp_plugin_role_arn(pl);
    if (parn && strcmp(parn, arn) == 0) r = buckets_xstrdup(buckets_idp_plugin_role_policy(pl));
    buckets_plugins_release(pl);
  }
  return r;
}

static void config_changed(void *ud, const char *subsys, bool local) {
  buckets_s3_server *s = ud;
  if (!*subsys || strcmp(subsys, "identity_openid") == 0) rebuild_openid(s);
  if (!*subsys || strcmp(subsys, "policy_plugin") == 0 || strcmp(subsys, "policy_opa") == 0 ||
      strcmp(subsys, "identity_plugin") == 0) {
    rebuild_plugins(s);
  }
  if (local && s->peers) buckets_peer_notify_iam(s->peers, "config", *subsys ? subsys : "all");
}

void buckets_s3_peer_bucket(void *server, const char *bucket) {
  buckets_s3_server *s = server;
  if (s->meta) buckets_metasys_invalidate(s->meta, bucket);
}

char *buckets_s3_peer_server_info(void *server) { return buckets_admin_local_server_json(server); }

void buckets_s3_server_init(buckets_s3_server *s, buckets_objlayer *layer, const char *root_user,
                            const char *root_password, const char *region) {
  memset(s, 0, sizeof(*s));
  s->root_user = root_user;
  s->root_password = root_password;
  s->region = region ? region : "";
  s->iam = buckets_iam_new(root_user, root_password);
  buckets_iam_set_notify(s->iam, notify_iam, s);
  s->config = buckets_config_sys_new(root_user, root_password);
  buckets_config_sys_set_hook(s->config, config_changed, s);
  pthread_mutex_init(&s->oidc_mu, NULL);
  g_region = s->region;
  buckets_config_register_validator("identity_openid", validate_openid);
  buckets_config_register_validator("policy_plugin", validate_plugins);
  buckets_config_register_validator("identity_plugin", validate_plugins);
  buckets_iam_set_authz(s->iam, authz_hook, s);
  buckets_iam_openid_hooks hooks = {oidc_claim_name, oidc_role_policy, s};
  buckets_iam_set_openid_hooks(s->iam, &hooks);
  if (layer) buckets_s3_server_set_layer(s, layer);
}

/* Loads IAM once the object layer is up, retrying while it lacks quorum
 * (other servers still starting); then refreshes it periodically. */
static void *iam_start_main(void *arg) {
  buckets_s3_server *s = arg;
  int delay_ms = 250;
  /* The configuration first: identity providers come from it. */
  char err[512];
  while (!buckets_config_sys_load(s->config, s->layer, err, sizeof(err))) {
    buckets_log_warn("config: %s; retrying", err);
    struct timespec ts = {delay_ms / 1000, (delay_ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
    if (delay_ms < 5000) delay_ms *= 2;
  }
  rebuild_openid(s);
  rebuild_plugins(s);
  delay_ms = 250;
  while (!buckets_iam_start(s->iam, s->layer)) {
    buckets_log_warn("iam: unable to load IAM data yet, retrying");
    struct timespec ts = {delay_ms / 1000, (delay_ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
    if (delay_ms < 5000) delay_ms *= 2;
  }
  const char *env = getenv("BUCKETS_IAM_REFRESH_INTERVAL");
  if (!env) env = getenv("MINIO_IAM_REFRESH_INTERVAL");
  int interval = env ? atoi(env) : 600;
  buckets_iam_start_refresh(s->iam, interval > 0 ? interval : 600);
  return NULL;
}

void buckets_s3_server_set_layer(buckets_s3_server *s, buckets_objlayer *layer) {
  uint8_t h[32];
  buckets_sha256(layer->deployment_id_str, strlen(layer->deployment_id_str), h);
  buckets_hex_encode(h, 32, s->host_id);
  s->meta = buckets_metasys_new(layer, s->meta_ttl_ms);
  buckets_metasys_set_notify(s->meta, notify_bucket, s);
  s->layer = layer; /* atomic store, after host_id and meta */
  pthread_t t;
  if (pthread_create(&t, NULL, iam_start_main, s) == 0) pthread_detach(t);
}

/* ---- response helpers ---------------------------------------------------- */

static void common_headers(s3_ctx *c) {
  buckets_http_response *r = c->resp;
  buckets_http_resp_header(r, "X-Amz-Request-Id", c->request_id);
  buckets_http_resp_header(r, "X-Amz-Id-2", c->s->host_id);
  buckets_http_resp_header(r, "Accept-Ranges", "bytes");
  buckets_http_resp_header(r, "Vary", "Origin, Accept-Encoding");
  buckets_http_resp_header(r, "X-Content-Type-Options", "nosniff");
  buckets_http_resp_header(r, "X-Xss-Protection", "1; mode=block");
  buckets_http_resp_header(r, "Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

void buckets_s3_write_error_msg(s3_ctx *c, buckets_s3_error e, const char *message) {
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  c->resp->status = info->status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
  buckets_buf_reset(&c->resp->body);
  buckets_s3_error_xml_msg(&c->resp->body, e, message, c->path ? c->path : "/", c->bucket, c->object, c->request_id,
                           c->s->host_id);
}

void buckets_s3_write_error(s3_ctx *c, buckets_s3_error e) { buckets_s3_write_error_msg(c, e, NULL); }

void buckets_s3_write_xml(s3_ctx *c, int status) {
  c->resp->status = status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
}

/* ---- request parsing ----------------------------------------------------- */

static bool has_bad_component(const char *path) {
  const char *p = path;
  while (*p) {
    while (*p == '/') p++;
    const char *seg = p;
    while (*p && *p != '/') p++;
    size_t n = (size_t)(p - seg);
    if ((n == 1 && seg[0] == '.') || (n == 2 && seg[0] == '.' && seg[1] == '.')) return true;
  }
  return false;
}

/* Splits "/bucket/obj/ect" into bucket and object (path-style addressing). */
static buckets_s3_error parse_path(s3_ctx *c) {
  buckets_str raw = c->req->path;
  char *decoded = buckets_xmalloc(raw.n + 1);
  long n = buckets_url_decode(raw, decoded, false);
  if (n < 0) {
    free(decoded);
    return BUCKETS_ERR_INVALID_RESOURCE_NAME;
  }
  decoded[n] = '\0';
  c->path = decoded;
  if (memchr(decoded, '\0', (size_t)n) || has_bad_component(decoded)) return BUCKETS_ERR_INVALID_RESOURCE_NAME;

  const char *p = decoded;
  while (*p == '/') p++;
  if (!*p) return BUCKETS_ERR_NONE;
  const char *slash = strchr(p, '/');
  if (!slash) {
    c->bucket = buckets_xstrdup(p);
  } else {
    c->bucket = buckets_xstrndup(p, (size_t)(slash - p));
    if (slash[1]) c->object = buckets_xstrdup(slash + 1);
  }
  return BUCKETS_ERR_NONE;
}

bool buckets_s3_lookup_secret(void *ud, buckets_str access_key, char secret[BUCKETS_SECRET_MAX]) {
  s3_ctx *c = ud;
  char *ak = buckets_xstrndup(access_key.p, access_key.n);
  buckets_iam_ident *id;
  c->key_status = buckets_iam_get_key(c->s->iam, ak, &id);
  free(ak);
  if (c->key_status != BUCKETS_IAM_KEY_OK) return false;
  snprintf(secret, BUCKETS_SECRET_MAX, "%s", id->secret_key);
  buckets_iam_ident_release(c->ident);
  c->ident = id;
  return true;
}

/* getSessionToken: the header, else the query parameter. */
static char *session_token(s3_ctx *c) {
  buckets_str h = buckets_http_header_get(c->req, "X-Amz-Security-Token");
  if (h.p && h.n) return buckets_xstrndup(h.p, h.n);
  const char *q = buckets_query_get(&c->q, "X-Amz-Security-Token");
  return q && *q ? buckets_xstrdup(q) : NULL;
}

buckets_s3_error buckets_s3_check_credential(s3_ctx *c, buckets_s3_error verify_err, const char *form_token) {
  if (verify_err == BUCKETS_ERR_INVALID_ACCESS_KEY_ID) {
    if (c->key_status == BUCKETS_IAM_KEY_DISABLED) return BUCKETS_ERR_ACCESS_KEY_DISABLED;
    if (c->key_status == BUCKETS_IAM_KEY_NOT_READY) return BUCKETS_ERR_IAM_NOT_INITIALIZED;
  }
  if (verify_err != BUCKETS_ERR_NONE) return verify_err;
  char *token = form_token ? buckets_xstrdup(form_token) : session_token(c);
  buckets_iam_token_status ts = buckets_iam_check_token(c->s->iam, c->ident, token, &c->owner);
  free(token);
  switch (ts) {
    case BUCKETS_IAM_TOKEN_OK: return BUCKETS_ERR_NONE;
    case BUCKETS_IAM_TOKEN_NO_ACCESS_KEY: return BUCKETS_ERR_NO_ACCESS_KEY;
    case BUCKETS_IAM_TOKEN_INVALID: return BUCKETS_ERR_INVALID_TOKEN;
    case BUCKETS_IAM_TOKEN_EXPIRED: return BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
  }
  return BUCKETS_ERR_ACCESS_DENIED;
}

static bool is_hex64(const char *s) {
  if (strlen(s) != 64) return false;
  for (int i = 0; i < 64; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

buckets_s3_error buckets_s3_read_doc(s3_ctx *c) {
  const buckets_http_request *req = c->req;
  if (req->body_len > BUCKETS_S3_MAX_DOC_SIZE) return BUCKETS_ERR_ENTITY_TOO_LARGE;
  if (c->auth == BUCKETS_AUTH_SIGV4_STREAMING) return BUCKETS_ERR_NOT_IMPLEMENTED; /* aws-chunked documents */
  buckets_buf_reset(&c->doc);
  buckets_buf_reserve(&c->doc, (size_t)req->body_len);
  buckets_http_body_cursor cur = {req, 0};
  char tmp[65536];
  long n;
  while ((n = buckets_http_body_read(&cur, tmp, sizeof(tmp))) > 0) buckets_buf_append(&c->doc, tmp, (size_t)n);
  if (n < 0) return BUCKETS_ERR_INTERNAL_ERROR;

  buckets_str md5h = buckets_http_header_get(req, "Content-MD5");
  if (md5h.p) {
    uint8_t want[BUCKETS_MD5_LEN + 3], got[BUCKETS_MD5_LEN];
    if (md5h.n != 24 || buckets_base64_decode(md5h.p, md5h.n, want) != BUCKETS_MD5_LEN) {
      return BUCKETS_ERR_INVALID_DIGEST;
    }
    buckets_md5(c->doc.data, c->doc.len, got);
    if (memcmp(want, got, BUCKETS_MD5_LEN) != 0) return BUCKETS_ERR_BAD_DIGEST;
  }
  const char *payload_hash = c->sig.payload_hash;
  if (!*payload_hash || strcmp(payload_hash, BUCKETS_UNSIGNED_PAYLOAD) == 0) return BUCKETS_ERR_NONE;
  if (!is_hex64(payload_hash)) return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
  uint8_t sum[32];
  char hex[65];
  buckets_sha256(c->doc.data, c->doc.len, sum);
  buckets_hex_encode(sum, 32, hex);
  for (int i = 0; i < 64; i++) {
    if (hex[i] != tolower((unsigned char)payload_hash[i])) return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
  }
  return BUCKETS_ERR_NONE;
}

static buckets_s3_error authenticate(s3_ctx *c) {
  buckets_sigv4_config cfg = {
      .region = c->s->region,
      .service = "s3",
      .now = time(NULL),
      .lookup = buckets_s3_lookup_secret,
      .lookup_ud = c,
  };
  buckets_sigv4_result *res = &c->sig;
  buckets_s3_error err;
  c->auth = buckets_auth_classify(c->req, &c->q);
  switch (c->auth) {
    case BUCKETS_AUTH_SIGV4_HEADER:
    case BUCKETS_AUTH_SIGV4_STREAMING: /* seed signature; chunks are verified while reading */
      err = buckets_sigv4_verify_header(&cfg, c->req, &c->q, res);
      break;
    case BUCKETS_AUTH_SIGV4_PRESIGNED:
      err = buckets_sigv4_verify_presigned(&cfg, c->req, &c->q, res);
      break;
    case BUCKETS_AUTH_ANONYMOUS: {
      /* Authorized per action against the bucket policy; a token needs a key. */
      char *token = session_token(c);
      bool has = token != NULL;
      free(token);
      return has ? BUCKETS_ERR_NO_ACCESS_KEY : BUCKETS_ERR_NONE;
    }
    case BUCKETS_AUTH_SIGV2:
      err = buckets_sigv2_verify_header(&cfg, c->req, res);
      break;
    case BUCKETS_AUTH_SIGV2_PRESIGNED:
      err = buckets_sigv2_verify_presigned(&cfg, c->req, res);
      break;
    case BUCKETS_AUTH_POST_POLICY:
      return BUCKETS_ERR_NONE; /* the signed policy inside the form is verified by the handler */
    case BUCKETS_AUTH_JWT:
      return BUCKETS_ERR_NOT_IMPLEMENTED;
    default:
      return BUCKETS_ERR_SIGNATURE_VERSION_NOT_SUPPORTED;
  }
  if ((err = buckets_s3_check_credential(c, err, NULL)) != BUCKETS_ERR_NONE) return err;
  snprintf(c->access_key, sizeof(c->access_key), "%s", res->access_key);
  return BUCKETS_ERR_NONE;
}

/* ---- service-level handlers ---------------------------------------------- */

static void list_buckets(s3_ctx *c) {
  /* ListAllMyBuckets, else only the buckets the caller may list or locate. */
  buckets_s3_error aerr = buckets_s3_authorize(c, "s3:ListAllMyBuckets", NULL, NULL, NULL);
  if (!c->ident) aerr = BUCKETS_ERR_ACCESS_DENIED;
  if (aerr != BUCKETS_ERR_NONE && (aerr != BUCKETS_ERR_ACCESS_DENIED || !c->ident)) {
    buckets_s3_write_error(c, aerr);
    return;
  }
  bool filter = aerr == BUCKETS_ERR_ACCESS_DENIED;
  if (filter) {
    buckets_s3_cond_override(c, "prefix", "");
    buckets_s3_cond_override(c, "delimiter", "/");
  }
  buckets_bucket_info *vols;
  size_t n;
  buckets_obj_err lerr = buckets_obj_list_buckets(c->s->layer, &vols, &n);
  if (lerr) {
    buckets_s3_write_error(c, buckets_s3_obj_error(lerr));
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListAllMyBucketsResult", BUCKETS_S3_XMLNS);
  buckets_xml_open(b, "Owner");
  buckets_xml_elem(b, "ID", BUCKETS_S3_OWNER_ID);
  buckets_xml_elem(b, "DisplayName", BUCKETS_S3_OWNER_NAME);
  buckets_xml_close(b, "Owner");
  buckets_xml_open(b, "Buckets");
  for (size_t i = 0; i < n; i++) {
    if (buckets_bucket_name_reserved(vols[i].name) || !buckets_bucket_name_valid(vols[i].name)) continue;
    if (filter && !buckets_s3_allowed(c, "s3:ListBucket", vols[i].name, NULL, false) &&
        !buckets_s3_allowed(c, "s3:GetBucketLocation", vols[i].name, NULL, false)) {
      continue;
    }
    /* Creation time comes from bucket metadata (as in MinIO), else the directory. */
    time_t created = vols[i].created;
    buckets_bucket_meta bm;
    if (buckets_bucket_meta_load(c->s->layer, vols[i].name, &bm)) {
      int64_t ns = buckets_bucket_meta_created_ns(&bm);
      if (ns) created = (time_t)(ns / 1000000000LL);
      buckets_bucket_meta_free(&bm);
    }
    char ts[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601(created, ts);
    buckets_xml_open(b, "Bucket");
    buckets_xml_elem(b, "Name", vols[i].name);
    buckets_xml_elem(b, "CreationDate", ts);
    buckets_xml_close(b, "Bucket");
  }
  buckets_xml_close(b, "Buckets");
  buckets_xml_close(b, "ListAllMyBucketsResult");
  buckets_bucket_info_free(vols, n);
  buckets_s3_write_xml(c, 200);
}

/* ---- bucket-level handlers ----------------------------------------------- */

static bool bucket_exists(s3_ctx *c) { return buckets_obj_stat_bucket(c->s->layer, c->bucket) == BUCKETS_OBJ_OK; }

static void create_bucket(s3_ctx *c) {
  if (!buckets_bucket_name_valid_strict(c->bucket)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_BUCKET_NAME);
    return;
  }
  buckets_str lock = buckets_http_header_get(c->req, "X-Amz-Bucket-Object-Lock-Enabled");
  if (lock.p && buckets_str_ieq_c(lock, "true")) {
    buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED); /* object lock lands with bucket features */
    return;
  }

  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr != BUCKETS_ERR_NONE) {
    buckets_s3_write_error(c, derr);
    return;
  }
  if (c->doc.len > 0) {
    buckets_xml_doc doc;
    if (!buckets_xml_parse(buckets_buf_str(&c->doc), &doc) || !buckets_str_eq_c(doc.nodes[0].name, "CreateBucketConfiguration")) {
      if (doc.nodes) buckets_xml_doc_free(&doc);
      buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
      return;
    }
    size_t lc = buckets_xml_child(&doc, 0, "LocationConstraint");
    buckets_buf loc = BUCKETS_BUF_INIT;
    bool ok = !lc || buckets_xml_unescape(doc.nodes[lc].text, &loc);
    buckets_xml_doc_free(&doc);
    if (!ok) {
      buckets_buf_free(&loc);
      buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
      return;
    }
    bool region_ok = loc.len == 0 || !*c->s->region || strcmp(loc.data, c->s->region) == 0;
    buckets_buf_free(&loc);
    if (!region_ok) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_REGION);
      return;
    }
  }

  switch (buckets_obj_make_bucket(c->s->layer, c->bucket)) {
    case BUCKETS_OBJ_OK: {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      buckets_bucket_meta bm;
      buckets_bucket_meta_init(&bm, c->bucket, (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec);
      if (!buckets_bucket_meta_save(c->s->layer, &bm)) buckets_log_warn("could not save metadata for bucket %s", c->bucket);
      buckets_bucket_meta_free(&bm);
      buckets_metasys_changed(c->s->meta, c->bucket);
      buckets_http_resp_headerf(c->resp, "Location", "/%s", c->bucket);
      c->resp->status = 200;
      return;
    }
    case BUCKETS_OBJ_ERR_BUCKET_EXISTS:
      buckets_s3_write_error(c, BUCKETS_ERR_BUCKET_ALREADY_OWNED_BY_YOU);
      return;
    default:
      buckets_s3_write_error(c, BUCKETS_ERR_SLOW_DOWN_WRITE);
      return;
  }
}

static void delete_bucket(s3_ctx *c) {
  buckets_obj_err err = buckets_obj_delete_bucket(c->s->layer, c->bucket);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  buckets_bucket_meta_delete(c->s->layer, c->bucket);
  buckets_metasys_changed(c->s->meta, c->bucket);
  c->resp->status = 204;
}

static void get_bucket_location(s3_ctx *c) {
  const char *region = c->s->region;
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "LocationConstraint", BUCKETS_S3_XMLNS);
  if (*region && strcmp(region, DEFAULT_REGION) != 0) buckets_xml_text(b, region, strlen(region));
  buckets_xml_close(b, "LocationConstraint");
  buckets_s3_write_xml(c, 200);
}

static void get_bucket_versioning(s3_ctx *c) {
  /* Versioning is not implemented yet, so every bucket is unversioned: S3
   * represents that as an empty configuration. */
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_buf_appendf(b, "<VersioningConfiguration xmlns=\"%s\"></VersioningConfiguration>", BUCKETS_S3_XMLNS);
  buckets_s3_write_xml(c, 200);
}

/* ---- bucket policy (?policy) -------------------------------------------------- */

#define MAX_BUCKET_POLICY_SIZE (20 * 1024)

static void put_bucket_policy(s3_ctx *c) {
  if (c->req->body_len <= 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_MISSING_CONTENT_LENGTH);
    return;
  }
  if (c->req->body_len > MAX_BUCKET_POLICY_SIZE) {
    buckets_s3_write_error(c, BUCKETS_ERR_POLICY_TOO_LARGE);
    return;
  }
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_policy *p;
  char err[512];
  if (!buckets_bucket_policy_parse(c->doc.data, c->doc.len, c->bucket, &p, err, sizeof(err))) {
    /* APIError{Code: "MalformedPolicy", 400, err.Error()} */
    c->resp->status = 400;
    buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
    buckets_buf *b = &c->resp->body;
    buckets_buf_reset(b);
    buckets_xml_header(b);
    buckets_xml_open(b, "Error");
    buckets_xml_elem(b, "Code", "MalformedPolicy");
    buckets_xml_elem(b, "Message", err);
    buckets_xml_elem(b, "BucketName", c->bucket);
    buckets_xml_elem(b, "Resource", c->path);
    buckets_xml_elem(b, "RequestId", c->request_id);
    buckets_xml_elem(b, "HostId", c->s->host_id);
    buckets_xml_close(b, "Error");
    return;
  }
  bool no_version = !*buckets_policy_version(p);
  buckets_policy_free(p);
  if (no_version) {
    buckets_s3_write_error(c, BUCKETS_ERR_POLICY_INVALID_VERSION);
    return;
  }
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_POLICY, c->doc.data, c->doc.len)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 204;
}

static void get_bucket_policy(s3_ctx *c) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  const buckets_buf *pol = &st->meta.config[BUCKETS_BCFG_POLICY];
  if (!pol->len) {
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET_POLICY);
  } else {
    c->resp->status = 200;
    buckets_http_resp_header(c->resp, "Content-Type", "application/json");
    buckets_buf_append(&c->resp->body, pol->data, pol->len);
  }
  buckets_bucket_state_release(st);
}

static void delete_bucket_policy(s3_ctx *c) {
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_POLICY, NULL, 0)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 204;
}

/* Query keys that select a bucket sub-resource (as opposed to list parameters). */
static bool has_unhandled_subresource(const buckets_query *q) {
  static const char *const list_params[] = {"prefix",     "delimiter",          "marker",      "max-keys",
                                            "encoding-type", "list-type",       "continuation-token",
                                            "fetch-owner", "start-after",   "metadata"};
  for (size_t i = 0; i < q->n; i++) {
    const char *k = q->items[i].key;
    if (strncasecmp(k, "x-amz-", 6) == 0) continue; /* presign parameters */
    bool known = false;
    for (size_t j = 0; j < BUCKETS_ARRAY_LEN(list_params); j++) {
      if (strcmp(k, list_params[j]) == 0) known = true;
    }
    if (!known) return true;
  }
  return false;
}

/* The policy action of a bucket-level request (MinIO's router + handlers). */
static bool authorize_bucket_request(s3_ctx *c) {
  buckets_str m = c->req->method;
  const char *action = NULL;
  if (buckets_query_has(&c->q, "acl")) {
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetBucketPolicy";
    else if (buckets_str_eq_c(m, "PUT")) action = "s3:PutBucketPolicy";
  } else if (buckets_query_has(&c->q, "policy")) {
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetBucketPolicy";
    else if (buckets_str_eq_c(m, "PUT")) action = "s3:PutBucketPolicy";
    else if (buckets_str_eq_c(m, "DELETE")) action = "s3:DeleteBucketPolicy";
  } else if (buckets_str_eq_c(m, "PUT")) {
    if (c->q.n == 0) action = "s3:CreateBucket";
  } else if (buckets_str_eq_c(m, "HEAD")) {
    if (buckets_s3_authorize(c, "s3:HeadBucket", c->bucket, NULL, NULL) == BUCKETS_ERR_NONE) return true;
    action = "s3:ListBucket";
  } else if (buckets_str_eq_c(m, "DELETE")) {
    buckets_str force = buckets_http_header_get(c->req, "X-Minio-Force-Delete");
    if (c->q.n == 0) action = force.p && buckets_str_ieq_c(force, "true") ? "s3:ForceDeleteBucket" : "s3:DeleteBucket";
  } else if (buckets_str_eq_c(m, "GET")) {
    if (buckets_query_has(&c->q, "location")) action = "s3:GetBucketLocation";
    else if (buckets_query_has(&c->q, "versioning")) action = "s3:GetBucketVersioning";
    else if (buckets_query_has(&c->q, "uploads")) action = "s3:ListBucketMultipartUploads";
    else if (!has_unhandled_subresource(&c->q)) action = "s3:ListBucket";
  }
  /* DeleteObjects and POST policy uploads are authorized per object. */
  return !action || buckets_s3_require(c, action, c->bucket, NULL, NULL);
}

static void route_bucket(s3_ctx *c) {
  if (buckets_bucket_name_reserved(c->bucket)) {
    buckets_s3_write_error(c, BUCKETS_ERR_ALL_ACCESS_DISABLED);
    return;
  }
  if (!buckets_bucket_name_valid(c->bucket)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_BUCKET_NAME);
    return;
  }
  buckets_str m = c->req->method;
  if (!authorize_bucket_request(c)) return;
  if (buckets_query_has(&c->q, "acl")) {
    if (!bucket_exists(c)) {
      buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    } else if (buckets_str_eq_c(m, "GET")) {
      buckets_s3_write_private_acl(c);
    } else if (buckets_str_eq_c(m, "PUT")) {
      buckets_s3_put_acl(c);
    } else {
      buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    }
    return;
  }
  if (buckets_query_has(&c->q, "policy")) {
    if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    else if (buckets_str_eq_c(m, "GET")) get_bucket_policy(c);
    else if (buckets_str_eq_c(m, "PUT")) put_bucket_policy(c);
    else if (buckets_str_eq_c(m, "DELETE")) delete_bucket_policy(c);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  if (buckets_str_eq_c(m, "PUT")) {
    if (c->q.n > 0) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
    create_bucket(c);
    return;
  }

  if (!bucket_exists(c)) {
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    return;
  }
  if (buckets_str_eq_c(m, "HEAD")) {
    c->resp->status = 200;
    return;
  }
  if (buckets_str_eq_c(m, "DELETE")) {
    if (c->q.n > 0) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
    delete_bucket(c);
    return;
  }
  if (buckets_str_eq_c(m, "GET")) {
    if (buckets_query_has(&c->q, "location")) {
      get_bucket_location(c);
    } else if (buckets_query_has(&c->q, "versioning")) {
      get_bucket_versioning(c);
    } else if (buckets_query_has(&c->q, "uploads")) {
      buckets_s3_list_uploads(c);
    } else if (has_unhandled_subresource(&c->q)) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
    } else {
      const char *lt = buckets_query_get(&c->q, "list-type");
      buckets_s3_list_objects(c, lt && strcmp(lt, "2") == 0);
    }
    return;
  }
  if (buckets_str_eq_c(m, "POST")) {
    if (buckets_query_has(&c->q, "delete")) {
      buckets_s3_delete_objects(c);
    } else if (c->auth == BUCKETS_AUTH_POST_POLICY) {
      buckets_s3_post_policy(c);
    } else {
      buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    }
    return;
  }
  buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
}

/* ---- entry point --------------------------------------------------------- */

static bool is_health_path(buckets_str path) {
  static const char *const paths[] = {
      "/minio/health/live", "/minio/health/ready", "/minio/health/cluster", "/minio/health/cluster/read",
      "/buckets/health/live", "/buckets/health/ready", "/buckets/health/cluster", "/buckets/health/cluster/read",
  };
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(paths); i++) {
    if (buckets_str_eq_c(path, paths[i])) return true;
  }
  return false;
}

void buckets_s3_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_s3_server *s = ud;

  buckets_objlayer *layer = s->layer;
  if (is_health_path(req->path) && (buckets_str_eq_c(req->method, "GET") || buckets_str_eq_c(req->method, "HEAD"))) {
    /* live: the process answers. ready: initialized. cluster: every erasure
     * set has write (cluster/read: read) quorum of online drives. */
    bool live = buckets_str_has_suffix(req->path, "/live");
    bool cluster = buckets_str_has_suffix(req->path, "/cluster") || buckets_str_has_suffix(req->path, "/cluster/read");
    bool ok = live || (layer && (!cluster || buckets_objlayer_has_quorum(layer, !buckets_str_has_suffix(req->path, "/read"))));
    resp->status = ok ? 200 : 503;
    return;
  }

  s3_ctx c = {.s = s, .req = req, .resp = resp};
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  uint64_t nanos = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec + (s->request_seq++ % 1000);
  snprintf(c.request_id, sizeof(c.request_id), "%016llX", (unsigned long long)nanos);
  common_headers(&c);

  buckets_s3_error err;
  if (!buckets_query_parse(req->query, &c.q)) {
    err = BUCKETS_ERR_INVALID_QUERY_PARAMS;
    goto fail;
  }
  if (!layer) {
    err = BUCKETS_ERR_SERVER_NOT_INITIALIZED;
    goto fail;
  }
  if ((err = parse_path(&c)) != BUCKETS_ERR_NONE) goto fail;
  if (buckets_admin_is_admin_path(req->path)) {
    if ((err = authenticate(&c)) != BUCKETS_ERR_NONE) buckets_admin_error(&c, err);
    else buckets_admin_handle(&c);
    goto done;
  }
  c.auth = buckets_auth_classify(req, &c.q);
  if (buckets_sts_matches(&c)) {
    buckets_sts_handle(&c);
    goto done;
  }
  if (buckets_str_has_prefix(req->path, "/minio/")) {
    err = BUCKETS_ERR_NOT_IMPLEMENTED; /* metrics and other MinIO APIs come later */
    goto fail;
  }
  if ((err = authenticate(&c)) != BUCKETS_ERR_NONE) goto fail;

  if (!c.bucket) {
    if (buckets_str_eq_c(req->method, "GET")) {
      list_buckets(&c);
    } else {
      buckets_s3_write_error(&c, buckets_str_eq_c(req->method, "POST") ? BUCKETS_ERR_NOT_IMPLEMENTED
                                                             : BUCKETS_ERR_METHOD_NOT_ALLOWED);
    }
  } else if (!c.object) {
    route_bucket(&c);
  } else {
    buckets_s3_route_object(&c);
  }
  goto done;

fail:
  buckets_s3_write_error(&c, err);
done:
  buckets_log_debug("%.*s %.*s -> %d", BUCKETS_STR_ARG(req->method), BUCKETS_STR_ARG(req->target), resp->status);
  buckets_query_free(&c.q);
  free(c.path);
  free(c.bucket);
  free(c.object);
  buckets_buf_free(&c.doc);
  buckets_iam_ident_release(c.ident);
  buckets_s3_conds_free(c.conds);
}
