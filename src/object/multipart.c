/* Multipart uploads for the single-drive object layer, laid out like MinIO
 * cmd/erasure-multipart.go so in-flight uploads survive a switch-over.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/log.h"
#include "core/msgpack.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "object/internal.h"
#include "object/object.h"

#define ACTUAL_SIZE_KEY "X-Minio-Internal-actual-size"

/* ---- paths ---------------------------------------------------------------- */

static char *sha_dir(buckets_drive *d, const char *bucket, const char *object) {
  buckets_buf key = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&key, "%s/%s", bucket, object);
  uint8_t sum[32];
  char hex[65];
  buckets_sha256(key.data, key.len, sum);
  buckets_hex_encode(sum, 32, hex);
  buckets_buf_free(&key);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/" BUCKETS_META_BUCKET "/multipart/%s", d->root, hex);
  return p.data;
}

/* Upload UUIDs look like "<uuid>x<nanos>"; anything else could escape the
 * multipart directory, so it is rejected before touching the filesystem. */
static bool safe_upload_uuid(const char *s) {
  if (!*s || strlen(s) > 80) return false;
  for (; *s; s++) {
    if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || *s == '-' || *s == 'x')) return false;
  }
  return true;
}

/* Returns <sha-dir>/<upload-uuid>, or NULL for a malformed upload ID. */
static char *upload_dir(buckets_drive *d, const char *bucket, const char *object, const char *upload_id) {
  size_t n = strlen(upload_id);
  if (n == 0 || n >= BUCKETS_UPLOAD_ID_MAX) return NULL;
  uint8_t *raw = buckets_xmalloc(n + 4);
  long rl = buckets_base64url_raw_decode(upload_id, n, raw);
  char *uuid = NULL;
  if (rl > 0) {
    char *dec = buckets_xstrndup((char *)raw, (size_t)rl);
    char *dot = strchr(dec, '.');
    if (dot && safe_upload_uuid(dot + 1)) uuid = buckets_xstrdup(dot + 1);
    free(dec);
  }
  free(raw);
  if (!uuid) return NULL;
  char *sd = sha_dir(d, bucket, object);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/%s", sd, uuid);
  free(sd);
  free(uuid);
  return p.data;
}

/* Loads the upload's xl.meta and decodes its (single) version. */
static buckets_obj_err load_upload(const char *dir, buckets_xl_object *o) {
  buckets_xlmeta x;
  buckets_objx_load_result lr = buckets_objx_load_xlmeta(dir, &x);
  if (lr == BUCKETS_OBJX_LOAD_MISSING) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  if (lr == BUCKETS_OBJX_LOAD_ERR) return BUCKETS_OBJ_ERR_CORRUPT;
  buckets_obj_err err = buckets_objx_pick_version(&x, NULL, o);
  buckets_xlmeta_free(&x);
  return err == BUCKETS_OBJ_ERR_NO_SUCH_KEY ? BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD : err;
}

/* ---- part.N.meta (ObjectPartInfo msgpack) --------------------------------- */

static void encode_part_meta(buckets_buf *b, const buckets_part_info *p) {
  buckets_mp_map(b, 5);
  buckets_mp_cstr(b, "e");
  buckets_mp_cstr(b, p->etag);
  buckets_mp_cstr(b, "n");
  buckets_mp_int(b, p->number);
  buckets_mp_cstr(b, "s");
  buckets_mp_int(b, p->size);
  buckets_mp_cstr(b, "as");
  buckets_mp_int(b, p->actual_size);
  buckets_mp_cstr(b, "mt");
  buckets_mp_time(b, p->mod_time_ns);
}

static bool decode_part_meta(const char *path, buckets_part_info *p) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  uint8_t buf[4096];
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n <= 0) return false;
  memset(p, 0, sizeof(*p));
  buckets_mp_reader r = buckets_mp_reader_init(buf, (size_t)n);
  uint32_t fields;
  if (!buckets_mp_read_map(&r, &fields)) return false;
  for (uint32_t i = 0; i < fields; i++) {
    buckets_str k, s;
    int64_t v;
    if (!buckets_mp_read_str(&r, &k)) return false;
    if (buckets_str_eq_c(k, "e")) {
      if (!buckets_mp_read_str(&r, &s) || s.n >= sizeof(p->etag)) return false;
      memcpy(p->etag, s.p, s.n);
      p->etag[s.n] = '\0';
    } else if (buckets_str_eq_c(k, "n")) {
      if (!buckets_mp_read_int(&r, &v)) return false;
      p->number = (int)v;
    } else if (buckets_str_eq_c(k, "s")) {
      if (!buckets_mp_read_int(&r, &p->size)) return false;
    } else if (buckets_str_eq_c(k, "as")) {
      if (!buckets_mp_read_int(&r, &p->actual_size)) return false;
    } else if (buckets_str_eq_c(k, "mt")) {
      if (!buckets_mp_read_time(&r, &p->mod_time_ns)) return false;
    } else if (!buckets_mp_skip(&r)) {
      return false;
    }
  }
  return !r.err;
}

static bool write_file_atomic(buckets_drive *d, const char *dst, const void *data, size_t n) {
  char *tmp = buckets_objx_tmp_path(d);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  bool ok = fd >= 0 && buckets_objx_write_full(fd, data, n) && fsync(fd) == 0;
  if (fd >= 0) close(fd);
  ok = ok && rename(tmp, dst) == 0;
  if (!ok) unlink(tmp);
  free(tmp);
  return ok;
}

/* ---- operations ----------------------------------------------------------- */

buckets_obj_err buckets_obj_mpu_new(buckets_drive *d, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                    size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  buckets_obj_err err = buckets_obj_check_name(object);
  if (err) return err;
  if ((err = buckets_objx_check_namespace(d, bucket, object)) != BUCKETS_OBJ_OK) return err;

  uint8_t data_dir[16];
  char data_dir_s[37];
  buckets_objx_new_data_dir(data_dir, data_dir_s);
  buckets_xl_object o;
  buckets_objx_init_version(&o, data_dir, 0);
  for (size_t i = 0; i < nmeta; i++) {
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, meta[i].key, meta[i].value, meta[i].value_len);
  }

  /* "<uuid>x<unix-nanos>" as in MinIO, wrapped with the deployment ID. */
  char uuid[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(uuid);
  char upload_uuid[80];
  snprintf(upload_uuid, sizeof(upload_uuid), "%sx%lld", uuid, (long long)o.mod_time);
  char plain[160];
  int pl = snprintf(plain, sizeof(plain), "%s.%s", d->deployment_id, upload_uuid);
  buckets_base64url_raw_encode((const uint8_t *)plain, (size_t)pl, upload_id);

  char *sd = sha_dir(d, bucket, object);
  buckets_buf dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&dir, "%s/%s", sd, upload_uuid);
  free(sd);

  buckets_xlmeta x = {0};
  buckets_buf enc = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(&o, &enc, &hdr);
  buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)enc.data, enc.len);
  if (buckets_objx_mkdir_all(dir.data) != 0) {
    err = BUCKETS_OBJ_ERR_IO;
  } else {
    err = buckets_objx_write_xlmeta(d, dir.data, &x);
  }
  buckets_xlmeta_free(&x);
  buckets_xl_object_free(&o);
  buckets_buf_free(&dir);
  return err;
}

buckets_obj_err buckets_obj_mpu_put_part(buckets_drive *d, const char *bucket, const char *object, const char *upload_id,
                                         int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  if (part_number < 1 || part_number > BUCKETS_MAX_PARTS) return BUCKETS_OBJ_ERR_INVALID_PART;
  char *dir = upload_dir(d, bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  buckets_xl_object up;
  buckets_obj_err err = load_upload(dir, &up);
  if (err) {
    free(dir);
    return err;
  }
  char data_dir[37];
  buckets_xl_version_id_string(up.data_dir, data_dir);
  buckets_xl_object_free(&up);

  char *tmp = buckets_objx_tmp_path(d);
  uint8_t md5[16];
  err = buckets_objx_write_data(d, rd, rd_ud, size, opts, false, tmp, data_dir, part_number, NULL, md5);
  if (!err) {
    buckets_buf from = BUCKETS_BUF_INIT, to_dir = BUCKETS_BUF_INIT, to = BUCKETS_BUF_INIT, meta = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&from, "%s/%s/part.%d", tmp, data_dir, part_number);
    buckets_buf_appendf(&to_dir, "%s/%s", dir, data_dir);
    buckets_buf_appendf(&to, "%s/part.%d", to_dir.data, part_number);
    buckets_part_info pi = {.number = part_number, .size = size, .actual_size = size,
                            .mod_time_ns = buckets_objx_now_ns()};
    buckets_hex_encode(md5, 16, pi.etag);
    if (buckets_objx_mkdir_all(to_dir.data) != 0 || rename(from.data, to.data) != 0) {
      err = errno == ENOENT ? BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD : BUCKETS_OBJ_ERR_IO;
    } else {
      buckets_buf enc = BUCKETS_BUF_INIT;
      encode_part_meta(&enc, &pi);
      buckets_buf_append_c(&meta, to.data);
      buckets_buf_append_c(&meta, ".meta");
      if (!write_file_atomic(d, meta.data, enc.data, enc.len)) err = BUCKETS_OBJ_ERR_IO;
      buckets_buf_free(&enc);
    }
    if (!err && out) *out = pi;
    buckets_buf_free(&from);
    buckets_buf_free(&to_dir);
    buckets_buf_free(&to);
    buckets_buf_free(&meta);
  }
  buckets_objx_rm_rf(tmp);
  free(tmp);
  free(dir);
  return err;
}

static int part_cmp(const void *a, const void *b) {
  return ((const buckets_part_info *)a)->number - ((const buckets_part_info *)b)->number;
}

/* All recorded parts of an upload, ascending by number. */
static buckets_obj_err read_parts(const char *dir, const char *data_dir, buckets_part_info **parts, size_t *n) {
  *parts = NULL;
  *n = 0;
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/%s", dir, data_dir);
  DIR *dh = opendir(p.data);
  if (!dh) {
    buckets_buf_free(&p);
    return BUCKETS_OBJ_OK; /* no parts yet */
  }
  size_t cap = 0;
  struct dirent *e;
  while ((e = readdir(dh))) {
    int num;
    char tail[8];
    if (sscanf(e->d_name, "part.%d%7s", &num, tail) != 2 || strcmp(tail, ".meta") != 0) continue;
    buckets_buf mp = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&mp, "%s/%s", p.data, e->d_name);
    buckets_part_info pi;
    bool ok = decode_part_meta(mp.data, &pi) && pi.number == num;
    buckets_buf_free(&mp);
    if (!ok) continue;
    if (*n == cap) {
      cap = cap ? cap * 2 : 16;
      *parts = buckets_xrealloc(*parts, cap * sizeof(buckets_part_info));
    }
    (*parts)[(*n)++] = pi;
  }
  closedir(dh);
  buckets_buf_free(&p);
  if (*n) qsort(*parts, *n, sizeof(buckets_part_info), part_cmp);
  return BUCKETS_OBJ_OK;
}

buckets_obj_err buckets_obj_mpu_list_parts(buckets_drive *d, const char *bucket, const char *object,
                                           const char *upload_id, int marker, int max, buckets_part_info **parts,
                                           size_t *n, bool *truncated) {
  *parts = NULL;
  *n = 0;
  *truncated = false;
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  char *dir = upload_dir(d, bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  buckets_xl_object up;
  buckets_obj_err err = load_upload(dir, &up);
  if (err) {
    free(dir);
    return err;
  }
  char data_dir[37];
  buckets_xl_version_id_string(up.data_dir, data_dir);
  buckets_xl_object_free(&up);
  buckets_part_info *all;
  size_t total;
  read_parts(dir, data_dir, &all, &total);
  free(dir);
  size_t start = 0;
  while (start < total && all[start].number <= marker) start++;
  size_t count = total - start;
  if (max >= 0 && count > (size_t)max) {
    count = (size_t)max;
    *truncated = true;
  }
  if (count) {
    *parts = buckets_xmalloc(count * sizeof(buckets_part_info));
    memcpy(*parts, all + start, count * sizeof(buckets_part_info));
  }
  *n = count;
  free(all);
  return BUCKETS_OBJ_OK;
}

static void prune_sha_dir(const char *upload_dir_path) {
  char *parent = buckets_xstrdup(upload_dir_path);
  char *slash = strrchr(parent, '/');
  if (slash) {
    *slash = '\0';
    rmdir(parent); /* only succeeds when no other uploads remain */
  }
  free(parent);
}

buckets_obj_err buckets_obj_mpu_abort(buckets_drive *d, const char *bucket, const char *object, const char *upload_id) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  char *dir = upload_dir(d, bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  buckets_xl_object up;
  buckets_obj_err err = load_upload(dir, &up);
  if (!err) {
    buckets_xl_object_free(&up);
    char *trash = buckets_objx_tmp_path(d);
    if (rename(dir, trash) == 0) {
      buckets_objx_rm_rf(trash);
      prune_sha_dir(dir);
    } else {
      err = BUCKETS_OBJ_ERR_IO;
    }
    free(trash);
  }
  free(dir);
  return err;
}

/* canonicalizeETag: strips surrounding quotes. */
static void canonical_etag(const char *in, char *out, size_t cap) {
  while (*in == '"') in++;
  size_t n = strlen(in);
  while (n && in[n - 1] == '"') n--;
  snprintf(out, cap, "%.*s", (int)n, in);
}

buckets_obj_err buckets_obj_mpu_complete(buckets_drive *d, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *req, size_t nreq,
                                         buckets_object_info *out) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  buckets_obj_err err = buckets_obj_check_name(object);
  if (err) return err;
  char *dir = upload_dir(d, bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  buckets_xl_object up;
  if ((err = load_upload(dir, &up)) != BUCKETS_OBJ_OK) {
    free(dir);
    return err;
  }
  if ((err = buckets_objx_check_namespace(d, bucket, object)) != BUCKETS_OBJ_OK) {
    buckets_xl_object_free(&up);
    free(dir);
    return err;
  }
  char data_dir[37];
  buckets_xl_version_id_string(up.data_dir, data_dir);
  buckets_part_info *have;
  size_t nhave;
  read_parts(dir, data_dir, &have, &nhave);

  buckets_xl_object o;
  buckets_objx_init_version(&o, up.data_dir, 0);
  buckets_md5_ctx etag_md5;
  buckets_md5_init(&etag_md5);
  int64_t total = 0;
  if (nreq == 0) err = BUCKETS_OBJ_ERR_INVALID_PART;
  for (size_t i = 0; i < nreq && !err; i++) {
    if (i > 0 && req[i].number <= req[i - 1].number) {
      err = BUCKETS_OBJ_ERR_INVALID_PART_ORDER;
      break;
    }
    const buckets_part_info *p = NULL;
    for (size_t j = 0; j < nhave; j++) {
      if (have[j].number == req[i].number) p = &have[j];
    }
    char want[80];
    canonical_etag(req[i].etag ? req[i].etag : "", want, sizeof(want));
    if (!p || strcmp(p->etag, want) != 0) {
      err = BUCKETS_OBJ_ERR_INVALID_PART;
      break;
    }
    if (i + 1 < nreq && p->actual_size < BUCKETS_MIN_PART_SIZE) {
      err = BUCKETS_OBJ_ERR_PART_TOO_SMALL;
      break;
    }
    uint8_t raw[16];
    for (int k = 0; k < 16; k++) {
      unsigned v;
      sscanf(p->etag + 2 * k, "%2x", &v);
      raw[k] = (uint8_t)v;
    }
    buckets_md5_update(&etag_md5, raw, 16);
    buckets_xl_part_add(&o, p->number, p->size, p->actual_size, NULL);
    total += p->size;
  }

  if (!err) {
    o.size = total;
    for (size_t i = 0; i < up.nmeta_user; i++) {
      buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, up.meta_user[i].key, up.meta_user[i].value,
                        up.meta_user[i].value_len);
    }
    uint8_t sum[16];
    char etag[48];
    buckets_md5_final(&etag_md5, sum);
    buckets_hex_encode(sum, 16, etag);
    snprintf(etag + 32, sizeof(etag) - 32, "-%zu", nreq);
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", etag, strlen(etag));
    char actual[32];
    int al = snprintf(actual, sizeof(actual), "%lld", (long long)total);
    buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, ACTUAL_SIZE_KEY, actual, (size_t)al);

    /* Drop part.N.meta files and parts the client left out, then install. */
    buckets_buf pd = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&pd, "%s/%s", dir, data_dir);
    for (size_t j = 0; j < nhave; j++) {
      buckets_buf f = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&f, "%s/part.%d.meta", pd.data, have[j].number);
      unlink(f.data);
      bool used = false;
      for (size_t i = 0; i < nreq; i++) used |= req[i].number == have[j].number;
      if (!used) {
        buckets_buf_reset(&f);
        buckets_buf_appendf(&f, "%s/part.%d", pd.data, have[j].number);
        unlink(f.data);
      }
      buckets_buf_free(&f);
    }
    err = buckets_objx_commit(d, bucket, object, &o, NULL, pd.data, out);
    buckets_buf_free(&pd);
    if (!err) {
      buckets_objx_rm_rf(dir);
      prune_sha_dir(dir);
    }
  }
  buckets_xl_object_free(&o);
  buckets_xl_object_free(&up);
  free(have);
  free(dir);
  return err;
}

buckets_obj_err buckets_obj_mpu_list_uploads(buckets_drive *d, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n) {
  *uploads = NULL;
  *n = 0;
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  if (!object || !*object || buckets_obj_check_name(object) != BUCKETS_OBJ_OK) return BUCKETS_OBJ_OK;
  char *sd = sha_dir(d, bucket, object);
  DIR *dh = opendir(sd);
  if (!dh) {
    free(sd);
    return BUCKETS_OBJ_OK;
  }
  struct dirent *e;
  size_t cap = 0;
  while ((e = readdir(dh))) {
    if (!safe_upload_uuid(e->d_name)) continue;
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p, "%s/%s", sd, e->d_name);
    buckets_xl_object up;
    if (load_upload(p.data, &up) == BUCKETS_OBJ_OK) {
      if (*n == cap) {
        cap = cap ? cap * 2 : 8;
        *uploads = buckets_xrealloc(*uploads, cap * sizeof(buckets_upload_info));
      }
      buckets_upload_info *u = &(*uploads)[(*n)++];
      u->object = buckets_xstrdup(object);
      u->initiated_ns = up.mod_time;
      char plain[160];
      int pl = snprintf(plain, sizeof(plain), "%s.%s", d->deployment_id, e->d_name);
      buckets_base64url_raw_encode((const uint8_t *)plain, (size_t)pl, u->upload_id);
      buckets_xl_object_free(&up);
    }
    buckets_buf_free(&p);
  }
  closedir(dh);
  free(sd);
  return BUCKETS_OBJ_OK;
}

void buckets_upload_info_free(buckets_upload_info *u, size_t n) {
  for (size_t i = 0; i < n; i++) free(u[i].object);
  free(u);
}
