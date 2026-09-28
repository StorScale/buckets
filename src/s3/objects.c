/* S3 object handlers: Put/Get/Head/Delete/Copy, DeleteObjects, ListObjects v1/v2.
 * Mirrors MinIO cmd/object-handlers.go, bucket-listobjects-handlers.go.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/log.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "s3/chunked.h"
#include "s3/internal.h"
#include "s3/xml.h"

/* ---- error mapping -------------------------------------------------------- */

buckets_s3_error buckets_s3_obj_error(buckets_obj_err e) {
  switch (e) {
    case BUCKETS_OBJ_OK: return BUCKETS_ERR_NONE;
    case BUCKETS_OBJ_ERR_NO_SUCH_BUCKET: return BUCKETS_ERR_NO_SUCH_BUCKET;
    case BUCKETS_OBJ_ERR_NO_SUCH_KEY: return BUCKETS_ERR_NO_SUCH_KEY;
    case BUCKETS_OBJ_ERR_NO_SUCH_VERSION: return BUCKETS_ERR_NO_SUCH_VERSION;
    case BUCKETS_OBJ_ERR_INVALID_NAME: return BUCKETS_ERR_INVALID_OBJECT_NAME;
    case BUCKETS_OBJ_ERR_NAME_TOO_LONG: return BUCKETS_ERR_KEY_TOO_LONG_ERROR;
    case BUCKETS_OBJ_ERR_NAME_PREFIX_SLASH: return BUCKETS_ERR_INVALID_OBJECT_NAME_PREFIX_SLASH;
    case BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY: return BUCKETS_ERR_OBJECT_EXISTS_AS_DIRECTORY;
    case BUCKETS_OBJ_ERR_BAD_DIGEST: return BUCKETS_ERR_BAD_DIGEST;
    case BUCKETS_OBJ_ERR_SHA256_MISMATCH: return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
    case BUCKETS_OBJ_ERR_INCOMPLETE_BODY: return BUCKETS_ERR_INCOMPLETE_BODY;
    case BUCKETS_OBJ_ERR_READER: return BUCKETS_ERR_INCOMPLETE_BODY;
    case BUCKETS_OBJ_ERR_CORRUPT: return BUCKETS_ERR_INTERNAL_ERROR;
    case BUCKETS_OBJ_ERR_IO: return BUCKETS_ERR_INTERNAL_ERROR;
  }
  return BUCKETS_ERR_INTERNAL_ERROR;
}

/* ---- helpers -------------------------------------------------------------- */

/* Go's http.CanonicalHeaderKey for ASCII token names. */
static void canonical_key(const char *in, char *out, size_t cap) {
  bool upper = true;
  size_t i = 0;
  for (; in[i] && i + 1 < cap; i++) {
    char ch = in[i];
    out[i] = upper ? (char)toupper((unsigned char)ch) : (char)tolower((unsigned char)ch);
    upper = ch == '-';
  }
  out[i] = '\0';
}

static bool has_prefix_fold(const char *s, const char *prefix) { return strncasecmp(s, prefix, strlen(prefix)) == 0; }

static bool is_hex64(const char *s) {
  if (strlen(s) != 64) return false;
  for (int i = 0; i < 64; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

static bool hex_decode32(const char *s, uint8_t out[32]) {
  if (!is_hex64(s)) return false;
  for (int i = 0; i < 32; i++) {
    unsigned v;
    sscanf(s + 2 * i, "%2x", &v);
    out[i] = (uint8_t)v;
  }
  return true;
}

static void add_kv(buckets_xl_kv **kvs, size_t *n, const char *key, buckets_str value) {
  /* Repeated headers join with ',' like Go's strings.Join(values, ","). */
  const buckets_xl_kv *have = buckets_xl_kv_get(*kvs, *n, key);
  if (have) {
    buckets_buf joined = BUCKETS_BUF_INIT;
    buckets_buf_append(&joined, have->value, have->value_len);
    buckets_buf_append_char(&joined, ',');
    buckets_buf_append_str(&joined, value);
    buckets_xl_kv_set(kvs, n, key, joined.data, joined.len);
    buckets_buf_free(&joined);
    return;
  }
  buckets_xl_kv_set(kvs, n, key, value.p ? value.p : "", value.n);
}

static void free_kvs(buckets_xl_kv *kvs, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(kvs[i].key);
    free(kvs[i].value);
  }
  free(kvs);
}

/* MinIO extractMetadata: supported headers under their MinIO spelling, user
 * metadata under the canonical header name, from query form then headers. */
static const char *const k_supported[] = {
    "content-type",        "cache-control", "content-language", "content-encoding", "content-disposition",
    "x-amz-storage-class", "X-Amz-Storage-Class", "X-Amz-Tagging", "expires",
};

static void extract_one(buckets_xl_kv **kvs, size_t *n, buckets_str name, buckets_str value) {
  char key[256];
  char *raw = buckets_str_dup(name);
  canonical_key(raw, key, sizeof(key));
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_supported); i++) {
    char want[64];
    canonical_key(k_supported[i], want, sizeof(want));
    if (strcmp(want, key) == 0) add_kv(kvs, n, k_supported[i], value);
  }
  if (has_prefix_fold(raw, "x-amz-meta-") || has_prefix_fold(raw, "x-minio-meta-")) add_kv(kvs, n, key, value);
  free(raw);
}

static buckets_s3_error extract_metadata(s3_ctx *c, buckets_xl_kv **kvs, size_t *n) {
  for (size_t i = 0; i < c->q.n; i++) {
    extract_one(kvs, n, buckets_str_c(c->q.items[i].key), buckets_str_c(c->q.items[i].value));
  }
  for (size_t i = 0; i < c->req->nheaders; i++) {
    extract_one(kvs, n, c->req->headers[i].name, c->req->headers[i].value);
  }
  if (!buckets_xl_kv_get(*kvs, *n, "content-type")) buckets_xl_kv_set(kvs, n, "content-type", "binary/octet-stream", 19);

  /* aws-chunked is a transfer detail, not the object's content encoding. */
  const buckets_xl_kv *ce = buckets_xl_kv_get(*kvs, *n, "content-encoding");
  if (ce) {
    buckets_buf kept = BUCKETS_BUF_INIT;
    buckets_str rest = {(const char *)ce->value, ce->value_len}, part;
    while (rest.n) {
      buckets_str_cut(rest, ',', &part, &rest);
      part = buckets_str_trim(part);
      if (part.n == 0 || buckets_str_eq_c(part, "aws-chunked")) continue;
      if (kept.len) buckets_buf_append_char(&kept, ',');
      buckets_buf_append_str(&kept, part);
    }
    if (kept.len) {
      buckets_xl_kv_set(kvs, n, "content-encoding", kept.data, kept.len);
    } else {
      for (size_t i = 0; i < *n; i++) {
        if (strcmp((*kvs)[i].key, "content-encoding") == 0) {
          free((*kvs)[i].key);
          free((*kvs)[i].value);
          (*kvs)[i] = (*kvs)[--*n];
          break;
        }
      }
    }
    buckets_buf_free(&kept);
  }

  const buckets_xl_kv *sc = buckets_xl_kv_get(*kvs, *n, "X-Amz-Storage-Class");
  if (sc) {
    const char *v = (const char *)sc->value;
    if (strcmp(v, "STANDARD") != 0 && strcmp(v, "REDUCED_REDUNDANCY") != 0) return BUCKETS_ERR_INVALID_STORAGE_CLASS;
    if (strcmp(v, "STANDARD") == 0) {
      for (size_t i = 0; i < *n; i++) {
        if (strcmp((*kvs)[i].key, "X-Amz-Storage-Class") == 0) {
          free((*kvs)[i].key);
          free((*kvs)[i].value);
          (*kvs)[i] = (*kvs)[--*n];
          break;
        }
      }
    }
  }
  return BUCKETS_ERR_NONE;
}

static bool parse_content_md5(s3_ctx *c, uint8_t out[16], bool *present, buckets_s3_error *err) {
  buckets_str h = buckets_http_header_get(c->req, "Content-MD5");
  *present = h.p != NULL;
  if (!h.p) return true;
  uint8_t tmp[19];
  if (h.n != 24 || buckets_base64_decode(h.p, h.n, tmp) != 16) {
    *err = BUCKETS_ERR_INVALID_DIGEST;
    return false;
  }
  memcpy(out, tmp, 16);
  return true;
}

static void etag_header(buckets_http_response *r, const char *etag) {
  buckets_http_resp_headerf(r, "ETag", "\"%s\"", etag);
}

/* ---- body sources --------------------------------------------------------- */

static long body_source(void *ud, void *buf, size_t n) { return buckets_http_body_read(ud, buf, n); }

static long reader_source(void *ud, void *buf, size_t n) { return buckets_obj_read(ud, buf, n); }

/* ---- PutObject ------------------------------------------------------------ */

static void copy_object(s3_ctx *c);

static void put_object(s3_ctx *c) {
  if (buckets_http_header_get(c->req, "X-Amz-Copy-Source").p) {
    copy_object(c);
    return;
  }
  buckets_s3_error serr = BUCKETS_ERR_NONE;
  uint8_t md5[16];
  bool has_md5;
  if (!parse_content_md5(c, md5, &has_md5, &serr)) {
    buckets_s3_write_error(c, serr);
    return;
  }

  int64_t size = c->req->body_len;
  buckets_chunked *ch = NULL;
  buckets_read_fn rd = body_source;
  buckets_http_body_cursor cur = {c->req, 0};
  void *rd_ud = &cur;
  uint8_t sha[32];
  bool want_sha = false;

  buckets_str mode = buckets_http_header_get(c->req, "X-Amz-Content-Sha256");
  if (mode.p && buckets_str_has_prefix(mode, "STREAMING-")) {
    ch = buckets_chunked_new(c->req, mode, c->auth == BUCKETS_AUTH_SIGV4_STREAMING ? &c->sig : NULL);
    if (!ch) {
      buckets_s3_write_error(c, BUCKETS_ERR_CONTENT_SHA256_MISMATCH);
      return;
    }
    buckets_str dl = buckets_http_header_get(c->req, "X-Amz-Decoded-Content-Length");
    char *s = dl.p ? buckets_str_dup(dl) : NULL;
    char *end = NULL;
    size = s ? strtoll(s, &end, 10) : -1;
    if (!s || !*s || *end || size < 0) size = -1;
    free(s);
    if (size < 0) {
      buckets_chunked_free(ch);
      buckets_s3_write_error(c, BUCKETS_ERR_MISSING_CONTENT_LENGTH);
      return;
    }
    rd = buckets_chunked_read;
    rd_ud = ch;
  } else if (c->sig.payload_hash[0] && strcmp(c->sig.payload_hash, BUCKETS_UNSIGNED_PAYLOAD) != 0) {
    if (!hex_decode32(c->sig.payload_hash, sha)) {
      buckets_s3_write_error(c, BUCKETS_ERR_CONTENT_SHA256_MISMATCH);
      return;
    }
    want_sha = true;
  }
  if (size > BUCKETS_S3_MAX_OBJECT_SIZE) {
    buckets_chunked_free(ch);
    buckets_s3_write_error(c, BUCKETS_ERR_ENTITY_TOO_LARGE);
    return;
  }

  buckets_xl_kv *meta = NULL;
  size_t nmeta = 0;
  if ((serr = extract_metadata(c, &meta, &nmeta)) != BUCKETS_ERR_NONE) {
    free_kvs(meta, nmeta);
    buckets_chunked_free(ch);
    buckets_s3_write_error(c, serr);
    return;
  }
  buckets_put_opts opts = {
      .meta = meta,
      .nmeta = nmeta,
      .want_md5 = has_md5 ? md5 : NULL,
      .want_sha256 = want_sha ? sha : NULL,
  };
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_put(c->s->drive, c->bucket, c->object, rd, rd_ud, size, &opts, &oi);
  free_kvs(meta, nmeta);
  if (err == BUCKETS_OBJ_ERR_READER && ch && buckets_chunked_error(ch)) {
    buckets_s3_write_error(c, buckets_chunked_error(ch));
  } else if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
  } else {
    etag_header(c->resp, oi.etag);
    c->resp->status = 200;
    buckets_object_info_free(&oi);
  }
  buckets_chunked_free(ch);
}

/* ---- GetObject / HeadObject ----------------------------------------------- */

typedef struct {
  bool present;
  bool suffix;
  int64_t start, end; /* end -1: open-ended; suffix: start = length */
} range_spec;

/* parseRequestRangeSpec: returns false only for errInvalidRange (416);
 * other malformed ranges are ignored like S3 does. */
static bool parse_range(buckets_str h, range_spec *rs) {
  memset(rs, 0, sizeof(*rs));
  if (!h.p || !buckets_str_has_prefix(h, "bytes=")) return true;
  char *s = buckets_xstrndup(h.p + 6, h.n - 6);
  char *dash = strchr(s, '-');
  bool ok = true;
  if (dash) {
    *dash = '\0';
    const char *a = s, *b = dash + 1;
    int64_t begin = -1, end = -1;
    char *e;
    bool valid = true;
    if (*a) {
      if (*a == '+' || !isdigit((unsigned char)*a)) valid = false;
      begin = strtoll(a, &e, 10);
      if (*e) valid = false;
    }
    if (*b) {
      if (*b == '+' || !isdigit((unsigned char)*b)) valid = false;
      end = strtoll(b, &e, 10);
      if (*e) valid = false;
    }
    if (valid) {
      if (begin > -1 && end > -1) {
        if (begin > end) ok = false;
        else *rs = (range_spec){true, false, begin, end};
      } else if (begin > -1) {
        *rs = (range_spec){true, false, begin, -1};
      } else if (end > -1) {
        if (end == 0) ok = false;
        else *rs = (range_spec){true, true, end, -1};
      }
    }
  }
  free(s);
  return ok;
}

/* GetOffsetLength. Returns false for an unsatisfiable range. */
static bool resolve_range(const range_spec *rs, int64_t size, int64_t *off, int64_t *len) {
  if (!rs->present) {
    *off = 0;
    *len = size;
    return true;
  }
  if (rs->suffix) {
    *len = BUCKETS_MIN(rs->start, size);
    *off = size - *len;
    return true;
  }
  if (rs->start >= size) return false;
  int64_t end = rs->end > -1 && rs->end < size ? rs->end : size - 1;
  *off = rs->start;
  *len = end - rs->start + 1;
  return true;
}

/* canonicalizeETag + isETagEqual */
static bool etag_matches(const char *etag, buckets_str given) {
  given = buckets_str_trim(given);
  if (buckets_str_eq_c(given, "*")) return true;
  while (given.n && given.p[0] == '"') {
    given.p++;
    given.n--;
  }
  while (given.n && given.p[given.n - 1] == '"') given.n--;
  return buckets_str_eq_c(given, etag);
}

static void write_object_headers_min(s3_ctx *c, const buckets_object_info *oi) {
  char lm[BUCKETS_TIME_HTTP_LEN + 1];
  buckets_time_http((time_t)(oi->mod_time_ns / 1000000000LL), lm);
  buckets_http_resp_header(c->resp, "Last-Modified", lm);
  if (oi->etag[0]) etag_header(c->resp, oi->etag);
  const char *cc = buckets_object_meta(oi, "cache-control");
  if (cc) buckets_http_resp_header(c->resp, "Cache-Control", cc);
}

/* checkPreconditions: returns true when a response was written. */
static bool check_preconditions(s3_ctx *c, const buckets_object_info *oi) {
  time_t mt = (time_t)(oi->mod_time_ns / 1000000000LL);
  buckets_str inm = buckets_http_header_get(c->req, "If-None-Match");
  if (inm.p && inm.n && etag_matches(oi->etag, inm)) {
    write_object_headers_min(c, oi);
    c->resp->status = 304;
    return true;
  }
  time_t t;
  buckets_str ims = buckets_http_header_get(c->req, "If-Modified-Since");
  if (ims.p && buckets_time_parse_http(ims, &t) && oi->mod_time_ns < (int64_t)(t + 1) * 1000000000LL) {
    write_object_headers_min(c, oi);
    c->resp->status = 304;
    return true;
  }
  buckets_str im = buckets_http_header_get(c->req, "If-Match");
  if (im.p && im.n && !etag_matches(oi->etag, im)) {
    write_object_headers_min(c, oi);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
    return true;
  }
  buckets_str ius = buckets_http_header_get(c->req, "If-Unmodified-Since");
  if (ius.p && !(im.p && im.n) && buckets_time_parse_http(ius, &t) &&
      oi->mod_time_ns >= (int64_t)(t + 1) * 1000000000LL) {
    write_object_headers_min(c, oi);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
    return true;
  }
  (void)mt;
  return false;
}

/* setObjectHeaders (user metadata as MinIO emits it). */
static void write_object_headers(s3_ctx *c, const buckets_object_info *oi) {
  write_object_headers_min(c, oi);
  for (size_t i = 0; i < oi->nmeta; i++) {
    const char *k = oi->meta[i].key;
    const char *v = (const char *)oi->meta[i].value;
    if (has_prefix_fold(k, BUCKETS_XL_RESERVED_PREFIX) || strcasecmp(k, "expires") == 0 ||
        strcasecmp(k, "cache-control") == 0) {
      continue;
    }
    if (has_prefix_fold(k, "x-amz-meta-") || has_prefix_fold(k, "x-minio-meta-")) {
      char lower[256];
      size_t j = 0;
      for (; k[j] && j + 1 < sizeof(lower); j++) lower[j] = (char)tolower((unsigned char)k[j]);
      lower[j] = '\0';
      buckets_http_resp_header(c->resp, lower, v);
    } else {
      char canon[256];
      canonical_key(k, canon, sizeof(canon));
      buckets_http_resp_header(c->resp, canon, v);
    }
  }
  const char *exp = buckets_object_meta(oi, "expires");
  time_t et;
  if (exp && buckets_time_parse_http(buckets_str_c(exp), &et)) {
    char buf[BUCKETS_TIME_HTTP_LEN + 1];
    buckets_time_http(et, buf);
    buckets_http_resp_header(c->resp, "Expires", buf);
  }
}

/* response-* query overrides (setHeadGetRespHeaders). */
static void response_overrides(s3_ctx *c) {
  static const struct {
    const char *param, *header;
  } map[] = {{"response-content-type", "Content-Type"},
             {"response-content-language", "Content-Language"},
             {"response-expires", "Expires"},
             {"response-cache-control", "Cache-Control"},
             {"response-content-disposition", "Content-Disposition"},
             {"response-content-encoding", "Content-Encoding"}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(map); i++) {
    const char *v = buckets_query_get(&c->q, map[i].param);
    if (v) buckets_http_resp_header(c->resp, map[i].header, v);
  }
}

static void reader_free(void *ud) { buckets_obj_reader_free(ud); }

static void get_object(s3_ctx *c, bool head) {
  const char *version = buckets_query_get(&c->q, "versionId");
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_stat(c->s->drive, c->bucket, c->object, version, &oi);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  if (check_preconditions(c, &oi)) {
    buckets_object_info_free(&oi);
    return;
  }
  range_spec rs;
  int64_t off = 0, len = oi.size;
  if (!parse_range(buckets_http_header_get(c->req, "Range"), &rs) || !resolve_range(&rs, oi.size, &off, &len)) {
    buckets_http_resp_headerf(c->resp, "Content-Range", "bytes */%lld", (long long)oi.size);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_RANGE);
    buckets_object_info_free(&oi);
    return;
  }

  buckets_obj_reader *r = NULL;
  if (!head) {
    buckets_object_info oi2;
    err = buckets_obj_open(c->s->drive, c->bucket, c->object, version, off, len, &r, &oi2);
    if (err) {
      buckets_object_info_free(&oi);
      buckets_s3_write_error(c, buckets_s3_obj_error(err));
      return;
    }
    buckets_object_info_free(&oi2);
  }
  write_object_headers(c, &oi);
  if (rs.present) {
    buckets_http_resp_headerf(c->resp, "Content-Range", "bytes %lld-%lld/%lld", (long long)off,
                              (long long)(off + len - 1), (long long)oi.size);
  }
  if (!head) response_overrides(c);
  c->resp->status = rs.present ? 206 : 200;
  c->resp->content_length = len;
  if (r) {
    c->resp->stream = (buckets_http_body_fn)reader_source;
    c->resp->stream_ud = r;
    c->resp->stream_free = reader_free;
  }
  buckets_object_info_free(&oi);
}

/* ---- DeleteObject --------------------------------------------------------- */

static void delete_object(s3_ctx *c) {
  const char *version = buckets_query_get(&c->q, "versionId");
  buckets_obj_err err = buckets_obj_delete(c->s->drive, c->bucket, c->object, version);
  /* S3 deletes are idempotent: a missing key still succeeds. */
  if (err && err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  c->resp->status = 204;
}

/* ---- CopyObject ----------------------------------------------------------- */

static void copy_object(s3_ctx *c) {
  buckets_str src_h = buckets_http_header_get(c->req, "X-Amz-Copy-Source");
  char *decoded = buckets_xmalloc(src_h.n + 1);
  long dn = buckets_url_decode(src_h, decoded, false);
  if (dn < 0) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_COPY_SOURCE);
    return;
  }
  decoded[dn] = '\0';
  char *path = decoded;
  char *version = NULL;
  char *q = strchr(path, '?');
  if (q) {
    *q = '\0';
    if (strncmp(q + 1, "versionId=", 10) == 0) version = q + 11;
  }
  while (*path == '/') path++;
  char *slash = strchr(path, '/');
  if (!slash || !slash[1]) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_COPY_SOURCE);
    return;
  }
  *slash = '\0';
  const char *src_bucket = path, *src_object = slash + 1;

  buckets_str directive = buckets_http_header_get(c->req, "X-Amz-Metadata-Directive");
  bool replace = directive.p && buckets_str_eq_c(directive, "REPLACE");
  if (directive.p && !replace && !buckets_str_eq_c(directive, "COPY")) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_METADATA_DIRECTIVE);
    return;
  }
  if (strcmp(src_bucket, c->bucket) == 0 && strcmp(src_object, c->object) == 0 && !replace &&
      !(version && *version)) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_COPY_DEST);
    return;
  }

  buckets_obj_reader *r = NULL;
  buckets_object_info src;
  buckets_obj_err err = buckets_obj_open(c->s->drive, src_bucket, src_object, version, 0, INT64_MAX, &r, &src);
  if (err) {
    free(decoded);
    buckets_s3_write_error(c, err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET ? BUCKETS_ERR_NO_SUCH_BUCKET
                                                                    : buckets_s3_obj_error(err));
    return;
  }

  /* x-amz-copy-source-if-* preconditions */
  buckets_str h;
  time_t t;
  bool failed = false;
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-Match")).p && !etag_matches(src.etag, h)) failed = true;
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-None-Match")).p && etag_matches(src.etag, h)) failed = true;
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-Modified-Since")).p && buckets_time_parse_http(h, &t) &&
      src.mod_time_ns < (int64_t)(t + 1) * 1000000000LL) {
    failed = true;
  }
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-Unmodified-Since")).p &&
      buckets_time_parse_http(h, &t) && src.mod_time_ns >= (int64_t)(t + 1) * 1000000000LL) {
    failed = true;
  }
  if (failed) {
    buckets_obj_reader_free(r);
    buckets_object_info_free(&src);
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
    return;
  }

  buckets_xl_kv *meta = NULL;
  size_t nmeta = 0;
  buckets_s3_error serr = BUCKETS_ERR_NONE;
  if (replace) {
    serr = extract_metadata(c, &meta, &nmeta);
  } else {
    for (size_t i = 0; i < src.nmeta; i++) {
      buckets_xl_kv_set(&meta, &nmeta, src.meta[i].key, src.meta[i].value, src.meta[i].value_len);
    }
  }
  buckets_object_info oi;
  if (!serr) {
    buckets_put_opts opts = {.meta = meta, .nmeta = nmeta};
    err = buckets_obj_put(c->s->drive, c->bucket, c->object, reader_source, r, src.size, &opts, &oi);
    serr = buckets_s3_obj_error(err);
  }
  free_kvs(meta, nmeta);
  buckets_obj_reader_free(r);
  buckets_object_info_free(&src);
  free(decoded);
  if (serr) {
    buckets_s3_write_error(c, serr);
    return;
  }
  char lm[BUCKETS_TIME_ISO8601_LEN + 1];
  buckets_time_iso8601((time_t)(oi.mod_time_ns / 1000000000LL), lm);
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "CopyObjectResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "LastModified", lm);
  buckets_buf_appendf(b, "<ETag>&quot;%s&quot;</ETag>", oi.etag);
  buckets_xml_close(b, "CopyObjectResult");
  buckets_s3_write_xml(c, 200);
  buckets_object_info_free(&oi);
}

/* ---- routing -------------------------------------------------------------- */

void buckets_s3_route_object(s3_ctx *c) {
  buckets_str m = c->req->method;
  static const char *const unsupported[] = {"uploads", "uploadId", "tagging", "retention", "legal-hold", "acl",
                                            "attributes", "select", "restore", "torrent", "partNumber"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(unsupported); i++) {
    if (buckets_query_has(&c->q, unsupported[i])) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
  }
  if (buckets_str_eq_c(m, "PUT")) {
    put_object(c);
  } else if (buckets_str_eq_c(m, "GET")) {
    get_object(c, false);
  } else if (buckets_str_eq_c(m, "HEAD")) {
    get_object(c, true);
  } else if (buckets_str_eq_c(m, "DELETE")) {
    delete_object(c);
  } else if (buckets_str_eq_c(m, "POST")) {
    buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
  } else {
    buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
  }
}

/* ---- DeleteObjects (POST ?delete) ----------------------------------------- */

#define MAX_DELETE_LIST 1000

void buckets_s3_delete_objects(s3_ctx *c) {
  buckets_s3_error err = buckets_s3_read_doc(c);
  if (err) {
    buckets_s3_write_error(c, err);
    return;
  }
  buckets_xml_doc doc;
  if (!buckets_xml_parse(buckets_buf_str(&c->doc), &doc) || !buckets_str_eq_c(doc.nodes[0].name, "Delete")) {
    if (doc.nodes) buckets_xml_doc_free(&doc);
    buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    return;
  }
  bool quiet = false;
  size_t qn = buckets_xml_child(&doc, 0, "Quiet");
  if (qn) quiet = buckets_str_eq_c(buckets_str_trim(doc.nodes[qn].text), "true");
  size_t count = 0;
  for (size_t i = doc.nodes[0].first_child; i; i = doc.nodes[i].next_sibling) {
    if (buckets_str_eq_c(doc.nodes[i].name, "Object")) count++;
  }
  if (count == 0 || count > MAX_DELETE_LIST) {
    buckets_xml_doc_free(&doc);
    buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    return;
  }

  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "DeleteResult", BUCKETS_S3_XMLNS);
  for (size_t i = doc.nodes[0].first_child; i; i = doc.nodes[i].next_sibling) {
    if (!buckets_str_eq_c(doc.nodes[i].name, "Object")) continue;
    size_t kn = buckets_xml_child(&doc, i, "Key"), vn = buckets_xml_child(&doc, i, "VersionId");
    buckets_buf key = BUCKETS_BUF_INIT, ver = BUCKETS_BUF_INIT;
    bool ok = kn && buckets_xml_unescape(doc.nodes[kn].text, &key) && key.len > 0 &&
              (!vn || buckets_xml_unescape(doc.nodes[vn].text, &ver));
    buckets_s3_error e = BUCKETS_ERR_NONE;
    if (!ok) {
      e = BUCKETS_ERR_INVALID_OBJECT_NAME;
    } else {
      buckets_obj_err oe = buckets_obj_delete(c->s->drive, c->bucket, key.data, ver.len ? ver.data : NULL);
      if (oe && oe != BUCKETS_OBJ_ERR_NO_SUCH_KEY && oe != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) e = buckets_s3_obj_error(oe);
    }
    if (e) {
      const buckets_s3_error_info *info = buckets_s3_error_get(e);
      buckets_xml_open(b, "Error");
      buckets_xml_elem(b, "Key", key.data ? key.data : "");
      if (ver.len) buckets_xml_elem(b, "VersionId", ver.data);
      buckets_xml_elem(b, "Code", info->code);
      buckets_xml_elem(b, "Message", info->message);
      buckets_xml_close(b, "Error");
    } else if (!quiet) {
      buckets_xml_open(b, "Deleted");
      buckets_xml_elem(b, "Key", key.data);
      if (ver.len) buckets_xml_elem(b, "VersionId", ver.data);
      buckets_xml_close(b, "Deleted");
    }
    buckets_buf_free(&key);
    buckets_buf_free(&ver);
  }
  buckets_xml_close(b, "DeleteResult");
  buckets_xml_doc_free(&doc);
  buckets_s3_write_xml(c, 200);
}

/* ---- ListObjects v1 / v2 -------------------------------------------------- */

/* s3URLEncode: like url.QueryEscape but '/' kept and space as %20. */
static void url_encode_key(buckets_buf *out, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~' || *p == '/') {
      buckets_buf_append_char(out, (char)*p);
    } else {
      char e[3] = {'%', hex[*p >> 4], hex[*p & 15]};
      buckets_buf_append(out, e, 3);
    }
  }
}

static void xml_key(buckets_buf *b, const char *tag, const char *value, bool url) {
  if (!url) {
    buckets_xml_elem(b, tag, value);
    return;
  }
  buckets_buf enc = BUCKETS_BUF_INIT;
  url_encode_key(&enc, value ? value : "");
  buckets_xml_elem(b, tag, enc.data ? enc.data : "");
  buckets_buf_free(&enc);
}

void buckets_s3_list_objects(s3_ctx *c, bool v2) {
  const char *max_keys_s = buckets_query_get(&c->q, "max-keys");
  long long max_keys = BUCKETS_MAX_LIST_KEYS;
  if (max_keys_s) {
    char *end = NULL;
    max_keys = strtoll(max_keys_s, &end, 10);
    if (!*max_keys_s || *end || max_keys < 0 || max_keys > 2147483647LL) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_MAX_KEYS);
      return;
    }
  }
  const char *encoding = buckets_query_get(&c->q, "encoding-type");
  if (encoding && *encoding && strcasecmp(encoding, "url") != 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ENCODING_METHOD);
    return;
  }
  bool url = encoding && *encoding;
  const char *prefix = buckets_query_get(&c->q, "prefix");
  const char *delimiter = buckets_query_get(&c->q, "delimiter");
  const char *start_after = v2 ? buckets_query_get(&c->q, "start-after") : NULL;
  const char *token = v2 ? buckets_query_get(&c->q, "continuation-token") : NULL;
  bool fetch_owner = v2 && buckets_query_get(&c->q, "fetch-owner") &&
                     strcmp(buckets_query_get(&c->q, "fetch-owner"), "true") == 0;

  /* v2 continuation tokens are the base64 of the next marker (as MinIO does). */
  char *marker = NULL;
  if (v2 && token) {
    size_t tl = strlen(token);
    uint8_t *dec = buckets_xmalloc(tl + 3);
    long n = tl ? buckets_base64_decode(token, tl, dec) : -1;
    if (n <= 0) {
      free(dec);
      buckets_s3_write_error(c, BUCKETS_ERR_INCORRECT_CONTINUATION_TOKEN);
      return;
    }
    marker = buckets_xstrndup((char *)dec, (size_t)n);
    free(dec);
  } else if (v2) {
    marker = start_after ? buckets_xstrdup(start_after) : NULL;
  } else {
    const char *m = buckets_query_get(&c->q, "marker");
    marker = m ? buckets_xstrdup(m) : NULL;
  }

  buckets_obj_listing l;
  buckets_obj_err err = buckets_obj_list(c->s->drive, c->bucket, prefix ? prefix : "", marker, delimiter,
                                         (int)BUCKETS_MIN(max_keys, BUCKETS_MAX_LIST_KEYS), &l);
  if (err) {
    free(marker);
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }

  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListBucketResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Name", c->bucket);
  xml_key(b, "Prefix", prefix, url);
  if (v2) {
    if (start_after) xml_key(b, "StartAfter", start_after, url);
    if (token) buckets_xml_elem(b, "ContinuationToken", token);
    buckets_buf_appendf(b, "<KeyCount>%zu</KeyCount>", l.nobjects + l.nprefixes);
  } else {
    xml_key(b, "Marker", buckets_query_get(&c->q, "marker"), url);
  }
  buckets_buf_appendf(b, "<MaxKeys>%lld</MaxKeys>", max_keys);
  if (delimiter) xml_key(b, "Delimiter", delimiter, url);
  if (url) buckets_xml_elem(b, "EncodingType", "url");
  buckets_xml_elem(b, "IsTruncated", l.truncated ? "true" : "false");
  if (l.truncated && l.next_marker) {
    if (v2) {
      size_t nl = strlen(l.next_marker);
      char *tok = buckets_xmalloc(4 * ((nl + 2) / 3) + 1);
      buckets_base64_encode((const uint8_t *)l.next_marker, nl, tok);
      buckets_xml_elem(b, "NextContinuationToken", tok);
      free(tok);
    } else if (delimiter && *delimiter) {
      xml_key(b, "NextMarker", l.next_marker, url);
    }
  }
  for (size_t i = 0; i < l.nobjects; i++) {
    const buckets_object_info *o = &l.objects[i];
    char lm[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601((time_t)(o->mod_time_ns / 1000000000LL), lm);
    buckets_xml_open(b, "Contents");
    xml_key(b, "Key", o->name, url);
    buckets_xml_elem(b, "LastModified", lm);
    buckets_buf_appendf(b, "<ETag>&quot;%s&quot;</ETag>", o->etag);
    buckets_buf_appendf(b, "<Size>%lld</Size>", (long long)o->size);
    if (!v2 || fetch_owner) {
      buckets_xml_open(b, "Owner");
      buckets_xml_elem(b, "ID", BUCKETS_S3_OWNER_ID);
      buckets_xml_elem(b, "DisplayName", BUCKETS_S3_OWNER_NAME);
      buckets_xml_close(b, "Owner");
    }
    const char *sc = buckets_object_meta(o, "X-Amz-Storage-Class");
    buckets_xml_elem(b, "StorageClass", sc ? sc : "STANDARD");
    buckets_xml_close(b, "Contents");
  }
  for (size_t i = 0; i < l.nprefixes; i++) {
    buckets_xml_open(b, "CommonPrefixes");
    xml_key(b, "Prefix", l.prefixes[i], url);
    buckets_xml_close(b, "CommonPrefixes");
  }
  buckets_xml_close(b, "ListBucketResult");
  buckets_obj_list_free(&l);
  free(marker);
  buckets_s3_write_xml(c, 200);
}
