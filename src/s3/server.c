/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/server.h"

#include <ctype.h>
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
#include "s3/bucketname.h"
#include "s3/errors.h"
#include "s3/sigv4.h"
#include "s3/internal.h"
#include "s3/xml.h"

#define DEFAULT_REGION "us-east-1"


void buckets_s3_server_init(buckets_s3_server *s, buckets_drive *drive, const char *root_user,
                            const char *root_password, const char *region) {
  memset(s, 0, sizeof(*s));
  s->drive = drive;
  s->root_user = root_user;
  s->root_password = root_password;
  s->region = region ? region : "";
  uint8_t h[32];
  buckets_sha256(drive->drive_id, strlen(drive->drive_id), h);
  buckets_hex_encode(h, 32, s->host_id);
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

void buckets_s3_write_error(s3_ctx *c, buckets_s3_error e) {
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  c->resp->status = info->status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
  buckets_buf_reset(&c->resp->body);
  buckets_s3_error_xml(&c->resp->body, e, c->path ? c->path : "/", c->bucket, c->object, c->request_id,
                       c->s->host_id);
}

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

static const char *lookup_secret(void *ud, buckets_str access_key) {
  buckets_s3_server *s = ud;
  /* IAM (users, service accounts, STS) replaces this root-only lookup. */
  if (buckets_str_eq_c(access_key, s->root_user)) return s->root_password;
  return NULL;
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
      .lookup = lookup_secret,
      .lookup_ud = c->s,
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
    case BUCKETS_AUTH_ANONYMOUS:
      /* Anonymous access is governed by bucket policies, which are not implemented yet. */
      return BUCKETS_ERR_ACCESS_DENIED;
    case BUCKETS_AUTH_SIGV2:
    case BUCKETS_AUTH_SIGV2_PRESIGNED:
    case BUCKETS_AUTH_POST_POLICY:
    case BUCKETS_AUTH_JWT:
      return BUCKETS_ERR_NOT_IMPLEMENTED;
    default:
      return BUCKETS_ERR_SIGNATURE_VERSION_NOT_SUPPORTED;
  }
  if (err != BUCKETS_ERR_NONE) return err;
  snprintf(c->access_key, sizeof(c->access_key), "%s", res->access_key);
  return BUCKETS_ERR_NONE;
}

/* ---- service-level handlers ---------------------------------------------- */

static void list_buckets(s3_ctx *c) {
  buckets_vol_info *vols;
  size_t n;
  if (buckets_drive_list_vols(c->s->drive, &vols, &n) != BUCKETS_DRIVE_OK) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
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
    char ts[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601(vols[i].created, ts);
    buckets_xml_open(b, "Bucket");
    buckets_xml_elem(b, "Name", vols[i].name);
    buckets_xml_elem(b, "CreationDate", ts);
    buckets_xml_close(b, "Bucket");
  }
  buckets_xml_close(b, "Buckets");
  buckets_xml_close(b, "ListAllMyBucketsResult");
  buckets_vol_info_free(vols, n);
  buckets_s3_write_xml(c, 200);
}

/* ---- bucket-level handlers ----------------------------------------------- */

static bool bucket_exists(s3_ctx *c) {
  return buckets_drive_stat_vol(c->s->drive, c->bucket, NULL) == BUCKETS_DRIVE_OK;
}

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

  switch (buckets_drive_make_vol(c->s->drive, c->bucket)) {
    case BUCKETS_DRIVE_OK:
      buckets_http_resp_headerf(c->resp, "Location", "/%s", c->bucket);
      c->resp->status = 200;
      return;
    case BUCKETS_DRIVE_ERR_EXISTS:
      buckets_s3_write_error(c, BUCKETS_ERR_BUCKET_ALREADY_OWNED_BY_YOU);
      return;
    default:
      buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
      return;
  }
}

static void delete_bucket(s3_ctx *c) {
  switch (buckets_drive_delete_vol(c->s->drive, c->bucket)) {
    case BUCKETS_DRIVE_OK: c->resp->status = 204; return;
    case BUCKETS_DRIVE_ERR_NOT_FOUND: buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET); return;
    case BUCKETS_DRIVE_ERR_NOT_EMPTY: buckets_s3_write_error(c, BUCKETS_ERR_BUCKET_NOT_EMPTY); return;
    default: buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR); return;
  }
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

/* Query keys that select a bucket sub-resource (as opposed to list parameters). */
static bool has_unhandled_subresource(const buckets_query *q) {
  static const char *const list_params[] = {"prefix",     "delimiter",          "marker",      "max-keys",
                                            "encoding-type", "list-type",       "continuation-token",
                                            "fetch-owner", "start-after"};
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
    } else {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED); /* POST policy uploads */
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

  if (is_health_path(req->path) && (buckets_str_eq_c(req->method, "GET") || buckets_str_eq_c(req->method, "HEAD"))) {
    /* Single drive: if we are serving, we have quorum. */
    resp->status = 200;
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
  if ((err = parse_path(&c)) != BUCKETS_ERR_NONE) goto fail;
  if (buckets_str_has_prefix(req->path, "/minio/")) {
    err = BUCKETS_ERR_NOT_IMPLEMENTED; /* admin, STS, metrics and peer APIs come later */
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
}
