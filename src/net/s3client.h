/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_S3CLIENT_H
#define BUCKETS_NET_S3CLIENT_H

#include "core/buf.h"
#include "net/client.h"
#include "net/tls.h"

/* An S3 client for remote MinIO/Buckets (or any S3) endpoints: bucket
 * replication targets, remote tiers and batch jobs (MinIO uses minio-go for
 * these). Requests are path-style and SigV4-signed; payloads are either
 * hashed (small documents) or sent as UNSIGNED-PAYLOAD (streams). */

typedef struct buckets_s3c buckets_s3c;

typedef struct {
  const char *endpoint; /* "host[:port]" */
  bool secure;
  const char *access_key, *secret_key, *session_token;
  const char *region;     /* NULL or "": us-east-1 */
  buckets_tls_client *tls; /* for secure endpoints (borrowed); NULL: system roots */
  int timeout_ms;          /* 0: 5 minutes */
  const char *app_info;    /* appended to the User-Agent (minio-go SetAppInfo), or NULL */
} buckets_s3c_config;

buckets_s3c *buckets_s3c_new(const buckets_s3c_config *cfg);
void buckets_s3c_free(buckets_s3c *c);
const char *buckets_s3c_endpoint(const buckets_s3c *c);
bool buckets_s3c_secure(const buckets_s3c *c);

typedef struct {
  int status;               /* 0: the request never got a response */
  buckets_buf headers;      /* raw "Name: value\r\n" lines */
  buckets_buf body;         /* the response body (not for streamed GETs) */
  char code[64];            /* S3 error code (from the XML body or x-minio-error-code), or "" */
  char message[512];        /* S3 error message, or the transport failure */
  bool network;             /* a transport failure (minio.IsNetworkOrHostDown) */
} buckets_s3c_result;

void buckets_s3c_result_free(buckets_s3c_result *r);
const char *buckets_s3c_header(const buckets_s3c_result *r, const char *name, size_t *len);
/* A header value copied into out (""). */
void buckets_s3c_header_copy(const buckets_s3c_result *r, const char *name, char *out, size_t cap);
/* True for a 2xx response. */
bool buckets_s3c_ok(const buckets_s3c_result *r);
/* A Go-style description of a failed call ("<message>" or the transport error). */
const char *buckets_s3c_error(const buckets_s3c_result *r);

/* One request. bucket and object may be NULL; query is raw
 * ("versionId=...&tagging="), may be NULL. The body comes from
 * body/body_len (hashed) or, when rd is set, is streamed (body_len bytes,
 * unsigned). The whole response body is read into res->body. Returns
 * buckets_s3c_ok(res). */
bool buckets_s3c_do(buckets_s3c *c, const char *method, const char *bucket, const char *object, const char *query,
                    const buckets_http_kv *hdrs, size_t nhdrs, const void *body, size_t body_len,
                    buckets_s3c_result *res);
bool buckets_s3c_do_stream(buckets_s3c *c, const char *method, const char *bucket, const char *object,
                           const char *query, const buckets_http_kv *hdrs, size_t nhdrs, buckets_http_read_fn rd,
                           void *rd_ud, int64_t body_len, buckets_s3c_result *res);
/* A GET whose body is read by the caller: NULL on failure (res says why),
 * else a stream for buckets_http_stream_read / buckets_http_stream_free
 * (res holds status and headers). */
buckets_http_stream *buckets_s3c_open(buckets_s3c *c, const char *method, const char *bucket, const char *object,
                                      const char *query, const buckets_http_kv *hdrs, size_t nhdrs,
                                      buckets_s3c_result *res);

/* GET <scheme>://<endpoint>/minio/health/<which> without credentials, with
 * a timeout; the response's X-Amz-Request-Id-Host... headers in res. */
bool buckets_s3c_health(buckets_s3c *c, const char *which, int timeout_ms, buckets_s3c_result *res);

/* Headers shared by callers. */
#define BUCKETS_H_REPL_STATUS "X-Amz-Replication-Status"
#define BUCKETS_H_SRC_MTIME "X-Minio-Source-Mtime"
#define BUCKETS_H_SRC_ETAG "X-Minio-Source-Etag"
#define BUCKETS_H_SRC_DELETE_MARKER "X-Minio-Source-DeleteMarker"
#define BUCKETS_H_SRC_PROXY "X-Minio-Source-Proxy-Request"
#define BUCKETS_H_SRC_REPL_REQUEST "X-Minio-Source-Replication-Request"
#define BUCKETS_H_SRC_REPL_CHECK "X-Minio-Source-Replication-Check"
#define BUCKETS_H_SRC_TAG_TS "X-Minio-Source-Replication-Tagging-Timestamp"
#define BUCKETS_H_SRC_RET_TS "X-Minio-Source-Replication-Retention-Timestamp"
#define BUCKETS_H_SRC_LH_TS "X-Minio-Source-Replication-LegalHold-Timestamp"
#define BUCKETS_H_REPL_READY "X-Minio-Replication-Ready"
#define BUCKETS_H_CHECK_REPL_READY "X-Minio-Check-Replication-Ready"
#define BUCKETS_H_REPL_ACTUAL_SIZE "X-Minio-Replication-Actual-Object-Size"
#define BUCKETS_H_REPL_SSEC_CRC "X-Minio-Replication-Ssec-Crc"

#endif
