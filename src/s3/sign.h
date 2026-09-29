/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SIGN_H
#define BUCKETS_S3_SIGN_H

#include <time.h>

#include "core/buf.h"
#include "net/client.h"

/* A SigV4 client signer (the console BFF's proxy, replication later). */

typedef struct {
  const char *access_key, *secret_key;
  const char *session_token; /* NULL or "" for long-term keys */
  const char *region;        /* NULL: us-east-1 */
  const char *service;       /* NULL: s3 */
} buckets_sigv4_creds;

#define BUCKETS_SIGN_MAX_HEADERS 48

/* The headers to send: the request's own plus X-Amz-Date,
 * X-Amz-Content-Sha256, X-Amz-Security-Token and Authorization. */
typedef struct {
  buckets_http_kv kv[BUCKETS_SIGN_MAX_HEADERS];
  size_t n;
  char date[17];
  char payload[80];
  char auth[1536];
} buckets_sigv4_signed;

/* Signs method + raw (percent-encoded) path and query for host (as the Host
 * header carries it, "name:port"). hdrs are sent and signed as given;
 * payload_hash is the body's hex SHA-256 or "UNSIGNED-PAYLOAD". hdrs must
 * outlive out. False when there are too many headers. */
bool buckets_sigv4_sign(const buckets_sigv4_creds *cr, const char *method, const char *path, const char *query,
                        const char *host, const buckets_http_kv *hdrs, size_t nhdrs, const char *payload_hash, time_t now,
                        buckets_sigv4_signed *out);

/* A presigned URL's query (query-string SigV4, UNSIGNED-PAYLOAD, signing
 * only host) for method + raw path at host, valid for expires seconds:
 * "X-Amz-Algorithm=...&X-Amz-Signature=...". extra_query (raw, may be NULL)
 * is signed along. */
void buckets_sigv4_presign(const buckets_sigv4_creds *cr, const char *method, const char *path, const char *extra_query,
                           const char *host, int expires, time_t now, buckets_buf *query);

#endif
