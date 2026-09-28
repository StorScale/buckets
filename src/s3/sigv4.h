/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SIGV4_H
#define BUCKETS_S3_SIGV4_H

#include <time.h>

#include "core/buf.h"
#include "core/query.h"
#include "net/http.h"
#include "s3/errors.h"

/* AWS Signature Version 4, following MinIO's cmd/signature-v4*.go semantics. */

#define BUCKETS_SIGV4_ALGORITHM "AWS4-HMAC-SHA256"
#define BUCKETS_UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"
#define BUCKETS_EMPTY_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define BUCKETS_MAX_SKEW_SECONDS (15 * 60)
#define BUCKETS_MAX_PRESIGN_EXPIRES 604800
#define BUCKETS_SIGV4_AMZ_DATE_LEN 16

typedef enum {
  BUCKETS_AUTH_ANONYMOUS,
  BUCKETS_AUTH_SIGV4_HEADER,
  BUCKETS_AUTH_SIGV4_PRESIGNED,
  BUCKETS_AUTH_SIGV4_STREAMING, /* STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER] */
  BUCKETS_AUTH_SIGV2,
  BUCKETS_AUTH_SIGV2_PRESIGNED,
  BUCKETS_AUTH_POST_POLICY,
  BUCKETS_AUTH_JWT,
  BUCKETS_AUTH_UNKNOWN,
} buckets_auth_type;

buckets_auth_type buckets_auth_classify(const buckets_http_request *req, const buckets_query *q);

/* Returns the secret key for an access key, or NULL if unknown. */
/* Copies the secret key for access_key into secret (NUL-terminated);
 * false for unknown or disabled keys. Called from request threads. */
#define BUCKETS_SECRET_MAX 256
typedef bool (*buckets_secret_lookup)(void *ud, buckets_str access_key, char secret[BUCKETS_SECRET_MAX]);

typedef struct {
  const char *region;  /* configured region; "" accepts any */
  const char *service; /* "s3" or "sts" */
  time_t now;
  buckets_secret_lookup lookup;
  void *lookup_ud;
} buckets_sigv4_config;

typedef struct {
  char access_key[256];
  /* Hex SHA-256 the body must match, "UNSIGNED-PAYLOAD", or a STREAMING-* marker. */
  char payload_hash[80];
  /* Needed to verify aws-chunked chunk signatures, which chain from the seed. */
  char amz_date[BUCKETS_SIGV4_AMZ_DATE_LEN + 1];
  char scope[128]; /* date/region/service/aws4_request */
  uint8_t signing_key[32];
  char seed_signature[65];
} buckets_sigv4_result;

buckets_s3_error buckets_sigv4_verify_header(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                             const buckets_query *q, buckets_sigv4_result *out);
buckets_s3_error buckets_sigv4_verify_presigned(const buckets_sigv4_config *cfg,
                                                const buckets_http_request *req, const buckets_query *q,
                                                buckets_sigv4_result *out);

/* Building blocks, exposed for tests and for the SigV4 client used by
 * replication and the console BFF. */
bool buckets_sigv4_canonical_uri(buckets_str raw_path, buckets_buf *out);
void buckets_sigv4_canonical_query(const buckets_query *q, bool skip_signature, buckets_buf *out);
void buckets_sigv4_signing_key(const char *secret, buckets_str date8, buckets_str region, const char *service,
                               uint8_t key[32]);

#endif
