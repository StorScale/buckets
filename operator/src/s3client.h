/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_S3CLIENT_H
#define BUCKETS_OPERATOR_S3CLIENT_H

#include "core/buf.h"

/* A SigV4-signing client for one Buckets cluster's S3 and admin APIs, as
 * the operator uses them to apply BucketsUser, BucketsPolicy and Bucket. */
typedef struct s3c s3c;

/* url: http(s)://host[:port]; ca_file may be NULL (system roots). */
s3c *s3c_new(const char *url, const char *ca_file, const char *access_key, const char *secret_key, char *err,
             size_t errlen);
void s3c_free(s3c *c);

/* One signed request. path is raw (already percent-encoded), query is
 * "k=v&..." (encoded) or NULL. Returns the HTTP status, 0 on a transport
 * failure; the body goes to out (may be NULL). */
int s3c_request(s3c *c, const char *method, const char *path, const char *query, const char *content_type,
                const void *body, size_t len, buckets_buf *out);

/* An admin API call (/minio/admin/v3/<api>): with encrypt, the body is
 * madmin-encrypted with the secret key, and so is decrypt for the reply. */
int s3c_admin(s3c *c, const char *method, const char *api, const char *query, const void *body, size_t len,
              bool encrypt, bool decrypt, buckets_buf *out);

/* The "Code" of an admin JSON error body (or the S3 XML one), or "". */
void s3c_error_code(const buckets_buf *body, char *out, size_t cap);

#endif
