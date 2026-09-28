/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SIGV2_H
#define BUCKETS_S3_SIGV2_H

#include "s3/sigv4.h"

/* AWS Signature Version 2 (MinIO cmd/signature-v2.go): "Authorization: AWS
 * AKID:base64(HMAC-SHA1)" and presigned ?AWSAccessKeyId=&Expires=&Signature=. */
buckets_s3_error buckets_sigv2_verify_header(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                             buckets_sigv4_result *out);
buckets_s3_error buckets_sigv2_verify_presigned(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                                buckets_sigv4_result *out);
/* base64(HMAC-SHA1(secret, string_to_sign)); out holds 29 bytes. */
void buckets_sigv2_sign(const char *secret, const char *string_to_sign, size_t n, char *out);

#endif
