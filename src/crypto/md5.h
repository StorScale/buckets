/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_MD5_H
#define BUCKETS_CRYPTO_MD5_H

#include "core/common.h"

#define BUCKETS_MD5_LEN 16

/* MD5 is only used for S3 ETags and Content-MD5; it is not a security primitive here, and comes from OpenSSL's
 * default provider even in FIPS mode. A context holds an allocation from init until final or cleanup. */
typedef struct {
  void *evp; /* an EVP_MD_CTX from init to final (or cleanup) */
} buckets_md5_ctx;

void buckets_md5_init(buckets_md5_ctx *ctx);
void buckets_md5_update(buckets_md5_ctx *ctx, const void *data, size_t n);
void buckets_md5_final(buckets_md5_ctx *ctx, uint8_t out[BUCKETS_MD5_LEN]);
/* Frees a context that was started but will not be finished; safe after final, and on a zeroed one. */
void buckets_md5_cleanup(buckets_md5_ctx *ctx);
void buckets_md5(const void *data, size_t n, uint8_t out[BUCKETS_MD5_LEN]);

#endif
