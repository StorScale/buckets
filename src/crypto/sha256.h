/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_SHA256_H
#define BUCKETS_CRYPTO_SHA256_H

#include "core/common.h"

#define BUCKETS_SHA256_LEN 32
#define BUCKETS_SHA256_BLOCK 64

/* SHA-256 through OpenSSL's EVP interface: the FIPS provider in FIPS mode (crypto/fips.h), hardware SHA
 * instructions where available. A context holds an allocation from init until final or cleanup. */
typedef struct {
  void *evp; /* an EVP_MD_CTX from init to final (or cleanup) */
} buckets_sha256_ctx;

void buckets_sha256_init(buckets_sha256_ctx *ctx);
void buckets_sha256_update(buckets_sha256_ctx *ctx, const void *data, size_t n);
void buckets_sha256_final(buckets_sha256_ctx *ctx, uint8_t out[BUCKETS_SHA256_LEN]);
/* Frees a context that was started but will not be finished; safe after final, and on a zeroed one. */
void buckets_sha256_cleanup(buckets_sha256_ctx *ctx);
void buckets_sha256(const void *data, size_t n, uint8_t out[BUCKETS_SHA256_LEN]);

void buckets_hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len,
                         uint8_t out[BUCKETS_SHA256_LEN]);

#endif
