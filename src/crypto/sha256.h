/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_SHA256_H
#define BUCKETS_CRYPTO_SHA256_H

#include "core/common.h"

#define BUCKETS_SHA256_LEN 32
#define BUCKETS_SHA256_BLOCK 64

/* SHA-256 (OpenSSL underneath: hardware SHA instructions where available).
 * The context is a plain value: no allocation, nothing to free. */
typedef struct {
  uint64_t opaque[16];
} buckets_sha256_ctx;

void buckets_sha256_init(buckets_sha256_ctx *ctx);
void buckets_sha256_update(buckets_sha256_ctx *ctx, const void *data, size_t n);
void buckets_sha256_final(buckets_sha256_ctx *ctx, uint8_t out[BUCKETS_SHA256_LEN]);
void buckets_sha256(const void *data, size_t n, uint8_t out[BUCKETS_SHA256_LEN]);

void buckets_hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len,
                         uint8_t out[BUCKETS_SHA256_LEN]);

#endif
