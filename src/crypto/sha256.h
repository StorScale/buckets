/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_SHA256_H
#define BUCKETS_CRYPTO_SHA256_H

#include "core/common.h"

#define BUCKETS_SHA256_LEN 32
#define BUCKETS_SHA256_BLOCK 64

/* Portable SHA-256. Hot paths (object payload hashing) will move to a
 * multi-buffer SIMD implementation; this one is the reference. */
typedef struct {
  uint32_t state[8];
  uint64_t bytes;
  uint8_t block[BUCKETS_SHA256_BLOCK];
  size_t used;
} buckets_sha256_ctx;

void buckets_sha256_init(buckets_sha256_ctx *ctx);
void buckets_sha256_update(buckets_sha256_ctx *ctx, const void *data, size_t n);
void buckets_sha256_final(buckets_sha256_ctx *ctx, uint8_t out[BUCKETS_SHA256_LEN]);
void buckets_sha256(const void *data, size_t n, uint8_t out[BUCKETS_SHA256_LEN]);

void buckets_hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len,
                         uint8_t out[BUCKETS_SHA256_LEN]);

#endif
