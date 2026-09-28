/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_SHA1_H
#define BUCKETS_CRYPTO_SHA1_H

#include "core/common.h"

#define BUCKETS_SHA1_LEN 20

/* SHA-1, only for the S3 x-amz-checksum-sha1 integrity checksum. */
typedef struct {
  uint32_t state[5];
  uint64_t bytes;
  uint8_t block[64];
  size_t used;
} buckets_sha1_ctx;

void buckets_sha1_init(buckets_sha1_ctx *ctx);
void buckets_sha1_update(buckets_sha1_ctx *ctx, const void *data, size_t n);
void buckets_sha1_final(buckets_sha1_ctx *ctx, uint8_t out[BUCKETS_SHA1_LEN]);

/* HMAC-SHA1 (AWS Signature Version 2 and POST policy v2). */
void buckets_hmac_sha1(const void *key, size_t key_len, const void *msg, size_t msg_len,
                       uint8_t out[BUCKETS_SHA1_LEN]);

#endif
