/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_MD5_H
#define BUCKETS_CRYPTO_MD5_H

#include "core/common.h"

#define BUCKETS_MD5_LEN 16

/* MD5 is only used for S3 ETags and Content-MD5; it is not a security primitive here. */
typedef struct {
  uint64_t opaque[16]; /* OpenSSL's MD5_CTX; a plain value, nothing to free */
} buckets_md5_ctx;

void buckets_md5_init(buckets_md5_ctx *ctx);
void buckets_md5_update(buckets_md5_ctx *ctx, const void *data, size_t n);
void buckets_md5_final(buckets_md5_ctx *ctx, uint8_t out[BUCKETS_MD5_LEN]);
void buckets_md5(const void *data, size_t n, uint8_t out[BUCKETS_MD5_LEN]);

#endif
