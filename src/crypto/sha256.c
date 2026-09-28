/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SHA-256 on OpenSSL's block function, which uses the CPU's SHA extensions
 * (ARMv8, SHA-NI) where present. The low-level API is deprecated in OpenSSL 3
 * but needs no allocation, which the value-type context here relies on. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "crypto/sha256.h"

#include <openssl/sha.h>
#include <string.h>

_Static_assert(sizeof(SHA256_CTX) <= sizeof(((buckets_sha256_ctx *)0)->opaque), "SHA256_CTX does not fit");

void buckets_sha256_init(buckets_sha256_ctx *ctx) { SHA256_Init((SHA256_CTX *)ctx->opaque); }

void buckets_sha256_update(buckets_sha256_ctx *ctx, const void *data, size_t n) {
  if (n) SHA256_Update((SHA256_CTX *)ctx->opaque, data, n);
}

void buckets_sha256_final(buckets_sha256_ctx *ctx, uint8_t out[BUCKETS_SHA256_LEN]) {
  SHA256_Final(out, (SHA256_CTX *)ctx->opaque);
}

void buckets_sha256(const void *data, size_t n, uint8_t out[BUCKETS_SHA256_LEN]) {
  buckets_sha256_ctx ctx;
  buckets_sha256_init(&ctx);
  buckets_sha256_update(&ctx, data, n);
  buckets_sha256_final(&ctx, out);
}

void buckets_hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len,
                         uint8_t out[BUCKETS_SHA256_LEN]) {
  uint8_t k[BUCKETS_SHA256_BLOCK] = {0};
  if (key_len > BUCKETS_SHA256_BLOCK) {
    buckets_sha256(key, key_len, k);
  } else if (key_len) {
    memcpy(k, key, key_len);
  }
  uint8_t ipad[BUCKETS_SHA256_BLOCK], opad[BUCKETS_SHA256_BLOCK];
  for (int i = 0; i < BUCKETS_SHA256_BLOCK; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  uint8_t inner[BUCKETS_SHA256_LEN];
  buckets_sha256_ctx ctx;
  buckets_sha256_init(&ctx);
  buckets_sha256_update(&ctx, ipad, sizeof(ipad));
  buckets_sha256_update(&ctx, msg, msg_len);
  buckets_sha256_final(&ctx, inner);
  buckets_sha256_init(&ctx);
  buckets_sha256_update(&ctx, opad, sizeof(opad));
  buckets_sha256_update(&ctx, inner, sizeof(inner));
  buckets_sha256_final(&ctx, out);
}
