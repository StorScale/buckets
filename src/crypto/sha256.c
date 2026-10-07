/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SHA-256 and HMAC-SHA256 through EVP: OpenSSL picks the CPU's SHA extensions (ARMv8, SHA-NI) where present, and
 * in FIPS mode the computation stays inside the FIPS provider (crypto/fips.h). */
#include "crypto/sha256.h"

#include "crypto/evpmd.h"
#include "crypto/fips.h"

void buckets_sha256_init(buckets_sha256_ctx *ctx) { ctx->evp = buckets_evpmd_init(buckets_md_sha256()); }
void buckets_sha256_update(buckets_sha256_ctx *ctx, const void *data, size_t n) {
  buckets_evpmd_update(ctx->evp, data, n);
}
void buckets_sha256_final(buckets_sha256_ctx *ctx, uint8_t out[BUCKETS_SHA256_LEN]) {
  buckets_evpmd_final(&ctx->evp, out);
}
void buckets_sha256_cleanup(buckets_sha256_ctx *ctx) { buckets_evpmd_cleanup(&ctx->evp); }

void buckets_sha256(const void *data, size_t n, uint8_t out[BUCKETS_SHA256_LEN]) {
  buckets_evpmd_oneshot(buckets_md_sha256(), data, n, out);
}

void buckets_hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len,
                         uint8_t out[BUCKETS_SHA256_LEN]) {
  buckets_evp_hmac("SHA2-256", key, key_len, msg, msg_len, out, BUCKETS_SHA256_LEN);
}
