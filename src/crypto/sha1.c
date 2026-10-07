/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SHA-1 and HMAC-SHA1 through EVP: inside the FIPS provider in FIPS mode (crypto/fips.h), which approves SHA-1 for
 * HMAC and integrity checksums though not for signatures. */
#include "crypto/sha1.h"

#include "crypto/evpmd.h"
#include "crypto/fips.h"

void buckets_sha1_init(buckets_sha1_ctx *ctx) { ctx->evp = buckets_evpmd_init(buckets_md_sha1()); }
void buckets_sha1_update(buckets_sha1_ctx *ctx, const void *data, size_t n) {
  buckets_evpmd_update(ctx->evp, data, n);
}
void buckets_sha1_final(buckets_sha1_ctx *ctx, uint8_t out[BUCKETS_SHA1_LEN]) {
  buckets_evpmd_final(&ctx->evp, out);
}
void buckets_sha1_cleanup(buckets_sha1_ctx *ctx) { buckets_evpmd_cleanup(&ctx->evp); }

void buckets_hmac_sha1(const void *key, size_t key_len, const void *msg, size_t msg_len,
                       uint8_t out[BUCKETS_SHA1_LEN]) {
  buckets_evp_hmac("SHA1", key, key_len, msg, msg_len, out, BUCKETS_SHA1_LEN);
}
