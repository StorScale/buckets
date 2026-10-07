/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* MD5 through EVP, from OpenSSL's default provider in every mode (crypto/fips.h): S3 ETags and Content-MD5 need it,
 * and it protects nothing. */
#include "crypto/md5.h"

#include "crypto/evpmd.h"
#include "crypto/fips.h"

void buckets_md5_init(buckets_md5_ctx *ctx) { ctx->evp = buckets_evpmd_init(buckets_md_md5()); }
void buckets_md5_update(buckets_md5_ctx *ctx, const void *data, size_t n) {
  buckets_evpmd_update(ctx->evp, data, n);
}
void buckets_md5_final(buckets_md5_ctx *ctx, uint8_t out[BUCKETS_MD5_LEN]) {
  buckets_evpmd_final(&ctx->evp, out);
}
void buckets_md5_cleanup(buckets_md5_ctx *ctx) { buckets_evpmd_cleanup(&ctx->evp); }

void buckets_md5(const void *data, size_t n, uint8_t out[BUCKETS_MD5_LEN]) {
  buckets_evpmd_oneshot(buckets_md_md5(), data, n, out);
}
