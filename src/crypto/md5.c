/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* MD5 on OpenSSL's assembly block function (about 2.5x the portable C on
 * arm64). MD5 feeds every PUT's ETag, so it is on the hot path. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "crypto/md5.h"

#include <openssl/md5.h>
#include <string.h>

_Static_assert(sizeof(MD5_CTX) <= sizeof(((buckets_md5_ctx *)0)->opaque), "MD5_CTX does not fit");

void buckets_md5_init(buckets_md5_ctx *ctx) { MD5_Init((MD5_CTX *)ctx->opaque); }

void buckets_md5_update(buckets_md5_ctx *ctx, const void *data, size_t n) {
  if (n) MD5_Update((MD5_CTX *)ctx->opaque, data, n);
}

void buckets_md5_final(buckets_md5_ctx *ctx, uint8_t out[BUCKETS_MD5_LEN]) { MD5_Final(out, (MD5_CTX *)ctx->opaque); }

void buckets_md5(const void *data, size_t n, uint8_t out[BUCKETS_MD5_LEN]) {
  buckets_md5_ctx ctx;
  buckets_md5_init(&ctx);
  buckets_md5_update(&ctx, data, n);
  buckets_md5_final(&ctx, out);
}
