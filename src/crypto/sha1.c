/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/sha1.h"

#include <string.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void compress(uint32_t s[5], const uint8_t *p) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
  }
  for (int i = 16; i < 80; i++) w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t t = ROL(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = ROL(b, 30);
    b = a;
    a = t;
  }
  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
}

void buckets_sha1_init(buckets_sha1_ctx *ctx) {
  static const uint32_t iv[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  memcpy(ctx->state, iv, sizeof(iv));
  ctx->bytes = 0;
  ctx->used = 0;
}

void buckets_sha1_update(buckets_sha1_ctx *ctx, const void *data, size_t n) {
  const uint8_t *p = data;
  ctx->bytes += n;
  if (ctx->used) {
    size_t take = BUCKETS_MIN(n, 64 - ctx->used);
    memcpy(ctx->block + ctx->used, p, take);
    ctx->used += take;
    p += take;
    n -= take;
    if (ctx->used < 64) return;
    compress(ctx->state, ctx->block);
    ctx->used = 0;
  }
  for (; n >= 64; p += 64, n -= 64) compress(ctx->state, p);
  if (n) {
    memcpy(ctx->block, p, n);
    ctx->used = n;
  }
}

void buckets_sha1_final(buckets_sha1_ctx *ctx, uint8_t out[BUCKETS_SHA1_LEN]) {
  uint64_t bits = ctx->bytes * 8;
  uint8_t pad = 0x80, zero = 0;
  buckets_sha1_update(ctx, &pad, 1);
  while (ctx->used != 56) buckets_sha1_update(ctx, &zero, 1);
  uint8_t len[8];
  for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
  buckets_sha1_update(ctx, len, 8);
  for (int i = 0; i < 5; i++) {
    out[4 * i] = (uint8_t)(ctx->state[i] >> 24);
    out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
    out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
    out[4 * i + 3] = (uint8_t)ctx->state[i];
  }
}

void buckets_hmac_sha1(const void *key, size_t key_len, const void *msg, size_t msg_len,
                       uint8_t out[BUCKETS_SHA1_LEN]) {
  uint8_t k[64] = {0};
  if (key_len > 64) {
    buckets_sha1_ctx c;
    buckets_sha1_init(&c);
    buckets_sha1_update(&c, key, key_len);
    buckets_sha1_final(&c, k);
  } else if (key_len) {
    memcpy(k, key, key_len);
  }
  uint8_t ipad[64], opad[64], inner[BUCKETS_SHA1_LEN];
  for (int i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  buckets_sha1_ctx c;
  buckets_sha1_init(&c);
  buckets_sha1_update(&c, ipad, 64);
  buckets_sha1_update(&c, msg, msg_len);
  buckets_sha1_final(&c, inner);
  buckets_sha1_init(&c);
  buckets_sha1_update(&c, opad, 64);
  buckets_sha1_update(&c, inner, sizeof(inner));
  buckets_sha1_final(&c, out);
}
