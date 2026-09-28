/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/md5.h"

#include <string.h>

static const uint32_t T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const uint8_t R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void compress(uint32_t s[4], const uint8_t *p) {
  uint32_t m[16];
  for (int i = 0; i < 16; i++) {
    m[i] = (uint32_t)p[4 * i] | (uint32_t)p[4 * i + 1] << 8 | (uint32_t)p[4 * i + 2] << 16 |
           (uint32_t)p[4 * i + 3] << 24;
  }
  uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
  for (int i = 0; i < 64; i++) {
    uint32_t f;
    int g;
    if (i < 16) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    uint32_t tmp = d;
    d = c;
    c = b;
    b = b + ROL(a + f + T[i] + m[g], R[i]);
    a = tmp;
  }
  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
}

void buckets_md5_init(buckets_md5_ctx *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->bytes = 0;
  ctx->used = 0;
}

void buckets_md5_update(buckets_md5_ctx *ctx, const void *data, size_t n) {
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
  while (n >= 64) {
    compress(ctx->state, p);
    p += 64;
    n -= 64;
  }
  if (n) {
    memcpy(ctx->block, p, n);
    ctx->used = n;
  }
}

void buckets_md5_final(buckets_md5_ctx *ctx, uint8_t out[BUCKETS_MD5_LEN]) {
  uint64_t bits = ctx->bytes * 8;
  uint8_t pad = 0x80, zero = 0;
  buckets_md5_update(ctx, &pad, 1);
  while (ctx->used != 56) buckets_md5_update(ctx, &zero, 1);
  uint8_t len[8];
  for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (8 * i));
  buckets_md5_update(ctx, len, 8);
  for (int i = 0; i < 4; i++) {
    out[4 * i] = (uint8_t)ctx->state[i];
    out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 8);
    out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 16);
    out[4 * i + 3] = (uint8_t)(ctx->state[i] >> 24);
  }
}

void buckets_md5(const void *data, size_t n, uint8_t out[BUCKETS_MD5_LEN]) {
  buckets_md5_ctx ctx;
  buckets_md5_init(&ctx);
  buckets_md5_update(&ctx, data, n);
  buckets_md5_final(&ctx, out);
}
