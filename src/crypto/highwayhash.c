/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Port of highwayhash_generic.go / highwayhash.go from github.com/minio/highwayhash. */
#include "crypto/highwayhash.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum { V0 = 0, V1 = 4, MUL0 = 8, MUL1 = 12 };

const uint8_t buckets_bitrot_key[BUCKETS_HH_KEY_LEN] = {
    0x4b, 0xe7, 0x34, 0xfa, 0x8e, 0x23, 0x8a, 0xcd, 0x26, 0x3e, 0x83, 0xe6, 0xbb, 0x96, 0x85, 0x52,
    0x04, 0x0f, 0x93, 0x5d, 0xa3, 0x9f, 0x44, 0x14, 0x97, 0xe0, 0x9d, 0x13, 0x22, 0xde, 0x36, 0xa0};

static const uint64_t k_init0[4] = {0xdbe6d5d5fe4cce2full, 0xa4093822299f31d0ull, 0x13198a2e03707344ull,
                                    0x243f6a8885a308d3ull};
static const uint64_t k_init1[4] = {0x3bd39e10cb0ef593ull, 0xc0acf169b5f18a8cull, 0xbe5466cf34e90c6cull,
                                    0x452821e638d01377ull};

static uint64_t le64(const uint8_t *p) {
  return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
         (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 | (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

static void put_le64(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void put_le32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void initialize(uint64_t state[16], const uint8_t *k) {
  uint64_t key[4] = {le64(k), le64(k + 8), le64(k + 16), le64(k + 24)};
  memcpy(state + MUL0, k_init0, sizeof(k_init0));
  memcpy(state + MUL1, k_init1, sizeof(k_init1));
  for (int i = 0; i < 4; i++) state[V0 + i] = k_init0[i] ^ key[i];
  for (int i = 0; i < 4; i++) {
    key[i] = key[i] >> 32 | key[i] << 32;
    state[V1 + i] = k_init1[i] ^ key[i];
  }
}

static void zipper_merge(uint64_t v0, uint64_t v1, uint64_t *d0, uint64_t *d1) {
  uint64_t res = v0 & (0xffull << (2 * 8));
  uint64_t res2 = (v0 & (0xffull << (7 * 8))) + (v1 & (0xffull << (2 * 8)));
  res += (v1 & (0xffull << (7 * 8))) >> 8;
  res2 += (v0 & (0xffull << (6 * 8))) >> 8;
  res += ((v0 & (0xffull << (5 * 8))) + (v1 & (0xffull << (6 * 8)))) >> 16;
  res2 += (v1 & (0xffull << (5 * 8))) >> 16;
  res += ((v0 & (0xffull << (3 * 8))) + (v1 & (0xffull << (4 * 8)))) >> 24;
  res2 += ((v1 & (0xffull << (3 * 8))) + (v0 & (0xffull << (4 * 8)))) >> 24;
  res += (v0 & (0xffull << (1 * 8))) << 32;
  res2 += (v1 & 0xffull) << 48;
  res += v0 << 56;
  res2 += (v1 & (0xffull << (1 * 8))) << 24;
  *d0 += res;
  *d1 += res2;
}

static void update_scalar(uint64_t s[16], const uint8_t *msg, size_t n) {
  for (; n >= 32; msg += 32, n -= 32) {
    for (int i = 0; i < 4; i++) {
      s[V1 + i] += le64(msg + 8 * i) + s[MUL0 + i];
      s[MUL0 + i] ^= (uint64_t)(uint32_t)s[V1 + i] * (s[V0 + i] >> 32);
      s[V0 + i] += s[MUL1 + i];
      s[MUL1 + i] ^= (uint64_t)(uint32_t)s[V0 + i] * (s[V1 + i] >> 32);
    }
    zipper_merge(s[V1 + 0], s[V1 + 1], &s[V0 + 0], &s[V0 + 1]);
    zipper_merge(s[V1 + 2], s[V1 + 3], &s[V0 + 2], &s[V0 + 3]);
    zipper_merge(s[V0 + 0], s[V0 + 1], &s[V1 + 0], &s[V1 + 1]);
    zipper_merge(s[V0 + 2], s[V0 + 3], &s[V1 + 2], &s[V1 + 3]);
  }
}

/* The bulk update in 128-bit SIMD: each state row of four 64-bit lanes is
 * two vectors, 32x32->64 multiplies are native, and ZipperMerge is one byte
 * shuffle per 128-bit half (the permutation of Google's SSE4.1 reference).
 * Bit-identical to update_scalar; verified by the golden vectors. */
#if defined(__aarch64__)
#include <arm_neon.h>
#define HAVE_SIMD 1
static void update_simd(uint64_t s[16], const uint8_t *msg, size_t n) {
  static const uint8_t zm[16] = {3, 12, 2, 5, 14, 1, 15, 0, 11, 4, 10, 13, 9, 6, 8, 7};
  const uint8x16_t mask = vld1q_u8(zm);
  uint64x2_t v0a = vld1q_u64(s + V0), v0b = vld1q_u64(s + V0 + 2);
  uint64x2_t v1a = vld1q_u64(s + V1), v1b = vld1q_u64(s + V1 + 2);
  uint64x2_t m0a = vld1q_u64(s + MUL0), m0b = vld1q_u64(s + MUL0 + 2);
  uint64x2_t m1a = vld1q_u64(s + MUL1), m1b = vld1q_u64(s + MUL1 + 2);
  for (; n >= 32; msg += 32, n -= 32) {
    uint64x2_t pa = vreinterpretq_u64_u8(vld1q_u8(msg)), pb = vreinterpretq_u64_u8(vld1q_u8(msg + 16));
    v1a = vaddq_u64(v1a, vaddq_u64(pa, m0a));
    v1b = vaddq_u64(v1b, vaddq_u64(pb, m0b));
    m0a = veorq_u64(m0a, vmull_u32(vmovn_u64(v1a), vshrn_n_u64(v0a, 32)));
    m0b = veorq_u64(m0b, vmull_u32(vmovn_u64(v1b), vshrn_n_u64(v0b, 32)));
    v0a = vaddq_u64(v0a, m1a);
    v0b = vaddq_u64(v0b, m1b);
    m1a = veorq_u64(m1a, vmull_u32(vmovn_u64(v0a), vshrn_n_u64(v1a, 32)));
    m1b = veorq_u64(m1b, vmull_u32(vmovn_u64(v0b), vshrn_n_u64(v1b, 32)));
    v0a = vaddq_u64(v0a, vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v1a), mask)));
    v0b = vaddq_u64(v0b, vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v1b), mask)));
    v1a = vaddq_u64(v1a, vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v0a), mask)));
    v1b = vaddq_u64(v1b, vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v0b), mask)));
  }
  vst1q_u64(s + V0, v0a), vst1q_u64(s + V0 + 2, v0b);
  vst1q_u64(s + V1, v1a), vst1q_u64(s + V1 + 2, v1b);
  vst1q_u64(s + MUL0, m0a), vst1q_u64(s + MUL0 + 2, m0b);
  vst1q_u64(s + MUL1, m1a), vst1q_u64(s + MUL1 + 2, m1b);
}
static bool simd_ok(void) { return true; }
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define HAVE_SIMD 1
__attribute__((target("ssse3"))) static void update_simd(uint64_t s[16], const uint8_t *msg, size_t n) {
  const __m128i mask = _mm_set_epi64x(0x070806090D0A040Bll, 0x000F010E05020C03ll);
  __m128i v0a = _mm_loadu_si128((const __m128i *)(s + V0)), v0b = _mm_loadu_si128((const __m128i *)(s + V0 + 2));
  __m128i v1a = _mm_loadu_si128((const __m128i *)(s + V1)), v1b = _mm_loadu_si128((const __m128i *)(s + V1 + 2));
  __m128i m0a = _mm_loadu_si128((const __m128i *)(s + MUL0)), m0b = _mm_loadu_si128((const __m128i *)(s + MUL0 + 2));
  __m128i m1a = _mm_loadu_si128((const __m128i *)(s + MUL1)), m1b = _mm_loadu_si128((const __m128i *)(s + MUL1 + 2));
  for (; n >= 32; msg += 32, n -= 32) {
    __m128i pa = _mm_loadu_si128((const __m128i *)msg), pb = _mm_loadu_si128((const __m128i *)(msg + 16));
    v1a = _mm_add_epi64(v1a, _mm_add_epi64(pa, m0a));
    v1b = _mm_add_epi64(v1b, _mm_add_epi64(pb, m0b));
    m0a = _mm_xor_si128(m0a, _mm_mul_epu32(v1a, _mm_srli_epi64(v0a, 32)));
    m0b = _mm_xor_si128(m0b, _mm_mul_epu32(v1b, _mm_srli_epi64(v0b, 32)));
    v0a = _mm_add_epi64(v0a, m1a);
    v0b = _mm_add_epi64(v0b, m1b);
    m1a = _mm_xor_si128(m1a, _mm_mul_epu32(v0a, _mm_srli_epi64(v1a, 32)));
    m1b = _mm_xor_si128(m1b, _mm_mul_epu32(v0b, _mm_srli_epi64(v1b, 32)));
    v0a = _mm_add_epi64(v0a, _mm_shuffle_epi8(v1a, mask));
    v0b = _mm_add_epi64(v0b, _mm_shuffle_epi8(v1b, mask));
    v1a = _mm_add_epi64(v1a, _mm_shuffle_epi8(v0a, mask));
    v1b = _mm_add_epi64(v1b, _mm_shuffle_epi8(v0b, mask));
  }
  _mm_storeu_si128((__m128i *)(s + V0), v0a), _mm_storeu_si128((__m128i *)(s + V0 + 2), v0b);
  _mm_storeu_si128((__m128i *)(s + V1), v1a), _mm_storeu_si128((__m128i *)(s + V1 + 2), v1b);
  _mm_storeu_si128((__m128i *)(s + MUL0), m0a), _mm_storeu_si128((__m128i *)(s + MUL0 + 2), m0b);
  _mm_storeu_si128((__m128i *)(s + MUL1), m1a), _mm_storeu_si128((__m128i *)(s + MUL1 + 2), m1b);
}
static bool simd_ok(void) { return __builtin_cpu_supports("ssse3"); }
#endif

static _Atomic int g_simd = -1; /* -1: decide on first use (threads may race; they agree) */

void buckets_hh_set_simd(bool on) { g_simd = on; }

static void update(uint64_t s[16], const uint8_t *msg, size_t n) {
#ifdef HAVE_SIMD
  int simd = atomic_load_explicit(&g_simd, memory_order_relaxed);
  if (simd < 0) {
    simd = simd_ok() && !getenv("BUCKETS_NO_SIMD");
    atomic_store_explicit(&g_simd, simd, memory_order_relaxed);
  }
  if (n >= 32 && simd) {
    update_simd(s, msg, n & ~(size_t)31);
    return;
  }
#endif
  update_scalar(s, msg, n);
}

static void hash_buffer(uint64_t s[16], const uint8_t buffer[32], size_t offset) {
  uint8_t block[32] = {0};
  uint64_t mod32 = ((uint64_t)offset << 32) + (uint64_t)offset;
  for (int i = 0; i < 4; i++) s[i] += mod32;
  for (int i = 0; i < 4; i++) {
    uint32_t t0 = (uint32_t)s[i + 4];
    t0 = (t0 << offset) | (t0 >> (32 - offset));
    uint32_t t1 = (uint32_t)(s[i + 4] >> 32);
    t1 = (t1 << offset) | (t1 >> (32 - offset));
    s[i + 4] = ((uint64_t)t1 << 32) | t0;
  }
  size_t mod4 = offset & 3;
  size_t remain = offset - mod4;
  memcpy(block, buffer, remain);
  if (offset >= 16) {
    memcpy(block + 28, buffer + offset - 4, 4);
  } else if (mod4 != 0) {
    uint32_t last = buffer[remain];
    last += (uint32_t)buffer[remain + (mod4 >> 1)] << 8;
    last += (uint32_t)buffer[offset - 1] << 16;
    put_le32(block + 16, last);
  }
  update(s, block, 32);
}

static void reduce_mod(uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3, uint64_t *r0, uint64_t *r1) {
  v3 &= 0x3FFFFFFFFFFFFFFFull;
  uint64_t a0 = v2, a1 = v3;
  v3 = (v3 << 1) | (v2 >> 63);
  v2 <<= 1;
  a1 = (a1 << 2) | (a0 >> 62);
  a0 <<= 2;
  *r0 = a0 ^ v0 ^ v2;
  *r1 = a1 ^ v1 ^ v3;
}

static void finalize256(uint8_t out[32], uint64_t s[16]) {
  uint8_t tmp[32];
  for (int i = 0; i < 10; i++) {
    uint64_t p0 = s[V0 + 2] >> 32 | s[V0 + 2] << 32;
    uint64_t p1 = s[V0 + 3] >> 32 | s[V0 + 3] << 32;
    uint64_t p2 = s[V0 + 0] >> 32 | s[V0 + 0] << 32;
    uint64_t p3 = s[V0 + 1] >> 32 | s[V0 + 1] << 32;
    put_le64(tmp, p0);
    put_le64(tmp + 8, p1);
    put_le64(tmp + 16, p2);
    put_le64(tmp + 24, p3);
    update(s, tmp, 32);
  }
  uint64_t h0, h1;
  reduce_mod(s[V0 + 0] + s[MUL0 + 0], s[V0 + 1] + s[MUL0 + 1], s[V1 + 0] + s[MUL1 + 0], s[V1 + 1] + s[MUL1 + 1],
             &h0, &h1);
  put_le64(out, h0);
  put_le64(out + 8, h1);
  reduce_mod(s[V0 + 2] + s[MUL0 + 2], s[V0 + 3] + s[MUL0 + 3], s[V1 + 2] + s[MUL1 + 2], s[V1 + 3] + s[MUL1 + 3],
             &h0, &h1);
  put_le64(out + 16, h0);
  put_le64(out + 24, h1);
}

void buckets_hh_init(buckets_hh_ctx *ctx, const uint8_t key[BUCKETS_HH_KEY_LEN]) {
  memcpy(ctx->key, key, BUCKETS_HH_KEY_LEN);
  buckets_hh_reset(ctx);
}

void buckets_hh_reset(buckets_hh_ctx *ctx) {
  initialize(ctx->state, ctx->key);
  ctx->offset = 0;
}

void buckets_hh_update(buckets_hh_ctx *ctx, const void *data, size_t n) {
  const uint8_t *p = data;
  if (ctx->offset > 0) {
    size_t remaining = 32 - ctx->offset;
    if (n < remaining) {
      memcpy(ctx->buffer + ctx->offset, p, n);
      ctx->offset += n;
      return;
    }
    memcpy(ctx->buffer + ctx->offset, p, remaining);
    update(ctx->state, ctx->buffer, 32);
    p += remaining;
    n -= remaining;
    ctx->offset = 0;
  }
  size_t whole = n & ~(size_t)31;
  if (whole) {
    update(ctx->state, p, whole);
    p += whole;
    n -= whole;
  }
  if (n) {
    memcpy(ctx->buffer, p, n);
    ctx->offset = n;
  }
}

void buckets_hh_final256(const buckets_hh_ctx *ctx, uint8_t out[BUCKETS_HH256_LEN]) {
  uint64_t s[16];
  memcpy(s, ctx->state, sizeof(s));
  if (ctx->offset > 0) hash_buffer(s, ctx->buffer, ctx->offset);
  finalize256(out, s);
}

void buckets_hh256(const uint8_t key[BUCKETS_HH_KEY_LEN], const void *data, size_t n,
                   uint8_t out[BUCKETS_HH256_LEN]) {
  buckets_hh_ctx ctx;
  buckets_hh_init(&ctx, key);
  buckets_hh_update(&ctx, data, n);
  buckets_hh_final256(&ctx, out);
}
