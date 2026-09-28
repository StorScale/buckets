/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/xxhash.h"

#define P1 11400714785074694791ull
#define P2 14029467366897019727ull
#define P3 1609587929392839161ull
#define P4 9650029242287828579ull
#define P5 2870177450012600261ull

static uint64_t rotl(uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }

static uint64_t rd64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
  return v;
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t round64(uint64_t acc, uint64_t input) {
  acc += input * P2;
  acc = rotl(acc, 31);
  return acc * P1;
}

static uint64_t merge_round(uint64_t acc, uint64_t val) {
  acc ^= round64(0, val);
  return acc * P1 + P4;
}

uint64_t buckets_xxh64(const void *data, size_t n) {
  const uint8_t *p = data, *end = p + n;
  uint64_t h;
  if (n >= 32) {
    uint64_t v1 = P1 + P2, v2 = P2, v3 = 0, v4 = (uint64_t)0 - P1;
    do {
      v1 = round64(v1, rd64(p));
      v2 = round64(v2, rd64(p + 8));
      v3 = round64(v3, rd64(p + 16));
      v4 = round64(v4, rd64(p + 24));
      p += 32;
    } while (p + 32 <= end);
    h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    h = merge_round(h, v1);
    h = merge_round(h, v2);
    h = merge_round(h, v3);
    h = merge_round(h, v4);
  } else {
    h = P5;
  }
  h += (uint64_t)n;
  for (; p + 8 <= end; p += 8) {
    h ^= round64(0, rd64(p));
    h = rotl(h, 27) * P1 + P4;
  }
  if (p + 4 <= end) {
    h ^= (uint64_t)rd32(p) * P1;
    h = rotl(h, 23) * P2 + P3;
    p += 4;
  }
  for (; p < end; p++) {
    h ^= (uint64_t)*p * P5;
    h = rotl(h, 11) * P1;
  }
  h ^= h >> 33;
  h *= P2;
  h ^= h >> 29;
  h *= P3;
  h ^= h >> 32;
  return h;
}

/* ---- XXH3-64 ------------------------------------------------------------- */

#define P32_1 0x9E3779B1u
#define P32_2 0x85EBCA77u
#define P32_3 0xC2B2AE3Du
#define PRIME_MX1 0x165667919E3779F9ull
#define PRIME_MX2 0x9FB21C651E98DF25ull
#define SECRET_SIZE 192

static const uint8_t k_secret[SECRET_SIZE] = {
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c, 0xde, 0xd4,
    0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e,
    0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43,
    0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb,
    0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19,
    0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7,
    0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78,
    0x73, 0x64, 0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16,
    0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
    0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

static uint64_t mul128_fold64(uint64_t a, uint64_t b) {
#if defined(__SIZEOF_INT128__)
  __extension__ unsigned __int128 p = (unsigned __int128)a * b;
  return (uint64_t)p ^ (uint64_t)(p >> 64);
#else
  uint64_t lo_lo = (a & 0xffffffff) * (b & 0xffffffff), hi_lo = (a >> 32) * (b & 0xffffffff);
  uint64_t lo_hi = (a & 0xffffffff) * (b >> 32), hi_hi = (a >> 32) * (b >> 32);
  uint64_t cross = (lo_lo >> 32) + (hi_lo & 0xffffffff) + lo_hi;
  uint64_t upper = (hi_lo >> 32) + (cross >> 32) + hi_hi;
  uint64_t lower = (cross << 32) | (lo_lo & 0xffffffff);
  return lower ^ upper;
#endif
}

static uint64_t xxh64_avalanche(uint64_t h) {
  h ^= h >> 33;
  h *= P2;
  h ^= h >> 29;
  h *= P3;
  h ^= h >> 32;
  return h;
}

static uint64_t xxh3_avalanche(uint64_t h) {
  h ^= h >> 37;
  h *= PRIME_MX1;
  h ^= h >> 32;
  return h;
}

static uint64_t rrmxmx(uint64_t h, uint64_t len) {
  h ^= rotl(h, 49) ^ rotl(h, 24);
  h *= PRIME_MX2;
  h ^= (h >> 35) + len;
  h *= PRIME_MX2;
  h ^= h >> 28;
  return h;
}

static uint64_t bswap64(uint64_t x) {
  uint64_t r = 0;
  for (int i = 0; i < 8; i++) r = r << 8 | ((x >> (8 * i)) & 0xff);
  return r;
}

static uint64_t mix16(const uint8_t *in, const uint8_t *sec) {
  return mul128_fold64(rd64(in) ^ rd64(sec), rd64(in + 8) ^ rd64(sec + 8));
}

static void accumulate_512(uint64_t acc[8], const uint8_t *in, const uint8_t *sec) {
  for (int i = 0; i < 8; i++) {
    uint64_t v = rd64(in + 8 * i);
    uint64_t k = v ^ rd64(sec + 8 * i);
    acc[i ^ 1] += v;
    acc[i] += (k & 0xffffffff) * (k >> 32);
  }
}

static void scramble(uint64_t acc[8], const uint8_t *sec) {
  for (int i = 0; i < 8; i++) {
    uint64_t a = acc[i];
    a ^= a >> 47;
    a ^= rd64(sec + 8 * i);
    a *= P32_1;
    acc[i] = a;
  }
}

static uint64_t hash_long(const uint8_t *in, size_t len) {
  enum { STRIPE = 64, STRIPES_PER_BLOCK = (SECRET_SIZE - STRIPE) / 8, BLOCK = STRIPE * STRIPES_PER_BLOCK };
  uint64_t acc[8] = {P32_3, P1, P2, P3, P4, P32_2, P5, P32_1};
  size_t nb_blocks = (len - 1) / BLOCK;
  for (size_t b = 0; b < nb_blocks; b++) {
    for (size_t s = 0; s < STRIPES_PER_BLOCK; s++) accumulate_512(acc, in + b * BLOCK + s * STRIPE, k_secret + s * 8);
    scramble(acc, k_secret + SECRET_SIZE - STRIPE);
  }
  size_t nb_stripes = ((len - 1) - BLOCK * nb_blocks) / STRIPE;
  for (size_t s = 0; s < nb_stripes; s++) accumulate_512(acc, in + nb_blocks * BLOCK + s * STRIPE, k_secret + s * 8);
  accumulate_512(acc, in + len - STRIPE, k_secret + SECRET_SIZE - STRIPE - 7);
  uint64_t result = (uint64_t)len * P1;
  for (int i = 0; i < 4; i++) {
    result += mul128_fold64(acc[2 * i] ^ rd64(k_secret + 11 + 16 * i), acc[2 * i + 1] ^ rd64(k_secret + 11 + 16 * i + 8));
  }
  return xxh3_avalanche(result);
}

uint64_t buckets_xxh3_64(const void *data, size_t len) {
  const uint8_t *in = data;
  const uint8_t *s = k_secret;
  if (len == 0) return xxh64_avalanche(rd64(s + 56) ^ rd64(s + 64));
  if (len <= 3) {
    uint32_t c1 = in[0], c2 = in[len >> 1], c3 = in[len - 1];
    uint32_t combined = (c1 << 16) | (c2 << 24) | c3 | ((uint32_t)len << 8);
    uint64_t bitflip = (uint64_t)(rd32(s) ^ rd32(s + 4));
    return xxh64_avalanche((uint64_t)combined ^ bitflip);
  }
  if (len <= 8) {
    uint32_t in1 = rd32(in), in2 = rd32(in + len - 4);
    uint64_t bitflip = rd64(s + 8) ^ rd64(s + 16);
    uint64_t in64 = in2 + ((uint64_t)in1 << 32);
    return rrmxmx(in64 ^ bitflip, len);
  }
  if (len <= 16) {
    uint64_t lo = rd64(in) ^ (rd64(s + 24) ^ rd64(s + 32));
    uint64_t hi = rd64(in + len - 8) ^ (rd64(s + 40) ^ rd64(s + 48));
    uint64_t acc = len + bswap64(lo) + hi + mul128_fold64(lo, hi);
    return xxh3_avalanche(acc);
  }
  if (len <= 128) {
    uint64_t acc = len * P1;
    if (len > 32) {
      if (len > 64) {
        if (len > 96) {
          acc += mix16(in + 48, s + 96);
          acc += mix16(in + len - 64, s + 112);
        }
        acc += mix16(in + 32, s + 64);
        acc += mix16(in + len - 48, s + 80);
      }
      acc += mix16(in + 16, s + 32);
      acc += mix16(in + len - 32, s + 48);
    }
    acc += mix16(in, s);
    acc += mix16(in + len - 16, s + 16);
    return xxh3_avalanche(acc);
  }
  if (len <= 240) {
    uint64_t acc = len * P1;
    size_t rounds = len / 16;
    for (size_t i = 0; i < 8; i++) acc += mix16(in + 16 * i, s + 16 * i);
    acc = xxh3_avalanche(acc);
    for (size_t i = 8; i < rounds; i++) acc += mix16(in + 16 * i, s + 16 * (i - 8) + 3);
    acc += mix16(in + len - 16, s + 136 - 17);
    return xxh3_avalanche(acc);
  }
  return hash_long(in, len);
}
