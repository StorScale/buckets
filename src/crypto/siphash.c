/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/siphash.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                   \
  do {                                                             \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);      \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                         \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                         \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);      \
  } while (0)

uint64_t buckets_siphash24(uint64_t k0, uint64_t k1, const void *msg, size_t n) {
  const uint8_t *p = msg;
  uint64_t v0 = 0x736f6d6570736575ull ^ k0, v1 = 0x646f72616e646f6dull ^ k1;
  uint64_t v2 = 0x6c7967656e657261ull ^ k0, v3 = 0x7465646279746573ull ^ k1;
  size_t blocks = n / 8;
  for (size_t i = 0; i < blocks; i++, p += 8) {
    uint64_t m = 0;
    for (int j = 7; j >= 0; j--) m = m << 8 | p[j];
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;
  }
  uint64_t b = (uint64_t)n << 56;
  for (size_t j = 0; j < (n & 7); j++) b |= (uint64_t)p[j] << (8 * j);
  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;
  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  return v0 ^ v1 ^ v2 ^ v3;
}
