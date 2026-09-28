/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Slice-by-8 table CRCs. Hardware CRC32C/PCLMUL paths are a later optimization. */
#include "crypto/crc.h"

#include <pthread.h>

static uint32_t t32[8][256], t32c[8][256];
static uint64_t t64[8][256];
static pthread_once_t once = PTHREAD_ONCE_INIT;

static void build32(uint32_t t[8][256], uint32_t poly) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ poly : c >> 1;
    t[0][i] = c;
  }
  for (int s = 1; s < 8; s++) {
    for (int i = 0; i < 256; i++) t[s][i] = (t[s - 1][i] >> 8) ^ t[0][t[s - 1][i] & 0xff];
  }
}

static void build_tables(void) {
  build32(t32, 0xEDB88320u);  /* IEEE, reflected */
  build32(t32c, 0x82F63B78u); /* Castagnoli, reflected */
  const uint64_t poly = 0x9A6C9329AC4BC9B5ull; /* bits.Reverse64(0xad93d23594c93659): CRC-64/NVME */
  for (uint64_t i = 0; i < 256; i++) {
    uint64_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ poly : c >> 1;
    t64[0][i] = c;
  }
  for (int s = 1; s < 8; s++) {
    for (int i = 0; i < 256; i++) t64[s][i] = (t64[s - 1][i] >> 8) ^ t64[0][t64[s - 1][i] & 0xff];
  }
}

static uint32_t crc32_generic(uint32_t t[8][256], uint32_t crc, const uint8_t *p, size_t n) {
  crc = ~crc;
  while (n >= 8) {
    uint32_t lo = crc ^ ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
    uint32_t hi = (uint32_t)p[4] | (uint32_t)p[5] << 8 | (uint32_t)p[6] << 16 | (uint32_t)p[7] << 24;
    crc = t[7][lo & 0xff] ^ t[6][(lo >> 8) & 0xff] ^ t[5][(lo >> 16) & 0xff] ^ t[4][lo >> 24] ^ t[3][hi & 0xff] ^
          t[2][(hi >> 8) & 0xff] ^ t[1][(hi >> 16) & 0xff] ^ t[0][hi >> 24];
    p += 8;
    n -= 8;
  }
  while (n--) crc = t[0][(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return ~crc;
}

uint32_t buckets_crc32_ieee(uint32_t crc, const void *data, size_t n) {
  pthread_once(&once, build_tables);
  return crc32_generic(t32, crc, data, n);
}

uint32_t buckets_crc32c(uint32_t crc, const void *data, size_t n) {
  pthread_once(&once, build_tables);
  return crc32_generic(t32c, crc, data, n);
}

uint64_t buckets_crc64_nvme(uint64_t crc, const void *data, size_t n) {
  pthread_once(&once, build_tables);
  const uint8_t *p = data;
  crc = ~crc;
  while (n >= 8) {
    uint64_t v = crc;
    for (int i = 0; i < 8; i++) v ^= (uint64_t)p[i] << (8 * i);
    crc = t64[7][v & 0xff] ^ t64[6][(v >> 8) & 0xff] ^ t64[5][(v >> 16) & 0xff] ^ t64[4][(v >> 24) & 0xff] ^
          t64[3][(v >> 32) & 0xff] ^ t64[2][(v >> 40) & 0xff] ^ t64[1][(v >> 48) & 0xff] ^ t64[0][v >> 56];
    p += 8;
    n -= 8;
  }
  while (n--) crc = t64[0][(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return ~crc;
}
