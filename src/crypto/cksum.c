/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/cksum.h"

#include <string.h>

#include "crypto/base64.h"
#include "crypto/crc.h"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

static bool is(uint32_t c, uint32_t t) { return (c & t) == t; }

/* ChecksumType.RawByteLen precedence: CRC32, CRC32C, SHA1, SHA256, CRC64NVME. */
size_t buckets_cksum_raw_len(uint32_t type) {
  if (is(type, BUCKETS_CKSUM_CRC32) || is(type, BUCKETS_CKSUM_CRC32C)) return 4;
  if (is(type, BUCKETS_CKSUM_SHA1)) return 20;
  if (is(type, BUCKETS_CKSUM_SHA256)) return 32;
  if (is(type, BUCKETS_CKSUM_CRC64NVME)) return 8;
  return 0;
}

/* ---- hashing -------------------------------------------------------------- */

void buckets_cksum_hasher_init(buckets_cksum_hasher *h, uint32_t type) {
  memset(h, 0, sizeof(*h));
  h->type = type & BUCKETS_CKSUM_BASE_MASK;
  if (is(h->type, BUCKETS_CKSUM_SHA1)) buckets_sha1_init(&h->s1);
  else if (is(h->type, BUCKETS_CKSUM_SHA256)) buckets_sha256_init(&h->s256);
}

void buckets_cksum_hasher_cleanup(buckets_cksum_hasher *h) {
  buckets_sha1_cleanup(&h->s1);
  buckets_sha256_cleanup(&h->s256);
}

void buckets_cksum_hasher_update(buckets_cksum_hasher *h, const void *data, size_t n) {
  if (is(h->type, BUCKETS_CKSUM_CRC32)) h->c32 = buckets_crc32_ieee(h->c32, data, n);
  else if (is(h->type, BUCKETS_CKSUM_CRC32C)) h->c32 = buckets_crc32c(h->c32, data, n);
  else if (is(h->type, BUCKETS_CKSUM_SHA1)) buckets_sha1_update(&h->s1, data, n);
  else if (is(h->type, BUCKETS_CKSUM_SHA256)) buckets_sha256_update(&h->s256, data, n);
  else if (is(h->type, BUCKETS_CKSUM_CRC64NVME)) h->c64 = buckets_crc64_nvme(h->c64, data, n);
}

size_t buckets_cksum_hasher_final(buckets_cksum_hasher *h, uint8_t *raw) {
  /* Go's hash.Sum appends CRCs big-endian. */
  if (is(h->type, BUCKETS_CKSUM_CRC32) || is(h->type, BUCKETS_CKSUM_CRC32C)) {
    for (int i = 0; i < 4; i++) raw[i] = (uint8_t)(h->c32 >> (24 - 8 * i));
    return 4;
  }
  if (is(h->type, BUCKETS_CKSUM_SHA1)) {
    buckets_sha1_final(&h->s1, raw);
    return 20;
  }
  if (is(h->type, BUCKETS_CKSUM_SHA256)) {
    buckets_sha256_final(&h->s256, raw);
    return 32;
  }
  if (is(h->type, BUCKETS_CKSUM_CRC64NVME)) {
    for (int i = 0; i < 8; i++) raw[i] = (uint8_t)(h->c64 >> (56 - 8 * i));
    return 8;
  }
  return 0;
}

/* ---- CRC combination (zlib crc32_combine, generalized to 64-bit) --------- */

static uint64_t gf2_times(const uint64_t *mat, uint64_t vec) {
  uint64_t sum = 0;
  for (; vec; vec >>= 1, mat++) {
    if (vec & 1) sum ^= *mat;
  }
  return sum;
}

static void gf2_square(uint64_t *square, const uint64_t *mat, int n) {
  for (int i = 0; i < n; i++) square[i] = gf2_times(mat, mat[i]);
}

static uint64_t crc_combine(uint64_t crc1, uint64_t crc2, int64_t len2, uint64_t poly, int bits) {
  if (len2 <= 0) return crc1;
  uint64_t even[64], odd[64];
  odd[0] = poly; /* operator for one zero bit */
  uint64_t row = 1;
  for (int i = 1; i < bits; i++) {
    odd[i] = row;
    row <<= 1;
  }
  gf2_square(even, odd, bits); /* two zero bits */
  gf2_square(odd, even, bits); /* four zero bits */
  do {
    gf2_square(even, odd, bits);
    if (len2 & 1) crc1 = gf2_times(even, crc1);
    len2 >>= 1;
    if (!len2) break;
    gf2_square(odd, even, bits);
    if (len2 & 1) crc1 = gf2_times(odd, crc1);
    len2 >>= 1;
  } while (len2);
  return crc1 ^ crc2;
}

static uint64_t be(const uint8_t *p, size_t n) {
  uint64_t v = 0;
  for (size_t i = 0; i < n; i++) v = v << 8 | p[i];
  return v;
}

static void put_be(uint8_t *p, uint64_t v, size_t n) {
  for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
}

bool buckets_cksum_combine(uint32_t type, uint8_t *raw_a, const uint8_t *raw_b, int64_t len_b) {
  if (is(type, BUCKETS_CKSUM_CRC32)) {
    put_be(raw_a, crc_combine(be(raw_a, 4), be(raw_b, 4), len_b, 0xEDB88320u, 32), 4);
  } else if (is(type, BUCKETS_CKSUM_CRC32C)) {
    put_be(raw_a, crc_combine(be(raw_a, 4), be(raw_b, 4), len_b, 0x82F63B78u, 32), 4);
  } else if (is(type, BUCKETS_CKSUM_CRC64NVME)) {
    put_be(raw_a, crc_combine(be(raw_a, 8), be(raw_b, 8), len_b, 0x9A6C9329AC4BC9B5ull, 64), 8);
  } else {
    return false;
  }
  return true;
}

/* ---- values and storage form ------------------------------------------------ */

static bool cksum_is_set(uint32_t c) {
  return !is(c, BUCKETS_CKSUM_INVALID) && (c & BUCKETS_CKSUM_BASE_MASK) != 0;
}

const char *buckets_cksum_type_name(uint32_t type) {
  if (is(type, BUCKETS_CKSUM_CRC32)) return "CRC32";
  if (is(type, BUCKETS_CKSUM_CRC32C)) return "CRC32C";
  if (is(type, BUCKETS_CKSUM_SHA1)) return "SHA1";
  if (is(type, BUCKETS_CKSUM_SHA256)) return "SHA256";
  if (is(type, BUCKETS_CKSUM_CRC64NVME)) return "CRC64NVME";
  return type == 0 ? "" : "invalid";
}

uint32_t buckets_cksum_type_parse(const char *alg, const char *obj_type) {
  uint32_t full = BUCKETS_CKSUM_FULL_OBJECT;
  if (!obj_type || !*obj_type || strcmp(obj_type, "COMPOSITE") == 0) {
    full = 0;
  } else if (strcmp(obj_type, "FULL_OBJECT") != 0) {
    return BUCKETS_CKSUM_INVALID;
  }
  if (!alg || !*alg) return full ? BUCKETS_CKSUM_INVALID : 0;
  if (strcasecmp(alg, "CRC32") == 0) return BUCKETS_CKSUM_CRC32 | full;
  if (strcasecmp(alg, "CRC32C") == 0) return BUCKETS_CKSUM_CRC32C | full;
  if (strcasecmp(alg, "SHA1") == 0) return full ? BUCKETS_CKSUM_INVALID : BUCKETS_CKSUM_SHA1;
  if (strcasecmp(alg, "SHA256") == 0) return full ? BUCKETS_CKSUM_INVALID : BUCKETS_CKSUM_SHA256;
  if (strcasecmp(alg, "CRC64NVME") == 0) return BUCKETS_CKSUM_CRC64NVME;
  return BUCKETS_CKSUM_INVALID;
}

void buckets_checksum_encode(const buckets_checksum *c, char *out) { buckets_base64_encode(c->raw, c->raw_len, out); }

bool buckets_checksum_parse_value(uint32_t type, const char *value, buckets_checksum *c) {
  memset(c, 0, sizeof(*c));
  if (!cksum_is_set(type)) return false;
  const char *dash = strchr(value, '-');
  size_t vlen = dash ? (size_t)(dash - value) : strlen(value);
  if (dash) {
    char *end;
    long parts = strtol(dash + 1, &end, 10);
    if (!dash[1] || *end || strchr(dash + 1, '-')) return false;
    type |= BUCKETS_CKSUM_MULTIPART;
    c->want_parts = (int)parts;
  }
  uint8_t raw[40];
  if (vlen > 48) return false;
  long n = buckets_base64_decode(value, vlen, raw);
  if (n < 0 || (size_t)n != buckets_cksum_raw_len(type)) return false;
  c->type = type;
  memcpy(c->raw, raw, (size_t)n);
  c->raw_len = (size_t)n;
  return true;
}

static void put_uvarint(buckets_buf *b, uint64_t v) {
  while (v >= 0x80) {
    buckets_buf_append_char(b, (char)(v | 0x80));
    v >>= 7;
  }
  buckets_buf_append_char(b, (char)v);
}

void buckets_checksum_append(const buckets_checksum *c, const uint8_t *parts, size_t parts_len, buckets_buf *out) {
  uint32_t type = c->type;
  uint32_t stored = type; /* AppendTo writes the type before clearing TRAILING */
  if (is(type, BUCKETS_CKSUM_TRAILING)) type ^= BUCKETS_CKSUM_TRAILING;
  if (c->raw_len != buckets_cksum_raw_len(type)) return;
  put_uvarint(out, stored);
  buckets_buf_append(out, c->raw, c->raw_len);
  if (is(type, BUCKETS_CKSUM_MULTIPART)) {
    size_t len = buckets_cksum_raw_len(type);
    uint64_t n = (c->want_parts > 0 && !is(type, BUCKETS_CKSUM_INCLUDES_MULTIPART)) ? (uint64_t)c->want_parts : 0;
    if (parts_len && len && parts_len % len == 0) n = parts_len / len;
    put_uvarint(out, n);
    if (is(type, BUCKETS_CKSUM_INCLUDES_MULTIPART) && parts_len) buckets_buf_append(out, parts, parts_len);
  }
}

