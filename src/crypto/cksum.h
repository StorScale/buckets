/* S3 additional-checksum types and hashing (MinIO internal/hash/checksum.go flags).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_CKSUM_H
#define BUCKETS_CRYPTO_CKSUM_H

#include "core/common.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "core/buf.h"

enum {
  BUCKETS_CKSUM_TRAILING = 1u << 0,
  BUCKETS_CKSUM_SHA256 = 1u << 1,
  BUCKETS_CKSUM_SHA1 = 1u << 2,
  BUCKETS_CKSUM_CRC32 = 1u << 3,
  BUCKETS_CKSUM_CRC32C = 1u << 4,
  BUCKETS_CKSUM_INVALID = 1u << 5,
  BUCKETS_CKSUM_MULTIPART = 1u << 6,
  BUCKETS_CKSUM_INCLUDES_MULTIPART = 1u << 7,
  BUCKETS_CKSUM_CRC64NVME = 1u << 8,
  BUCKETS_CKSUM_FULL_OBJECT = 1u << 9,
};
#define BUCKETS_CKSUM_BASE_MASK \
  (BUCKETS_CKSUM_SHA256 | BUCKETS_CKSUM_SHA1 | BUCKETS_CKSUM_CRC32 | BUCKETS_CKSUM_CRC32C | BUCKETS_CKSUM_CRC64NVME)
#define BUCKETS_CKSUM_META "x-minio-internal-crc"

typedef struct {
  uint32_t type; /* 0 = none */
  uint8_t raw[32];
  size_t raw_len;
  int want_parts;
} buckets_checksum;

typedef struct {
  uint32_t type;
  uint32_t c32;
  uint64_t c64;
  buckets_sha1_ctx s1;
  buckets_sha256_ctx s256;
} buckets_cksum_hasher;

size_t buckets_cksum_raw_len(uint32_t type);
void buckets_cksum_hasher_init(buckets_cksum_hasher *h, uint32_t type);
void buckets_cksum_hasher_update(buckets_cksum_hasher *h, const void *data, size_t n);
size_t buckets_cksum_hasher_final(buckets_cksum_hasher *h, uint8_t *raw);
/* Frees a hasher started but not finished; safe after final, and on a zeroed one. */
void buckets_cksum_hasher_cleanup(buckets_cksum_hasher *h);

/* Checksum of A||B from checksum(A), checksum(B) and len(B), for the CRC
 * types (FULL_OBJECT multipart checksums). raw values are big-endian. */
bool buckets_cksum_combine(uint32_t type, uint8_t *raw_a, const uint8_t *raw_b, int64_t len_b);

/* Parses a base64 value (optionally "-N" for composite multipart) into c. */
bool buckets_checksum_parse_value(uint32_t type, const char *value, buckets_checksum *c);
void buckets_checksum_encode(const buckets_checksum *c, char *out); /* base64 of raw, out >= 48 bytes */
/* Checksum.AppendTo(nil, parts): the stored "x-minio-internal-crc" form. */
void buckets_checksum_append(const buckets_checksum *c, const uint8_t *parts, size_t parts_len, buckets_buf *out);
/* ChecksumType.String / NewChecksumType(alg, objType): 0 = none, INVALID on error. */
const char *buckets_cksum_type_name(uint32_t type);
uint32_t buckets_cksum_type_parse(const char *alg, const char *obj_type);

#endif
