/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_CRC_H
#define BUCKETS_CRYPTO_CRC_H

#include "core/common.h"

/* Streaming CRCs for S3 additional checksums. Semantics match Go's
 * hash/crc32 (IEEE, Castagnoli) and hash/crc64 with MinIO's NVMe table:
 * pass 0 to start, feed the previous value to continue. */
uint32_t buckets_crc32_ieee(uint32_t crc, const void *data, size_t n);
uint32_t buckets_crc32c(uint32_t crc, const void *data, size_t n);
uint64_t buckets_crc64_nvme(uint64_t crc, const void *data, size_t n);

#endif
