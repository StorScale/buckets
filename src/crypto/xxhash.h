/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_XXHASH_H
#define BUCKETS_CRYPTO_XXHASH_H

#include "core/common.h"

/* XXH64 with seed 0 (github.com/cespare/xxhash/v2). xl.meta stores the low
 * 32 bits of XXH64 over its metadata section as an integrity check. */
uint64_t buckets_xxh64(const void *data, size_t n);

/* XXH3-64 with seed 0 and the default secret (github.com/zeebo/xxh3). Used by
 * MinIO's xl.meta version signatures (hashDeterministicString/Bytes). */
uint64_t buckets_xxh3_64(const void *data, size_t n);

#endif
