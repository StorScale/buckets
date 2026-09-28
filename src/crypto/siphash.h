/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_SIPHASH_H
#define BUCKETS_CRYPTO_SIPHASH_H

#include "core/common.h"

/* SipHash-2-4 (github.com/dchest/siphash Hash(k0, k1, msg)). MinIO maps
 * objects to erasure sets with it (sipHashMod), keyed by the deployment ID. */
uint64_t buckets_siphash24(uint64_t k0, uint64_t k1, const void *msg, size_t n);

#endif
