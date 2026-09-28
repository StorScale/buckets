/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_ERASURE_RS_H
#define BUCKETS_ERASURE_RS_H

#include "core/common.h"

/* Systematic Reed-Solomon over GF(2^8) (polynomial 0x11d), bit-compatible with
 * github.com/klauspost/reedsolomon's default encoder as MinIO configures it:
 * the encoding matrix is a (data+parity) x data Vandermonde matrix multiplied
 * by the inverse of its top square. Verified against MinIO's erasureSelfTest. */

#define BUCKETS_RS_MAX_SHARDS 256

typedef struct buckets_rs buckets_rs;

buckets_rs *buckets_rs_new(int data, int parity);
void buckets_rs_free(buckets_rs *rs);
int buckets_rs_data(const buckets_rs *rs);
int buckets_rs_parity(const buckets_rs *rs);

/* Computes shards[data..data+parity) from shards[0..data), each len bytes. */
void buckets_rs_encode(const buckets_rs *rs, uint8_t *const *shards, size_t len);

/* Rebuilds missing shards (present[i] == false) in place; missing shards
 * must point at len-byte buffers. With data_only, only data shards are
 * rebuilt (ReconstructData). Returns false if fewer than `data` shards remain. */
bool buckets_rs_reconstruct(const buckets_rs *rs, uint8_t *const *shards, const bool *present, size_t len,
                            bool data_only);

/* Split: shard size for a block of n bytes, ceil(n / data). */
static inline size_t buckets_rs_shard_size(const buckets_rs *rs, size_t n) {
  int d = buckets_rs_data(rs);
  return (n + (size_t)d - 1) / (size_t)d;
}

/* Tests: force the portable (false) or SIMD (true) arithmetic. */
void buckets_rs_set_simd(bool on);

#endif
