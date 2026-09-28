/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_HIGHWAYHASH_H
#define BUCKETS_CRYPTO_HIGHWAYHASH_H

#include "core/common.h"

/* HighwayHash-256, a port of the portable implementation in
 * github.com/minio/highwayhash. MinIO uses it (with a fixed key) for bitrot
 * protection of every erasure shard, so it must be bit-exact. */

#define BUCKETS_HH_KEY_LEN 32
#define BUCKETS_HH256_LEN 32

typedef struct {
  uint64_t state[16];
  uint8_t key[BUCKETS_HH_KEY_LEN];
  uint8_t buffer[32];
  size_t offset;
} buckets_hh_ctx;

void buckets_hh_init(buckets_hh_ctx *ctx, const uint8_t key[BUCKETS_HH_KEY_LEN]);
void buckets_hh_reset(buckets_hh_ctx *ctx);
void buckets_hh_update(buckets_hh_ctx *ctx, const void *data, size_t n);
/* Does not modify ctx (like Go's hash.Sum). */
void buckets_hh_final256(const buckets_hh_ctx *ctx, uint8_t out[BUCKETS_HH256_LEN]);
void buckets_hh256(const uint8_t key[BUCKETS_HH_KEY_LEN], const void *data, size_t n,
                   uint8_t out[BUCKETS_HH256_LEN]);

/* MinIO's magicHighwayHash256Key (cmd/bitrot.go). */
extern const uint8_t buckets_bitrot_key[BUCKETS_HH_KEY_LEN];

#endif
