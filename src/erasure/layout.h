/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_ERASURE_LAYOUT_H
#define BUCKETS_ERASURE_LAYOUT_H

#include "core/common.h"

/* Drive layout and placement, ported from MinIO cmd/endpoint-ellipses.go,
 * minio/pkg ellipses, cmd/erasure-sets.go and cmd/erasure-metadata-utils.go. */

/* One ellipsis pattern: prefix + seq[i] + suffix. */
typedef struct {
  char *prefix;
  char *suffix;
  char **seq;
  size_t nseq;
} buckets_ell_pattern;

/* All patterns of one argument, rightmost first (as FindEllipsesPatterns). */
typedef struct {
  buckets_ell_pattern *p;
  size_t n;
} buckets_ell_arg;

bool buckets_ell_has(const char *arg);
bool buckets_ell_parse(const char *arg, buckets_ell_arg *out);
/* Expanded strings in MinIO's order (leftmost pattern varies fastest). */
char **buckets_ell_expand(const buckets_ell_arg *a, size_t *n);
void buckets_ell_arg_free(buckets_ell_arg *a);

/* getSetIndexes: the erasure set size for pools of the given drive counts.
 * set_drive_count 0 chooses automatically. Returns 0 with err set on failure. */
size_t buckets_layout_set_size(const size_t *total_sizes, size_t n, size_t set_drive_count,
                               const buckets_ell_arg *patterns, size_t npatterns, char *err, size_t errlen);

typedef struct {
  char **drives; /* in set order: set k is drives[k*set_size .. (k+1)*set_size) */
  size_t ndrives;
  size_t set_size;
} buckets_pool_layout;

/* One pool from command-line arguments: either a single ellipsis argument, or
 * a plain list of drives. */
bool buckets_layout_pool(char *const *args, size_t nargs, size_t set_drive_count, buckets_pool_layout *out,
                         char *err, size_t errlen);
void buckets_layout_free(buckets_pool_layout *l);

/* storageclass.DefaultParityBlocks */
int buckets_default_parity(int set_drives);
/* sipHashMod(object, nsets, deploymentID) */
size_t buckets_set_index(const char *object, size_t nsets, const uint8_t deployment_id[16]);
/* hashOrder(key, n): 1-based shard index for each drive position. */
void buckets_hash_order(const char *key, int n, int *out);

#endif
