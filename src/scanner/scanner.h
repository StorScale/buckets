/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SCANNER_SCANNER_H
#define BUCKETS_SCANNER_SCANNER_H

#include "object/object.h"

/* The data scanner (MinIO cmd/data-scanner.go). Once per cycle it walks
 * every object:
 *  - every node heals the objects of the erasure sets it leads (writes made
 *    while a node was down, for instance);
 *  - the cluster leader (whoever leads pool 0, set 0) walks every version,
 *    hands each object to the object hook (lifecycle), counts what remains
 *    and stores the data usage in .minio.sys/buckets/.usage.json, as MinIO's
 *    scanner does, for quotas, the admin API and metrics.
 * The cycle length comes from the hooks (MinIO's `scanner speed`), unless
 * BUCKETS_SCANNER_INTERVAL gives it in seconds (0 disables the scanner). */
typedef struct buckets_scanner buckets_scanner;

typedef struct {
  /* Seconds between cycles; read before every cycle. */
  int (*cycle_seconds)(void *ud);
  /* Whether versions of object count as versions (bucket versioning is
   * enabled or suspended for it). */
  bool (*versioned)(void *ud, const char *bucket, const char *object);
  /* Every version of one object, newest first (delete markers included),
   * before it is counted; sets removed[i] for the versions it deleted.
   * NULL: nothing to apply. */
  void (*object)(void *ud, const char *bucket, const buckets_object_info *versions, size_t n, bool *removed);
  void *ud;
} buckets_scanner_hooks;

typedef struct {
  uint64_t cycles;      /* completed */
  uint64_t scanned;     /* objects looked at for healing */
  uint64_t healed;      /* objects a scan healed */
  uint64_t usage_saves; /* data usage stored (leader) */
} buckets_scanner_stats;

buckets_scanner *buckets_scanner_start(buckets_objlayer *L, const buckets_scanner_hooks *hooks);
void buckets_scanner_stop(buckets_scanner *s);
void buckets_scanner_stats_get(buckets_scanner *s, buckets_scanner_stats *out);

#endif
