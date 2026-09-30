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
  /* The size a version counts with (GetActualSize: plaintext sizes of
   * compressed and encrypted objects). NULL: the stored size. */
  int64_t (*actual_size)(void *ud, const buckets_object_info *version);
  /* A free version (a deleted transitioned version's remnant), to sweep:
   * its remote copy and then itself. NULL: left alone. */
  void (*free_version)(void *ud, const char *bucket, const buckets_object_info *fv);
  /* The configured remote tiers' names (strings and array to free), for the
   * per-tier usage; none: no tierStats. */
  size_t (*tier_names)(void *ud, char ***names);
  void *ud;
} buckets_scanner_hooks;

typedef struct {
  uint64_t cycles;      /* completed */
  uint64_t scanned;     /* objects looked at for healing */
  uint64_t healed;      /* objects a scan healed */
  uint64_t usage_saves; /* data usage stored (leader) */
  /* lifetime counts, as MinIO's scanner metrics */
  uint64_t objects, versions, folders;
  uint64_t bucket_scans_started, bucket_scans_finished;
  int64_t last_activity_ns; /* the last cycle's end (0: none yet) */
  /* currentScannerCycle, on the node running the cycles (the leader) once
   * one started: its number (0 between cycles), start and the last 16 ends */
  bool have_cycle;
  uint64_t current_cycle;
  int64_t current_started_ns;
  int64_t completed_ns[16];
  size_t ncompleted;
  char active[1024]; /* "<bucket>/<key>" being scanned now, "" between buckets */
} buckets_scanner_stats;

buckets_scanner *buckets_scanner_start(buckets_objlayer *L, const buckets_scanner_hooks *hooks);
void buckets_scanner_stop(buckets_scanner *s);
void buckets_scanner_stats_get(buckets_scanner *s, buckets_scanner_stats *out);

#endif
