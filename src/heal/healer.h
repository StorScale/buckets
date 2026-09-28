/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_HEAL_HEALER_H
#define BUCKETS_HEAL_HEALER_H

#include "object/object.h"

/* The background healer: one thread that drains
 *  - the MRF queue (MinIO cmd/mrf.go): objects a read found short of a
 *    shard, or a write left short of a drive, reported by the object layer;
 *  - drive heals (MinIO cmd/background-newdisks-heal-ops.go): a replaced
 *    drive, formatted into its slot at startup, is filled by healing every
 *    object of its erasure set. Progress lives in a tracker file on the
 *    drive, so an interrupted heal resumes after a restart.
 * and a second thread, the scanner (MinIO cmd/data-scanner.go), which walks
 * every object of the sets this node leads, once per cycle, and heals what
 * it finds short -- writes made while a node was down, for instance.
 * BUCKETS_SCANNER_INTERVAL sets the pause between cycles in seconds
 * (default 60; 0 disables the scanner). */
typedef struct buckets_healer buckets_healer;

typedef struct {
  uint64_t queued, healed, failed, dropped; /* MRF */
  uint64_t scan_cycles, scanned;            /* scanner */
  size_t drives_healing;
  uint64_t drive_objects_healed;
} buckets_healer_stats;

/* Registers as the layer's degraded hook and starts the thread. */
buckets_healer *buckets_healer_start(buckets_objlayer *L);
/* Stops the thread; queued MRF entries are dropped (reads find them again). */
void buckets_healer_stop(buckets_healer *h);
void buckets_healer_enqueue(buckets_healer *h, const char *bucket, const char *object, const char *version_id,
                            bool deep);
void buckets_healer_stats_get(buckets_healer *h, buckets_healer_stats *out);
/* Blocks until the MRF queue is empty and no drive heal is running (tests). */
void buckets_healer_wait_idle(buckets_healer *h);

/* The tracker marking a drive as being healed. */
#define BUCKETS_HEALING_TRACKER "buckets-healing.json"

#endif
