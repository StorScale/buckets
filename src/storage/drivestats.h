/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_DRIVESTATS_H
#define BUCKETS_STORAGE_DRIVESTATS_H

#include <stdint.h>

#include "storage/drive.h"

/* Per-drive call statistics (MinIO's xlStorageDiskIDCheck metrics): the
 * last minute's latency of each storage API, errors, calls in flight. */

typedef enum {
  BUCKETS_DOP_MAKE_VOL,
  BUCKETS_DOP_STAT_VOL,
  BUCKETS_DOP_DELETE_VOL,
  BUCKETS_DOP_LIST_VOLS,
  BUCKETS_DOP_READ_ALL,
  BUCKETS_DOP_WRITE_ALL,
  BUCKETS_DOP_CREATE_FILE,
  BUCKETS_DOP_APPEND_FILE,
  BUCKETS_DOP_FSYNC_FILE,
  BUCKETS_DOP_OPEN_FILE,
  BUCKETS_DOP_READ_FILE,
  BUCKETS_DOP_RENAME_DATA,
  BUCKETS_DOP_DELETE,
  BUCKETS_DOP_LIST_DIR,
  BUCKETS_DOP_DISK_INFO,
  BUCKETS_DOP_STAT_FILE,
  BUCKETS_DOP_RENAME_FILE,
  BUCKETS_DOP__N
} buckets_drive_op;

/* The name MinIO's storage metrics use for an op ("storage." is prefixed
 * in the metric label). */
const char *buckets_drive_op_name(buckets_drive_op op);

void buckets_drive_stats_begin(buckets_drive *d);
void buckets_drive_stats_end(buckets_drive *d, buckets_drive_op op, int64_t ns, buckets_drive_err err);
void buckets_drive_stats_free(buckets_drive *d);

typedef struct {
  uint64_t errors_availability, errors_timeout;
  int64_t waiting;
  uint64_t count[BUCKETS_DOP__N];  /* calls in the last minute */
  double avg_us[BUCKETS_DOP__N];   /* their mean latency */
  uint64_t acc_ns[BUCKETS_DOP__N]; /* their summed latency */
  uint64_t total[BUCKETS_DOP__N];  /* calls since start */
} buckets_drive_stats_view;
void buckets_drive_stats_get(buckets_drive *d, buckets_drive_stats_view *out);

#endif
