/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_HEALTH_H
#define BUCKETS_STORAGE_HEALTH_H

/* Local drive health, as MinIO's xlStorageDiskIDCheck tracks it: a drive that
 * fails, hangs or is swapped from under its mount point goes offline (the
 * quorum checks, `mc admin info` and the drive metrics then say so), and
 * comes back once it works again.
 *
 * Each local drive has a checker thread: every interval it reads the drive's
 * format.json (its "this" must still be the drive's ID), then writes, reads
 * back and removes a 4 KiB probe file in .minio.sys/tmp. A failure makes the
 * drive faulty; a format.json that is gone or names another drive makes it
 * changed; a check still running after the timeout makes it hung. A drive in
 * any of these states refuses every call at once: no request waits on a dead
 * disk, and nothing lands on an emptied one before it is formatted back
 * (storage/format.c writes its format.json directly).
 *
 * BUCKETS_DRIVE_CHECK_INTERVAL (seconds, default 15) and
 * BUCKETS_DRIVE_CHECK_TIMEOUT (seconds, default 30) tune it; an interval of
 * 0 turns the checks off. */

#include <stdbool.h>
#include <stddef.h>

#include "storage/drive.h"

typedef enum {
  BUCKETS_DRIVE_HEALTH_OK = 0,
  BUCKETS_DRIVE_HEALTH_FAULTY,  /* the probe failed */
  BUCKETS_DRIVE_HEALTH_CHANGED, /* format.json gone, or naming another drive */
  BUCKETS_DRIVE_HEALTH_HUNG,    /* a check has run past the timeout (derived, never stored) */
} buckets_drive_health;

/* One check of a local drive, now (the checker threads call it; tests too). Returns the new state. */
buckets_drive_health buckets_drive_health_check(buckets_drive *d);

/* The drive's state: OK for remote drives (their own server checks them). */
buckets_drive_health buckets_drive_health_state(buckets_drive *d);
/* Words for a state: "ok", "faulty: <why>", ... into out. */
void buckets_drive_health_describe(buckets_drive *d, char *out, size_t cap);

/* Whether a local drive is changed because its format.json is gone (an empty or replaced drive), rather than
 * naming another drive. */
bool buckets_drive_health_unformatted(buckets_drive *d);

/* Whether calls on a local drive must fail at once: any state but OK. It also looks whether format.json is
 * still there, at most once a second, so an emptied drive stops taking calls within about a second. */
bool buckets_drive_health_refuses(buckets_drive *d);
/* When the drive was found changed (wall-clock ms), 0 when it is not. */
long long buckets_drive_health_changed_since(buckets_drive *d);

/* Points each local drive among copies at the drive among drives with the same root, so both share its
 * checks (bucketsd serves its drives to peers through objects of their own). */
void buckets_drive_health_share(buckets_drive *const *copies, size_t ncopies, buckets_drive *const *drives, size_t n);

/* The checks' interval, in seconds (0: off). */
long buckets_drive_health_interval(void);

/* Starts the checker threads for the local drives among drives. */
void buckets_drive_health_start(buckets_drive *const *drives, size_t n);
/* Stops and joins them (before the drives are closed). */
void buckets_drive_health_stop(void);

#endif
