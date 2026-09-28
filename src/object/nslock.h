/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OBJECT_NSLOCK_H
#define BUCKETS_OBJECT_NSLOCK_H

#include "core/common.h"

/* Namespace locks: a read/write lock per (volume, path), created on demand
 * and dropped when unused. Replaces MinIO's cmd/namespace-lock.go for a
 * single node; distributed mode layers dsync on the same calls. Writers are
 * preferred so a stream of readers cannot starve them. A held lock may be
 * released from any thread. */
typedef struct buckets_nslock buckets_nslock;
typedef struct buckets_nslock_entry buckets_nslock_entry;

buckets_nslock *buckets_nslock_new(void);
void buckets_nslock_free(buckets_nslock *t);
/* Returns NULL if the lock was not granted within timeout_ms. */
buckets_nslock_entry *buckets_nslock_lock(buckets_nslock *t, const char *vol, const char *path, bool write,
                                          int timeout_ms);
void buckets_nslock_unlock(buckets_nslock_entry *e);

#endif
