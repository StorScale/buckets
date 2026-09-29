/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_DSYNC_H
#define BUCKETS_DIST_DSYNC_H

#include "net/client.h"
#include "core/buf.h"
#include "net/http.h"

/* Distributed read/write locks, after MinIO's internal/dsync.
 *
 * Every node runs a lock server: a non-blocking table that grants or refuses
 * a lock at once. A client asks all nodes in parallel and holds the lock when
 * a quorum granted it (writes: n/2+1; reads: n - n/2), otherwise it releases
 * what it got and retries with jitter until its deadline. Held locks are
 * refreshed every 10 s; a lock server drops holders silent for 60 s, so a
 * crashed node's locks expire. */

typedef struct buckets_lock_server buckets_lock_server;
buckets_lock_server *buckets_lock_server_new(void);
void buckets_lock_server_free(buckets_lock_server *s);
/* Handler for BUCKETS_INTERNODE_PREFIX "lock/". */
void buckets_lock_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);
size_t buckets_lock_server_held(buckets_lock_server *s); /* resources with holders */
/* Every held lock as JSON: {"resource": [{"uid", "writer", "ts" (granted,
 * unix ns), "quorum", "owner", "source"}, ...], ...} (DupLockMap). */
void buckets_lock_server_dump(buckets_lock_server *s, buckets_buf *out);
/* Drops every holder of a resource (ForceUnlock). */
void buckets_lock_server_force_unlock(buckets_lock_server *s, const char *resource);
/* localLocker.stats: locked resources, read holders, write locks. */
void buckets_lock_server_stats(buckets_lock_server *s, size_t *total, size_t *reads, size_t *writes);

typedef struct buckets_dsync buckets_dsync;
/* peers: the other nodes (borrowed); local: this node's lock server. */
buckets_dsync *buckets_dsync_new(buckets_http_client *const *peers, size_t npeers, buckets_lock_server *local);
void buckets_dsync_free(buckets_dsync *d);
/* The owner the lock servers record for this node's locks. */
void buckets_dsync_set_owner(buckets_dsync *d, const char *owner);
/* NULL when no quorum granted the lock before the timeout. */
void *buckets_dsync_lock(buckets_dsync *d, const char *resource, bool write, int timeout_ms);
/* The same, recording where the lock was taken (top locks' "source"). */
void *buckets_dsync_lock_src(buckets_dsync *d, const char *resource, bool write, int timeout_ms, const char *source);
void buckets_dsync_unlock(buckets_dsync *d, void *handle);

#endif
