/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_DSYNC_H
#define BUCKETS_DIST_DSYNC_H

#include "net/client.h"
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
/* localLocker.stats: locked resources, read holders, write locks. */
void buckets_lock_server_stats(buckets_lock_server *s, size_t *total, size_t *reads, size_t *writes);

typedef struct buckets_dsync buckets_dsync;
/* peers: the other nodes (borrowed); local: this node's lock server. */
buckets_dsync *buckets_dsync_new(buckets_http_client *const *peers, size_t npeers, buckets_lock_server *local);
void buckets_dsync_free(buckets_dsync *d);
/* NULL when no quorum granted the lock before the timeout. */
void *buckets_dsync_lock(buckets_dsync *d, const char *resource, bool write, int timeout_ms);
void buckets_dsync_unlock(buckets_dsync *d, void *handle);

#endif
