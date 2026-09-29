/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_TIERING_H
#define BUCKETS_S3_TIERING_H

#include <stdbool.h>
#include <stdint.h>

#include "core/buf.h"
#include "object/object.h"

/* Lifecycle transitions and the rest of tiering on the server side (MinIO's
 * transitionState, getTransitionedObjectReader, expireTransitionedObject,
 * the tier journal and the free-version sweep): workers that move due
 * versions to their remote tier, reads of transitioned versions, and the
 * removal of remote copies that are no longer referenced. */

struct buckets_s3_server;
typedef struct buckets_tiering buckets_tiering;

/* Installs the object layer's remote-read hook and starts the workers. */
buckets_tiering *buckets_tiering_new(struct buckets_s3_server *s, buckets_objlayer *layer);
void buckets_tiering_stop(buckets_tiering *t);

/* queueTransitionTask: a version due for transition to tier (immediate:
 * right after a write, counted as missed when the queue is full). */
void buckets_tiering_queue(buckets_tiering *t, const char *bucket, const buckets_object_info *oi, const char *tier,
                           const char *rule_id, int64_t due_ns, bool noncurrent, bool immediate);
/* The tier journal: removes a remote copy in the background. */
void buckets_tiering_remove_remote(buckets_tiering *t, const char *tier, const char *remote, const char *version);
/* deleteObjectFromRemoteTier, now: true when removed (or already gone). */
bool buckets_tiering_remove_remote_now(struct buckets_s3_server *s, const char *tier, const char *remote,
                                       const char *version);

typedef struct {
  int64_t pending, active, missed_immediate;
} buckets_tiering_stats;
void buckets_tiering_stats_get(buckets_tiering *t, buckets_tiering_stats *out);

/* Requests served from each tier (tierMetrics): per tier name. */
typedef struct {
  char tier[128];
  uint64_t success, failure;
  uint64_t ttlb_buckets[11]; /* cumulative counts for 0.01,0.1,1,2,5,10,60,300,900,1800s and +Inf */
  double ttlb_sum;
} buckets_tier_request_stats;
size_t buckets_tiering_request_stats(buckets_tier_request_stats **out);

/* The last day's transitions per tier, in hourly bins (lastDayTierStats):
 * this node's, and merged with the peers'. */
typedef struct {
  uint64_t size, versions, objects;
} buckets_tier_stat;
typedef struct {
  char tier[128];
  buckets_tier_stat bins[24];
  int64_t updated_ns;
} buckets_tier_day;
size_t buckets_tiering_day_stats(buckets_tiering *t, buckets_tier_day **out);
/* The internode form, and a peer's merged into a list (DailyAllTierStats.merge). */
void buckets_tier_days_json(const buckets_tier_day *d, size_t n, buckets_buf *out);
void buckets_tier_days_merge_json(buckets_tier_day **d, size_t *n, const char *json);

#endif
