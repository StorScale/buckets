/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_REPLICATE_H
#define BUCKETS_S3_REPLICATE_H

#include "bucket/replication.h"
#include "bucket/targets.h"
#include "core/buf.h"
#include "net/s3client.h"
#include "object/object.h"

struct buckets_s3_server;

/* Bucket replication (MinIO's cmd/bucket-replication*.go, bucket-targets.go):
 * the remote targets and their health, the replication decision for writes
 * and deletes, and the workers that replicate object versions and deletes
 * to remote MinIO/Buckets clusters, recording each target's status on the
 * source version. */

typedef struct buckets_repl buckets_repl;

buckets_repl *buckets_repl_new(struct buckets_s3_server *s);
/* Stops the workers and health checks (queued work is dropped). */
void buckets_repl_stop(buckets_repl *r);
void buckets_repl_free(buckets_repl *r);

/* ---- decisions (ReplicateDecision) ---- */
typedef struct {
  char *arn;
  bool replicate, sync;
} buckets_repl_tdec;

typedef struct buckets_repl_dsc_s {
  buckets_repl_tdec *t;
  size_t n;
} buckets_repl_dsc;

void buckets_repl_dsc_free(buckets_repl_dsc *d);
bool buckets_repl_dsc_any(const buckets_repl_dsc *d);
bool buckets_repl_dsc_sync(const buckets_repl_dsc *d);
/* PendingStatus: "arn=PENDING;" for each target to replicate to. */
void buckets_repl_dsc_pending(const buckets_repl_dsc *d, buckets_buf *out);

/* mustReplicate. meta: the version's user metadata (for SSE-C, tags and a
 * REPLICA status); user_tags overrides its X-Amz-Tagging when set. */
void buckets_repl_must(struct buckets_s3_server *s, const char *bucket, const char *object, const buckets_xl_kv *meta,
                       size_t nmeta, const buckets_xl_kv *sys, size_t nsys, const char *user_tags, buckets_repl_type op,
                       bool replication_request, buckets_repl_dsc *out);
/* checkReplicateDelete: goi the version found (NULL: none). */
void buckets_repl_check_delete(struct buckets_s3_server *s, const char *bucket, const char *object,
                               const char *version_id, const buckets_object_info *goi, bool versioned,
                               bool replication_request, buckets_repl_dsc *out);

/* scheduleReplication for a version just written: replicates now for
 * synchronous targets, else queues. event is the audit trigger
 * ("replicate:incoming", "replicate:heal", ...). */
void buckets_repl_schedule(struct buckets_s3_server *s, const char *bucket, const buckets_object_info *oi,
                           const buckets_repl_dsc *d, buckets_repl_type op, const char *event);
/* scheduleReplicationDelete: res from the object layer's delete. */
void buckets_repl_schedule_delete(struct buckets_s3_server *s, const char *bucket, const char *object,
                                  const buckets_delete_result *res, const char *event);

/* The composite status of a stored version (the X-Amz-Replication-Status
 * clients see), or NULL. */
const char *buckets_repl_version_status(const buckets_object_info *oi, char *buf, size_t cap);

/* ---- existing objects ---- */
/* ResetBucketReplicationStart's resync (resyncer.start): 0, or -1 with err. */
int buckets_repl_resync_start(buckets_repl *r, const char *bucket, const char *arn, const char *reset_id,
                              int64_t before_ns, char *err, size_t errlen);
/* ResetBucketReplicationStatus: ResyncTargetsInfo JSON. */
bool buckets_repl_resync_status(buckets_repl *r, const char *bucket, const char *arn, buckets_buf *out, char *err,
                                size_t errlen);
/* queueReplicationHeal: the scanner's check of one version (pending or
 * failed replication, existing objects). */
void buckets_repl_heal(struct buckets_s3_server *s, const char *bucket, const buckets_object_info *oi, int retry);
/* ReplicationDiff: DiffInfo JSON lines for versions not replicated. */
void buckets_repl_diff(struct buckets_s3_server *s, const char *bucket, const char *prefix, const char *arn, bool verbose,
                       buckets_buf *out);
/* The MRF backlog as ReplicationMRF JSON lines (bucket "" for all). */
void buckets_repl_mrf_json(buckets_repl *r, const char *bucket, const char *node_name, buckets_buf *out);
/* Resumes unfinished resyncs (after startup). */
void buckets_repl_resync_resume(buckets_repl *r);

/* ---- remote targets ---- */
/* A client for a bucket's target, or NULL; release with buckets_repl_target_put. */
typedef struct buckets_repl_target buckets_repl_target;
buckets_repl_target *buckets_repl_target_get(buckets_repl *r, const char *bucket, const char *arn);
void buckets_repl_target_put(buckets_repl_target *t);
buckets_s3c *buckets_repl_target_client(buckets_repl_target *t);
const buckets_bucket_target *buckets_repl_target_info(buckets_repl_target *t);
/* A client for a target description (validation before it is stored). */
buckets_s3c *buckets_repl_client_for(buckets_repl *r, const buckets_bucket_target *t);
/* The endpoint's health (ListRemoteTargets). */
void buckets_repl_health_fill(buckets_repl *r, buckets_bucket_target *t);
bool buckets_repl_offline(buckets_repl *r, const char *endpoint, bool secure);

/* Health-check statistics of every endpoint in use (the metrics). */
typedef struct {
  char endpoint[256];
  bool online;
  int64_t offline_ns, last_online_sec;
  int64_t lat_curr, lat_avg, lat_max;
  int64_t offline_count;
} buckets_repl_ep_health;
size_t buckets_repl_health_list(buckets_repl *r, buckets_repl_ep_health **out);

/* Active-active proxying (proxyHeadToReplicationTarget and friends): when a
 * version is missing here, a HEAD/GET is answered from a target. */
typedef struct {
  buckets_repl_target *t;
  buckets_s3c_result res; /* the target's response */
  buckets_http_stream *body; /* GET: the body to relay */
} buckets_repl_proxy;
bool buckets_repl_proxy_open(buckets_repl *r, const char *bucket, const char *object, const char *version_id,
                             const char *range, bool head, buckets_repl_proxy *out);
void buckets_repl_proxy_close(buckets_repl_proxy *p);

/* ---- statistics since startup (replstats.c) ---- */
typedef struct {
  char arn[256];
  int64_t repl_size, repl_count;
  int64_t fail_min_count, fail_min_bytes, fail_hour_count, fail_hour_bytes, fail_total_count, fail_total_bytes;
  int64_t lat[6][60][3]; /* by size: per second {total ns, size, n} */
  int64_t lat_last_sec[6];
  double xfer[2][3]; /* large, small: curr, avg, peak (bytes/s) */
} buckets_repl_target_stats;

typedef struct {
  buckets_repl_target_stats *t;
  size_t n;
  int64_t replica_size, replica_count;
  int64_t q_count, q_bytes, q_max_count, q_max_bytes;
  double q_avg_count, q_avg_bytes;
  uint64_t proxy[5][2]; /* get, head, put/get/remove tagging: total, failed */
} buckets_repl_bucket_stats;

typedef struct {
  int64_t uptime;
  int64_t workers_curr, workers_max;
  double workers_avg;
  double xfer[2][3];
  int64_t q_count, q_bytes, q_max_count, q_max_bytes;
  double q_avg_count, q_avg_bytes;
  int64_t mrf_failed_last5, mrf_dropped_count, mrf_dropped_bytes;
} buckets_repl_node_stats;

enum { BUCKETS_REPL_PROXY_GET, BUCKETS_REPL_PROXY_HEAD, BUCKETS_REPL_PROXY_PUT_TAG, BUCKETS_REPL_PROXY_GET_TAG,
       BUCKETS_REPL_PROXY_RM_TAG };

void buckets_repl_stats_init(void);
/* A version replicated (completed) or not (failed) to arn, dur_ns the transfer. */
void buckets_repl_stats_update(const char *bucket, const char *arn, bool completed, bool failed, int64_t size,
                               int64_t dur_ns);
void buckets_repl_stats_replica(const char *bucket, int64_t size);
void buckets_repl_stats_queue(const char *bucket, int64_t size, int delta);
void buckets_repl_stats_workers(int delta);
void buckets_repl_stats_mrf_dropped(int64_t size);
void buckets_repl_stats_mrf_failed(int64_t n);
void buckets_repl_stats_proxy(const char *bucket, int api, bool failed);
void buckets_repl_stats_delete_bucket(const char *bucket);
/* false when the bucket has no statistics (out is zeroed) */
bool buckets_repl_stats_get(const char *bucket, buckets_repl_bucket_stats *out);
void buckets_repl_bucket_stats_free(buckets_repl_bucket_stats *s);
void buckets_repl_stats_node(buckets_repl_node_stats *out);
/* GetBucketReplicationMetrics (v1: BucketReplicationStats) or V2 (BucketStats). */
void buckets_repl_stats_json(const char *bucket, const char *node_name, bool v2, buckets_buf *out);
void buckets_repl_stats_upload_latency(const buckets_repl_target_stats *t, const char **tags, uint64_t *ms);

#endif
