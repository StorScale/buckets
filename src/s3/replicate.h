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

#endif
