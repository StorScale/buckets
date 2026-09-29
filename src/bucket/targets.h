/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_TARGETS_H
#define BUCKETS_BUCKET_TARGETS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

struct buckets_kms;

/* Bucket remote targets (madmin.BucketTarget / BucketTargets): the JSON the
 * admin API exchanges and the bucket metadata stores (BucketTargetsConfigJSON,
 * SSE-S3-encrypted with its BucketTargetsConfigMetaJSON when a KMS is
 * configured), and replication ARNs. */

typedef struct {
  char *source_bucket, *endpoint, *target_bucket;
  bool has_creds;
  char *access_key, *secret_key, *session_token;
  int64_t creds_exp_sec; /* Go zero time: BUCKETS_GO_ZERO_SEC */
  int32_t creds_exp_nsec;
  bool secure;
  char *path, *api, *arn, *type, *region, *storage_class, *reset_id, *deployment_id;
  int64_t bandwidth_limit;
  bool replication_sync, disable_proxy, edge, edge_sync_before_expiry;
  int64_t health_check_ns;
  int64_t reset_before_sec; /* Go zero time: BUCKETS_GO_ZERO_SEC */
  int32_t reset_before_nsec;
  /* reported (ListRemoteTargets) */
  int64_t total_downtime_ns;
  int64_t last_online_sec;
  int32_t last_online_nsec;
  bool online;
  int64_t lat_curr, lat_avg, lat_max;
  int64_t offline_count;
} buckets_bucket_target;

/* Seconds of Go's zero time.Time (0001-01-01T00:00:00Z). */
#define BUCKETS_GO_ZERO_SEC (-62135596800LL)

typedef struct {
  buckets_bucket_target *t;
  size_t n;
} buckets_bucket_targets;

void buckets_bucket_target_init(buckets_bucket_target *t);
void buckets_bucket_target_free(buckets_bucket_target *t);
void buckets_bucket_target_copy(buckets_bucket_target *dst, const buckets_bucket_target *src);
void buckets_bucket_targets_free(buckets_bucket_targets *ts);

/* One BucketTarget object (json.Unmarshal); err as encoding/json. */
bool buckets_bucket_target_parse(const char *json, size_t len, buckets_bucket_target *out, char *err, size_t errlen);
/* {"targets":[...]} */
bool buckets_bucket_targets_parse(const char *json, size_t len, buckets_bucket_targets *out, char *err, size_t errlen);
/* json.Marshal(target) / (&targets); clone: t.Clone() (credentials reduced to the access key). */
void buckets_bucket_target_json(const buckets_bucket_target *t, bool clone, buckets_buf *out);
void buckets_bucket_targets_json(const buckets_bucket_targets *ts, buckets_buf *out);

/* The stored form: encrypted (meta_json filled) when kms is set. */
bool buckets_bucket_targets_seal(struct buckets_kms *kms, const char *bucket, const void *json, size_t len,
                                 buckets_buf *data, buckets_buf *meta_json);
/* parseBucketTargetConfig: decrypts when meta_json says so. */
bool buckets_bucket_targets_open(struct buckets_kms *kms, const char *bucket, const void *data, size_t len,
                                 const void *meta_json, size_t meta_len, buckets_bucket_targets *out);

/* madmin.ARN */
typedef struct {
  char type[32], region[64], id[64], bucket[256];
} buckets_arn;
/* ParseARN: "arn:minio:<type>:<region>:<id>:<bucket>" */
bool buckets_arn_parse(const char *s, buckets_arn *out);
/* ARN.String() for a new target (id: a fresh UUID unless given) */
void buckets_arn_generate(const char *type, const char *region, const char *id, const char *bucket, char *out,
                          size_t cap);

#endif
