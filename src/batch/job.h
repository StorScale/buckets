/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BATCH_JOB_H
#define BUCKETS_BATCH_JOB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* Batch job definitions (MinIO's BatchJobRequest and friends in
 * cmd/batch-*.go): the YAML users submit, the msgp MinIO keeps in
 * .minio.sys/batch-jobs/<id>, the YAML `mc batch describe` prints, and the
 * job reports (batchJobInfo) in .minio.sys/batch-jobs/reports/<id>/. */

#define BUCKETS_BATCH_PREFIX "batch-jobs"
#define BUCKETS_BATCH_REPORTS_PREFIX "batch-jobs/reports"
#define BUCKETS_BATCH_REDACTED "**REDACTED**"

typedef struct {
  int64_t sec;
  int32_t nsec;
  bool set; /* false: Go's zero time */
} buckets_batch_time;

typedef struct {
  char *key, *value;
  int line, col;
} buckets_batch_kv;

typedef struct {
  buckets_batch_kv *v;
  size_t n;
} buckets_batch_kvs;

typedef struct {
  char *endpoint, *token;
  int line, col;
} buckets_batch_notify;

typedef struct {
  int64_t attempts, delay_ns;
  int line, col;
} buckets_batch_retry;

typedef struct {
  char *access_key, *secret_key, *session_token;
} buckets_batch_creds;

/* BatchJobPrefix: one prefix or several */
typedef struct {
  char **v;
  size_t n;
} buckets_batch_strs;

typedef struct {
  signed char disable, inmemory, compress, skip_errs; /* -1: unset (nil) */
  bool has_batch;
  int64_t batch;
  char *smaller_than; /* NULL: unset */
  int line, col;
} buckets_batch_snowball;

typedef struct {
  int64_t newer_than_ns, older_than_ns;
  buckets_batch_time created_after, created_before;
  buckets_batch_kvs tags, metadata;
  char *kms_key_id; /* keyrotate only */
} buckets_batch_filter;

typedef struct {
  buckets_batch_filter filter;
  buckets_batch_notify notify;
  buckets_batch_retry retry;
} buckets_batch_flags;

typedef struct {
  char *type, *bucket, *prefix, *endpoint, *path;
  buckets_batch_creds creds;
} buckets_batch_repl_target;

typedef struct {
  char *type, *bucket;
  buckets_batch_strs prefix;
  char *endpoint, *path;
  buckets_batch_creds creds;
  buckets_batch_snowball snowball;
} buckets_batch_repl_source;

typedef struct {
  char *api_version;
  buckets_batch_flags flags;
  buckets_batch_repl_target target;
  buckets_batch_repl_source source;
} buckets_batch_replicate;

typedef struct {
  char *api_version;
  buckets_batch_flags flags;
  char *bucket, *prefix;
  char *enc_type, *enc_key, *enc_context;
  /* encryption.includeUnencrypted (a Buckets extension): unencrypted versions
   * are encrypted in place too, not skipped; onlyUnencrypted: only they are,
   * encrypted versions are left as they are */
  bool include_unencrypted, only_unencrypted;
} buckets_batch_keyrotate;

typedef struct {
  int64_t older_than_ns;
  buckets_batch_time created_before; /* set: given (a *time.Time) */
  buckets_batch_kvs tags, metadata;
  int64_t size_lt, size_gt; /* lessThan, greaterThan */
  int size_line, size_col;
  char *type, *name;
  int64_t retain_versions;
  int purge_line, purge_col;
  int line, col;
} buckets_batch_expire_rule;

typedef struct {
  char *api_version, *bucket;
  buckets_batch_strs prefix;
  buckets_batch_notify notify;
  buckets_batch_retry retry;
  buckets_batch_expire_rule *rules;
  size_t nrules;
  int line, col;
} buckets_batch_expire;

typedef struct {
  char *id, *user;
  buckets_batch_time started;
  buckets_batch_replicate *replicate;
  buckets_batch_keyrotate *keyrotate;
  buckets_batch_expire *expire;
} buckets_batch_job;

void buckets_batch_job_free(buckets_batch_job *j);

/* yaml.Unmarshal of a job definition; false with the error MinIO reports
 * (yaml's syntax and type errors, or an unmarshaler's). */
bool buckets_batch_job_parse(const char *yaml, size_t n, buckets_batch_job *out, char **err);
/* StartBatchJob's snowball defaults for replicate jobs. */
void buckets_batch_job_defaults(buckets_batch_job *j);
/* "replicate", "keyrotate", "expire" or "unknown" (BatchJobRequest.Type). */
const char *buckets_batch_job_type(const buckets_batch_job *j);
/* RedactSensitive */
void buckets_batch_job_redact(buckets_batch_job *j);

/* job.bin: BatchJobRequest.MarshalMsg and its inverse. */
void buckets_batch_job_msgp(const buckets_batch_job *j, buckets_buf *out);
bool buckets_batch_job_from_msgp(const void *p, size_t n, buckets_batch_job *out);
/* yaml.Marshal(BatchJobRequest), for mc batch describe. */
void buckets_batch_job_yaml(const buckets_batch_job *j, buckets_buf *out);

/* Validation errors: code, description and HTTP status. code NULL means
 * MinIO's errInvalidArgument (XMinioAdminInvalidArgument, 400); internal
 * marks errors MinIO reports as InternalError with a cause. */
typedef struct {
  const char *code;
  char desc[512];
  int status;
  bool internal;
} buckets_batch_err;

/* BatchJobKV.Validate, BatchJobRetry.Validate, BatchJobSnowball.Validate,
 * BatchJobExpireFilter.Validate (MinIO's BatchJobYamlErr texts with their
 * "Hint: error near line" suffix). */
bool buckets_batch_kv_validate(const buckets_batch_kv *kv, buckets_batch_err *e);
bool buckets_batch_retry_validate(const buckets_batch_retry *r, buckets_batch_err *e);
bool buckets_batch_snowball_validate(const buckets_batch_snowball *s, buckets_batch_err *e);
bool buckets_batch_expire_rule_validate(const buckets_batch_expire_rule *r, int64_t now_sec, buckets_batch_err *e);
/* BatchJobKV.Match: key case-insensitively, value as a wildcard. */
bool buckets_batch_kv_match(const buckets_batch_kv *kv, const char *key, const char *value);

/* humanize.ParseBytes ("10MiB", "1KiB", "5 MB", "42"). */
bool buckets_humanize_parse_bytes(const char *s, uint64_t *out, char *err, size_t errlen);
/* xtime.ParseDuration: time.ParseDuration plus d (24h) and w (7d). */
bool buckets_xtime_parse_duration(const char *s, int64_t *ns, char *err, size_t errlen);

/* ---- job reports (batchJobInfo) ------------------------------------------------------------------ */

typedef struct {
  int64_t version;
  char *job_id, *job_type;
  buckets_batch_time start, last_update;
  int64_t retry_attempts, attempts;
  bool complete, failed;
  char *bucket, *object; /* the last one processed */
  int64_t objects, delete_markers, objects_failed, delete_markers_failed, bytes_transferred, bytes_failed;
} buckets_batch_info;

void buckets_batch_info_free(buckets_batch_info *ri);
void buckets_batch_info_copy(buckets_batch_info *dst, const buckets_batch_info *src);
/* The report's file name for a job type ("batch-replicate.bin",
 * "batch-rotate.bin", "batch-expire.bin"), or NULL. */
const char *buckets_batch_report_name(const char *job_type);
/* reports/<id>/<name>: the 4-byte header (format 1, version 1) and msgp */
void buckets_batch_info_encode(const buckets_batch_info *ri, buckets_buf *out);
/* false with a message on a bad file (errors as MinIO's loadByPath) */
bool buckets_batch_info_decode(const char *file_name, const void *p, size_t n, buckets_batch_info *out, char *err,
                               size_t errlen);
/* madmin.JobMetric JSON */
void buckets_batch_info_metric_json(const buckets_batch_info *ri, buckets_buf *out);
/* countItem, as trackCurrentBucketObject does with the lock held */
void buckets_batch_info_count(buckets_batch_info *ri, int64_t size, bool dmarker, bool success, int attempt);

#endif
