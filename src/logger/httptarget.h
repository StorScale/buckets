/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_LOGGER_HTTPTARGET_H
#define BUCKETS_LOGGER_HTTPTARGET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* MinIO's logger HTTP target (internal/logger/target/http), behind the
 * logger_webhook and audit_webhook sub-systems: entries (JSON) are queued,
 * sent in batches of batch_size as newline-terminated JSON, retried every
 * retry_interval (max_retry times, 0: forever), and with a queue_dir kept in
 * MinIO's queue store (<queue_dir>/minio-http-<name>/<uuid>.http.log.snappy)
 * until delivered. */

typedef struct {
  const char *name;       /* "audit-<target>" or "logger-<target>" */
  const char *endpoint;
  const char *auth_token; /* sent as the Authorization header, as is */
  const char *ca_file;    /* extra trusted CAs, or NULL */
  const char *user_agent;
  const char *deployment_id;
  int batch_size;        /* 1..100 */
  int queue_size;        /* entries held in memory (or in the store) */
  const char *queue_dir; /* NULL or "": memory only */
  int max_retry;         /* 0: retry forever */
  int retry_interval_ms;
  int http_timeout_ms;
  /* Buckets' own targets (logger/sentinel.h): a batch as one JSON array instead of lines, and a bearer token got
   * for each POST (false: why in err, and the batch is retried later) */
  bool json_array;
  bool (*bearer)(void *ud, char *token, size_t cap, char *err, size_t errlen);
  void *bearer_ud;
} buckets_http_target_cfg;

typedef struct buckets_http_target buckets_http_target;

buckets_http_target *buckets_http_target_new(const buckets_http_target_cfg *cfg, char *err, size_t errlen);
/* Stops the worker (entries in a store stay there). */
void buckets_http_target_free(buckets_http_target *t);
/* Queues one entry; false when the queue is full (it is dropped). */
bool buckets_http_target_send(buckets_http_target *t, const char *json, size_t n);
const char *buckets_http_target_name(const buckets_http_target *t);
const char *buckets_http_target_endpoint(const buckets_http_target *t);

typedef struct {
  uint64_t total, failed; /* messages taken in, messages whose delivery failed */
  uint64_t queued;        /* waiting now */
  bool online;
} buckets_http_target_stats;
void buckets_http_target_stats_get(buckets_http_target *t, buckets_http_target_stats *out);

#endif
