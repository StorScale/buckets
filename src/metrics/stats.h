/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_METRICS_STATS_H
#define BUCKETS_METRICS_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The server's request statistics (MinIO's globalHTTPStats, globalConnStats
 * and their per-bucket counterparts), read by the metrics endpoints. */

/* MinIO's S3 API names as metrics label them (the handler name,
 * lowercase), and the rejected ones (notImplemented routes). */
int buckets_api_index(const char *name); /* -1 when unknown */
const char *buckets_api_name(int api);         /* lowercase (v2) */
const char *buckets_api_handler_name(int api); /* as the handler is named (v3) */
size_t buckets_api_count(void);

/* The TTFB histogram of MinIO's s3_ttfb_seconds: these upper bounds, then +Inf. */
#define BUCKETS_TTFB_NBOUNDS 8
extern const double buckets_ttfb_bounds[BUCKETS_TTFB_NBOUNDS];

typedef struct {
  uint64_t total, errors, err4xx, err5xx, canceled;
  int64_t inflight;
  uint64_t ttfb[BUCKETS_TTFB_NBOUNDS + 1]; /* per bucket, not cumulative */
  double ttfb_sum;
} buckets_api_stats;

typedef enum {
  BUCKETS_REJECT_AUTH,
  BUCKETS_REJECT_HEADER,
  BUCKETS_REJECT_TIMESTAMP,
  BUCKETS_REJECT_INVALID,
  BUCKETS_REJECT__N
} buckets_reject_kind;

/* A request to api (an index) begins; bucket: an existing bucket it names
 * (per-bucket statistics), or NULL. */
void buckets_stats_begin(int api, const char *bucket);
/* ...and ends: its status, time to first byte, and body bytes in and out. */
void buckets_stats_end(int api, const char *bucket, int status, double ttfb_s, uint64_t rx, uint64_t tx);
void buckets_stats_reject(buckets_reject_kind k);
/* Requests queued for a worker (waiting) and being read (incoming). */
void buckets_stats_waiting(int delta);

typedef struct {
  buckets_api_stats *api; /* buckets_api_count() entries */
  uint64_t rejected[BUCKETS_REJECT__N];
  int64_t waiting, incoming;
  uint64_t rx, tx;
} buckets_stats_snapshot;
void buckets_stats_get(buckets_stats_snapshot *out);
/* Requests in flight now, over every API (reads nothing else). */
int64_t buckets_stats_inflight(void);
void buckets_stats_snapshot_free(buckets_stats_snapshot *s);

typedef struct {
  char *bucket;
  buckets_api_stats *api; /* buckets_api_count() entries */
  uint64_t rx, tx;
} buckets_bucket_stats;
/* Per-bucket statistics, sorted by bucket. */
size_t buckets_stats_buckets(buckets_bucket_stats **out);
void buckets_stats_buckets_free(buckets_bucket_stats *v, size_t n);
/* Drops a removed bucket's statistics. */
void buckets_stats_forget_bucket(const char *bucket);

#endif
