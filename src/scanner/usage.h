/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SCANNER_USAGE_H
#define BUCKETS_SCANNER_USAGE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "core/buf.h"
#include "object/object.h"

/* MinIO's DataUsageInfo, as the scanner stores it in
 * .minio.sys/buckets/.usage.json (and .usage.json.bkp every tenth time). */

#define BUCKETS_USAGE_SIZE_BINS 11   /* ObjectsHistogramIntervals */
#define BUCKETS_USAGE_VERSION_BINS 7 /* ObjectsVersionCountIntervals */
#define BUCKETS_USAGE_PATH "buckets/.usage.json"

typedef struct {
  char *name;
  uint64_t size, objects, versions, delete_markers;
  uint64_t sizes[BUCKETS_USAGE_SIZE_BINS];
  uint64_t version_counts[BUCKETS_USAGE_VERSION_BINS];
} buckets_bucket_usage;

/* One tier's share (tierStats): the hot tier's storage classes (STANDARD,
 * RRS) and the remote tiers. */
typedef struct {
  char *name;
  uint64_t size, versions, objects;
} buckets_tier_usage;

typedef struct {
  int64_t last_update_ns;
  uint64_t objects, versions, delete_markers, total_size, buckets_count;
  buckets_bucket_usage *buckets; /* sorted by name */
  size_t nbuckets;
  buckets_tier_usage *tiers; /* tierStats, sorted by name; none when no tier is configured */
  size_t ntiers;
} buckets_data_usage;

void buckets_data_usage_free(buckets_data_usage *u);
/* The histogram ranges' names (the keys MinIO stores and labels metrics with). */
const char *buckets_usage_size_bin_name(size_t i);
const char *buckets_usage_version_bin_name(size_t i);
/* The bucket's entry, or NULL. */
const buckets_bucket_usage *buckets_data_usage_bucket(const buckets_data_usage *u, const char *bucket);
/* Adds a bucket entry (names must arrive sorted) and returns it. */
buckets_bucket_usage *buckets_data_usage_add_bucket(buckets_data_usage *u, const char *bucket);
/* One object (every version of a key): its summed size, counted versions
 * and delete markers (dataUsageEntry.addSizes + Objects++). */
void buckets_bucket_usage_add_object(buckets_bucket_usage *b, uint64_t size, uint64_t versions, uint64_t delete_markers);
/* A tier's entry, added (zeroed, in order) when create is set; NULL otherwise. */
buckets_tier_usage *buckets_data_usage_tier(buckets_data_usage *u, const char *tier, bool create);
/* Recomputes the totals from the buckets. */
void buckets_data_usage_total(buckets_data_usage *u);

/* json.Marshal(DataUsageInfo) and its (lenient) inverse. */
void buckets_data_usage_json(const buckets_data_usage *u, buckets_buf *out);
bool buckets_data_usage_parse(const char *json, size_t len, buckets_data_usage *out);

/* The stored usage, reloaded at most every ttl_ms (MinIO's bucketStorageCache:
 * 10s), for any node. */
typedef struct buckets_usage_cache_s {
  buckets_objlayer *L;
  int ttl_ms;
  pthread_mutex_t mu;
  int64_t loaded_ns;
  buckets_data_usage u;
} buckets_usage_cache;

void buckets_usage_cache_init(buckets_usage_cache *c, buckets_objlayer *L, int ttl_ms);
void buckets_usage_cache_free(buckets_usage_cache *c);
/* A bucket's size (0 when unknown). */
uint64_t buckets_usage_cache_bucket_size(buckets_usage_cache *c, const char *bucket);
/* A copy of the whole usage; false when none has been stored yet. */
bool buckets_usage_cache_get(buckets_usage_cache *c, buckets_data_usage *out);

#endif
