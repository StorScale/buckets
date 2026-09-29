/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "scanner/usage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "object/sysconfig.h"

#define KIB 1024ull
#define MIB (1024ull * 1024ull)

static const struct {
  const char *name;
  uint64_t start, end;
} k_size_bins[BUCKETS_USAGE_SIZE_BINS] = {
    {"LESS_THAN_1024_B", 0, KIB - 1},
    {"BETWEEN_1024_B_AND_64_KB", KIB, 64 * KIB - 1},
    {"BETWEEN_64_KB_AND_256_KB", 64 * KIB, 256 * KIB - 1},
    {"BETWEEN_256_KB_AND_512_KB", 256 * KIB, 512 * KIB - 1},
    {"BETWEEN_512_KB_AND_1_MB", 512 * KIB, MIB - 1},
    {"BETWEEN_1024B_AND_1_MB", KIB, MIB - 1}, /* the sum of the four above (sizeHistogram.toMap) */
    {"BETWEEN_1_MB_AND_10_MB", MIB, 10 * MIB - 1},
    {"BETWEEN_10_MB_AND_64_MB", 10 * MIB, 64 * MIB - 1},
    {"BETWEEN_64_MB_AND_128_MB", 64 * MIB, 128 * MIB - 1},
    {"BETWEEN_128_MB_AND_512_MB", 128 * MIB, 512 * MIB - 1},
    {"GREATER_THAN_512_MB", 512 * MIB, INT64_MAX},
};

static const struct {
  const char *name;
  uint64_t start, end;
} k_version_bins[BUCKETS_USAGE_VERSION_BINS] = {
    {"UNVERSIONED", 0, 0},
    {"SINGLE_VERSION", 1, 1},
    {"BETWEEN_2_AND_10", 2, 9},
    {"BETWEEN_10_AND_100", 10, 99},
    {"BETWEEN_100_AND_1000", 100, 999},
    {"BETWEEN_1000_AND_10000", 1000, 9999},
    {"GREATER_THAN_10000", 10000, INT64_MAX},
};

const char *buckets_usage_size_bin_name(size_t i) { return i < BUCKETS_USAGE_SIZE_BINS ? k_size_bins[i].name : ""; }
const char *buckets_usage_version_bin_name(size_t i) {
  return i < BUCKETS_USAGE_VERSION_BINS ? k_version_bins[i].name : "";
}

void buckets_data_usage_free(buckets_data_usage *u) {
  for (size_t i = 0; i < u->nbuckets; i++) free(u->buckets[i].name);
  free(u->buckets);
  for (size_t i = 0; i < u->ntiers; i++) free(u->tiers[i].name);
  free(u->tiers);
  memset(u, 0, sizeof(*u));
}

const buckets_bucket_usage *buckets_data_usage_bucket(const buckets_data_usage *u, const char *bucket) {
  size_t lo = 0, hi = u->nbuckets;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    int c = strcmp(u->buckets[mid].name, bucket);
    if (!c) return &u->buckets[mid];
    if (c < 0) lo = mid + 1;
    else hi = mid;
  }
  return NULL;
}

buckets_bucket_usage *buckets_data_usage_add_bucket(buckets_data_usage *u, const char *bucket) {
  u->buckets = buckets_xrealloc(u->buckets, (u->nbuckets + 1) * sizeof(*u->buckets));
  buckets_bucket_usage *b = &u->buckets[u->nbuckets++];
  memset(b, 0, sizeof(*b));
  b->name = buckets_xstrdup(bucket);
  return b;
}

void buckets_bucket_usage_add_object(buckets_bucket_usage *b, uint64_t size, uint64_t versions, uint64_t delete_markers) {
  b->objects++;
  b->size += size;
  b->versions += versions;
  b->delete_markers += delete_markers;
  for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++) {
    if (size >= k_size_bins[i].start && size <= k_size_bins[i].end) {
      b->sizes[i]++;
      break;
    }
  }
  for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++) {
    if (versions >= k_version_bins[i].start && versions <= k_version_bins[i].end) {
      b->version_counts[i]++;
      break;
    }
  }
}

buckets_tier_usage *buckets_data_usage_tier(buckets_data_usage *u, const char *tier, bool create) {
  size_t i = 0;
  for (; i < u->ntiers; i++) {
    int c = strcmp(u->tiers[i].name, tier);
    if (!c) return &u->tiers[i];
    if (c > 0) break;
  }
  if (!create) return NULL;
  u->tiers = buckets_xrealloc(u->tiers, (u->ntiers + 1) * sizeof(*u->tiers));
  memmove(&u->tiers[i + 1], &u->tiers[i], (u->ntiers - i) * sizeof(*u->tiers));
  u->ntiers++;
  memset(&u->tiers[i], 0, sizeof(u->tiers[i]));
  u->tiers[i].name = buckets_xstrdup(tier);
  return &u->tiers[i];
}

void buckets_data_usage_total(buckets_data_usage *u) {
  u->objects = u->versions = u->delete_markers = u->total_size = 0;
  for (size_t i = 0; i < u->nbuckets; i++) {
    u->objects += u->buckets[i].objects;
    u->versions += u->buckets[i].versions;
    u->delete_markers += u->buckets[i].delete_markers;
    u->total_size += u->buckets[i].size;
  }
  u->buckets_count = u->nbuckets;
}

/* ---- JSON ------------------------------------------------------------------------------ */

/* Go marshals map keys sorted. */
static int cmp_names(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }

static void histogram_json(buckets_buf *out, const char *const *names, const uint64_t *counts, size_t n) {
  const char *sorted[16];
  uint64_t val[16];
  for (size_t i = 0; i < n; i++) sorted[i] = names[i];
  qsort(sorted, n, sizeof(*sorted), cmp_names);
  for (size_t i = 0; i < n; i++)
    for (size_t j = 0; j < n; j++)
      if (sorted[i] == names[j]) val[i] = counts[j];
  buckets_buf_append_c(out, "{");
  for (size_t i = 0; i < n; i++) buckets_buf_appendf(out, "%s\"%s\":%llu", i ? "," : "", sorted[i], (unsigned long long)val[i]);
  buckets_buf_append_c(out, "}");
}

static void json_str(buckets_buf *out, const char *s) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  size_t n;
  char *enc = yyjson_mut_val_write(yyjson_mut_str(d, s), 0, &n);
  buckets_buf_append(out, enc, n);
  free(enc);
  yyjson_mut_doc_free(d);
}

void buckets_data_usage_json(const buckets_data_usage *u, buckets_buf *out) {
  char ts[64];
  buckets_time_rfc3339_nano(u->last_update_ns / 1000000000LL, (long)(u->last_update_ns % 1000000000LL), ts);
  buckets_buf_appendf(out,
                      "{\"lastUpdate\":\"%s\",\"objectsCount\":%llu,\"versionsCount\":%llu,\"deleteMarkersCount\":%llu,"
                      "\"objectsTotalSize\":%llu,\"objectsReplicationInfo\":null,\"bucketsCount\":%llu,\"bucketsUsageInfo\":{",
                      ts, (unsigned long long)u->objects, (unsigned long long)u->versions,
                      (unsigned long long)u->delete_markers, (unsigned long long)u->total_size,
                      (unsigned long long)u->buckets_count);
  const char *sn[BUCKETS_USAGE_SIZE_BINS], *vn[BUCKETS_USAGE_VERSION_BINS];
  for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++) sn[i] = k_size_bins[i].name;
  for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++) vn[i] = k_version_bins[i].name;
  for (size_t i = 0; i < u->nbuckets; i++) {
    const buckets_bucket_usage *b = &u->buckets[i];
    uint64_t sizes[BUCKETS_USAGE_SIZE_BINS];
    memcpy(sizes, b->sizes, sizeof(sizes));
    sizes[5] = sizes[1] + sizes[2] + sizes[3] + sizes[4];
    if (i) buckets_buf_append_c(out, ",");
    json_str(out, b->name);
    buckets_buf_appendf(out,
                        ":{\"size\":%llu,\"objectsPendingReplicationTotalSize\":0,\"objectsFailedReplicationTotalSize\":0,"
                        "\"objectsReplicatedTotalSize\":0,\"objectsPendingReplicationCount\":0,"
                        "\"objectsFailedReplicationCount\":0,\"objectsCount\":%llu,\"objectsSizesHistogram\":",
                        (unsigned long long)b->size, (unsigned long long)b->objects);
    histogram_json(out, sn, sizes, BUCKETS_USAGE_SIZE_BINS);
    buckets_buf_append_c(out, ",\"objectsVersionsHistogram\":");
    histogram_json(out, vn, b->version_counts, BUCKETS_USAGE_VERSION_BINS);
    buckets_buf_appendf(out,
                        ",\"versionsCount\":%llu,\"deleteMarkersCount\":%llu,\"objectReplicaTotalSize\":0,"
                        "\"objectReplicaCount\":0,\"objectsReplicationInfo\":null}",
                        (unsigned long long)b->versions, (unsigned long long)b->delete_markers);
  }
  buckets_buf_append_c(out, "},\"bucketsSizes\":{");
  for (size_t i = 0; i < u->nbuckets; i++) {
    if (i) buckets_buf_append_c(out, ",");
    json_str(out, u->buckets[i].name);
    buckets_buf_appendf(out, ":%llu", (unsigned long long)u->buckets[i].size);
  }
  buckets_buf_append_c(out, "}");
  /* TierStats *allTierStats `json:"tierStats,omitempty"`: Go field names */
  if (u->ntiers) {
    buckets_buf_append_c(out, ",\"tierStats\":{\"Tiers\":{");
    for (size_t i = 0; i < u->ntiers; i++) {
      if (i) buckets_buf_append_c(out, ",");
      json_str(out, u->tiers[i].name);
      buckets_buf_appendf(out, ":{\"TotalSize\":%llu,\"NumVersions\":%llu,\"NumObjects\":%llu}",
                          (unsigned long long)u->tiers[i].size, (unsigned long long)u->tiers[i].versions,
                          (unsigned long long)u->tiers[i].objects);
    }
    buckets_buf_append_c(out, "}}");
  }
  buckets_buf_append_c(out, "}");
}

static uint64_t u64(yyjson_val *o, const char *key) {
  yyjson_val *v = yyjson_obj_get(o, key);
  return yyjson_is_uint(v) ? yyjson_get_uint(v) : 0;
}

static int cmp_bucket(const void *a, const void *b) {
  return strcmp(((const buckets_bucket_usage *)a)->name, ((const buckets_bucket_usage *)b)->name);
}

bool buckets_data_usage_parse(const char *json, size_t len, buckets_data_usage *out) {
  memset(out, 0, sizeof(*out));
  yyjson_doc *d = yyjson_read(json, len, 0);
  yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
  if (!yyjson_is_obj(root)) {
    yyjson_doc_free(d);
    return false;
  }
  long long sec;
  long nsec;
  const char *lu = yyjson_get_str(yyjson_obj_get(root, "lastUpdate"));
  if (lu && buckets_time_parse_rfc3339(lu, &sec, &nsec)) out->last_update_ns = sec * 1000000000LL + nsec;
  out->objects = u64(root, "objectsCount");
  out->versions = u64(root, "versionsCount");
  out->delete_markers = u64(root, "deleteMarkersCount");
  out->total_size = u64(root, "objectsTotalSize");
  out->buckets_count = u64(root, "bucketsCount");
  yyjson_val *bu = yyjson_obj_get(root, "bucketsUsageInfo");
  yyjson_obj_iter it = yyjson_obj_iter_with(bu);
  yyjson_val *k;
  while (yyjson_is_obj(bu) && (k = yyjson_obj_iter_next(&it))) {
    yyjson_val *v = yyjson_obj_iter_get_val(k);
    buckets_bucket_usage *b = buckets_data_usage_add_bucket(out, yyjson_get_str(k));
    b->size = u64(v, "size");
    b->objects = u64(v, "objectsCount");
    b->versions = u64(v, "versionsCount");
    b->delete_markers = u64(v, "deleteMarkersCount");
    yyjson_val *sh = yyjson_obj_get(v, "objectsSizesHistogram"), *vh = yyjson_obj_get(v, "objectsVersionsHistogram");
    for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++) b->sizes[i] = u64(sh, k_size_bins[i].name);
    b->sizes[5] = 0; /* derived */
    for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++) b->version_counts[i] = u64(vh, k_version_bins[i].name);
  }
  /* Older files carry only bucketsSizes (loadDataUsageFromBackend). */
  yyjson_val *bs = yyjson_obj_get(root, "bucketsSizes");
  if (!out->nbuckets && yyjson_is_obj(bs)) {
    it = yyjson_obj_iter_with(bs);
    while ((k = yyjson_obj_iter_next(&it))) buckets_data_usage_add_bucket(out, yyjson_get_str(k))->size = yyjson_get_uint(yyjson_obj_iter_get_val(k));
  }
  yyjson_val *ts = yyjson_obj_get(yyjson_obj_get(root, "tierStats"), "Tiers");
  if (yyjson_is_obj(ts)) {
    it = yyjson_obj_iter_with(ts);
    while ((k = yyjson_obj_iter_next(&it))) {
      yyjson_val *v = yyjson_obj_iter_get_val(k);
      buckets_tier_usage *t = buckets_data_usage_tier(out, yyjson_get_str(k), true);
      t->size = u64(v, "TotalSize");
      t->versions = u64(v, "NumVersions");
      t->objects = u64(v, "NumObjects");
    }
  }
  if (out->nbuckets) qsort(out->buckets, out->nbuckets, sizeof(*out->buckets), cmp_bucket);
  yyjson_doc_free(d);
  return true;
}

/* ---- the cache ---------------------------------------------------------------------- */

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

void buckets_usage_cache_init(buckets_usage_cache *c, buckets_objlayer *L, int ttl_ms) {
  memset(c, 0, sizeof(*c));
  c->L = L;
  c->ttl_ms = ttl_ms;
  pthread_mutex_init(&c->mu, NULL);
}

void buckets_usage_cache_free(buckets_usage_cache *c) {
  buckets_data_usage_free(&c->u);
  pthread_mutex_destroy(&c->mu);
}

/* Reloads when stale; call with mu held. Keeps the last good value on errors
 * (cachevalue's ReturnLastGood). */
static void refresh(buckets_usage_cache *c) {
  int64_t now = now_ns();
  if (c->loaded_ns && now - c->loaded_ns < (int64_t)c->ttl_ms * 1000000LL) return;
  c->loaded_ns = now;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_obj_err err = buckets_sysconfig_read(c->L, BUCKETS_USAGE_PATH, &b, NULL);
  if (err) err = buckets_sysconfig_read(c->L, BUCKETS_USAGE_PATH ".bkp", &b, NULL);
  buckets_data_usage u;
  if (!err && buckets_data_usage_parse(b.data, b.len, &u)) {
    buckets_data_usage_free(&c->u);
    c->u = u;
  }
  buckets_buf_free(&b);
}

uint64_t buckets_usage_cache_bucket_size(buckets_usage_cache *c, const char *bucket) {
  pthread_mutex_lock(&c->mu);
  refresh(c);
  const buckets_bucket_usage *b = buckets_data_usage_bucket(&c->u, bucket);
  uint64_t size = b ? b->size : 0;
  pthread_mutex_unlock(&c->mu);
  return size;
}

bool buckets_usage_cache_get(buckets_usage_cache *c, buckets_data_usage *out) {
  pthread_mutex_lock(&c->mu);
  refresh(c);
  bool have = c->u.last_update_ns != 0;
  memset(out, 0, sizeof(*out));
  if (have) {
    *out = c->u;
    out->buckets = buckets_xcalloc(c->u.nbuckets ? c->u.nbuckets : 1, sizeof(*out->buckets));
    for (size_t i = 0; i < c->u.nbuckets; i++) {
      out->buckets[i] = c->u.buckets[i];
      out->buckets[i].name = buckets_xstrdup(c->u.buckets[i].name);
    }
    out->tiers = c->u.ntiers ? buckets_xcalloc(c->u.ntiers, sizeof(*out->tiers)) : NULL;
    for (size_t i = 0; i < c->u.ntiers; i++) {
      out->tiers[i] = c->u.tiers[i];
      out->tiers[i].name = buckets_xstrdup(c->u.tiers[i].name);
    }
  }
  pthread_mutex_unlock(&c->mu);
  return have;
}
