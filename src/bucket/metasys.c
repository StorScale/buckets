/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/metasys.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/log.h"
#include "core/strmap.h"

struct buckets_metasys {
  buckets_objlayer *layer;
  int ttl_ms;
  pthread_mutex_t mu;       /* guards cache */
  pthread_mutex_t write_mu; /* serializes read-modify-write updates */
  buckets_strmap cache;     /* bucket -> buckets_bucket_state */
  void (*notify)(void *ud, const char *bucket);
  void *notify_ud;
};

static long long now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

void buckets_bucket_state_release(buckets_bucket_state *st) {
  if (!st || atomic_fetch_sub(&st->refs, 1) != 1) return;
  buckets_bucket_meta_free(&st->meta);
  buckets_policy_free(st->policy);
  free(st);
}

buckets_metasys *buckets_metasys_new(buckets_objlayer *layer, int ttl_ms) {
  buckets_metasys *m = buckets_xcalloc(1, sizeof(*m));
  m->layer = layer;
  m->ttl_ms = ttl_ms;
  pthread_mutex_init(&m->mu, NULL);
  pthread_mutex_init(&m->write_mu, NULL);
  return m;
}

void buckets_metasys_free(buckets_metasys *m) {
  if (!m) return;
  size_t it = 0;
  void *v;
  while (buckets_strmap_next(&m->cache, &it, NULL, &v)) buckets_bucket_state_release(v);
  buckets_strmap_free(&m->cache);
  pthread_mutex_destroy(&m->mu);
  pthread_mutex_destroy(&m->write_mu);
  free(m);
}

static buckets_bucket_state *build(const char *bucket, buckets_bucket_meta *meta, bool exists) {
  buckets_bucket_state *st = buckets_xcalloc(1, sizeof(*st));
  atomic_init(&st->refs, 1);
  st->exists = exists;
  st->meta = *meta;
  st->loaded_ns = now_ns();
  const buckets_buf *pol = &st->meta.config[BUCKETS_BCFG_POLICY];
  if (pol->len) {
    char err[256];
    if (!buckets_bucket_policy_parse(pol->data, pol->len, bucket, &st->policy, err, sizeof(err))) {
      buckets_log_warn("bucket %s: stored policy does not parse: %s", bucket, err);
      st->policy = NULL;
    }
  }
  return st;
}

static buckets_bucket_state *load(buckets_metasys *m, const char *bucket) {
  buckets_bucket_meta meta;
  bool exists = buckets_bucket_meta_load(m->layer, bucket, &meta);
  if (!exists) buckets_bucket_meta_init(&meta, bucket, 0);
  return build(bucket, &meta, exists);
}

static void publish(buckets_metasys *m, const char *bucket, buckets_bucket_state *st) {
  atomic_fetch_add(&st->refs, 1);
  pthread_mutex_lock(&m->mu);
  buckets_bucket_state_release(buckets_strmap_put(&m->cache, bucket, st));
  pthread_mutex_unlock(&m->mu);
}

buckets_bucket_state *buckets_metasys_get(buckets_metasys *m, const char *bucket) {
  pthread_mutex_lock(&m->mu);
  buckets_bucket_state *st = buckets_strmap_get(&m->cache, bucket);
  bool fresh = st && (m->ttl_ms <= 0 || now_ns() - st->loaded_ns < (long long)m->ttl_ms * 1000000LL);
  if (fresh) atomic_fetch_add(&st->refs, 1);
  pthread_mutex_unlock(&m->mu);
  if (fresh) return st;
  st = load(m, bucket);
  publish(m, bucket, st);
  return st;
}

bool buckets_metasys_update(buckets_metasys *m, const char *bucket, buckets_bucket_cfg cfg, const void *data,
                            size_t len) {
  pthread_mutex_lock(&m->write_mu);
  buckets_bucket_meta meta;
  if (!buckets_bucket_meta_load(m->layer, bucket, &meta)) {
    /* Buckets created before metadata existed: start one, as MinIO does. */
    buckets_bucket_meta_init(&meta, bucket, now_ns());
  }
  buckets_buf_reset(&meta.config[cfg]);
  if (data && len) buckets_buf_append(&meta.config[cfg], data, len);
  long long ns = now_ns();
  meta.updated[cfg] = (buckets_gotime){ns / 1000000000LL, (int32_t)(ns % 1000000000LL)};
  bool ok = buckets_bucket_meta_save(m->layer, &meta);
  if (ok) {
    buckets_bucket_state *st = build(bucket, &meta, true);
    publish(m, bucket, st);
    buckets_bucket_state_release(st);
    if (m->notify) m->notify(m->notify_ud, bucket);
  } else {
    buckets_bucket_meta_free(&meta);
  }
  pthread_mutex_unlock(&m->write_mu);
  return ok;
}

void buckets_metasys_invalidate(buckets_metasys *m, const char *bucket) {
  pthread_mutex_lock(&m->mu);
  buckets_bucket_state_release(buckets_strmap_del(&m->cache, bucket));
  pthread_mutex_unlock(&m->mu);
}

void buckets_metasys_set_notify(buckets_metasys *m, void (*fn)(void *ud, const char *bucket), void *ud) {
  m->notify = fn;
  m->notify_ud = ud;
}

void buckets_metasys_changed(buckets_metasys *m, const char *bucket) {
  buckets_metasys_invalidate(m, bucket);
  if (m->notify) m->notify(m->notify_ud, bucket);
}
