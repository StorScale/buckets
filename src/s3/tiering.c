/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Transitions to remote tiers and reads back from them (MinIO's
 * transitionState and transitionObject in cmd/bucket-lifecycle.go, and
 * getTransitionedObjectReader). */
#include "s3/tiering.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/auditctx.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "crypto/xxhash.h"
#include "s3/internal.h"
#include "tier/tier.h"

#define ILM_TRANSITION_UA "Internal: [ILM-Transition]"
#define QUEUE_CAP 100000

typedef struct task {
  struct task *next;
  bool remove; /* a tier journal entry, not a transition */
  char *bucket, *object, *version_id, *etag, *tier, *rule_id;
  char *remote, *remote_version;
  int64_t mod_time_ns, size, due_ns;
  bool noncurrent, is_latest;
} task;

struct buckets_tiering {
  buckets_s3_server *s;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  task *head, *tail;
  int64_t queued, active, missed;
  bool stop;
  pthread_t *threads;
  int nthreads;
  buckets_tier_day *days; /* under mu */
  size_t ndays;
};

static void task_free(task *t) {
  free(t->bucket);
  free(t->object);
  free(t->version_id);
  free(t->etag);
  free(t->tier);
  free(t->rule_id);
  free(t->remote);
  free(t->remote_version);
  free(t);
}

static char *dupz(const char *s) { return buckets_xstrdup(s ? s : ""); }

/* ---- tier request metrics ---------------------------------------------------------------- */

static pthread_mutex_t g_stats_mu = PTHREAD_MUTEX_INITIALIZER;
static buckets_tier_request_stats *g_stats;
static size_t g_nstats;
static const double k_ttlb_bounds[10] = {0.01, 0.1, 1, 2, 5, 10, 60, 300, 900, 1800};

static void record_request(const char *tier, bool ok, double secs) {
  pthread_mutex_lock(&g_stats_mu);
  size_t i = 0;
  for (; i < g_nstats && strcmp(g_stats[i].tier, tier) != 0; i++) {
  }
  if (i == g_nstats) {
    g_stats = buckets_xrealloc(g_stats, (g_nstats + 1) * sizeof(*g_stats));
    memset(&g_stats[g_nstats], 0, sizeof(*g_stats));
    snprintf(g_stats[g_nstats].tier, sizeof(g_stats[g_nstats].tier), "%s", tier);
    g_nstats++;
  }
  buckets_tier_request_stats *st = &g_stats[i];
  if (ok) {
    st->success++;
    for (size_t b = 0; b < 10; b++)
      if (secs <= k_ttlb_bounds[b]) st->ttlb_buckets[b]++;
    st->ttlb_buckets[10]++;
    st->ttlb_sum += secs;
  } else {
    st->failure++;
  }
  pthread_mutex_unlock(&g_stats_mu);
}

size_t buckets_tiering_request_stats(buckets_tier_request_stats **out) {
  pthread_mutex_lock(&g_stats_mu);
  *out = buckets_xcalloc(g_nstats + 1, sizeof(**out));
  memcpy(*out, g_stats, g_nstats * sizeof(**out));
  size_t n = g_nstats;
  pthread_mutex_unlock(&g_stats_mu);
  return n;
}

/* ---- last day's transitions ---------------------------------------------------------------- */

#define HOUR_NS 3600000000000LL

static int hour_of(int64_t ns) {
  time_t t = (time_t)(ns / 1000000000LL);
  struct tm tm;
  localtime_r(&t, &tm);
  return tm.tm_hour;
}

/* lastDayTierStats.forwardTo: clears the bins between the last update and t. */
static void day_forward(buckets_tier_day *d, int64_t t) {
  int64_t since = t - d->updated_ns;
  if (since < HOUR_NS) return;
  int idx = hour_of(t), last = hour_of(d->updated_ns);
  d->updated_ns = t;
  if (since >= 24 * HOUR_NS) {
    memset(d->bins, 0, sizeof(d->bins));
    return;
  }
  while (last != idx) {
    last = (last + 1) % 24;
    memset(&d->bins[last], 0, sizeof(d->bins[last]));
  }
}

static buckets_tier_day *day_find(buckets_tier_day **d, size_t *n, const char *tier) {
  for (size_t i = 0; i < *n; i++)
    if (!strcmp((*d)[i].tier, tier)) return &(*d)[i];
  *d = buckets_xrealloc(*d, (*n + 1) * sizeof(**d));
  buckets_tier_day *e = &(*d)[(*n)++];
  memset(e, 0, sizeof(*e));
  snprintf(e->tier, sizeof(e->tier), "%s", tier);
  return e;
}

static int64_t wall_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void add_day_stats(buckets_tiering *tg, const char *tier, const task *t) {
  int64_t now = wall_ns();
  pthread_mutex_lock(&tg->mu);
  buckets_tier_day *d = day_find(&tg->days, &tg->ndays, tier);
  day_forward(d, now);
  buckets_tier_stat *b = &d->bins[hour_of(now)];
  b->size += t->size > 0 ? (uint64_t)t->size : 0;
  b->versions++;
  b->objects += t->is_latest;
  pthread_mutex_unlock(&tg->mu);
}

size_t buckets_tiering_day_stats(buckets_tiering *tg, buckets_tier_day **out) {
  *out = NULL;
  if (!tg) return 0;
  pthread_mutex_lock(&tg->mu);
  size_t n = tg->ndays;
  *out = buckets_xcalloc(n + 1, sizeof(**out));
  memcpy(*out, tg->days, n * sizeof(**out));
  pthread_mutex_unlock(&tg->mu);
  return n;
}

void buckets_tier_days_json(const buckets_tier_day *d, size_t n, buckets_buf *out) {
  buckets_buf_append_c(out, "{");
  for (size_t i = 0; i < n; i++) {
    buckets_buf_appendf(out, "%s\"%s\":{\"updated\":%lld,\"bins\":[", i ? "," : "", d[i].tier,
                        (long long)d[i].updated_ns);
    for (int h = 0; h < 24; h++)
      buckets_buf_appendf(out, "%s[%llu,%llu,%llu]", h ? "," : "", (unsigned long long)d[i].bins[h].size,
                          (unsigned long long)d[i].bins[h].versions, (unsigned long long)d[i].bins[h].objects);
    buckets_buf_append_c(out, "]}");
  }
  buckets_buf_append_c(out, "}");
}

/* lastDayTierStats.merge: both forwarded to the later update, then summed. */
void buckets_tier_days_merge_json(buckets_tier_day **d, size_t *n, const char *json) {
  yyjson_doc *doc = json ? yyjson_read(json, strlen(json), 0) : NULL;
  yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
  yyjson_obj_iter it = yyjson_obj_iter_with(root);
  yyjson_val *k;
  while (yyjson_is_obj(root) && (k = yyjson_obj_iter_next(&it))) {
    yyjson_val *v = yyjson_obj_iter_get_val(k), *bins = yyjson_obj_get(v, "bins");
    const char *tier = yyjson_get_str(k);
    if (!tier || strlen(tier) >= sizeof((*d)->tier)) continue;
    buckets_tier_day m = {0};
    m.updated_ns = (int64_t)yyjson_get_uint(yyjson_obj_get(v, "updated"));
    for (int h = 0; h < 24 && yyjson_is_arr(bins); h++) {
      yyjson_val *b = yyjson_arr_get(bins, (size_t)h);
      m.bins[h].size = yyjson_get_uint(yyjson_arr_get(b, 0));
      m.bins[h].versions = yyjson_get_uint(yyjson_arr_get(b, 1));
      m.bins[h].objects = yyjson_get_uint(yyjson_arr_get(b, 2));
    }
    buckets_tier_day *l = day_find(d, n, tier);
    if (l->updated_ns > m.updated_ns) day_forward(&m, l->updated_ns);
    else day_forward(l, m.updated_ns);
    if (m.updated_ns > l->updated_ns) l->updated_ns = m.updated_ns;
    for (int h = 0; h < 24; h++) {
      l->bins[h].size += m.bins[h].size;
      l->bins[h].versions += m.bins[h].versions;
      l->bins[h].objects += m.bins[h].objects;
    }
  }
  yyjson_doc_free(doc);
}

static double mono_secs(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---- reading transitioned versions -------------------------------------------------------- */

typedef struct {
  buckets_warm *w;
  buckets_warm_stream *st;
  int64_t want, got;
  double start;
  bool failed;
} remote_reader;

static long remote_read(void *ud, void *buf, size_t n) {
  remote_reader *r = ud;
  long k = buckets_warm_stream_read(r->st, buf, n);
  if (k > 0) r->got += k;
  if (k < 0) r->failed = true;
  return k;
}

static void remote_free(void *ud) {
  remote_reader *r = ud;
  record_request(buckets_warm_tier(r->w), !r->failed && r->got == r->want, mono_secs() - r->start);
  buckets_warm_stream_free(r->st);
  buckets_warm_release(r->w);
  free(r);
}

static bool tier_open(void *ud, const char *tier, const char *remote, const char *version, int64_t off, int64_t len,
                      long (**rd)(void *, void *, size_t), void (**rd_free)(void *), void **rd_ud) {
  buckets_s3_server *s = ud;
  char err[512];
  buckets_warm *w = buckets_tiers_driver(s->tiers, tier, err, sizeof(err));
  if (!w) {
    buckets_log_warn("transition storage class not configured: %s", err);
    return false;
  }
  double start = mono_secs();
  buckets_warm_stream *st = NULL;
  buckets_warm_err e = buckets_warm_get(w, remote, version, off, len, &st, err, sizeof(err));
  if (e) {
    record_request(tier, false, 0);
    buckets_log_warn("tier %s: reading %s: %s", tier, remote, err);
    buckets_warm_release(w);
    return false;
  }
  remote_reader *r = buckets_xcalloc(1, sizeof(*r));
  *r = (remote_reader){.w = w, .st = st, .want = len, .start = start};
  *rd = remote_read;
  *rd_free = remote_free;
  *rd_ud = r;
  return true;
}

/* ---- transitions --------------------------------------------------------------------------- */

typedef struct {
  buckets_s3_server *s;
  const char *bucket, *object, *tier;
} upload_ctx;

/* genTransitionObjName: <xxh3(deployment/bucket) in hex>/<u[0:2]>/<u[2:4]>/<uuid> */
static void remote_name(buckets_s3_server *s, const char *bucket, char *out, size_t cap) {
  char u[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(u);
  buckets_buf k = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&k, "%s/%s", s->layer->deployment_id_str, bucket);
  uint64_t h = buckets_xxh3_64(k.data, k.len);
  buckets_buf_free(&k);
  snprintf(out, cap, "%llx/%.2s/%.2s/%s", (unsigned long long)h, u, u + 2, u);
}

static buckets_obj_err upload(void *ud, buckets_read_fn rd, void *rd_ud, int64_t size, char *remote, size_t rcap,
                              char *rv, size_t rvcap) {
  upload_ctx *u = ud;
  char err[512];
  buckets_warm *w = buckets_tiers_driver(u->s->tiers, u->tier, err, sizeof(err));
  if (!w) {
    buckets_log_warn("transition of %s/%s: tier %s: %s", u->bucket, u->object, u->tier, err);
    return BUCKETS_OBJ_ERR_TIER;
  }
  remote_name(u->s, u->bucket, remote, rcap);
  buckets_warm_err e = buckets_warm_put(w, remote, rd, rd_ud, size, u->object, rv, rvcap, err, sizeof(err));
  buckets_warm_release(w);
  if (e) {
    buckets_log_warn("Transition to %s failed for %s/%s: %s", u->tier, u->bucket, u->object, err);
    return BUCKETS_OBJ_ERR_TIER;
  }
  return BUCKETS_OBJ_OK;
}

/* auditLogLifecycle(ILMTransition) */
static void audit_transition(const task *t, const buckets_object_info *oi, buckets_obj_err err) {
  const char *keys[6], *values[6];
  size_t n = 0;
  char due[BUCKETS_TIME_AMZ_LEN + 1];
  keys[n] = "ilm-src", values[n++] = "Scanner";
  keys[n] = "ilm-action", values[n++] = t->noncurrent ? "TransitionVersionAction" : "TransitionAction";
  keys[n] = "ilm-rule-id", values[n++] = t->rule_id;
  if (t->due_ns) {
    buckets_time_amz((time_t)(t->due_ns / 1000000000LL), due);
    keys[n] = "ilm-due", values[n++] = due;
  }
  keys[n] = "ilm-tier", values[n++] = t->tier;
  keys[n] = "version-id", values[n++] = t->version_id;
  buckets_audit_internal(" ilm:transition", "ILMTransition", t->bucket, t->object, oi ? oi->version_id : t->version_id,
                         err ? buckets_obj_strerror(err) : NULL, keys, values, n);
}

static void run_transition(buckets_tiering *tg, task *t) {
  buckets_s3_server *s = tg->s;
  upload_ctx u = {s, t->bucket, t->object, t->tier};
  buckets_object_info oi;
  memset(&oi, 0, sizeof(oi));
  buckets_obj_err err = buckets_obj_transition(s->layer, t->bucket, t->object, t->version_id, t->mod_time_ns, t->etag,
                                               t->tier, upload, &u, &oi);
  if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) return; /* gone or replaced */
  if (!err) {
    add_day_stats(tg, t->tier, t);
    buckets_s3_send_internal_event(s, BUCKETS_EV_OBJECT_TRANSITION_COMPLETE, t->bucket, t->object, &oi,
                                   oi.version_id, ILM_TRANSITION_UA);
  } else {
    buckets_s3_send_internal_event(s, BUCKETS_EV_OBJECT_TRANSITION_FAILED, t->bucket, t->object, NULL, t->version_id,
                                   ILM_TRANSITION_UA);
  }
  audit_transition(t, err ? NULL : &oi, err);
  buckets_object_info_free(&oi);
}

bool buckets_tiering_remove_remote_now(buckets_s3_server *s, const char *tier, const char *remote, const char *version) {
  char err[512];
  buckets_warm *w = buckets_tiers_driver(s->tiers, tier, err, sizeof(err));
  if (!w) {
    buckets_log_warn("tier %s: %s", tier, err);
    return false;
  }
  buckets_warm_err e = buckets_warm_remove(w, remote, version, err, sizeof(err));
  buckets_warm_release(w);
  if (e && e != BUCKETS_WARM_ERR_NOT_FOUND) {
    buckets_log_warn("tier %s: removing %s: %s", tier, remote, err);
    return false;
  }
  return true;
}

static void *worker(void *arg) {
  buckets_tiering *tg = arg;
  pthread_mutex_lock(&tg->mu);
  for (;;) {
    while (!tg->head && !tg->stop) pthread_cond_wait(&tg->cv, &tg->mu);
    if (tg->stop) break;
    task *t = tg->head;
    tg->head = t->next;
    if (!tg->head) tg->tail = NULL;
    tg->queued--;
    tg->active++;
    pthread_mutex_unlock(&tg->mu);
    if (t->remove) buckets_tiering_remove_remote_now(tg->s, t->tier, t->remote, t->remote_version);
    else run_transition(tg, t);
    task_free(t);
    pthread_mutex_lock(&tg->mu);
    tg->active--;
  }
  pthread_mutex_unlock(&tg->mu);
  return NULL;
}

static bool push(buckets_tiering *tg, task *t) {
  pthread_mutex_lock(&tg->mu);
  bool ok = !tg->stop && tg->queued < QUEUE_CAP;
  if (ok) {
    if (tg->tail) tg->tail->next = t;
    else tg->head = t;
    tg->tail = t;
    tg->queued++;
    pthread_cond_signal(&tg->cv);
  }
  pthread_mutex_unlock(&tg->mu);
  return ok;
}

void buckets_tiering_queue(buckets_tiering *tg, const char *bucket, const buckets_object_info *oi, const char *tier,
                           const char *rule_id, int64_t due_ns, bool noncurrent, bool immediate) {
  if (!tg || oi->delete_marker) return;
  task *t = buckets_xcalloc(1, sizeof(*t));
  t->bucket = dupz(bucket);
  t->object = dupz(oi->name);
  t->version_id = dupz(oi->version_id[0] ? oi->version_id : "null");
  t->etag = dupz(oi->etag);
  t->tier = dupz(tier);
  t->rule_id = dupz(rule_id);
  t->mod_time_ns = oi->mod_time_ns;
  t->size = oi->size;
  t->due_ns = due_ns;
  t->noncurrent = noncurrent;
  t->is_latest = oi->is_latest;
  if (!push(tg, t)) {
    if (immediate) {
      pthread_mutex_lock(&tg->mu);
      tg->missed++;
      pthread_mutex_unlock(&tg->mu);
    }
    task_free(t);
  }
}

void buckets_tiering_remove_remote(buckets_tiering *tg, const char *tier, const char *remote, const char *version) {
  if (!tg) return;
  task *t = buckets_xcalloc(1, sizeof(*t));
  t->remove = true;
  t->tier = dupz(tier);
  t->remote = dupz(remote);
  t->remote_version = dupz(version);
  if (!push(tg, t)) task_free(t);
}

void buckets_tiering_stats_get(buckets_tiering *tg, buckets_tiering_stats *out) {
  memset(out, 0, sizeof(*out));
  if (!tg) return;
  pthread_mutex_lock(&tg->mu);
  out->pending = tg->queued;
  out->active = tg->active;
  out->missed_immediate = tg->missed;
  pthread_mutex_unlock(&tg->mu);
}

static int worker_count(void) {
  const char *e = getenv("BUCKETS_ILM_TRANSITION_WORKERS");
  int n = e ? atoi(e) : 0;
  return n > 0 ? n : 16;
}

buckets_tiering *buckets_tiering_new(buckets_s3_server *s, buckets_objlayer *layer) {
  buckets_tiering *tg = buckets_xcalloc(1, sizeof(*tg));
  tg->s = s;
  pthread_mutex_init(&tg->mu, NULL);
  pthread_cond_init(&tg->cv, NULL);
  layer->tier_open = tier_open;
  layer->tier_ud = s;
  tg->nthreads = worker_count();
  tg->threads = buckets_xcalloc((size_t)tg->nthreads, sizeof(pthread_t));
  for (int i = 0; i < tg->nthreads; i++) {
    if (pthread_create(&tg->threads[i], NULL, worker, tg) != 0) {
      tg->nthreads = i;
      break;
    }
  }
  return tg;
}

void buckets_tiering_stop(buckets_tiering *tg) {
  if (!tg) return;
  pthread_mutex_lock(&tg->mu);
  tg->stop = true;
  pthread_cond_broadcast(&tg->cv);
  pthread_mutex_unlock(&tg->mu);
  for (int i = 0; i < tg->nthreads; i++) pthread_join(tg->threads[i], NULL);
  tg->nthreads = 0;
  while (tg->head) {
    task *t = tg->head;
    tg->head = t->next;
    task_free(t);
  }
  tg->tail = NULL;
  pthread_mutex_lock(&tg->mu);
  free(tg->days);
  tg->days = NULL;
  tg->ndays = 0;
  pthread_mutex_unlock(&tg->mu);
}
