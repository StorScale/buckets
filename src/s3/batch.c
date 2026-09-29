/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Batch jobs (MinIO's cmd/batch-handlers.go, batch-expire.go,
 * batch-rotate.go): the job pool, the three job types and the admin API's
 * side of them. */
#include "s3/batch.h"

#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "admin/info.h"
#include "bucket/metasys.h"
#include "bucket/tags.h"
#include "bucket/versioning.h"
#include "config/sys.h"
#include "core/auditctx.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "dist/peer.h"
#include "kms/kms.h"
#include "net/fetch.h"
#include "net/s3client.h"
#include "notify/event.h"
#include "object/sysconfig.h"
#include "s3/internal.h"
#include "s3/replicate.h"
#include "s3/sse.h"
#include "storage/xlmeta.h"
#include "trace/trace.h"
#include "s3/xml.h"
#include "crypto/objkey.h"
#include "s3/errors.h"
#include <stdarg.h>

#define OLD_JOBS_EXPIRATION_NS (3LL * 24 * 3600 * 1000000000LL)
#define MAX_RUNNING 100 /* newBatchJobPool(..., 100) */
#define MAX_QUEUED 10000
#define LIST_PAGE 1000

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void sleep_ns(int64_t ns) {
  if (ns <= 0) return;
  struct timespec ts = {ns / 1000000000LL, ns % 1000000000LL};
  nanosleep(&ts, NULL);
}

static double rnd01(void) {
  static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
  static uint64_t state;
  pthread_mutex_lock(&mu);
  if (!state) state = (uint64_t)now_ns() | 1;
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  uint64_t v = state;
  pthread_mutex_unlock(&mu);
  return (double)(v >> 11) / 9007199254740992.0;
}

static char *dupz(const char *s) { return buckets_xstrdup(s ? s : ""); }

static buckets_batch_time time_now(void) {
  int64_t n = now_ns();
  return (buckets_batch_time){n / 1000000000LL, (int32_t)(n % 1000000000LL), true};
}

/* unset (Go's zero time): 0, older than anything that matters here */
static int64_t time_ns(const buckets_batch_time *t) { return t->set ? t->sec * 1000000000LL + t->nsec : 0; }

/* ---- the pool's state -------------------------------------------------------------------------------- */

typedef struct run {
  struct run *next;
  buckets_batch *b;
  buckets_batch_job job;
  _Atomic bool cancel;
  pthread_mutex_t mu; /* ri */
  buckets_batch_info ri;
} run;

typedef struct {
  buckets_batch_info ri;
} metric_entry;

struct buckets_batch {
  buckets_s3_server *s;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  run *queue, *queue_tail; /* waiting for a slot */
  size_t nqueued;
  run *running;
  int nrunning;
  bool stop;
  pthread_t bg;
  bool bg_started;
  /* batchJobMetrics: the last state of every job this node ran */
  buckets_batch_info *metrics;
  size_t nmetrics;
};

static void run_free(run *r) {
  buckets_batch_job_free(&r->job);
  buckets_batch_info_free(&r->ri);
  pthread_mutex_destroy(&r->mu);
  free(r);
}

static bool cancelled(run *r) { return atomic_load(&r->cancel) || r->b->stop; }

/* batchJobMetrics.save: a copy of the job's info (the lock held) */
static void metrics_save_locked(run *r) {
  buckets_batch *b = r->b;
  pthread_mutex_lock(&b->mu);
  size_t i = 0;
  for (; i < b->nmetrics && strcmp(b->metrics[i].job_id, r->ri.job_id) != 0; i++) {
  }
  if (i == b->nmetrics) {
    b->metrics = buckets_xrealloc(b->metrics, (b->nmetrics + 1) * sizeof(*b->metrics));
    b->nmetrics++;
  } else {
    buckets_batch_info_free(&b->metrics[i]);
  }
  buckets_batch_info_copy(&b->metrics[i], &r->ri);
  pthread_mutex_unlock(&b->mu);
}

static void metrics_save(run *r) {
  pthread_mutex_lock(&r->mu);
  metrics_save_locked(r);
  pthread_mutex_unlock(&r->mu);
}

static void report_path(const char *id, const char *type, buckets_buf *out) {
  buckets_buf_appendf(out, "%s/%s/%s", BUCKETS_BATCH_REPORTS_PREFIX, id, buckets_batch_report_name(type));
}

/* updateAfter: persists the report when duration has passed since the last save */
static void update_after(run *r, int64_t duration_ns) {
  int64_t now = now_ns();
  pthread_mutex_lock(&r->mu);
  if (r->ri.last_update.set && now - time_ns(&r->ri.last_update) < duration_ns) {
    pthread_mutex_unlock(&r->mu);
    return;
  }
  r->ri.version = 1;
  r->ri.last_update = (buckets_batch_time){now / 1000000000LL, (int32_t)(now % 1000000000LL), true};
  buckets_buf data = BUCKETS_BUF_INIT, path = BUCKETS_BUF_INIT;
  buckets_batch_info_encode(&r->ri, &data);
  report_path(r->ri.job_id, r->ri.job_type, &path);
  pthread_mutex_unlock(&r->mu);
  buckets_obj_err err = buckets_sysconfig_write(r->b->s->layer, path.data, data.data, data.len);
  if (err) buckets_log_warn("batch: saving %s: %s", path.data, buckets_obj_strerror(err));
  buckets_buf_free(&data);
  buckets_buf_free(&path);
}

/* trackCurrentBucketObject */
static void track_object(run *r, const char *bucket, const char *name, int64_t size, bool dm, bool success,
                         int attempt) {
  pthread_mutex_lock(&r->mu);
  if (success) {
    free(r->ri.bucket);
    free(r->ri.object);
    r->ri.bucket = dupz(bucket);
    r->ri.object = dupz(name);
  }
  buckets_batch_info_count(&r->ri, size, dm, success, attempt);
  metrics_save_locked(r);
  pthread_mutex_unlock(&r->mu);
}

/* ---- the job's info in JSON (json.Marshal(batchJobInfo), for notifications) ---- */

static void info_json(const buckets_batch_info *ri, buckets_buf *b) {
  char st[64], lu[64];
  buckets_time_rfc3339_nano(ri->start.set ? ri->start.sec : -62135596800LL, ri->start.nsec, st);
  buckets_time_rfc3339_nano(ri->last_update.set ? ri->last_update.sec : -62135596800LL, ri->last_update.nsec, lu);
  buckets_buf_append_c(b, "{\"jobID\":");
  buckets_json_go_string(b, ri->job_id ? ri->job_id : "", strlen(ri->job_id ? ri->job_id : ""));
  buckets_buf_append_c(b, ",\"jobType\":");
  buckets_json_go_string(b, ri->job_type ? ri->job_type : "", strlen(ri->job_type ? ri->job_type : ""));
  buckets_buf_appendf(b,
                      ",\"startTime\":\"%s\",\"lastUpdate\":\"%s\",\"retryAttempts\":%" PRId64 ",\"attempts\":%" PRId64
                      ",\"complete\":%s,\"failed\":%s,\"objects\":%" PRId64 ",\"deleteMarkers\":%" PRId64
                      ",\"objectsFailed\":%" PRId64 ",\"deleteMarkersFailed\":%" PRId64 ",\"bytesTransferred\":%" PRId64
                      ",\"bytesFailed\":%" PRId64 "}",
                      ri->start.set ? st : "0001-01-01T00:00:00Z", ri->last_update.set ? lu : "0001-01-01T00:00:00Z",
                      ri->retry_attempts, ri->attempts, ri->complete ? "true" : "false", ri->failed ? "true" : "false",
                      ri->objects, ri->delete_markers, ri->objects_failed, ri->delete_markers_failed,
                      ri->bytes_transferred, ri->bytes_failed);
}

/* notifyEndpoint: POSTs the job's info to the endpoint; json_ct adds the
 * Content-Type replicate and keyrotate jobs send. */
static void notify(run *r, const buckets_batch_notify *n, bool json_ct) {
  if (!n->endpoint || !*n->endpoint) return;
  buckets_buf body = BUCKETS_BUF_INIT;
  pthread_mutex_lock(&r->mu);
  info_json(&r->ri, &body);
  pthread_mutex_unlock(&r->mu);
  buckets_http_kv h[2];
  size_t nh = 0;
  if (n->token && *n->token) h[nh++] = (buckets_http_kv){"Authorization", n->token};
  if (json_ct) h[nh++] = (buckets_http_kv){"Content-Type", "application/json"};
  buckets_http_result res;
  char err[256];
  if (!buckets_fetch("POST", n->endpoint, NULL, h, nh, body.data, body.len, 10000, &res, err, sizeof(err))) {
    buckets_log_warn("batch: unable to notify %s", err);
  } else {
    if (res.status != 200) buckets_log_warn("batch: unable to notify %d", res.status);
    buckets_http_result_free(&res);
  }
  buckets_buf_free(&body);
}

/* ---- trace (batchJobTrace) ------------------------------------------------------------------------------ */

enum { M_REPLICATION, M_KEYROTATION, M_EXPIRE };

static uint64_t trace_type(int m) {
  return m == M_REPLICATION ? BUCKETS_TRACE_BATCH_REPLICATION
         : m == M_KEYROTATION ? BUCKETS_TRACE_BATCH_KEYROTATION
                              : BUCKETS_TRACE_BATCH_EXPIRE;
}

static const char *ordinal(int n, char *buf, size_t cap) {
  const char *suf = "th";
  int m100 = n % 100, m10 = n % 10;
  if (m100 < 11 || m100 > 13) {
    if (m10 == 1) suf = "st";
    else if (m10 == 2) suf = "nd";
    else if (m10 == 3) suf = "rd";
  }
  snprintf(buf, cap, "%d%s", n, suf);
  return buf;
}

static void trace(int m, const char *job, int64_t start, int attempts, const char *name, const char *vid,
                  const char *err) {
  uint64_t t = trace_type(m);
  if (!buckets_trace_wanted(t)) return;
  static const char *const fn[] = {"Replication", "KeyRotation", "Expire"};
  int64_t dur = now_ns() - start;
  char when[64], ord[16];
  buckets_time_rfc3339_nano(start / 1000000000LL, (long)(start % 1000000000LL), when);
  buckets_buf b = BUCKETS_BUF_INIT, f = BUCKETS_BUF_INIT, p = BUCKETS_BUF_INIT;
  if (attempts > 0) buckets_buf_appendf(&f, "%s() (job-name=%s,attempts=%s)", fn[m], job, ordinal(attempts, ord, sizeof(ord)));
  else buckets_buf_appendf(&f, "%s() (job-name=%s)", fn[m], job);
  buckets_buf_appendf(&p, "%s (versionID=%s)", name, vid ? vid : "");
  buckets_buf_appendf(&b, "{\"type\":%" PRIu64 ",\"nodename\":", t);
  const char *node = buckets_trace_node();
  buckets_json_go_string(&b, node, strlen(node));
  buckets_buf_append_c(&b, ",\"funcname\":");
  buckets_json_go_string(&b, f.data, f.len);
  buckets_buf_appendf(&b, ",\"time\":\"%s\",\"path\":", when);
  buckets_json_go_string(&b, p.data, p.len);
  buckets_buf_appendf(&b, ",\"dur\":%" PRId64, dur);
  if (err && *err) {
    buckets_buf_append_c(&b, ",\"error\":");
    buckets_json_go_string(&b, err, strlen(err));
  }
  buckets_buf_append_c(&b, "}");
  buckets_trace_meta tm = {.type = t, .dur_ns = dur};
  buckets_trace_publish(&tm, b.data, b.len);
  buckets_buf_free(&b);
  buckets_buf_free(&f);
  buckets_buf_free(&p);
}

/* ---- per-job workers (minio/pkg workers: Take/Give/Wait) ------------------------------------------------- */

typedef struct task {
  struct task *next;
  void (*fn)(void *);
  void *arg;
} task;

typedef struct {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  task *head, *tail;
  int busy, nthreads, queued, limit;
  bool closing;
  pthread_t *threads;
} wpool;

static void *wpool_main(void *arg) {
  wpool *p = arg;
  pthread_mutex_lock(&p->mu);
  for (;;) {
    while (!p->head && !p->closing) pthread_cond_wait(&p->cv, &p->mu);
    if (!p->head) break;
    task *t = p->head;
    p->head = t->next;
    if (!p->head) p->tail = NULL;
    p->queued--;
    p->busy++;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    t->fn(t->arg);
    free(t);
    pthread_mutex_lock(&p->mu);
    p->busy--;
    pthread_cond_broadcast(&p->cv);
  }
  pthread_mutex_unlock(&p->mu);
  return NULL;
}

static void wpool_init(wpool *p, int n) {
  memset(p, 0, sizeof(*p));
  if (n < 1) n = 1;
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->cv, NULL);
  p->limit = n;
  p->threads = buckets_xcalloc((size_t)n, sizeof(pthread_t));
  for (int i = 0; i < n; i++)
    if (pthread_create(&p->threads[i], NULL, wpool_main, p) == 0) p->nthreads++;
}

/* Take: waits for a free worker, then runs fn(arg) on it. */
static void wpool_go(wpool *p, void (*fn)(void *), void *arg) {
  task *t = buckets_xcalloc(1, sizeof(*t));
  t->fn = fn;
  t->arg = arg;
  pthread_mutex_lock(&p->mu);
  while (p->busy + p->queued >= p->limit) pthread_cond_wait(&p->cv, &p->mu);
  if (p->tail) p->tail->next = t;
  else p->head = t;
  p->tail = t;
  p->queued++;
  pthread_cond_broadcast(&p->cv);
  pthread_mutex_unlock(&p->mu);
}

static void wpool_wait(wpool *p) {
  pthread_mutex_lock(&p->mu);
  while (p->busy || p->queued) pthread_cond_wait(&p->cv, &p->mu);
  pthread_mutex_unlock(&p->mu);
}

static void wpool_close(wpool *p) {
  pthread_mutex_lock(&p->mu);
  p->closing = true;
  pthread_cond_broadcast(&p->cv);
  pthread_mutex_unlock(&p->mu);
  for (int i = 0; i < p->nthreads; i++) pthread_join(p->threads[i], NULL);
  free(p->threads);
  pthread_mutex_destroy(&p->mu);
  pthread_cond_destroy(&p->cv);
}

/* _MINIO_BATCH_*_WORKERS, default GOMAXPROCS/2 */
static int worker_count(const char *env) {
  const char *v = getenv(env);
  int n = v ? atoi(v) : 0;
  if (n > 0) return n;
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  n = (int)(cpus / 2);
  return n > 0 ? n : 1;
}

/* The batch config's per-object wait (replication_workers_wait, ...). */
static int64_t config_wait(buckets_batch *b, const char *key) {
  if (!b->s->config) return 0;
  char *v = buckets_config_sys_value(b->s->config, "batch", NULL, key);
  int64_t ns = 0;
  if (v && *v && !buckets_go_duration_parse(v, &ns)) ns = 0;
  free(v);
  return ns;
}

/* ---- walking a bucket (ObjectLayer.Walk) ----------------------------------------------------------------- */

/* One version as the jobs see it (ObjectInfo). */
typedef struct {
  char *name;
  char version_id[37]; /* "null" for the null version */
  int64_t size, mod_time_ns;
  bool delete_marker, is_latest;
  char *user_tags; /* X-Amz-Tagging */
  buckets_xl_kv *meta;
  size_t nmeta;
  buckets_xl_kv *meta_sys;
  size_t nmeta_sys;
} item;

static void item_free(item *it) {
  free(it->name);
  free(it->user_tags);
  for (size_t i = 0; i < it->nmeta; i++) free(it->meta[i].key), free(it->meta[i].value);
  free(it->meta);
  for (size_t i = 0; i < it->nmeta_sys; i++) free(it->meta_sys[i].key), free(it->meta_sys[i].value);
  free(it->meta_sys);
  memset(it, 0, sizeof(*it));
}

static void kvs_copy(const buckets_xl_kv *src, size_t n, buckets_xl_kv **dst, size_t *dn) {
  *dst = n ? buckets_xcalloc(n, sizeof(**dst)) : NULL;
  for (size_t i = 0; i < n; i++) {
    (*dst)[i].key = buckets_xstrdup(src[i].key);
    (*dst)[i].value = buckets_xmalloc(src[i].value_len + 1);
    memcpy((*dst)[i].value, src[i].value, src[i].value_len);
    ((char *)(*dst)[i].value)[src[i].value_len] = 0;
    (*dst)[i].value_len = src[i].value_len;
  }
  *dn = n;
}

static void item_from(item *it, const buckets_object_info *oi) {
  memset(it, 0, sizeof(*it));
  it->name = buckets_xstrdup(oi->name);
  snprintf(it->version_id, sizeof(it->version_id), "%s", oi->version_id);
  it->size = oi->size;
  it->mod_time_ns = oi->mod_time_ns;
  it->delete_marker = oi->delete_marker;
  it->is_latest = oi->is_latest;
  const char *t = buckets_object_meta(oi, "X-Amz-Tagging");
  it->user_tags = t ? buckets_xstrdup(t) : NULL;
  kvs_copy(oi->meta, oi->nmeta, &it->meta, &it->nmeta);
  kvs_copy(oi->meta_sys, oi->nmeta_sys, &it->meta_sys, &it->nmeta_sys);
}


typedef bool (*walk_fn)(void *ud, item *it); /* false: stop */

/* Every version under prefix (from marker on), oldest first within a key
 * (asc) or newest first; free versions are not visited. */
static bool walk(run *r, const char *bucket, const char *prefix, const char *marker, bool asc, walk_fn fn, void *ud,
                 char *err, size_t errlen) {
  buckets_objlayer *L = r->b->s->layer;
  char *key_marker = NULL, *ver_marker = NULL;
  item *group = NULL;
  size_t ng = 0, cap = 0;
  bool ok = true, go = true;
  /* a key's versions can span pages: flush a group when the key changes */
#define FLUSH()                                                           \
  do {                                                                    \
    for (size_t k_ = 0; k_ < ng && go; k_++) {                            \
      item *it_ = &group[asc ? ng - 1 - k_ : k_];                         \
      go = fn(ud, it_);                                                   \
    }                                                                     \
    for (size_t k_ = 0; k_ < ng; k_++) item_free(&group[k_]);             \
    ng = 0;                                                               \
  } while (0)
  while (go) {
    if (cancelled(r)) {
      snprintf(err, errlen, "context canceled");
      ok = false;
      break;
    }
    buckets_obj_listing l;
    buckets_obj_err e = buckets_obj_list_versions(L, bucket, prefix ? prefix : "", key_marker, ver_marker, NULL,
                                                  LIST_PAGE, &l);
    if (e) {
      snprintf(err, errlen, "%s", buckets_obj_strerror(e));
      ok = false;
      break;
    }
    for (size_t i = 0; i < l.nobjects && go; i++) {
      const buckets_object_info *oi = &l.objects[i];
      if (marker && *marker && strcmp(oi->name, marker) < 0) continue; /* forwardTo */
      if (ng && strcmp(group[0].name, oi->name) != 0) FLUSH();
      if (ng == cap) {
        cap = cap ? cap * 2 : 8;
        group = buckets_xrealloc(group, cap * sizeof(*group));
      }
      item_from(&group[ng++], oi);
    }
    free(key_marker);
    free(ver_marker);
    key_marker = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    ver_marker = l.truncated && l.next_version_marker ? buckets_xstrdup(l.next_version_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!key_marker) break;
  }
  if (ok && go) FLUSH();
#undef FLUSH
  for (size_t k = 0; k < ng; k++) item_free(&group[k]);
  free(group);
  free(key_marker);
  free(ver_marker);
  return ok;
}

/* ---- filters shared by the job types --------------------------------------------------------------------- */

static bool standard_header(const char *k) {
  static const char *const std[] = {"Content-Type", "Cache-Control", "Content-Encoding", "Content-Language",
                                    "Content-Disposition", "X-Amz-Storage-Class", "X-Amz-Tagging",
                                    "X-Amz-Replication-Status", "X-Amz-Object-Lock-Mode",
                                    "X-Amz-Object-Lock-Retain-Until-Date", "X-Amz-Object-Lock-Legal-Hold",
                                    "X-Amz-Tagging-Count", "X-Amz-Server-Side-Encryption"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(std); i++)
    if (strcasecmp(k, std[i]) == 0) return true;
  return false;
}

/* Does any kv match one of the object's tags? */
static bool tags_match_any(const buckets_batch_kvs *kvs, const char *user_tags) {
  buckets_tags t = {0};
  buckets_tags_error te;
  if (user_tags && *user_tags && !buckets_tags_parse_query(user_tags, true, &t, &te)) return false;
  bool m = false;
  for (size_t i = 0; i < kvs->n && !m; i++)
    for (size_t k = 0; k < t.n && !m; k++) m = buckets_batch_kv_match(&kvs->v[i], t.keys[k], t.values[k]);
  buckets_tags_free(&t);
  return m;
}

/* Does any kv match one of the object's user metadata or standard headers? */
static bool meta_match_any(const buckets_batch_kvs *kvs, const buckets_xl_kv *meta, size_t n) {
  for (size_t i = 0; i < kvs->n; i++)
    for (size_t k = 0; k < n; k++) {
      if (strncasecmp(meta[k].key, "x-amz-meta-", 11) != 0 && !standard_header(meta[k].key)) continue;
      if (buckets_batch_kv_match(&kvs->v[i], meta[k].key, (const char *)meta[k].value)) return true;
    }
  return false;
}

/* ---- expire ------------------------------------------------------------------------------------------------- */

/* BatchJobExpireFilter.Matches */
static bool expire_matches(const buckets_batch_expire_rule *rule, const item *it, int64_t now) {
  const char *type = rule->type ? rule->type : "";
  if (strcmp(type, "object") == 0) {
    if (it->delete_marker) return false;
  } else if (strcmp(type, "deleted") == 0) {
    if (!it->delete_marker) return false;
  } else {
    return false;
  }
  if (rule->name && *rule->name && !buckets_wildcard_match(rule->name, it->name)) return false;
  if (rule->older_than_ns > 0 && now - it->mod_time_ns <= rule->older_than_ns) return false;
  if (rule->created_before.set && !(it->mod_time_ns < time_ns(&rule->created_before))) return false;
  if (rule->tags.n && !it->delete_marker) {
    buckets_tags t = {0};
    buckets_tags_error te;
    if (it->user_tags && *it->user_tags && !buckets_tags_parse_query(it->user_tags, true, &t, &te)) return false;
    for (size_t i = 0; i < rule->tags.n; i++) {
      bool m = false;
      for (size_t k = 0; k < t.n; k++) m |= buckets_batch_kv_match(&rule->tags.v[i], t.keys[k], t.values[k]);
      if (!m) {
        buckets_tags_free(&t);
        return false;
      }
    }
    buckets_tags_free(&t);
  }
  if (rule->metadata.n && !it->delete_marker) {
    for (size_t i = 0; i < rule->metadata.n; i++) {
      bool m = false;
      for (size_t k = 0; k < it->nmeta; k++) {
        if (strncasecmp(it->meta[k].key, "x-amz-meta-", 11) != 0 && !standard_header(it->meta[k].key)) continue;
        m |= buckets_batch_kv_match(&rule->metadata.v[i], it->meta[k].key, (const char *)it->meta[k].value);
      }
      if (!m) return false;
    }
  }
  /* BatchJobSizeFilter.InRange */
  if (rule->size_lt > 0 && it->size > rule->size_lt) return false;
  if (rule->size_gt > 0 && it->size < rule->size_gt) return false;
  return true;
}

typedef struct {
  char *name;
  char version_id[37];
  int64_t size;
  bool delete_marker, expire_all;
  int64_t num_versions, dm_count; /* expire_all: the key's versions and markers */
} exp_obj;

typedef struct {
  run *r;
  exp_obj *objs;
  size_t n;
  int retries;
  int64_t delay_ns;
} exp_batch;

static void exp_batch_free(exp_batch *eb) {
  for (size_t i = 0; i < eb->n; i++) free(eb->objs[i].name);
  free(eb->objs);
  free(eb);
}

/* deletes every version of a key (DeletePrefix on the object) */
static bool delete_all_versions(buckets_s3_server *s, const char *bucket, const char *name, char *err, size_t errlen) {
  buckets_obj_listing l;
  buckets_obj_err e = buckets_obj_list_versions(s->layer, bucket, name, NULL, NULL, NULL, 100000, &l);
  if (e) {
    snprintf(err, errlen, "%s", buckets_obj_strerror(e));
    return false;
  }
  bool ok = true;
  for (size_t i = 0; i < l.nobjects; i++) {
    if (strcmp(l.objects[i].name, name) != 0) continue;
    buckets_delete_opts o = {.version_id = l.objects[i].version_id};
    buckets_delete_result dr;
    e = buckets_obj_delete_ex(s->layer, bucket, name, &o, &dr);
    if (e && e != BUCKETS_OBJ_ERR_NO_SUCH_KEY && e != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
      snprintf(err, errlen, "%s", buckets_obj_strerror(e));
      ok = false;
    }
  }
  buckets_obj_list_free(&l);
  return ok;
}

/* batchObjsForDelete's worker: whole keys first, then single versions */
static void exp_batch_run(void *arg) {
  exp_batch *eb = arg;
  run *r = eb->r;
  buckets_s3_server *s = r->b->s;
  const char *bucket = r->job.expire->bucket;
  for (size_t i = 0; i < eb->n; i++) {
    exp_obj *o = &eb->objs[i];
    if (!o->expire_all) continue;
    bool success = false;
    for (int attempts = 1; attempts <= eb->retries; attempts++) {
      if (cancelled(r)) break;
      int64_t start = now_ns();
      char err[256] = "";
      bool ok = delete_all_versions(s, bucket, o->name, err, sizeof(err));
      trace(M_EXPIRE, r->ri.job_id, start, attempts, o->name, o->version_id, ok ? NULL : err);
      if (ok) {
        success = true;
        break;
      }
      buckets_log_warn("batch: Failed to expire %s/%s due to %s (attempts=%d)", bucket, o->name, err, attempts);
    }
    /* trackMultipleObjectVersions */
    pthread_mutex_lock(&r->mu);
    if (success) {
      free(r->ri.bucket);
      free(r->ri.object);
      r->ri.bucket = dupz(bucket);
      r->ri.object = dupz(o->name);
      r->ri.objects += o->num_versions - o->dm_count;
      r->ri.delete_markers += o->dm_count;
    } else {
      r->ri.objects_failed += o->num_versions - o->dm_count;
      r->ri.delete_markers_failed += o->dm_count;
    }
    pthread_mutex_unlock(&r->mu);
    if (cancelled(r)) break;
  }
  /* the single versions, retried together */
  size_t n = 0;
  exp_obj **todo = buckets_xcalloc(eb->n + 1, sizeof(*todo));
  for (size_t i = 0; i < eb->n; i++)
    if (!eb->objs[i].expire_all) todo[n++] = &eb->objs[i];
  for (int attempts = 1; attempts <= eb->retries && n; attempts++) {
    if (cancelled(r)) break;
    size_t failed = 0, keep = 0;
    int64_t start = now_ns();
    for (size_t i = 0; i < n; i++) {
      exp_obj *o = todo[i];
      buckets_delete_opts d = {.version_id = o->version_id};
      buckets_delete_result dr;
      buckets_obj_err e = buckets_obj_delete_ex(s->layer, bucket, o->name, &d, &dr);
      if (e == BUCKETS_OBJ_ERR_NO_SUCH_KEY || e == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) e = BUCKETS_OBJ_OK;
      trace(M_EXPIRE, r->ri.job_id, start, attempts, o->name, o->version_id, e ? buckets_obj_strerror(e) : NULL);
      if (e) {
        buckets_log_warn("batch: Failed to expire %s/%s versionID=%s due to %s (attempts=%d)", bucket, o->name,
                         o->version_id, buckets_obj_strerror(e), attempts);
        failed++;
        track_object(r, bucket, o->name, o->size, o->delete_marker, false, attempts);
        if (attempts != eb->retries) todo[keep++] = o;
      } else {
        track_object(r, bucket, o->name, o->size, o->delete_marker, true, attempts);
      }
    }
    n = keep;
    metrics_save(r);
    if (!failed) break;
    if (attempts < eb->retries) sleep_ns(eb->delay_ns);
  }
  free(todo);
  exp_batch_free(eb);
}

typedef struct {
  run *r;
  int64_t now;
  wpool *wk;
  int retries;
  int64_t delay_ns, wait_ns;
  int batches;
  /* the walk's state (BatchJobExpire.Start) */
  char *prev;                       /* prevObj.Name */
  const buckets_batch_expire_rule *matched;
  int64_t versions_count;
  exp_obj *todel;
  size_t ntodel, cap;
  /* the key being walked: its versions and markers so far */
  char *cur;
  int64_t cur_versions, cur_dms;
} exp_walk;

static void exp_push(exp_walk *w, bool final) {
  /* the last whole-key entry gets its counts (deleteMarkerCountMap) */
  if (w->ntodel) {
    exp_obj *last = &w->todel[w->ntodel - 1];
    if (last->expire_all && w->cur && strcmp(last->name, w->cur) == 0) {
      last->num_versions = w->cur_versions;
      last->dm_count = w->cur_dms;
    }
  }
  if (w->ntodel > 10 || (final && w->ntodel)) { /* batch up to 10 objects/versions */
    if (w->batches++ > 0) sleep_ns(w->wait_ns);
    exp_batch *eb = buckets_xcalloc(1, sizeof(*eb));
    eb->r = w->r;
    eb->objs = w->todel;
    eb->n = w->ntodel;
    eb->retries = w->retries;
    eb->delay_ns = w->delay_ns;
    w->todel = NULL;
    w->ntodel = w->cap = 0;
    wpool_go(w->wk, exp_batch_run, eb);
  }
}

static void exp_add(exp_walk *w, const item *it, bool all) {
  if (w->ntodel == w->cap) {
    w->cap = w->cap ? w->cap * 2 : 16;
    w->todel = buckets_xrealloc(w->todel, w->cap * sizeof(*w->todel));
  }
  exp_obj *o = &w->todel[w->ntodel++];
  memset(o, 0, sizeof(*o));
  o->name = buckets_xstrdup(it->name);
  snprintf(o->version_id, sizeof(o->version_id), "%s", it->version_id);
  o->size = it->size;
  o->delete_marker = it->delete_marker;
  o->expire_all = all;
}

static bool exp_visit(void *ud, item *it) {
  exp_walk *w = ud;
  if (cancelled(w->r)) return false;
  if (!w->cur || strcmp(w->cur, it->name) != 0) {
    free(w->cur);
    w->cur = buckets_xstrdup(it->name);
    w->cur_versions = w->cur_dms = 0;
  }
  w->cur_versions++;
  w->cur_dms += it->delete_marker;
  /* whole-key entries take the key's final counts */
  if (w->ntodel) {
    exp_obj *last = &w->todel[w->ntodel - 1];
    if (last->expire_all && strcmp(last->name, it->name) == 0) {
      last->num_versions = w->cur_versions;
      last->dm_count = w->cur_dms;
    }
  }
  const buckets_batch_expire *e = w->r->job.expire;
  if (it->is_latest) {
    const buckets_batch_expire_rule *match = NULL;
    for (size_t i = 0; i < e->nrules && !match; i++)
      if (expire_matches(&e->rules[i], it, w->now)) match = &e->rules[i];
    if (!match) return true;
    if (!w->prev || strcmp(w->prev, it->name) != 0) exp_push(w, false);
    free(w->prev);
    w->prev = buckets_xstrdup(it->name);
    w->matched = match;
    w->versions_count = 1;
    if (match->retain_versions == 0) {
      exp_add(w, it, true);
      w->todel[w->ntodel - 1].num_versions = w->cur_versions;
      w->todel[w->ntodel - 1].dm_count = w->cur_dms;
      return true;
    }
  } else if (w->prev && strcmp(w->prev, it->name) == 0) {
    if (w->matched->retain_versions == 0) return true; /* the whole key goes already */
    w->versions_count++;
  } else {
    exp_push(w, false);
    return true; /* no latest version found for it */
  }
  if (w->versions_count <= w->matched->retain_versions) return true;
  exp_add(w, it, false);
  exp_push(w, false);
  return true;
}

static void run_expire(run *r) {
  buckets_batch_expire *e = r->job.expire;
  int retries = e->retry.attempts > 0 ? (int)e->retry.attempts : 3;
  int64_t delay = e->retry.delay_ns > 0 ? e->retry.delay_ns : 250000000LL;
  wpool wk;
  wpool_init(&wk, worker_count("_MINIO_BATCH_EXPIRATION_WORKERS"));
  exp_walk w = {.r = r, .now = now_ns(), .wk = &wk, .retries = retries, .delay_ns = delay,
                .wait_ns = config_wait(r->b, "expiration_workers_wait")};
  char *marker = dupz(r->ri.object);
  bool failed = false;
  size_t np = e->prefix.n ? e->prefix.n : 1;
  for (size_t i = 0; i < np && !cancelled(r); i++) {
    char err[256];
    if (!walk(r, e->bucket, e->prefix.n ? e->prefix.v[i] : "", marker, false, exp_visit, &w, err, sizeof(err))) {
      buckets_log_warn("batch: %s: walking %s: %s", r->ri.job_id, e->bucket, err);
      failed = true;
      break;
    }
  }
  free(marker);
  if (!cancelled(r)) exp_push(&w, true);
  wpool_wait(&wk);
  wpool_close(&wk);
  for (size_t i = 0; i < w.ntodel; i++) free(w.todel[i].name);
  free(w.todel);
  free(w.prev);
  free(w.cur);
  if (cancelled(r)) return;
  pthread_mutex_lock(&r->mu);
  r->ri.complete = !failed && r->ri.objects_failed == 0;
  r->ri.failed = failed || r->ri.objects_failed > 0;
  metrics_save_locked(r);
  pthread_mutex_unlock(&r->mu);
  update_after(r, 0);
  notify(r, &e->notify, false);
}

/* ---- keyrotate ------------------------------------------------------------------------------------------------ */

static const char *sys_get(const item *it, const char *key) {
  for (size_t i = 0; i < it->nmeta_sys; i++)
    if (strcasecmp(it->meta_sys[i].key, key) == 0) return (const char *)it->meta_sys[i].value;
  return NULL;
}

/* KeyRotate's selectObj (as MinIO has it: createdAfter keeps what is older) */
static bool rotate_select(const buckets_batch_keyrotate *k, const item *it, int64_t now) {
  const buckets_batch_filter *f = &k->flags.filter;
  if (f->older_than_ns > 0 && now - it->mod_time_ns < f->older_than_ns) return false;
  if (f->newer_than_ns > 0 && now - it->mod_time_ns >= f->newer_than_ns) return false;
  if (f->created_after.set && time_ns(&f->created_after) < it->mod_time_ns) return false;
  if (f->created_before.set && time_ns(&f->created_before) > it->mod_time_ns) return false;
  if (f->tags.n) return tags_match_any(&f->tags, it->user_tags);
  if (f->metadata.n) return meta_match_any(&f->metadata, it->meta, it->nmeta);
  if (f->kms_key_id && *f->kms_key_id) {
    const char *kid = sys_get(it, BUCKETS_SSE_META_KEY_ID);
    if (kid && buckets_s3_sse_kind_of_meta(it->meta_sys, it->nmeta_sys) == BUCKETS_SSE_KMS) {
      if (strncmp(kid, "arn:aws:kms:", 12) == 0) kid += 12;
      if (strcmp(kid, f->kms_key_id) != 0) return false;
    }
  }
  return true;
}

typedef struct {
  run *r;
  item it;
  int retries;
  int64_t delay_ns, wait_ns;
} rot_task;

typedef struct {
  const buckets_xl_kv *sys;
  size_t nsys;
} rot_edit;

static buckets_obj_err rot_apply(void *ud, const buckets_object_info *cur, buckets_xl_kv **user, size_t *nuser,
                                 buckets_xl_kv **sys, size_t *nsys) {
  (void)cur, (void)user, (void)nuser;
  rot_edit *e = ud;
  for (size_t i = 0; i < e->nsys; i++) buckets_xl_kv_set(sys, nsys, e->sys[i].key, e->sys[i].value, e->sys[i].value_len);
  return BUCKETS_OBJ_OK;
}

/* KeyRotate: one version's object key sealed anew */
static bool rotate_one(run *r, const item *it, char *err, size_t errlen) {
  buckets_s3_server *s = r->b->s;
  const buckets_batch_keyrotate *k = r->job.keyrotate;
  if (it->delete_marker) return true;
  buckets_sse_kind kind = buckets_s3_sse_kind_of_meta(it->meta_sys, it->nmeta_sys);
  bool kms = kind == BUCKETS_SSE_KMS, s3 = kind == BUCKETS_SSE_S3;
  if (!kms && !s3) {
    snprintf(err, errlen, "The encryption parameters are not applicable to this object");
    return false;
  }
  if (kms && strcmp(k->enc_type, "sse-s3") == 0) {
    snprintf(err, errlen, "The encryption parameters are not applicable to this object");
    return false;
  }
  buckets_object_info oi;
  buckets_obj_err e = buckets_obj_stat(s->layer, k->bucket, it->name, it->version_id, &oi);
  if (e) {
    snprintf(err, errlen, "%s", buckets_obj_strerror(e));
    return false;
  }
  const char *new_key = NULL;
  if (strcmp(k->enc_type, "sse-kms") == 0) {
    new_key = k->enc_key ? k->enc_key : "";
    if (strncmp(new_key, "arn:aws:kms:", 12) == 0) new_key += 12;
  }
  buckets_xl_kv *sys = NULL;
  size_t nsys = 0;
  buckets_s3_error se = buckets_s3_sse_rotate(s, &oi, k->bucket, it->name, new_key, &sys, &nsys);
  if (se) {
    snprintf(err, errlen, "%s", buckets_s3_error_get(se)->code);
    buckets_object_info_free(&oi);
    return false;
  }
  rot_edit ed = {sys, nsys};
  e = buckets_obj_update_meta(s->layer, k->bucket, it->name, oi.version_id, rot_apply, &ed, NULL);
  for (size_t i = 0; i < nsys; i++) free(sys[i].key), free(sys[i].value);
  free(sys);
  buckets_object_info_free(&oi);
  if (e) {
    snprintf(err, errlen, "%s", buckets_obj_strerror(e));
    return false;
  }
  return true;
}

static void rot_run(void *arg) {
  rot_task *t = arg;
  run *r = t->r;
  const char *bucket = r->job.keyrotate->bucket;
  for (int attempts = 1; attempts <= t->retries && !cancelled(r); attempts++) {
    int64_t start = now_ns();
    char err[256] = "";
    bool ok = rotate_one(r, &t->it, err, sizeof(err));
    trace(M_KEYROTATION, r->ri.job_id, start, attempts, t->it.name, t->it.version_id, ok ? NULL : err);
    if (!ok) {
      buckets_log_warn("batch: %s: rotating %s/%s: %s", r->ri.job_id, bucket, t->it.name, err);
      if (attempts >= t->retries) {
        const char *keys[1] = {"version-id"}, *vals[1] = {t->it.version_id};
        buckets_audit_internal("KeyRotate", "StartBatchJob", bucket, t->it.name, t->it.version_id, err, keys, vals, 1);
      }
    }
    track_object(r, bucket, t->it.name, t->it.size, t->it.delete_marker, ok, attempts);
    update_after(r, 10000000000LL);
    if (ok) break;
    sleep_ns(t->delay_ns + (int64_t)(rnd01() * (double)t->delay_ns));
  }
  sleep_ns(t->wait_ns);
  item_free(&t->it);
  free(t);
}

typedef struct {
  run *r;
  wpool *wk;
  int64_t now;
  int retries;
  int64_t delay_ns, wait_ns;
} rot_walk;

static bool rot_visit(void *ud, item *it) {
  rot_walk *w = ud;
  if (cancelled(w->r)) return false;
  if (!rotate_select(w->r->job.keyrotate, it, w->now)) return true;
  buckets_sse_kind kind = buckets_s3_sse_kind_of_meta(it->meta_sys, it->nmeta_sys);
  if (kind != BUCKETS_SSE_KMS && kind != BUCKETS_SSE_S3) return true;
  rot_task *t = buckets_xcalloc(1, sizeof(*t));
  t->r = w->r;
  t->it = *it; /* taken over */
  memset(it, 0, sizeof(*it));
  t->retries = w->retries;
  t->delay_ns = w->delay_ns;
  t->wait_ns = w->wait_ns;
  wpool_go(w->wk, rot_run, t);
  return true;
}

static void run_keyrotate(run *r) {
  buckets_batch_keyrotate *k = r->job.keyrotate;
  int retries = k->flags.retry.attempts > 0 ? (int)k->flags.retry.attempts : 3;
  int64_t delay = k->flags.retry.delay_ns > 0 ? k->flags.retry.delay_ns : 25000000LL;
  wpool wk;
  wpool_init(&wk, worker_count("_MINIO_BATCH_KEYROTATION_WORKERS"));
  rot_walk w = {r, &wk, now_ns(), retries, delay, config_wait(r->b, "keyrotation_workers_wait")};
  char *marker = dupz(r->ri.object);
  char err[256];
  bool failed = !walk(r, k->bucket, k->prefix, marker, true, rot_visit, &w, err, sizeof(err));
  if (failed) buckets_log_warn("batch: %s: walking %s: %s", r->ri.job_id, k->bucket, err);
  free(marker);
  wpool_wait(&wk);
  wpool_close(&wk);
  if (cancelled(r)) return;
  pthread_mutex_lock(&r->mu);
  r->ri.complete = !failed && r->ri.objects_failed == 0;
  r->ri.failed = failed || r->ri.objects_failed > 0;
  metrics_save_locked(r);
  pthread_mutex_unlock(&r->mu);
  update_after(r, 0);
  notify(r, &k->flags.notify, true);
}

/* ---- replicate -------------------------------------------------------------------------------------------------- */

static bool is_s3_type(const buckets_batch_replicate *rp) {
  return strcmp(rp->target.type ? rp->target.type : "", "s3") == 0 ||
         strcmp(rp->source.type ? rp->source.type : "", "s3") == 0;
}

/* The remote endpoint as a client ("http://host:port"). */
static buckets_s3c *remote_client(buckets_s3_server *s, const char *endpoint, const buckets_batch_creds *cr,
                                  const char *job_id, char *err, size_t errlen) {
  const char *hp = endpoint;
  bool secure = false;
  if (strncasecmp(hp, "https://", 8) == 0) hp += 8, secure = true;
  else if (strncasecmp(hp, "http://", 7) == 0) hp += 7;
  char host[512];
  snprintf(host, sizeof(host), "%s", hp);
  char *slash = strchr(host, '/');
  if (slash) *slash = '\0';
  if (!*host) {
    snprintf(err, errlen, "invalid endpoint %s", endpoint);
    return NULL;
  }
  char app[256];
  snprintf(app, sizeof(app), "minio-batch-jobs v1 %s", job_id ? job_id : "");
  buckets_s3c_config cfg = {.endpoint = host,
                            .secure = secure,
                            .access_key = cr->access_key ? cr->access_key : "",
                            .secret_key = cr->secret_key ? cr->secret_key : "",
                            .session_token = cr->session_token,
                            .tls = s->repl ? buckets_repl_tls(s->repl) : NULL,
                            .app_info = app};
  return buckets_s3c_new(&cfg);
}

/* Replicate's selectObj (the local walk of a push) */
static bool push_select(const buckets_batch_replicate *rp, const item *it, int64_t now) {
  const buckets_batch_filter *f = &rp->flags.filter;
  if (f->older_than_ns > 0 && now - it->mod_time_ns < f->older_than_ns) return false;
  if (f->newer_than_ns > 0 && now - it->mod_time_ns >= f->newer_than_ns) return false;
  if (f->created_after.set && time_ns(&f->created_after) > it->mod_time_ns) return false;
  if (f->created_before.set && time_ns(&f->created_before) < it->mod_time_ns) return false;
  if (f->tags.n) return tags_match_any(&f->tags, it->user_tags);
  if (f->metadata.n) return meta_match_any(&f->metadata, it->meta, it->nmeta);
  return !is_s3_type(rp) || it->is_latest;
}

typedef struct {
  run *r;
  buckets_s3c *c;
  item it;
  int attempt;
  bool retry;
  int64_t wait_ns;
} push_task;

static void push_run(void *arg) {
  push_task *t = arg;
  run *r = t->r;
  buckets_batch_replicate *rp = r->job.replicate;
  buckets_s3_server *s = r->b->s;
  if (!cancelled(r)) {
    bool plain = is_s3_type(rp);
    buckets_buf tobj = BUCKETS_BUF_INIT;
    if (rp->target.prefix && *rp->target.prefix) buckets_path_join(rp->target.prefix, t->it.name, &tobj);
    else buckets_buf_append_c(&tobj, t->it.name);
    char err[512] = "";
    int64_t start = now_ns();
    int res = t->it.delete_marker
                  ? buckets_repl_batch_delete(t->c, rp->target.bucket, tobj.data, t->it.version_id, t->it.mod_time_ns,
                                              plain, t->retry, err, sizeof(err))
                  : buckets_repl_batch_put(s, t->c, rp->source.bucket, t->it.name, t->it.version_id, rp->target.bucket,
                                           tobj.data, plain, t->retry, err, sizeof(err));
    buckets_buf_free(&tobj);
    if (res != BUCKETS_REPL_BATCH_SKIP) {
      bool ok = res == BUCKETS_REPL_BATCH_OK;
      trace(M_REPLICATION, r->ri.job_id, start, t->attempt, t->it.name, t->it.version_id, ok ? NULL : err);
      if (!ok) buckets_log_warn("batch: %s: replicating %s: %s", r->ri.job_id, t->it.name, err);
      track_object(r, rp->source.bucket, t->it.name, t->it.size, t->it.delete_marker, ok, t->attempt);
      update_after(r, 10000000000LL);
      sleep_ns(t->wait_ns);
    }
  }
  item_free(&t->it);
  free(t);
}

typedef struct {
  run *r;
  buckets_s3c *c;
  wpool *wk;
  int64_t now, wait_ns;
  int attempt;
  bool retry, s3type;
  char *prev;
  bool skip;
} push_walk;

static bool push_visit(void *ud, item *it) {
  push_walk *w = ud;
  if (cancelled(w->r)) return false;
  if (!push_select(w->r->job.replicate, it, w->now)) return true;
  if (!w->prev || strcmp(w->prev, it->name) != 0) {
    free(w->prev);
    w->prev = buckets_xstrdup(it->name);
    w->skip = it->delete_marker && w->s3type;
  }
  if (w->skip) return true;
  push_task *t = buckets_xcalloc(1, sizeof(*t));
  t->r = w->r;
  t->c = w->c;
  t->it = *it;
  memset(it, 0, sizeof(*it));
  t->attempt = w->attempt;
  t->retry = w->retry;
  t->wait_ns = w->wait_ns;
  wpool_go(w->wk, push_run, t);
  return true;
}

/* BatchJobReplicateV1.Start: local objects to the remote target (snowball
 * archives are not used: every version goes as it would one at a time) */
static void run_push(run *r) {
  buckets_batch_replicate *rp = r->job.replicate;
  int retries = rp->flags.retry.attempts > 0 ? (int)rp->flags.retry.attempts : 3;
  int64_t delay = rp->flags.retry.delay_ns > 0 ? rp->flags.retry.delay_ns : 1000000000LL;
  char err[256];
  buckets_s3c *c = remote_client(r->b->s, rp->target.endpoint, &rp->target.creds, r->ri.job_id, err, sizeof(err));
  if (!c) {
    buckets_log_warn("batch: %s: %s", r->ri.job_id, err);
    return;
  }
  char *marker = dupz(r->ri.object);
  bool retry = false;
  for (int attempts = 1; attempts <= retries && !cancelled(r); attempts++) {
    wpool wk;
    wpool_init(&wk, worker_count("_MINIO_BATCH_REPLICATION_WORKERS"));
    push_walk w = {r, c, &wk, now_ns(), config_wait(r->b, "replication_workers_wait"), attempts, retry, is_s3_type(rp),
                   NULL, false};
    bool walk_failed = false;
    size_t np = rp->source.prefix.n ? rp->source.prefix.n : 1;
    for (size_t i = 0; i < np && !cancelled(r); i++) {
      if (!walk(r, rp->source.bucket, rp->source.prefix.n ? rp->source.prefix.v[i] : "", marker, true, push_visit, &w,
                err, sizeof(err))) {
        buckets_log_warn("batch: %s: walking %s: %s", r->ri.job_id, rp->source.bucket, err);
        walk_failed = true;
        break;
      }
    }
    wpool_wait(&wk);
    wpool_close(&wk);
    free(w.prev);
    if (cancelled(r) || walk_failed) break;
    pthread_mutex_lock(&r->mu);
    r->ri.retry_attempts = attempts;
    r->ri.complete = r->ri.objects_failed == 0;
    r->ri.failed = r->ri.objects_failed > 0;
    metrics_save_locked(r);
    bool failed = r->ri.failed;
    pthread_mutex_unlock(&r->mu);
    update_after(r, 0);
    notify(r, &rp->flags.notify, true);
    if (!failed) break;
    pthread_mutex_lock(&r->mu);
    r->ri.objects_failed = 0;
    free(r->ri.bucket);
    free(r->ri.object);
    r->ri.bucket = dupz("");
    r->ri.object = dupz("");
    r->ri.objects = 0;
    r->ri.bytes_failed = 0;
    r->ri.bytes_transferred = 0;
    pthread_mutex_unlock(&r->mu);
    free(marker);
    marker = dupz("");
    retry = true;
    sleep_ns(delay + (int64_t)(rnd01() * (double)delay));
  }
  free(marker);
  buckets_s3c_free(c);
}

/* ---- pull: a remote bucket into a local one (StartFromSource) ---- */

/* One remote version, as listed (minio-go ObjectInfo with metadata). */
typedef struct {
  char *key, *version_id, *etag, *storage_class, *user_tags;
  int64_t size, mod_time_ns;
  bool is_latest, delete_marker;
  buckets_xl_kv *meta; /* UserMetadata */
  size_t nmeta;
} remote_obj;

static void remote_obj_free(remote_obj *o) {
  free(o->key), free(o->version_id), free(o->etag), free(o->storage_class), free(o->user_tags);
  for (size_t i = 0; i < o->nmeta; i++) free(o->meta[i].key), free(o->meta[i].value);
  free(o->meta);
  memset(o, 0, sizeof(*o));
}

static char *xml_child_text(const buckets_xml_doc *d, size_t node, const char *name) {
  size_t c = buckets_xml_child(d, node, name);
  if (!c) return NULL;
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_xml_unescape(d->nodes[c].text, &t);
  char *s = buckets_xstrndup(t.data ? t.data : "", t.len);
  buckets_buf_free(&t);
  return s;
}

static void meta_add(buckets_xl_kv **kv, size_t *n, const char *k, const char *v) {
  buckets_xl_kv_set(kv, n, k, v, strlen(v));
}

/* toObjectInfo's user tags: the canonical form of the listed tags */
static char *canonical_tags(const char *q) {
  buckets_tags t = {0};
  buckets_tags_error te;
  if (!q || !*q || !buckets_tags_parse_query(q, true, &t, &te)) return NULL;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_tags_string(&t, &b);
  buckets_tags_free(&t);
  buckets_buf_append_char(&b, '\0');
  return buckets_buf_detach(&b);
}

static void parse_remote_entry(const buckets_xml_doc *d, size_t n, bool dm, remote_obj *o) {
  memset(o, 0, sizeof(*o));
  o->key = xml_child_text(d, n, "Key");
  o->version_id = xml_child_text(d, n, "VersionId");
  char *etag = xml_child_text(d, n, "ETag");
  if (etag) {
    size_t l = strlen(etag);
    if (l >= 2 && etag[0] == '"' && etag[l - 1] == '"') {
      memmove(etag, etag + 1, l - 2);
      etag[l - 2] = 0;
    }
  }
  o->etag = etag;
  o->storage_class = xml_child_text(d, n, "StorageClass");
  char *sz = xml_child_text(d, n, "Size");
  o->size = sz ? strtoll(sz, NULL, 10) : 0;
  free(sz);
  char *lm = xml_child_text(d, n, "LastModified");
  long long sec;
  long nsec;
  if (lm && buckets_time_parse_rfc3339(lm, &sec, &nsec)) o->mod_time_ns = sec * 1000000000LL + nsec;
  free(lm);
  char *il = xml_child_text(d, n, "IsLatest");
  o->is_latest = il && strcmp(il, "true") == 0;
  free(il);
  o->delete_marker = dm;
  char *tags = xml_child_text(d, n, "UserTags");
  o->user_tags = canonical_tags(tags);
  free(tags);
  size_t um = buckets_xml_child(d, n, "UserMetadata");
  for (size_t c = um ? d->nodes[um].first_child : 0; c; c = d->nodes[c].next_sibling) {
    buckets_buf t = BUCKETS_BUF_INIT;
    buckets_xml_unescape(d->nodes[c].text, &t);
    buckets_buf_append_char(&t, '\0');
    char *k = buckets_str_dup(d->nodes[c].name);
    meta_add(&o->meta, &o->nmeta, k, t.data);
    free(k);
    buckets_buf_free(&t);
  }
  if (!o->key) o->key = buckets_xstrdup("");
  if (!o->version_id) o->version_id = buckets_xstrdup("");
  if (!o->etag) o->etag = buckets_xstrdup("");
}

/* A GET of (part of) a remote version as a local read source. */
typedef struct {
  buckets_http_stream *st;
} remote_rd;

static long remote_read(void *ud, void *buf, size_t n) {
  remote_rd *r = ud;
  return buckets_http_stream_read(r->st, buf, n);
}

typedef struct {
  const char *vid;
  int64_t mtime_ns;
} pull_commit;

static buckets_obj_err pull_pre_commit(void *ud, buckets_xl_object *o) {
  pull_commit *pc = ud;
  if (pc->vid && *pc->vid && strcmp(pc->vid, "null") != 0) {
    uint8_t id[16];
    if (buckets_xl_version_id_parse(pc->vid, id)) memcpy(o->version_id, id, 16);
  }
  if (pc->mtime_ns) o->mod_time = pc->mtime_ns;
  return BUCKETS_OBJ_OK;
}

static buckets_http_stream *remote_get(buckets_s3c *c, const char *bucket, const remote_obj *o, int part,
                                       char *err, size_t errlen) {
  buckets_buf q = BUCKETS_BUF_INIT;
  if (o->version_id && *o->version_id) {
    buckets_buf_append_c(&q, "versionId=");
    buckets_url_encode(&q, o->version_id, false);
  }
  if (part > 0) buckets_buf_appendf(&q, "%spartNumber=%d", q.len ? "&" : "", part);
  buckets_buf_append_char(&q, '\0');
  char im[300];
  snprintf(im, sizeof(im), "\"%s\"", o->etag);
  buckets_http_kv h[] = {{"If-Match", im}};
  buckets_s3c_result res;
  buckets_http_stream *st = buckets_s3c_open(c, "GET", bucket, o->key, q.len > 1 ? q.data : NULL, h, 1, &res);
  if (!st) snprintf(err, errlen, "%s", buckets_s3c_error(&res));
  buckets_s3c_result_free(&res);
  buckets_buf_free(&q);
  return st;
}

/* ReplicateFromSource: one remote version into the local target bucket */
static int pull_one(run *r, buckets_s3c *c, const remote_obj *o, char *err, size_t errlen) {
  buckets_s3_server *s = r->b->s;
  buckets_batch_replicate *rp = r->job.replicate;
  bool s3type = is_s3_type(rp);
  buckets_buf tobj = BUCKETS_BUF_INIT;
  if (rp->target.prefix && *rp->target.prefix) buckets_path_join(rp->target.prefix, o->key, &tobj);
  else buckets_buf_append_c(&tobj, o->key);
  const char *vid = s3type ? "" : o->version_id;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, rp->target.bucket);
  bool versioned = buckets_versioning_enabled_for(&st->versioning, tobj.data);
  buckets_bucket_state_release(st);
  int ret = BUCKETS_REPL_BATCH_OK;
  if (o->delete_marker) {
    buckets_delete_opts d = {.version_id = *vid ? vid : NULL, .versioned = true, .replica_marker = true,
                             .mod_time_ns = o->mod_time_ns};
    buckets_delete_result dr;
    buckets_obj_err e = buckets_obj_delete_ex(s->layer, rp->target.bucket, tobj.data, &d, &dr);
    if (e) snprintf(err, errlen, "%s", buckets_obj_strerror(e)), ret = BUCKETS_REPL_BATCH_FAILED;
    buckets_buf_free(&tobj);
    return ret;
  }
  /* UserDefined: the listed metadata, the storage class; the data is stored
   * as sent (encryption headers are not kept for plaintext) */
  buckets_xl_kv *meta = NULL;
  size_t nmeta = 0;
  for (size_t i = 0; i < o->nmeta; i++) {
    if (strncasecmp(o->meta[i].key, "X-Amz-Server-Side-Encryption", 28) == 0) continue;
    meta_add(&meta, &nmeta, o->meta[i].key, (const char *)o->meta[i].value);
  }
  bool has_sc = false;
  for (size_t i = 0; i < nmeta; i++) has_sc |= strcasecmp(meta[i].key, "x-amz-storage-class") == 0;
  if (!has_sc && o->storage_class && *o->storage_class) meta_add(&meta, &nmeta, "x-amz-storage-class", o->storage_class);
  if (o->user_tags && *o->user_tags) meta_add(&meta, &nmeta, "X-Amz-Tagging", o->user_tags);
  pull_commit pc = {vid, o->mod_time_ns};
  const char *dash = strrchr(o->etag, '-');
  int parts = dash ? atoi(dash + 1) : 0;
  if (parts > 0) { /* copyWithMultipartfromSource */
    char upload_id[BUCKETS_UPLOAD_ID_MAX];
    buckets_obj_err e = buckets_obj_mpu_new(s->layer, rp->target.bucket, tobj.data, meta, nmeta, upload_id);
    buckets_complete_part *cp = e ? NULL : buckets_xcalloc((size_t)parts, sizeof(*cp));
    char (*etags)[128] = e ? NULL : buckets_xcalloc((size_t)parts, sizeof(*etags));
    if (e) snprintf(err, errlen, "%s", buckets_obj_strerror(e)), ret = BUCKETS_REPL_BATCH_FAILED;
    for (int p = 1; p <= parts && ret == BUCKETS_REPL_BATCH_OK; p++) {
      remote_rd rd = {remote_get(c, rp->source.bucket, o, p, err, errlen)};
      if (!rd.st) {
        ret = BUCKETS_REPL_BATCH_FAILED;
        break;
      }
      buckets_part_info pi;
      buckets_put_opts po = {0};
      e = buckets_obj_mpu_put_part(s->layer, rp->target.bucket, tobj.data, upload_id, p, remote_read, &rd,
                                   buckets_http_stream_length(rd.st), &po, &pi);
      buckets_http_stream_free(rd.st);
      if (e) {
        snprintf(err, errlen, "%s", buckets_obj_strerror(e));
        ret = BUCKETS_REPL_BATCH_FAILED;
        break;
      }
      snprintf(etags[p - 1], sizeof(etags[p - 1]), "%s", pi.etag);
      cp[p - 1] = (buckets_complete_part){p, etags[p - 1], NULL};
    }
    if (ret == BUCKETS_REPL_BATCH_OK) {
      buckets_complete_opts co = {.versioned = versioned || *vid, .pre_commit = pull_pre_commit, .ud = &pc};
      buckets_object_info out;
      e = buckets_obj_mpu_complete(s->layer, rp->target.bucket, tobj.data, upload_id, cp, (size_t)parts, NULL, &co, &out);
      if (e) snprintf(err, errlen, "%s", buckets_obj_strerror(e)), ret = BUCKETS_REPL_BATCH_FAILED;
      else buckets_object_info_free(&out);
    }
    if (ret != BUCKETS_REPL_BATCH_OK && cp)
      for (int a = 0; a < 3; a++)
        if (buckets_obj_mpu_abort(s->layer, rp->target.bucket, tobj.data, upload_id) == BUCKETS_OBJ_OK) break;
    free(cp);
    free(etags);
  } else {
    remote_rd rd = {remote_get(c, rp->source.bucket, o, 0, err, errlen)};
    if (!rd.st) {
      ret = BUCKETS_REPL_BATCH_FAILED;
    } else {
      buckets_put_opts po = {.meta = meta, .nmeta = nmeta, .versioned = versioned, .version_id = *vid ? vid : NULL,
                             .mod_time_ns = o->mod_time_ns, .preserve_etag = o->etag};
      buckets_object_info out;
      buckets_obj_err e = buckets_obj_put(s->layer, rp->target.bucket, tobj.data, remote_read, &rd,
                                          buckets_http_stream_length(rd.st), &po, &out);
      buckets_http_stream_free(rd.st);
      if (e) snprintf(err, errlen, "%s", buckets_obj_strerror(e)), ret = BUCKETS_REPL_BATCH_FAILED;
      else buckets_object_info_free(&out);
    }
  }
  for (size_t i = 0; i < nmeta; i++) free(meta[i].key), free(meta[i].value);
  free(meta);
  buckets_buf_free(&tobj);
  return ret;
}

typedef struct {
  run *r;
  buckets_s3c *c;
  remote_obj o;
  int attempt;
  int64_t wait_ns;
} pull_task;

static void pull_run(void *arg) {
  pull_task *t = arg;
  run *r = t->r;
  if (!cancelled(r)) {
    char err[512] = "";
    int64_t start = now_ns();
    int res = pull_one(r, t->c, &t->o, err, sizeof(err));
    bool gone = res == BUCKETS_REPL_BATCH_FAILED && (strstr(err, "NoSuchKey") || strstr(err, "NoSuchVersion") ||
                                                    strstr(err, "does not exist"));
    if (!gone) {
      bool ok = res == BUCKETS_REPL_BATCH_OK;
      trace(M_REPLICATION, r->ri.job_id, start, t->attempt, t->o.key, t->o.version_id, ok ? NULL : err);
      if (!ok) buckets_log_warn("batch: %s: replicating %s: %s", r->ri.job_id, t->o.key, err);
      track_object(r, r->job.replicate->target.bucket, t->o.key, t->o.size, t->o.delete_marker, ok, t->attempt);
      update_after(r, 10000000000LL);
      sleep_ns(t->wait_ns);
    }
  }
  remote_obj_free(&t->o);
  free(t);
}

/* StartFromSource's skip (as MinIO has it: matching tags or metadata skip) */
static bool pull_skip(const buckets_batch_replicate *rp, const remote_obj *o, int64_t now) {
  const buckets_batch_filter *f = &rp->flags.filter;
  if (f->older_than_ns > 0 && now - o->mod_time_ns < f->older_than_ns) return true;
  if (f->newer_than_ns > 0 && now - o->mod_time_ns >= f->newer_than_ns) return true;
  if (f->created_after.set && time_ns(&f->created_after) > o->mod_time_ns) return true;
  if (f->created_before.set && time_ns(&f->created_before) < o->mod_time_ns) return true;
  if (f->tags.n) return tags_match_any(&f->tags, o->user_tags);
  return meta_match_any(&f->metadata, o->meta, o->nmeta);
}

/* Lists the remote bucket (versions from MinIO sources), handing each entry to the workers. */
static bool pull_list(run *r, buckets_s3c *c, const char *prefix, wpool *wk, int attempt, int64_t wait_ns,
                      char **prev, bool *skip_key, char *err, size_t errlen) {
  buckets_batch_replicate *rp = r->job.replicate;
  bool minio_src = strcmp(rp->source.type ? rp->source.type : "", "minio") == 0;
  bool s3type = is_s3_type(rp);
  char *key_marker = NULL, *ver_marker = NULL, *token = NULL;
  int64_t now = now_ns();
  bool ok = true;
  for (;;) {
    if (cancelled(r)) break;
    buckets_buf q = BUCKETS_BUF_INIT;
    if (minio_src) {
      buckets_buf_append_c(&q, "versions=&metadata=true&prefix=");
      buckets_url_encode(&q, prefix, false);
      if (key_marker) {
        buckets_buf_append_c(&q, "&key-marker=");
        buckets_url_encode(&q, key_marker, false);
      }
      if (ver_marker) {
        buckets_buf_append_c(&q, "&version-id-marker=");
        buckets_url_encode(&q, ver_marker, false);
      }
    } else {
      buckets_buf_append_c(&q, "list-type=2&metadata=true&prefix=");
      buckets_url_encode(&q, prefix, false);
      if (token) {
        buckets_buf_append_c(&q, "&continuation-token=");
        buckets_url_encode(&q, token, false);
      }
    }
    buckets_buf_append_char(&q, '\0');
    buckets_s3c_result res;
    bool rok = buckets_s3c_do(c, "GET", rp->source.bucket, NULL, q.data, NULL, 0, NULL, 0, &res);
    buckets_buf_free(&q);
    if (!rok) {
      snprintf(err, errlen, "%s", buckets_s3c_error(&res));
      buckets_s3c_result_free(&res);
      ok = false;
      break;
    }
    buckets_xml_doc d = {0};
    if (!buckets_xml_parse((buckets_str){res.body.data, res.body.len}, &d) || !d.count) {
      snprintf(err, errlen, "malformed listing");
      buckets_s3c_result_free(&res);
      ok = false;
      break;
    }
    for (size_t n = d.nodes[0].first_child; n; n = d.nodes[n].next_sibling) {
      bool is_ver = buckets_str_eq_c(d.nodes[n].name, "Version"), is_dm = buckets_str_eq_c(d.nodes[n].name, "DeleteMarker");
      bool is_obj = buckets_str_eq_c(d.nodes[n].name, "Contents");
      if (!is_ver && !is_dm && !is_obj) continue;
      remote_obj o;
      parse_remote_entry(&d, n, is_dm, &o);
      if (!minio_src) {
        free(o.version_id);
        o.version_id = buckets_xstrdup("");
        o.is_latest = true;
      }
      if (pull_skip(rp, &o, now)) {
        remote_obj_free(&o);
        continue;
      }
      if (!*prev || strcmp(*prev, o.key) != 0) {
        free(*prev);
        *prev = buckets_xstrdup(o.key);
        *skip_key = o.delete_marker && s3type;
      }
      if (*skip_key) {
        remote_obj_free(&o);
        continue;
      }
      pull_task *t = buckets_xcalloc(1, sizeof(*t));
      t->r = r;
      t->c = c;
      t->o = o;
      t->attempt = attempt;
      t->wait_ns = wait_ns;
      wpool_go(wk, pull_run, t);
    }
    char *trunc = xml_child_text(&d, 0, "IsTruncated");
    bool more = trunc && strcmp(trunc, "true") == 0;
    free(trunc);
    free(key_marker), free(ver_marker), free(token);
    key_marker = ver_marker = token = NULL;
    if (more) {
      key_marker = xml_child_text(&d, 0, "NextKeyMarker");
      ver_marker = xml_child_text(&d, 0, "NextVersionIdMarker");
      token = xml_child_text(&d, 0, "NextContinuationToken");
    }
    buckets_xml_doc_free(&d);
    buckets_s3c_result_free(&res);
    if (!more || (minio_src ? !key_marker : !token)) break;
  }
  free(key_marker), free(ver_marker), free(token);
  return ok;
}

static void run_pull(run *r) {
  buckets_batch_replicate *rp = r->job.replicate;
  int retries = rp->flags.retry.attempts > 0 ? (int)rp->flags.retry.attempts : 3;
  int64_t delay = rp->flags.retry.delay_ns > 0 ? rp->flags.retry.delay_ns : 1000000000LL;
  char err[256];
  buckets_s3c *c = remote_client(r->b->s, rp->source.endpoint, &rp->source.creds, r->ri.job_id, err, sizeof(err));
  if (!c) {
    buckets_log_warn("batch: %s: %s", r->ri.job_id, err);
    return;
  }
  for (int attempts = 1; attempts <= retries && !cancelled(r); attempts++) {
    wpool wk;
    wpool_init(&wk, worker_count("_MINIO_BATCH_REPLICATION_WORKERS"));
    char *prev = NULL;
    bool skip_key = false;
    size_t np = rp->source.prefix.n ? rp->source.prefix.n : 1;
    for (size_t i = 0; i < np && !cancelled(r); i++)
      if (!pull_list(r, c, rp->source.prefix.n ? rp->source.prefix.v[i] : "", &wk, attempts,
                     config_wait(r->b, "replication_workers_wait"), &prev, &skip_key, err, sizeof(err)))
        buckets_log_warn("batch: %s: listing %s: %s", r->ri.job_id, rp->source.bucket, err);
    wpool_wait(&wk);
    wpool_close(&wk);
    free(prev);
    if (cancelled(r)) break;
    pthread_mutex_lock(&r->mu);
    r->ri.retry_attempts = attempts;
    r->ri.complete = r->ri.objects_failed == 0;
    r->ri.failed = r->ri.objects_failed > 0;
    metrics_save_locked(r);
    bool failed = r->ri.failed;
    pthread_mutex_unlock(&r->mu);
    update_after(r, 0);
    notify(r, &rp->flags.notify, true);
    if (!failed) break;
    pthread_mutex_lock(&r->mu);
    r->ri.objects_failed = 0;
    free(r->ri.bucket);
    free(r->ri.object);
    r->ri.bucket = dupz("");
    r->ri.object = dupz("");
    r->ri.objects = 0;
    r->ri.bytes_failed = 0;
    r->ri.bytes_transferred = 0;
    pthread_mutex_unlock(&r->mu);
    sleep_ns(delay + (int64_t)(rnd01() * (double)delay));
  }
  buckets_s3c_free(c);
}

/* ---- running jobs ------------------------------------------------------------------------------------------------- */

static void job_path(const char *id, buckets_buf *out) { buckets_buf_appendf(out, "%s/%s", BUCKETS_BATCH_PREFIX, id); }

/* loadOrInit: the job's report so far, if any */
static void load_report(buckets_batch *b, run *r) {
  buckets_buf path = BUCKETS_BUF_INIT, data = BUCKETS_BUF_INIT;
  const char *type = buckets_batch_job_type(&r->job);
  report_path(r->job.id, type, &path);
  buckets_batch_info ri;
  char err[256];
  if (buckets_sysconfig_read(b->s->layer, path.data, &data, NULL) == BUCKETS_OBJ_OK &&
      buckets_batch_info_decode(buckets_batch_report_name(type), data.data, data.len, &ri, err, sizeof(err))) {
    if (!ri.job_id) ri.job_id = dupz(r->job.id);
    if (!ri.job_type) ri.job_type = dupz(type);
    buckets_batch_info_free(&r->ri);
    r->ri = ri;
  }
  buckets_buf_free(&path);
  buckets_buf_free(&data);
}

static void *job_main(void *arg) {
  run *r = arg;
  buckets_batch *b = r->b;
  r->ri.job_id = dupz(r->job.id);
  r->ri.job_type = dupz(buckets_batch_job_type(&r->job));
  r->ri.start = r->job.started;
  r->ri.version = 1;
  load_report(b, r);
  bool done = r->ri.complete && !r->job.expire;
  if (!done) {
    metrics_save(r);
    if (r->job.replicate) {
      bool pull = r->job.replicate->source.creds.access_key && *r->job.replicate->source.creds.access_key;
      pull |= r->job.replicate->source.creds.secret_key && *r->job.replicate->source.creds.secret_key;
      if (pull) run_pull(r);
      else run_push(r);
    } else if (r->job.keyrotate) {
      run_keyrotate(r);
    } else if (r->job.expire) {
      run_expire(r);
    }
  }
  pthread_mutex_lock(&b->mu);
  for (run **p = &b->running; *p; p = &(*p)->next) {
    if (*p == r) {
      *p = r->next;
      break;
    }
  }
  b->nrunning--;
  /* start what waits */
  run *next = NULL;
  if (b->queue && !b->stop) {
    next = b->queue;
    b->queue = next->next;
    if (!b->queue) b->queue_tail = NULL;
    b->nqueued--;
    next->next = b->running;
    b->running = next;
    b->nrunning++;
  }
  pthread_cond_broadcast(&b->cv);
  pthread_mutex_unlock(&b->mu);
  run_free(r);
  if (next) {
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &at, job_main, next) != 0) buckets_log_warn("batch: cannot start job %s", next->job.id);
    pthread_attr_destroy(&at);
  }
  return NULL;
}

/* queueJob: false when the queue is full */
static bool queue_job(buckets_batch *b, buckets_batch_job *job) {
  run *r = buckets_xcalloc(1, sizeof(*r));
  r->b = b;
  r->job = *job;
  memset(job, 0, sizeof(*job));
  pthread_mutex_init(&r->mu, NULL);
  pthread_mutex_lock(&b->mu);
  if (b->stop || b->nqueued >= MAX_QUEUED) {
    pthread_mutex_unlock(&b->mu);
    *job = r->job;
    memset(&r->job, 0, sizeof(r->job));
    run_free(r);
    return false;
  }
  bool start = b->nrunning < MAX_RUNNING;
  if (start) {
    r->next = b->running;
    b->running = r;
    b->nrunning++;
  } else {
    if (b->queue_tail) b->queue_tail->next = r;
    else b->queue = r;
    b->queue_tail = r;
    b->nqueued++;
  }
  pthread_mutex_unlock(&b->mu);
  if (start) {
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &at, job_main, r) != 0) {
      pthread_mutex_lock(&b->mu);
      for (run **p = &b->running; *p; p = &(*p)->next)
        if (*p == r) {
          *p = r->next;
          break;
        }
      b->nrunning--;
      pthread_mutex_unlock(&b->mu);
      run_free(r);
    }
    pthread_attr_destroy(&at);
  }
  return true;
}

/* ---- node identity (GetProxyEndpointLocalIndex) ---- */

static int local_index(buckets_s3_server *s) {
  buckets_cluster_info *ci = s->cluster;
  if (!ci || !ci->distributed || !ci->self) return -1;
  for (size_t i = 0; i < ci->nnodes; i++)
    if (strcmp(ci->nodes[i], ci->self) == 0) return (int)i;
  return -1;
}

/* parseRequestToken: the node index after the last ':' (-1: none) */
static int token_node(const char *id) {
  const char *c = strrchr(id, ':');
  if (!c) return -1;
  char *end;
  long v = strtol(c + 1, &end, 10);
  return *end ? -1 : (int)v;
}

/* shortuuid.New(): a random UUID in 22 base-57 digits, least significant first */
static void shortuuid(char out[23]) {
  static const char alphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  uint8_t u[16];
  buckets_random_bytes(u, sizeof(u));
  u[6] = (uint8_t)((u[6] & 0x0f) | 0x40); /* version 4 */
  u[8] = (uint8_t)((u[8] & 0x3f) | 0x80); /* RFC 4122 variant */
  unsigned __int128 num = 0;
  for (int i = 0; i < 16; i++) num = num << 8 | u[i];
  int n = 0;
  while ((uint64_t)num > 0 && n < 22) {
    out[n++] = alphabet[(int)(num % 57)];
    num /= 57;
  }
  while (n < 22) out[n++] = alphabet[0];
  out[22] = 0;
}

/* ---- validation (BatchJobRequest.Validate) --------------------------------------------------------------------------- */

static bool invalid(buckets_batch_err *e) {
  e->code = NULL;
  e->internal = false;
  e->status = 400;
  snprintf(e->desc, sizeof(e->desc), "Invalid arguments specified.");
  return false;
}

static bool job_err(buckets_batch_err *e, const char *code, int status, bool internal, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
static bool job_err(buckets_batch_err *e, const char *code, int status, bool internal, const char *fmt, ...) {
  e->code = code;
  e->status = status;
  e->internal = internal;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(e->desc, sizeof(e->desc), fmt, ap);
  va_end(ap);
  return false;
}

static bool empty(const char *s) { return !s || !*s; }

static bool creds_empty(const buckets_batch_creds *c) {
  return empty(c->access_key) && empty(c->secret_key) && empty(c->session_token);
}

static bool creds_valid(const buckets_batch_creds *c) {
  return c->access_key && strlen(c->access_key) >= 3 && c->secret_key && strlen(c->secret_key) >= 8;
}

static bool type_valid(const char *t) { return t && (strcmp(t, "minio") == 0 || strcmp(t, "s3") == 0); }

static bool path_valid(const char *p) {
  return !p || !*p || strcmp(p, "on") == 0 || strcmp(p, "off") == 0 || strcmp(p, "auto") == 0;
}

static bool bucket_exists(buckets_s3_server *s, const char *bucket) {
  return buckets_obj_stat_bucket(s->layer, bucket) == BUCKETS_OBJ_OK;
}

static bool validate_kvs(const buckets_batch_kvs *k, buckets_batch_err *e) {
  for (size_t i = 0; i < k->n; i++)
    if (!buckets_batch_kv_validate(&k->v[i], e)) return false;
  return true;
}

static bool validate_replicate(buckets_batch *b, const buckets_batch_job *j, buckets_batch_err *e) {
  buckets_s3_server *s = b->s;
  const buckets_batch_replicate *r = j->replicate;
  if (!r->api_version || strcmp(r->api_version, "v1") != 0) return invalid(e);
  if (!empty(r->source.endpoint) && !empty(r->target.endpoint)) return invalid(e);
  if (creds_empty(&r->source.creds) && creds_empty(&r->target.creds)) return invalid(e);
  if (empty(r->source.bucket) || empty(r->target.bucket)) return invalid(e);
  bool remote_to_local = !empty(r->source.endpoint);
  const char *local = remote_to_local ? r->target.bucket : r->source.bucket;
  if (!bucket_exists(s, local))
    return job_err(e, "NoSuchSourceBucket", 404, false, "The specified bucket %s does not exist", local);
  if (!type_valid(r->source.type)) return invalid(e);
  if (!buckets_batch_snowball_validate(&r->source.snowball, e)) return false;
  if (!creds_empty(&r->source.creds) && !creds_valid(&r->source.creds)) return invalid(e);
  if (empty(r->target.endpoint) && !creds_empty(&r->target.creds)) return invalid(e);
  if (empty(r->source.endpoint) && !creds_empty(&r->source.creds)) return invalid(e);
  if (!empty(r->source.endpoint) && strcmp(r->source.type, "minio") != 0 && !path_valid(r->source.path))
    return invalid(e);
  if (!empty(r->target.endpoint) && !(r->target.type && strcmp(r->target.type, "minio") == 0) &&
      !path_valid(r->target.path))
    return invalid(e);
  if (!creds_empty(&r->target.creds) && !creds_valid(&r->target.creds)) return invalid(e);
  if (!type_valid(r->target.type)) return invalid(e);
  if (!validate_kvs(&r->flags.filter.tags, e) || !validate_kvs(&r->flags.filter.metadata, e)) return false;
  if (!buckets_batch_retry_validate(&r->flags.retry, e)) return false;
  /* the remote bucket and its versioning */
  const char *ep = remote_to_local ? r->source.endpoint : r->target.endpoint;
  const char *rb = remote_to_local ? r->source.bucket : r->target.bucket;
  const buckets_batch_creds *cr = remote_to_local ? &r->source.creds : &r->target.creds;
  char err[256];
  buckets_s3c *c = remote_client(s, ep ? ep : "", cr, j->id, err, sizeof(err));
  if (!c) return job_err(e, "InternalError", 500, true, "%s", err);
  buckets_s3c_result res;
  bool ok = buckets_s3c_do(c, "GET", rb, NULL, "versioning=", NULL, 0, NULL, 0, &res);
  buckets_s3c_free(c);
  if (!ok) {
    bool nsb = strcmp(res.code, "NoSuchBucket") == 0;
    if (nsb) {
      buckets_s3c_result_free(&res);
      return job_err(e, "NoSuchTargetBucket", 404, false, "The specified target bucket does not exist");
    }
    if (res.status) job_err(e, res.code[0] ? res.code : "InternalError", res.status, false, "%s", res.message);
    else job_err(e, "InternalError", 500, true, "%s", buckets_s3c_error(&res));
    buckets_s3c_result_free(&res);
    return false;
  }
  bool remote_versioned = res.body.len && strstr(res.body.data, "<Status>Enabled</Status>");
  buckets_s3c_result_free(&res);
  buckets_bucket_state *st = buckets_metasys_get(s->meta, local);
  bool local_versioned = st->versioning.status == BUCKETS_VERSIONING_ENABLED;
  buckets_bucket_state_release(st);
  bool minio_types = r->target.type && strcmp(r->target.type, "minio") == 0 && strcmp(r->source.type, "minio") == 0;
  if (minio_types && ((local_versioned && !remote_versioned && !remote_to_local) ||
                      (!local_versioned && remote_versioned && remote_to_local)))
    return job_err(e, "InvalidBucketState", 400, false,
                   "The source '%s' has versioning enabled, target '%s' must have versioning enabled", r->source.bucket,
                   r->target.bucket);
  return true;
}

static bool validate_keyrotate(buckets_batch *b, const buckets_batch_job *j, buckets_batch_err *e) {
  buckets_s3_server *s = b->s;
  const buckets_batch_keyrotate *k = j->keyrotate;
  if (!k->api_version || strcmp(k->api_version, "v1") != 0) return invalid(e);
  if (empty(k->bucket)) return invalid(e);
  if (!bucket_exists(s, k->bucket))
    return job_err(e, "InternalError", 500, true, "The specified source bucket does not exist");
  if (!s->kms)
    return job_err(e, "NotImplemented", 501, false, "Server side encryption specified but KMS is not configured");
  const char *t = k->enc_type ? k->enc_type : "";
  if (strcmp(t, "sse-s3") != 0 && strcmp(t, "sse-kms") != 0) return invalid(e);
  if (strcmp(t, "sse-kms") == 0) {
    const char *key = k->enc_key ? k->enc_key : "";
    size_t n = strlen(key);
    if (n && (key[0] == ' ' || key[n - 1] == ' '))
      return job_err(e, "InternalError", 500, true, "The KMS key id contains invalid characters");
    buckets_buf ctx = BUCKETS_BUF_INIT;
    if (!empty(k->enc_context)) {
      uint8_t *raw = buckets_xmalloc(strlen(k->enc_context) + 3);
      long rn = buckets_base64_decode(k->enc_context, strlen(k->enc_context), raw);
      if (rn < 0) {
        free(raw);
        return job_err(e, "InternalError", 500, true, "illegal base64 data at input byte 0");
      }
      buckets_buf_append(&ctx, raw, (size_t)rn);
      free(raw);
    }
    buckets_buf_append_char(&ctx, '\0');
    const char *keys[1] = {"MinIO batch API"}, *vals[1] = {"batchrotate"};
    buckets_buf cj = BUCKETS_BUF_INIT;
    buckets_kms_context_text(keys, vals, 1, &cj);
    uint8_t pt[32];
    buckets_buf ct = BUCKETS_BUF_INIT;
    char kid[256];
    if (strncmp(key, "arn:aws:kms:", 12) == 0) key += 12;
    buckets_kms_err ke = buckets_kms_generate(s->kms, key, cj.data, pt, &ct, kid, sizeof(kid));
    buckets_buf_free(&ct);
    buckets_buf_free(&cj);
    buckets_buf_free(&ctx);
    if (ke) return job_err(e, "kms:KeyNotFound", 404, false, "key with given key ID does not exist");
  }
  if (!validate_kvs(&k->flags.filter.tags, e) || !validate_kvs(&k->flags.filter.metadata, e)) return false;
  return buckets_batch_retry_validate(&k->flags.retry, e);
}

static bool validate_expire(buckets_batch *b, const buckets_batch_job *j, buckets_batch_err *e) {
  const buckets_batch_expire *x = j->expire;
  if (!x->api_version || strcmp(x->api_version, "v1") != 0)
    return job_err(e, "InternalError", 500, true, "Unsupported batch expire API version");
  if (empty(x->bucket)) return job_err(e, "InternalError", 500, true, "Bucket argument missing");
  if (!bucket_exists(b->s, x->bucket))
    return job_err(e, "InternalError", 500, true, "The specified source bucket does not exist");
  if (x->nrules > 50)
    return job_err(e, "InternalError", 500, true, "Too many rules. Batch expire job can't have more than 100 rules");
  int64_t now = now_ns() / 1000000000LL;
  for (size_t i = 0; i < x->nrules; i++) {
    buckets_batch_err re = {0};
    if (!buckets_batch_expire_rule_validate(&x->rules[i], now, &re))
      return job_err(e, "InternalError", 500, true, "Invalid batch expire rule: %s", re.desc);
  }
  buckets_batch_err re = {0};
  if (!buckets_batch_retry_validate(&x->retry, &re))
    return job_err(e, "InternalError", 500, true, "Invalid batch expire retry configuration: %s", re.desc);
  return true;
}

static bool validate(buckets_batch *b, const buckets_batch_job *j, buckets_batch_err *e) {
  if (j->replicate) return validate_replicate(b, j, e);
  if (j->keyrotate) return validate_keyrotate(b, j, e);
  if (j->expire) return validate_expire(b, j, e);
  return invalid(e);
}

/* ---- the admin API's side ------------------------------------------------------------------------------------------ */

static void result_json(const buckets_batch_job *j, bool elapsed, buckets_buf *out) {
  char st[64];
  buckets_time_rfc3339_nano(j->started.set ? j->started.sec : -62135596800LL, j->started.nsec, st);
  buckets_buf_append_c(out, "{\"id\":");
  buckets_json_go_string(out, j->id ? j->id : "", strlen(j->id ? j->id : ""));
  buckets_buf_appendf(out, ",\"type\":\"%s\"", buckets_batch_job_type(j));
  if (!empty(j->user)) {
    buckets_buf_append_c(out, ",\"user\":");
    buckets_json_go_string(out, j->user, strlen(j->user));
  }
  buckets_buf_appendf(out, ",\"started\":\"%s\"", j->started.set ? st : "0001-01-01T00:00:00Z");
  if (elapsed && j->started.set) {
    int64_t d = now_ns() - time_ns(&j->started);
    if (d) buckets_buf_appendf(out, ",\"elapsed\":%" PRId64, d);
  }
  buckets_buf_append_c(out, "}");
}

bool buckets_batch_start(buckets_batch *b, buckets_batch_job *job, const char *user, buckets_buf *out,
                         buckets_batch_err *e) {
  buckets_batch_job_defaults(job);
  if (!validate(b, job, e)) return false;
  char su[23];
  shortuuid(su);
  char id[128];
  snprintf(id, sizeof(id), "%s-%s:%d", buckets_batch_job_type(job), su, local_index(b->s));
  free(job->id);
  job->id = buckets_xstrdup(id);
  free(job->user);
  job->user = dupz(user);
  job->started = time_now();
  /* save: validated again, then kept */
  buckets_buf bin = BUCKETS_BUF_INIT, path = BUCKETS_BUF_INIT;
  buckets_batch_job_msgp(job, &bin);
  job_path(job->id, &path);
  buckets_obj_err err = buckets_sysconfig_write(b->s->layer, path.data, bin.data, bin.len);
  buckets_buf_free(&bin);
  buckets_buf_free(&path);
  if (err) return job_err(e, "InternalError", 500, true, "%s", buckets_obj_strerror(err));
  buckets_buf res = BUCKETS_BUF_INIT;
  result_json(job, false, &res);
  if (!queue_job(b, job)) {
    buckets_buf_free(&res);
    return job_err(e, "InternalError", 500, true, "batch job queue is currently full please try again later");
  }
  buckets_buf_append(out, res.data, res.len);
  buckets_buf_free(&res);
  return true;
}

void buckets_batch_cancel(buckets_batch *b, const char *id, bool broadcast) {
  pthread_mutex_lock(&b->mu);
  for (run *r = b->running; r; r = r->next)
    if (r->job.id && strcmp(r->job.id, id) == 0) atomic_store(&r->cancel, true);
  for (run **p = &b->queue; *p;) { /* never started */
    run *r = *p;
    if (r->job.id && strcmp(r->job.id, id) == 0) {
      *p = r->next;
      b->nqueued--;
      run_free(r);
    } else {
      p = &r->next;
    }
  }
  b->queue_tail = NULL;
  for (run *r = b->queue; r; r = r->next) b->queue_tail = r;
  pthread_mutex_unlock(&b->mu);
  if (broadcast && b->s->peers) buckets_peer_notify_iam(b->s->peers, "batch-cancel", id);
  buckets_buf path = BUCKETS_BUF_INIT;
  job_path(id, &path);
  if (broadcast) buckets_sysconfig_delete(b->s->layer, path.data);
  buckets_buf_free(&path);
}

static bool load_job(buckets_batch *b, const char *id, buckets_batch_job *out) {
  buckets_buf path = BUCKETS_BUF_INIT, data = BUCKETS_BUF_INIT;
  job_path(id, &path);
  bool ok = buckets_sysconfig_read(b->s->layer, path.data, &data, NULL) == BUCKETS_OBJ_OK &&
            buckets_batch_job_from_msgp(data.data, data.len, out);
  buckets_buf_free(&path);
  buckets_buf_free(&data);
  return ok;
}

void buckets_batch_list(buckets_batch *b, const char *type, buckets_buf *out) {
  char **names = NULL;
  size_t n = 0;
  buckets_sysconfig_list(b->s->layer, BUCKETS_BATCH_PREFIX "/", false, &names, &n);
  size_t count = 0;
  buckets_buf_append_c(out, "{\"jobs\":");
  for (size_t i = 0; i < n; i++) {
    if (strncmp(names[i], "reports/", 8) == 0 || strchr(names[i], '/')) continue;
    buckets_batch_job j;
    if (!load_job(b, names[i], &j)) continue;
    if (!type || !*type || strcmp(type, buckets_batch_job_type(&j)) == 0) {
      buckets_buf_append_c(out, count++ ? "," : "[");
      result_json(&j, true, out);
    }
    buckets_batch_job_free(&j);
  }
  buckets_buf_append_c(out, count ? "]}" : "null}");
  buckets_sysconfig_names_free(names, n);
}

bool buckets_batch_status(buckets_batch *b, const char *id, buckets_buf *out, buckets_batch_err *e) {
  const char *type = NULL;
  const char *dash = strchr(id, '-');
  if (dash && dash > id) {
    size_t n = (size_t)(dash - id);
    if (n == 9 && strncmp(id, "replicate", 9) == 0) type = "replicate";
    else if (n == 9 && strncmp(id, "keyrotate", 9) == 0) type = "keyrotate";
    else if (n == 6 && strncmp(id, "expire", 6) == 0) type = "expire";
    else {
      job_err(e, "InternalError", 500, true, "job ID format unrecognized");
      return true;
    }
  }
  if (!type) {
    job_err(e, "InternalError", 500, true, "unknown job type");
    return true;
  }
  buckets_buf path = BUCKETS_BUF_INIT, data = BUCKETS_BUF_INIT;
  report_path(id, type, &path);
  buckets_obj_err err = buckets_sysconfig_read(b->s->layer, path.data, &data, NULL);
  buckets_buf_free(&path);
  if (err) {
    buckets_buf_free(&data);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY) return false;
    job_err(e, "InternalError", 500, true, "%s", buckets_obj_strerror(err));
    return true;
  }
  buckets_batch_info ri;
  char derr[256];
  bool ok = buckets_batch_info_decode(buckets_batch_report_name(type), data.data, data.len, &ri, derr, sizeof(derr));
  buckets_buf_free(&data);
  if (!ok) {
    job_err(e, "InternalError", 500, true, "%s", derr);
    return true;
  }
  buckets_buf_append_c(out, "{\"LastMetric\":");
  buckets_batch_info_metric_json(&ri, out);
  buckets_buf_append_c(out, "}");
  buckets_batch_info_free(&ri);
  e->status = 0;
  return true;
}

bool buckets_batch_describe(buckets_batch *b, const char *id, buckets_buf *out) {
  buckets_batch_job j;
  if (!load_job(b, id, &j)) return false;
  buckets_batch_job_redact(&j);
  buckets_batch_job_yaml(&j, out);
  buckets_batch_job_free(&j);
  return true;
}

void buckets_batch_metrics_json(buckets_batch *b, const char *id, buckets_buf *out) {
  pthread_mutex_lock(&b->mu);
  size_t k = 0;
  buckets_buf_append_c(out, "{");
  for (size_t i = 0; i < b->nmetrics; i++) {
    const buckets_batch_info *ri = &b->metrics[i];
    if (id && *id && strcmp(ri->job_id, id) != 0) continue;
    if (k++) buckets_buf_append_c(out, ",");
    buckets_json_go_string(out, ri->job_id, strlen(ri->job_id));
    buckets_buf_append_c(out, ":");
    buckets_batch_info_metric_json(ri, out);
  }
  buckets_buf_append_c(out, "}");
  pthread_mutex_unlock(&b->mu);
}

size_t buckets_batch_metrics(buckets_batch *b, buckets_batch_metric **out) {
  pthread_mutex_lock(&b->mu);
  *out = buckets_xcalloc(b->nmetrics + 1, sizeof(**out));
  for (size_t i = 0; i < b->nmetrics; i++) {
    const buckets_batch_info *ri = &b->metrics[i];
    buckets_batch_metric *m = &(*out)[i];
    snprintf(m->type, sizeof(m->type), "%s", ri->job_type);
    snprintf(m->bucket, sizeof(m->bucket), "%s", ri->bucket ? ri->bucket : "");
    snprintf(m->id, sizeof(m->id), "%s", ri->job_id);
    m->objects = (double)ri->objects;
    m->failed = (double)ri->objects_failed;
  }
  size_t n = b->nmetrics;
  pthread_mutex_unlock(&b->mu);
  return n;
}

/* ---- background: resume, and the three-day cleanups ------------------------------------------------------------------ */

static bool bg_sleep(buckets_batch *b, int64_t ns) {
  pthread_mutex_lock(&b->mu);
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  int64_t t = (int64_t)until.tv_sec * 1000000000LL + until.tv_nsec + ns;
  until.tv_sec = t / 1000000000LL;
  until.tv_nsec = t % 1000000000LL;
  while (!b->stop) {
    if (pthread_cond_timedwait(&b->cv, &b->mu, &until) != 0) break;
  }
  bool go = !b->stop;
  pthread_mutex_unlock(&b->mu);
  return go;
}

/* resume: the jobs this node started and did not finish */
static void resume(buckets_batch *b) {
  char **names = NULL;
  size_t n = 0;
  buckets_sysconfig_list(b->s->layer, BUCKETS_BATCH_PREFIX "/", false, &names, &n);
  int self = local_index(b->s);
  for (size_t i = 0; i < n && !b->stop; i++) {
    if (strncmp(names[i], "reports/", 8) == 0 || strchr(names[i], '/')) continue;
    buckets_batch_job j;
    if (!load_job(b, names[i], &j)) continue;
    int node = token_node(j.id ? j.id : "");
    if (node > -1 && node != self) {
      buckets_batch_job_free(&j);
      continue;
    }
    pthread_mutex_lock(&b->mu);
    bool known = false;
    for (run *r = b->running; r && !known; r = r->next) known = r->job.id && j.id && strcmp(r->job.id, j.id) == 0;
    pthread_mutex_unlock(&b->mu);
    if (!known && !queue_job(b, &j)) buckets_log_warn("batch: cannot resume %s", names[i]);
    buckets_batch_job_free(&j);
  }
  buckets_sysconfig_names_free(names, n);
}

/* cleanupReports and purgeJobMetrics: finished jobs older than three days */
static void cleanup(buckets_batch *b) {
  char **names = NULL;
  size_t n = 0;
  int64_t now = now_ns();
  buckets_sysconfig_list(b->s->layer, BUCKETS_BATCH_REPORTS_PREFIX "/", false, &names, &n);
  for (size_t i = 0; i < n && !b->stop; i++) {
    const char *slash = strrchr(names[i], '/');
    if (!slash) continue;
    buckets_buf path = BUCKETS_BUF_INIT, data = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "%s/%s", BUCKETS_BATCH_REPORTS_PREFIX, names[i]);
    buckets_batch_info ri;
    char err[256];
    if (buckets_sysconfig_read(b->s->layer, path.data, &data, NULL) == BUCKETS_OBJ_OK &&
        buckets_batch_info_decode(slash + 1, data.data, data.len, &ri, err, sizeof(err))) {
      if ((ri.complete || ri.failed) && now - time_ns(&ri.last_update) > OLD_JOBS_EXPIRATION_NS)
        buckets_sysconfig_delete(b->s->layer, path.data);
      buckets_batch_info_free(&ri);
    }
    buckets_buf_free(&path);
    buckets_buf_free(&data);
  }
  buckets_sysconfig_names_free(names, n);
  /* the metrics of old jobs, and their definitions */
  pthread_mutex_lock(&b->mu);
  char **old = buckets_xcalloc(b->nmetrics + 1, sizeof(char *));
  size_t nold = 0;
  for (size_t i = 0; i < b->nmetrics;) {
    buckets_batch_info *ri = &b->metrics[i];
    if ((ri->complete || ri->failed) && now - time_ns(&ri->last_update) > OLD_JOBS_EXPIRATION_NS) {
      old[nold++] = buckets_xstrdup(ri->job_id);
      buckets_batch_info_free(ri);
      memmove(ri, ri + 1, (b->nmetrics - i - 1) * sizeof(*ri));
      b->nmetrics--;
    } else {
      i++;
    }
  }
  pthread_mutex_unlock(&b->mu);
  for (size_t i = 0; i < nold; i++) {
    buckets_buf path = BUCKETS_BUF_INIT;
    job_path(old[i], &path);
    buckets_sysconfig_delete(b->s->layer, path.data);
    buckets_buf_free(&path);
    free(old[i]);
  }
  free(old);
}

/* batchJobMetrics.init: the reports of every job */
static void metrics_init(buckets_batch *b) {
  char **names = NULL;
  size_t n = 0;
  buckets_sysconfig_list(b->s->layer, BUCKETS_BATCH_REPORTS_PREFIX "/", false, &names, &n);
  for (size_t i = 0; i < n; i++) {
    const char *slash = strrchr(names[i], '/');
    if (!slash) continue;
    buckets_buf path = BUCKETS_BUF_INIT, data = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "%s/%s", BUCKETS_BATCH_REPORTS_PREFIX, names[i]);
    buckets_batch_info ri;
    char err[256];
    if (buckets_sysconfig_read(b->s->layer, path.data, &data, NULL) == BUCKETS_OBJ_OK &&
        buckets_batch_info_decode(slash + 1, data.data, data.len, &ri, err, sizeof(err)) && ri.job_id) {
      pthread_mutex_lock(&b->mu);
      b->metrics = buckets_xrealloc(b->metrics, (b->nmetrics + 1) * sizeof(*b->metrics));
      b->metrics[b->nmetrics++] = ri;
      pthread_mutex_unlock(&b->mu);
    }
    buckets_buf_free(&path);
    buckets_buf_free(&data);
  }
  buckets_sysconfig_names_free(names, n);
}

/* _BUCKETS_BATCH_RESUME_DELAY (MinIO waits up to an hour per drive) */
static int64_t resume_delay(void) {
  const char *v = getenv("_BUCKETS_BATCH_RESUME_DELAY");
  int64_t ns;
  if (v && buckets_go_duration_parse(v, &ns)) return ns;
  return (int64_t)(rnd01() * 5e9);
}

static void *bg_main(void *arg) {
  buckets_batch *b = arg;
  metrics_init(b);
  if (!bg_sleep(b, resume_delay())) return NULL;
  resume(b);
  while (bg_sleep(b, 6LL * 3600 * 1000000000LL)) cleanup(b);
  return NULL;
}

buckets_batch *buckets_batch_new(buckets_s3_server *s) {
  buckets_batch *b = buckets_xcalloc(1, sizeof(*b));
  b->s = s;
  pthread_mutex_init(&b->mu, NULL);
  pthread_cond_init(&b->cv, NULL);
  b->bg_started = pthread_create(&b->bg, NULL, bg_main, b) == 0;
  return b;
}

void buckets_batch_stop(buckets_batch *b) {
  if (!b) return;
  pthread_mutex_lock(&b->mu);
  b->stop = true;
  for (run *r = b->running; r; r = r->next) atomic_store(&r->cancel, true);
  pthread_cond_broadcast(&b->cv);
  while (b->nrunning) pthread_cond_wait(&b->cv, &b->mu);
  while (b->queue) {
    run *r = b->queue;
    b->queue = r->next;
    run_free(r);
  }
  b->queue_tail = NULL;
  b->nqueued = 0;
  pthread_mutex_unlock(&b->mu);
  if (b->bg_started) pthread_join(b->bg, NULL);
  b->bg_started = false;
}
