/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin speedtest / mc support perf object|drive: MinIO's object
 * speedtest (every node PUTs then GETs objects of a size with a concurrency
 * for a duration; with autotune the concurrency grows while GET throughput
 * does) and its drive speedtest (dperf on every formatted local drive).
 * Results stream as madmin.SpeedTestResult / DriveSpeedTestResult lines,
 * with MinIO's keepalives. Replaces ObjectSpeedTestHandler,
 * DriveSpeedtestHandler, cmd/speedtest.go and cmd/perf-tests.go. */
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "admin/jobstream.h"
#include "core/timefmt.h"
#include "core/yaml.h"
#include "core/uuid.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "storage/drive.h"

#define PERF_BUCKET "minio-perf-test-tmp-bucket" /* globalObjectPerfBucket */

/* humanize.IBytes */
static void humanize_ibytes(uint64_t v, char *out, size_t cap) {
  static const char *const sfx[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
  if (v < 10) {
    snprintf(out, cap, "%llu B", (unsigned long long)v);
    return;
  }
  int e = (int)floor(log((double)v) / log(1024.0));
  double val = floor((double)v / pow(1024.0, e) * 10 + 0.5) / 10;
  snprintf(out, cap, val < 10 ? "%.1f %s" : "%.0f %s", val, sfx[e]);
}

/* DeleteObject with DeletePrefix: everything under the prefix */
static void delete_prefix(buckets_objlayer *L, const char *bucket, const char *prefix) {
  for (int round = 0; round < 1000; round++) {
    buckets_obj_listing l;
    if (buckets_obj_list(L, bucket, prefix, NULL, NULL, 1000, &l) != BUCKETS_OBJ_OK) return;
    for (size_t i = 0; i < l.nobjects; i++) buckets_obj_delete(L, bucket, l.objects[i].name, NULL);
    bool more = l.nobjects > 0 && l.truncated;
    buckets_obj_list_free(&l);
    if (!more) return;
  }
}

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* ---- durations (madmin.TimeDurations) --------------------------------------------------------- */

typedef struct {
  int64_t *v;
  size_t n, cap;
} durs;

static void durs_add(durs *d, int64_t x) {
  if (d->n == d->cap) {
    d->cap = d->cap ? 2 * d->cap : 64;
    d->v = buckets_xrealloc(d->v, d->cap * sizeof(int64_t));
  }
  d->v[d->n++] = x;
}

static void durs_cat(durs *d, const durs *o) {
  for (size_t i = 0; i < o->n; i++) durs_add(d, o->v[i]);
}

static int cmp_i64(const void *a, const void *b) {
  int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
  return x < y ? -1 : x > y;
}

/* TimeDurations.Measure as madmin.Timings JSON */
static void timings_json(buckets_buf *b, durs *d) {
  int64_t avg = 0, p50 = 0, p75 = 0, p95 = 0, p99 = 0, p999 = 0, l5 = 0, s5 = 0, mn = 0, mx = 0, sd = 0;
  size_t n = d->n;
  if (n) {
    qsort(d->v, n, sizeof(int64_t), cmp_i64);
    int64_t total = 0;
    for (size_t i = 0; i < n; i++) total += d->v[i];
    avg = total / (int64_t)n;
#define P(p) d->v[(size_t)((double)n * (p) + 0.5) - 1]
    p50 = d->v[n / 2];
    p75 = P(0.75), p95 = P(0.95), p99 = P(0.99), p999 = P(0.999);
#undef P
    size_t from = (size_t)((double)n * 0.95 + 0.5);
    if (n - from <= 1) l5 = d->v[n - 1];
    else {
      int64_t t = 0;
      for (size_t i = from; i < n; i++) t += d->v[i];
      l5 = t / (int64_t)(n - from);
    }
    size_t to = (size_t)((double)n * 0.05 + 0.5);
    if (to <= 1) s5 = d->v[0];
    else {
      int64_t t = 0;
      for (size_t i = 0; i < to; i++) t += d->v[i];
      s5 = t / (int64_t)to;
    }
    mn = d->v[0], mx = d->v[n - 1];
    double s = 0;
    for (size_t i = 0; i < n; i++) s += pow((double)(avg - d->v[i]), 2);
    sd = (int64_t)sqrt(s / (double)n);
  }
  buckets_buf_appendf(b,
                      "{\"avg\":%lld,\"p50\":%lld,\"p75\":%lld,\"p95\":%lld,\"p99\":%lld,\"p999\":%lld,\"l5p\":%lld,"
                      "\"s5p\":%lld,\"max\":%lld,\"min\":%lld,\"sdev\":%lld,\"range\":%lld}",
                      (long long)avg, (long long)p50, (long long)p75, (long long)p95, (long long)p99, (long long)p999,
                      (long long)l5, (long long)s5, (long long)mx, (long long)mn, (long long)sd, (long long)(mx - mn));
}

/* ---- one node's speedtest (selfSpeedTest) ------------------------------------------------------ */

typedef struct {
  char endpoint[300];
  uint64_t uploads, downloads;
  durs up, down, ttfb;
  char error[512];
} node_result;

static void node_result_free(node_result *r) {
  free(r->up.v);
  free(r->down.v);
  free(r->ttfb.v);
}

typedef struct {
  buckets_objlayer *L;
  const char *bucket, *prefix;
  int64_t size, deadline;
  int index;
  uint64_t count;          /* objects written by this thread */
  pthread_mutex_t *mu;
  node_result *res;
  _Atomic bool *stop;
  const _Atomic bool *cancel;
} worker;

typedef struct {
  uint64_t state;
  int64_t left;
} rand_src;

/* randreader: pseudo-random bytes, fast */
static long rand_read(void *ud, void *buf, size_t n) {
  rand_src *r = ud;
  if (r->left <= 0) return 0;
  if ((int64_t)n > r->left) n = (size_t)r->left;
  uint8_t *p = buf;
  for (size_t i = 0; i < n; i += 8) {
    r->state ^= r->state << 13, r->state ^= r->state >> 7, r->state ^= r->state << 17;
    size_t k = n - i < 8 ? n - i : 8;
    memcpy(p + i, &r->state, k);
  }
  r->left -= (int64_t)n;
  return (long)n;
}

static bool stopped(worker *w) { return atomic_load(w->stop) || (w->cancel && atomic_load(w->cancel)); }

static void fail(worker *w, const char *msg) {
  pthread_mutex_lock(w->mu);
  if (!*w->res->error) snprintf(w->res->error, sizeof(w->res->error), "%s", msg);
  pthread_mutex_unlock(w->mu);
  atomic_store(w->stop, true);
}

static void *put_worker(void *arg) {
  worker *w = arg;
  buckets_put_opts po = {0};
  while (!stopped(w) && mono_ns() < w->deadline) {
    char name[512];
    snprintf(name, sizeof(name), "%s/%d/%llu", w->prefix, w->index, (unsigned long long)w->count);
    rand_src rs = {0x9e3779b97f4a7c15ULL ^ ((uint64_t)w->index << 32) ^ w->count ^ (uint64_t)mono_ns(), w->size};
    int64_t t0 = mono_ns();
    buckets_obj_err e = buckets_obj_put(w->L, w->bucket, name, rand_read, &rs, w->size, &po, NULL);
    if (e) {
      if (mono_ns() < w->deadline) fail(w, buckets_obj_strerror(e));
      break;
    }
    int64_t dt = mono_ns() - t0;
    w->count++;
    pthread_mutex_lock(w->mu);
    w->res->uploads += (uint64_t)w->size;
    durs_add(&w->res->up, dt);
    pthread_mutex_unlock(w->mu);
  }
  return NULL;
}

static void *get_worker(void *arg) {
  worker *w = arg;
  if (!w->count) return NULL;
  char *buf = buckets_xmalloc(1 << 20);
  uint64_t j = 0;
  while (!stopped(w) && mono_ns() < w->deadline) {
    if (j == w->count) j = 0;
    char name[512];
    snprintf(name, sizeof(name), "%s/%d/%llu", w->prefix, w->index, (unsigned long long)j);
    int64_t t0 = mono_ns(), first = 0;
    buckets_obj_reader *r;
    buckets_obj_err e = buckets_obj_open(w->L, w->bucket, name, NULL, 0, INT64_MAX, &r, NULL);
    if (e == BUCKETS_OBJ_ERR_NO_SUCH_KEY) {
      j++;
      continue;
    }
    if (e) {
      if (mono_ns() < w->deadline) fail(w, buckets_obj_strerror(e));
      break;
    }
    uint64_t got = 0;
    long n;
    while ((n = buckets_obj_read(r, buf, 1 << 20)) > 0) {
      if (!first) first = mono_ns();
      got += (uint64_t)n;
    }
    buckets_obj_reader_free(r);
    if (n < 0) {
      if (mono_ns() < w->deadline) fail(w, "read failed");
      break;
    }
    int64_t now = mono_ns();
    pthread_mutex_lock(w->mu);
    w->res->downloads += got;
    durs_add(&w->res->down, now - t0);
    durs_add(&w->res->ttfb, now - (first ? first : now));
    pthread_mutex_unlock(w->mu);
    j++;
  }
  free(buf);
  return NULL;
}

static void self_speedtest(buckets_s3_server *s, int64_t size, int conc, int64_t dur_ns, const char *bucket,
                           const _Atomic bool *cancel, node_result *res) {
  if (conc < 1) conc = 1;
  char uuid[BUCKETS_UUID_STR_LEN + 1], prefix[64];
  buckets_uuid_v4(uuid);
  snprintf(prefix, sizeof(prefix), "speedtest/%s", uuid);
  pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
  _Atomic bool stop = false;
  worker *w = buckets_xcalloc((size_t)conc, sizeof(*w));
  pthread_t *th = buckets_xcalloc((size_t)conc, sizeof(*th));
  int64_t deadline = mono_ns() + dur_ns;
  for (int i = 0; i < conc; i++) {
    w[i] = (worker){.L = s->layer, .bucket = bucket, .prefix = prefix, .size = size, .deadline = deadline, .index = i,
                    .mu = &mu, .res = res, .stop = &stop, .cancel = cancel};
    pthread_create(&th[i], NULL, put_worker, &w[i]);
  }
  for (int i = 0; i < conc; i++) pthread_join(th[i], NULL);
  if (!*res->error) {
    deadline = mono_ns() + dur_ns;
    for (int i = 0; i < conc; i++) {
      w[i].deadline = deadline;
      pthread_create(&th[i], NULL, get_worker, &w[i]);
    }
    for (int i = 0; i < conc; i++) pthread_join(th[i], NULL);
  }
  free(th);
  free(w);
}

static void node_result_json(const node_result *r, buckets_buf *b) {
  buckets_buf_append_c(b, "{\"endpoint\":");
  buckets_json_go_string(b, r->endpoint, strlen(r->endpoint));
  buckets_buf_appendf(b, ",\"uploads\":%llu,\"downloads\":%llu,\"error\":", (unsigned long long)r->uploads,
                      (unsigned long long)r->downloads);
  buckets_json_go_string(b, r->error, strlen(r->error));
  const durs *lists[3] = {&r->up, &r->down, &r->ttfb};
  const char *keys[3] = {"up", "down", "ttfb"};
  for (int k = 0; k < 3; k++) {
    buckets_buf_appendf(b, ",\"%s\":[", keys[k]);
    for (size_t i = 0; i < lists[k]->n; i++) buckets_buf_appendf(b, "%s%lld", i ? "," : "", (long long)lists[k]->v[i]);
    buckets_buf_append_char(b, ']');
  }
  buckets_buf_append_char(b, '}');
}

static bool node_result_parse(const char *json, size_t len, node_result *r) {
  yyjson_doc *d = yyjson_read(json, len, 0);
  yyjson_val *o = yyjson_doc_get_root(d);
  if (!yyjson_is_obj(o)) {
    yyjson_doc_free(d);
    return false;
  }
  r->uploads = yyjson_get_uint(yyjson_obj_get(o, "uploads"));
  r->downloads = yyjson_get_uint(yyjson_obj_get(o, "downloads"));
  const char *e = yyjson_get_str(yyjson_obj_get(o, "error"));
  snprintf(r->error, sizeof(r->error), "%s", e ? e : "");
  durs *lists[3] = {&r->up, &r->down, &r->ttfb};
  const char *keys[3] = {"up", "down", "ttfb"};
  for (int k = 0; k < 3; k++) {
    size_t i, max;
    yyjson_val *v;
    yyjson_arr_foreach(yyjson_obj_get(o, keys[k]), i, max, v) durs_add(lists[k], yyjson_get_sint(v));
  }
  yyjson_doc_free(d);
  return true;
}

/* ---- the cluster's run (objectSpeedTest) --------------------------------------------------------- */

typedef struct {
  buckets_s3_server *s;
  int64_t size;
  int concurrent;
  int64_t dur_ns;
  bool autotune, noclear, made_bucket;
  char bucket[256];
} obj_job;

static const char *scheme_of(const buckets_s3_server *s) { return s->cluster && s->cluster->secure ? "https" : "http"; }

typedef struct {
  buckets_s3_server *s;
  char node[300];
  char target[1024];
  node_result *res;
} peer_call;

static void *peer_speedtest(void *arg) {
  peer_call *pc = arg;
  buckets_buf body = BUCKETS_BUF_INIT;
  int status = 0;
  if (!buckets_peer_call(pc->s->peers, pc->node, pc->target, &status, &body) || status != 200 ||
      !node_result_parse(body.data ? body.data : "", body.len, pc->res)) {
    if (!*pc->res->error) snprintf(pc->res->error, sizeof(pc->res->error), "%s", "peer not reachable");
  }
  buckets_buf_free(&body);
  return NULL;
}

static int by_endpoint(const void *a, const void *b) {
  return strcmp(((const node_result *)a)->endpoint, ((const node_result *)b)->endpoint);
}

/* NotificationSys.SpeedTest: every peer's and this node's results. */
static node_result *run_round(obj_job *o, int conc, const _Atomic bool *cancel, size_t *n) {
  buckets_s3_server *s = o->s;
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  node_result *r = buckets_xcalloc(np + 1, sizeof(*r));
  peer_call *calls = buckets_xcalloc(np ? np : 1, sizeof(*calls));
  pthread_t *th = buckets_xcalloc(np ? np : 1, sizeof(*th));
  for (size_t i = 0; i < np; i++) {
    calls[i].s = s;
    snprintf(calls[i].node, sizeof(calls[i].node), "%s:%d", buckets_http_client_host(pcs[i]),
             buckets_http_client_port(pcs[i]));
    snprintf(r[i].endpoint, sizeof(r[i].endpoint), "%s://%s", scheme_of(s), calls[i].node);
    snprintf(calls[i].target, sizeof(calls[i].target),
             BUCKETS_INTERNODE_PREFIX "peer/admin?op=speedtest&size=%lld&concurrent=%d&duration=%lld&bucket=%s",
             (long long)o->size, conc, (long long)o->dur_ns, o->bucket);
    calls[i].res = &r[i];
    pthread_create(&th[i], NULL, peer_speedtest, &calls[i]);
  }
  snprintf(r[np].endpoint, sizeof(r[np].endpoint), "%s://%s", scheme_of(s), s->cluster ? s->cluster->self : "");
  self_speedtest(s, o->size, conc, o->dur_ns, o->bucket, cancel, &r[np]);
  for (size_t i = 0; i < np; i++) pthread_join(th[i], NULL);
  free(th);
  free(calls);
  *n = np + 1;
  qsort(r, *n, sizeof(*r), by_endpoint);
  return r;
}

static size_t total_endpoints(const buckets_s3_server *s) { return s->cluster ? s->cluster->neps : 0; }

/* the result line (sendResult) */
static void result_json(obj_job *o, int conc, uint64_t best_get, uint64_t best_put, node_result *r, size_t n,
                        buckets_buf *b) {
  uint64_t secs = (uint64_t)(o->dur_ns / 1000000000LL);
  if (!secs) secs = 1;
  uint64_t size = (uint64_t)(o->size > 0 ? o->size : 1);
  durs up = {0}, down = {0}, ttfb = {0};
  buckets_buf putsrv = BUCKETS_BUF_INIT, getsrv = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < n; i++) {
    const char *err = r[i].error;
    char msg[256];
    if (r[i].downloads == 0 && o->concurrent == conc) {
      snprintf(msg, sizeof(msg), "no results for downloads upon first attempt, concurrency %d and duration ",
               o->concurrent);
      buckets_go_duration_string(o->dur_ns, msg + strlen(msg), sizeof(msg) - strlen(msg));
      err = msg;
    }
    if (r[i].uploads == 0 && o->concurrent == conc) {
      snprintf(msg, sizeof(msg), "no results for uploads upon first attempt, concurrency %d and duration ", o->concurrent);
      buckets_go_duration_string(o->dur_ns, msg + strlen(msg), sizeof(msg) - strlen(msg));
      err = msg;
    }
    buckets_buf *lists[2] = {&putsrv, &getsrv};
    uint64_t bytes[2] = {r[i].uploads, r[i].downloads};
    for (int k = 0; k < 2; k++) {
      buckets_buf_append_c(lists[k], lists[k]->len ? ",{\"endpoint\":" : "[{\"endpoint\":");
      buckets_json_go_string(lists[k], r[i].endpoint, strlen(r[i].endpoint));
      buckets_buf_appendf(lists[k], ",\"throughputPerSec\":%llu,\"objectsPerSec\":%llu,\"err\":",
                          (unsigned long long)(bytes[k] / secs), (unsigned long long)(bytes[k] / size / secs));
      buckets_json_go_string(lists[k], err, strlen(err));
      buckets_buf_append_char(lists[k], '}');
    }
    durs_cat(&up, &r[i].up);
    durs_cat(&down, &r[i].down);
    durs_cat(&ttfb, &r[i].ttfb);
  }
  buckets_buf_appendf(b, "{\"version\":\"%s\",\"servers\":%zu,\"disks\":%zu,\"size\":%lld,\"concurrent\":%d,", BUCKETS_VERSION,
                      o->s->cluster ? (o->s->cluster->nnodes ? o->s->cluster->nnodes : 1) : 1, total_endpoints(o->s),
                      (long long)o->size, conc);
  buckets_buf_appendf(b, "\"PUTStats\":{\"throughputPerSec\":%llu,\"objectsPerSec\":%llu,\"responseTime\":",
                      (unsigned long long)(best_put / secs), (unsigned long long)(best_put / size / secs));
  timings_json(b, &up);
  buckets_buf_append_c(b, ",\"ttfb\":");
  durs none = {0};
  timings_json(b, &none);
  buckets_buf_append_c(b, ",\"servers\":");
  if (putsrv.len) buckets_buf_append(b, putsrv.data, putsrv.len), buckets_buf_append_char(b, ']');
  else buckets_buf_append_c(b, "null");
  buckets_buf_appendf(b, "},\"GETStats\":{\"throughputPerSec\":%llu,\"objectsPerSec\":%llu,\"responseTime\":",
                      (unsigned long long)(best_get / secs), (unsigned long long)(best_get / size / secs));
  timings_json(b, &down);
  buckets_buf_append_c(b, ",\"ttfb\":");
  timings_json(b, &ttfb);
  buckets_buf_append_c(b, ",\"servers\":");
  if (getsrv.len) buckets_buf_append(b, getsrv.data, getsrv.len), buckets_buf_append_char(b, ']');
  else buckets_buf_append_c(b, "null");
  buckets_buf_append_c(b, "}}\n");
  free(up.v);
  free(down.v);
  free(ttfb.v);
  buckets_buf_free(&putsrv);
  buckets_buf_free(&getsrv);
}

/* madmin.SpeedTestResult{} */
static void empty_result(buckets_buf *b) {
  static const char zero[] = "{\"avg\":0,\"p50\":0,\"p75\":0,\"p95\":0,\"p99\":0,\"p999\":0,\"l5p\":0,\"s5p\":0,\"max\":0,"
                             "\"min\":0,\"sdev\":0,\"range\":0}";
  buckets_buf_appendf(b,
                      "{\"version\":\"\",\"servers\":0,\"disks\":0,\"size\":0,\"concurrent\":0,\"PUTStats\":{"
                      "\"throughputPerSec\":0,\"objectsPerSec\":0,\"responseTime\":%s,\"ttfb\":%s,\"servers\":null},"
                      "\"GETStats\":{\"throughputPerSec\":0,\"objectsPerSec\":0,\"responseTime\":%s,\"ttfb\":%s,"
                      "\"servers\":null}}\n",
                      zero, zero, zero, zero);
}

static void results_free(node_result *r, size_t n) {
  for (size_t i = 0; i < n; i++) node_result_free(&r[i]);
  free(r);
}

static _Atomic bool g_never_cancel;

static void obj_job_run(buckets_jobstream *j, void *ud) {
  obj_job *o = ud;
  buckets_s3_server *s = o->s;
  int conc = o->concurrent;
  if (o->autotune) {
    size_t neps = total_endpoints(s);
    if (neps && neps < (size_t)conc) conc = (int)neps;
    /* the fewest local drives in any pool */
    for (size_t p = 0; s->cluster && p < (s->layer ? s->layer->npools : 0); p++) {
      int local = 0;
      for (size_t i = 0; i < s->cluster->neps; i++) local += s->cluster->eps[i].pool == p && s->cluster->eps[i].local;
      if (local < conc) conc = local;
    }
    if (conc < 4) conc = 4;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0 && ncpu < conc) conc = (int)ncpu;
  }
  uint64_t best_get = 0, best_put = 0;
  node_result *best = NULL;
  size_t nbest = 0;
  buckets_buf line = BUCKETS_BUF_INIT;
  for (;;) {
    if (buckets_jobstream_cancelled(j)) break;
    size_t n;
    node_result *r = run_round(o, conc, &g_never_cancel, &n);
    uint64_t put = 0, get = 0;
    for (size_t i = 0; i < n; i++) put += r[i].uploads, get += r[i].downloads;
    bool send_and_stop = false;
    if (get < best_get) {
      if (put > best_put) {
        results_free(best, nbest);
        best = r, nbest = n, r = NULL;
        best_put = put;
        best_get = get;
      }
      send_and_stop = true;
    } else {
      bool brk = get ? (double)(get - best_get) / (double)get < 0.025 : true;
      best_get = get, best_put = put;
      results_free(best, nbest);
      best = r, nbest = n, r = NULL;
      if (brk) send_and_stop = true;
      else {
        for (size_t i = 0; i < nbest && !send_and_stop; i++) send_and_stop = *best[i].error;
        if (!send_and_stop && !o->autotune) send_and_stop = true;
      }
    }
    if (r) results_free(r, n);
    buckets_buf_reset(&line);
    result_json(o, conc, best_get, best_put, best, nbest, &line);
    buckets_jobstream_emit(j, line.data, line.len);
    buckets_jobstream_set_keepalive(j, line.data, line.len); /* the last result, repeated */
    if (send_and_stop) break;
    conc += (conc + 1) / 2;
  }
  buckets_buf_free(&line);
  results_free(best, nbest);
  /* cleanup: the objects written, the bucket if made here; then thaw */
  if (!o->noclear) {
    delete_prefix(s->layer, o->bucket, "speedtest/");
    if (o->made_bucket) buckets_obj_delete_bucket_force(s->layer, o->bucket);
  }
  buckets_s3_service(s, "unfreeze", true);
}

/* strconv.Atoi, or the default */
static long long atoi_or(const char *s, long long dflt) {
  if (!s || !*s) return dflt;
  char *end;
  errno = 0;
  long long v = strtoll(s, &end, 10);
  return *end || errno ? dflt : v;
}

void buckets_admin_object_speedtest(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:OBDInfo")) return;
  buckets_s3_server *s = c->s;
  obj_job *o = buckets_xcalloc(1, sizeof(*o));
  o->s = s;
  o->size = atoi_or(buckets_query_get(&c->q, "size"), 64LL << 20);
  o->concurrent = (int)atoi_or(buckets_query_get(&c->q, "concurrent"), 32);
  int64_t dur = 0;
  const char *ds = buckets_query_get(&c->q, "duration");
  if (!ds || !buckets_go_duration_parse(ds, &dur)) dur = 10000000000LL;
  o->dur_ns = dur;
  const char *at = buckets_query_get(&c->q, "autotune"), *nc = buckets_query_get(&c->q, "noclear");
  o->autotune = at && strcmp(at, "true") == 0;
  o->noclear = nc && strcmp(nc, "true") == 0;
  /* validateObjPerfOptions: enough usable free space */
  uint64_t free_b = 0;
  for (size_t i = 0; s->layer && i < s->layer->nall; i++) {
    uint64_t t = 0, f = 0;
    if (s->layer->all[i] && buckets_drive_disk_info(s->layer->all[i], &t, &f) == BUCKETS_DRIVE_OK) free_b += f;
  }
  buckets_drive_place pl;
  buckets_objlayer_place(s->layer, 0, &pl);
  uint64_t usable = pl.set_size ? free_b / pl.set_size * (pl.set_size - (size_t)pl.parity) : free_b;
  uint64_t need = (uint64_t)o->concurrent * (uint64_t)o->size;
  if (usable < need) {
    char msg[256], a[32], b[32];
    humanize_ibytes(need, a, sizeof(a));
    humanize_ibytes(usable, b, sizeof(b));
    snprintf(msg, sizeof(msg), "not enough usable space available to perform speedtest - expected %s, got %s", a, b);
    buckets_admin_custom_error(c, 507, "XMinioSpeedtestInsufficientCapacity", msg);
    free(o);
    return;
  }
  if (o->autotune && usable < (uint64_t)(o->concurrent + (o->concurrent + 1) / 2) * (uint64_t)o->size) o->autotune = false;
  const char *cb = buckets_query_get(&c->q, "bucket");
  if (cb && *cb) {
    snprintf(o->bucket, sizeof(o->bucket), "%s", cb);
  } else {
    snprintf(o->bucket, sizeof(o->bucket), "%s", PERF_BUCKET);
    buckets_obj_err e = buckets_obj_make_bucket(s->layer, o->bucket);
    if (e && e != BUCKETS_OBJ_ERR_BUCKET_EXISTS) {
      buckets_admin_error(c, buckets_s3_obj_error(e));
      free(o);
      return;
    }
    o->made_bucket = !e;
  }
  buckets_s3_service(s, "freeze", true); /* ServiceFreeze on every node; the job thaws them */
  /* json.NewEncoder on the response with no Content-Type: Go sniffs text */
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
  buckets_buf ka = BUCKETS_BUF_INIT;
  empty_result(&ka);
  buckets_buf_append_char(&ka, '\0');
  buckets_jobstream_start(c->resp, obj_job_run, o, free, 500, ka.data);
  buckets_buf_free(&ka);
}

/* ---- drive speedtest (dperf) ----------------------------------------------------------------------- */

typedef struct {
  buckets_s3_server *s;
  bool serial;
  uint64_t block, file;
} drive_job;

#ifdef __linux__
/* one dperf file: written with O_DIRECT from random data, then read back */
static const char *dperf_file(const char *path, uint64_t block, uint64_t fsize, uint64_t *wt, uint64_t *rt) {
  static __thread char err[256];
  void *buf = NULL;
  if (posix_memalign(&buf, 4096, block ? block : 4096)) return "out of memory";
  rand_src rs = {0x2545F4914F6CDD1DULL ^ (uint64_t)mono_ns(), (int64_t)block};
  rand_read(&rs, buf, block);
  int64_t t0 = mono_ns();
  int fd = open(path, O_DIRECT | O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    snprintf(err, sizeof(err), "open %s: %s", path, strerror(errno));
    free(buf);
    return err;
  }
  uint64_t done = 0;
  while (done < fsize) {
    size_t n = fsize - done < block ? (size_t)(fsize - done) : (size_t)block;
    if (n % 4096) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_DIRECT);
    ssize_t w = write(fd, buf, n);
    if (w != (ssize_t)n) {
      snprintf(err, sizeof(err), "write %s: %s", path, w < 0 ? strerror(errno) : "short write");
      close(fd);
      free(buf);
      return err;
    }
    done += n;
  }
  fdatasync(fd);
  close(fd);
  *wt = (uint64_t)((double)fsize / (double)(mono_ns() - t0) * 1e9);
  t0 = mono_ns();
  fd = open(path, O_DIRECT | O_RDONLY);
  if (fd < 0) {
    snprintf(err, sizeof(err), "open %s: %s", path, strerror(errno));
    free(buf);
    return err;
  }
  done = 0;
  while (done < fsize) {
    size_t n = fsize - done < block ? (size_t)(fsize - done) : (size_t)block;
    if (n % 4096) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_DIRECT);
    ssize_t r = read(fd, buf, n);
    if (r <= 0) break;
    done += (uint64_t)r;
  }
  close(fd);
  free(buf);
  if (done != fsize) {
    snprintf(err, sizeof(err), "Expected read %llu, read %llu", (unsigned long long)fsize, (unsigned long long)done);
    return err;
  }
  *rt = (uint64_t)((double)fsize / (double)(mono_ns() - t0) * 1e9);
  return NULL;
}

typedef struct {
  const char *dir;
  int idx;
  uint64_t block, file, wt, rt;
  const char *err;
} dperf_io;

static void *dperf_io_run(void *arg) {
  dperf_io *io = arg;
  char p[4096];
  snprintf(p, sizeof(p), "%s/.writable-check.tmp-%d", io->dir, io->idx);
  io->err = dperf_file(p, io->block, io->file, &io->wt, &io->rt);
  return NULL;
}
#endif

/* runTests for one drive: (IOPerDrive) files at once; throughputs summed */
static void dperf_drive(const char *tmp, int ios, uint64_t block, uint64_t fsize, uint64_t *wt, uint64_t *rt, char *err,
                        size_t errcap) {
  *wt = *rt = 0;
#ifdef __linux__
  char dir[4096];
  char uuid[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(uuid);
  snprintf(dir, sizeof(dir), "%s/%s", tmp, uuid);
  mkdir(tmp, 0755);
  mkdir(dir, 0755);
  dperf_io *io = buckets_xcalloc((size_t)(ios ? ios : 1), sizeof(*io));
  pthread_t *th = buckets_xcalloc((size_t)(ios ? ios : 1), sizeof(*th));
  for (int i = 0; i < ios; i++) {
    io[i] = (dperf_io){.dir = dir, .idx = i, .block = block, .file = fsize};
    pthread_create(&th[i], NULL, dperf_io_run, &io[i]);
  }
  for (int i = 0; i < ios; i++) pthread_join(th[i], NULL);
  for (int i = 0; i < ios; i++) {
    if (io[i].err && !*err) snprintf(err, errcap, "%s", io[i].err);
    *wt += io[i].wt, *rt += io[i].rt;
  }
  if (*err) *wt = *rt = 0;
  for (int i = 0; i < ios; i++) {
    char p[4096];
    snprintf(p, sizeof(p), "%s/.writable-check.tmp-%d", dir, i);
    unlink(p);
  }
  rmdir(dir);
  free(io);
  free(th);
#else
  (void)tmp, (void)ios, (void)block, (void)fsize;
  snprintf(err, errcap, "%s", "not implemented"); /* dperf runs on Linux only */
#endif
}

/* driveSpeedTest: this node's result as JSON */
static void drive_speedtest(buckets_s3_server *s, bool serial, uint64_t block, uint64_t fsize, buckets_buf *out) {
  const buckets_cluster_info *ci = s->cluster;
  buckets_buf_appendf(out, "{\"version\":\"%s\",\"endpoint\":\"%s://%s\"", BUCKETS_VERSION, scheme_of(s),
                      ci ? ci->self : "");
  buckets_buf perfs = BUCKETS_BUF_INIT, ignored = BUCKETS_BUF_INIT;
  for (size_t i = 0; ci && i < ci->neps; i++) {
    const buckets_info_endpoint *ep = &ci->eps[i];
    if (!ep->local) continue;
    char fmt[4096], tmp[4096];
    snprintf(fmt, sizeof(fmt), "%s/%s/format.json", ep->path, BUCKETS_META_BUCKET);
    struct stat st;
    buckets_buf *dst = &perfs;
    uint64_t wt = 0, rt = 0;
    char err[512] = "";
    if (lstat(fmt, &st) != 0) {
      dst = &ignored;
      snprintf(err, sizeof(err), "%s", "drive is faulty"); /* errFaultyDisk */
    } else {
      snprintf(tmp, sizeof(tmp), "%s/%s/tmp", ep->path, BUCKETS_META_BUCKET);
      dperf_drive(tmp, serial ? 0 : 4, block, fsize, &wt, &rt, err, sizeof(err));
    }
    if (dst->len) buckets_buf_append_char(dst, ',');
    buckets_buf_append_c(dst, "{\"path\":");
    buckets_json_go_string(dst, ep->path, strlen(ep->path));
    buckets_buf_appendf(dst, ",\"readThroughput\":%llu,\"writeThroughput\":%llu", (unsigned long long)rt,
                        (unsigned long long)wt);
    if (*err) {
      buckets_buf_append_c(dst, ",\"error\":");
      buckets_json_go_string(dst, err, strlen(err));
    }
    buckets_buf_append_char(dst, '}');
  }
  if (perfs.len || ignored.len) {
    buckets_buf_append_c(out, ",\"drivePerf\":[");
    if (perfs.len) buckets_buf_append(out, perfs.data, perfs.len);
    if (perfs.len && ignored.len) buckets_buf_append_char(out, ',');
    if (ignored.len) buckets_buf_append(out, ignored.data, ignored.len);
    buckets_buf_append_char(out, ']');
  }
  buckets_buf_append_c(out, "}\n");
  buckets_buf_free(&perfs);
  buckets_buf_free(&ignored);
}

typedef struct {
  drive_job *dj;
  char node[300], target[512];
  buckets_buf out;
} drive_peer;

static void *drive_peer_run(void *arg) {
  drive_peer *p = arg;
  int status = 0;
  buckets_buf body = BUCKETS_BUF_INIT;
  bool ok = buckets_peer_call(p->dj->s->peers, p->node, p->target, &status, &body) && status == 200;
  /* the peer's line, without the whitespace it kept the connection with */
  const char *j = body.data ? body.data : "";
  size_t n = body.len;
  while (n && (*j == ' ' || *j == '\n')) j++, n--;
  if (ok && n) buckets_buf_append(&p->out, j, n);
  else buckets_buf_appendf(&p->out, "{\"version\":\"\",\"endpoint\":\"\",\"string\":\"peer %s not reachable\"}\n", p->node);
  buckets_buf_free(&body);
  return NULL;
}

static void drive_job_run(buckets_jobstream *j, void *ud) {
  drive_job *dj = ud;
  buckets_s3_server *s = dj->s;
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  drive_peer *peers = buckets_xcalloc(np ? np : 1, sizeof(*peers));
  pthread_t *th = buckets_xcalloc(np ? np : 1, sizeof(*th));
  for (size_t i = 0; i < np; i++) {
    peers[i].dj = dj;
    snprintf(peers[i].node, sizeof(peers[i].node), "%s:%d", buckets_http_client_host(pcs[i]),
             buckets_http_client_port(pcs[i]));
    snprintf(peers[i].target, sizeof(peers[i].target),
             BUCKETS_INTERNODE_PREFIX "peer/admin?op=drivespeedtest&serial=%s&blocksize=%llu&filesize=%llu",
             dj->serial ? "true" : "false", (unsigned long long)dj->block, (unsigned long long)dj->file);
    pthread_create(&th[i], NULL, drive_peer_run, &peers[i]);
  }
  buckets_buf local = BUCKETS_BUF_INIT;
  drive_speedtest(s, dj->serial, dj->block, dj->file, &local);
  buckets_jobstream_emit(j, local.data, local.len);
  buckets_buf_free(&local);
  for (size_t i = 0; i < np; i++) {
    pthread_join(th[i], NULL);
    buckets_jobstream_emit(j, peers[i].out.data, peers[i].out.len);
    buckets_buf_free(&peers[i].out);
  }
  free(peers);
  free(th);
  buckets_s3_service(s, "unfreeze", true);
}

static uint64_t parse_u64_or(const char *s, uint64_t dflt) {
  if (!s || !*s || *s == '-' || *s == '+') return dflt;
  char *end;
  errno = 0;
  unsigned long long v = strtoull(s, &end, 10);
  return *end || errno ? dflt : v;
}

void buckets_admin_drive_speedtest(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:OBDInfo")) return;
  drive_job *dj = buckets_xcalloc(1, sizeof(*dj));
  dj->s = c->s;
  const char *se = buckets_query_get(&c->q, "serial");
  dj->serial = se && strcmp(se, "true") == 0;
  dj->block = parse_u64_or(buckets_query_get(&c->q, "blocksize"), 4ULL << 20);
  dj->file = parse_u64_or(buckets_query_get(&c->q, "filesize"), 1ULL << 30);
  buckets_s3_service(c->s, "freeze", true);
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
  /* madmin.DriveSpeedTestResult{} while waiting */
  buckets_jobstream_start(c->resp, drive_job_run, dj, free, 500, "{\"version\":\"\",\"endpoint\":\"\"}\n");
}

/* ---- the peer side ------------------------------------------------------------------------------- */

typedef struct {
  buckets_s3_server *s;
  bool drive;
  int64_t size, dur_ns;
  int conc;
  bool serial;
  uint64_t block, file;
  char bucket[256];
} peer_job;

static void peer_job_run(buckets_jobstream *j, void *ud) {
  peer_job *p = ud;
  buckets_buf out = BUCKETS_BUF_INIT;
  if (p->drive) {
    drive_speedtest(p->s, p->serial, p->block, p->file, &out);
  } else {
    node_result r;
    memset(&r, 0, sizeof(r));
    self_speedtest(p->s, p->size, p->conc, p->dur_ns, p->bucket, &g_never_cancel, &r);
    node_result_json(&r, &out);
    node_result_free(&r);
  }
  buckets_jobstream_emit(j, out.data, out.len);
  buckets_buf_free(&out);
}

bool buckets_admin_perf_peer(buckets_s3_server *s, const char *op, const buckets_query *q, buckets_http_response *resp) {
  peer_job *p = buckets_xcalloc(1, sizeof(*p));
  p->s = s;
  if (strcmp(op, "speedtest") == 0) {
    p->size = atoi_or(buckets_query_get(q, "size"), 64LL << 20);
    p->conc = (int)atoi_or(buckets_query_get(q, "concurrent"), 32);
    p->dur_ns = atoi_or(buckets_query_get(q, "duration"), 10000000000LL);
    const char *b = buckets_query_get(q, "bucket");
    snprintf(p->bucket, sizeof(p->bucket), "%s", b && *b ? b : PERF_BUCKET);
  } else if (strcmp(op, "drivespeedtest") == 0) {
    p->drive = true;
    const char *se = buckets_query_get(q, "serial");
    p->serial = se && strcmp(se, "true") == 0;
    p->block = parse_u64_or(buckets_query_get(q, "blocksize"), 4ULL << 20);
    p->file = parse_u64_or(buckets_query_get(q, "filesize"), 1ULL << 30);
  } else {
    free(p);
    return false;
  }
  /* whitespace keeps the internode connection alive until the JSON is ready */
  buckets_jobstream_start(resp, peer_job_run, p, free, 1000, " ");
  return true;
}
