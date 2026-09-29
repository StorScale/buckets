/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Replication statistics since startup (MinIO's ReplicationStats,
 * bucket-stats.go / bucket-replication-stats.go / last-minute.go): per
 * target sent and failed counts, upload latency by object size, incoming
 * replicas, queue depth, workers, transfer rates and proxied requests. They
 * back GetBucketReplicationMetrics(V2) (`mc replicate status`) and the
 * replication metrics. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/common.h"
#include "notify/event.h"
#include "s3/replicate.h"

#define NSIZES 6

typedef struct {
  int64_t total, size, n;
} acc;

/* lastMinuteLatency */
typedef struct {
  acc totals[60];
  int64_t last_sec;
} lastmin;

typedef struct {
  int64_t count, bytes;
} cb;

/* A window of per-second (or per-minute) counters. */
typedef struct {
  cb slot[60];
  int64_t last; /* in the window's unit */
} window;

typedef struct {
  double curr, avg, peak;
  int64_t n;
  int64_t last_ns; /* when curr was last computed */
  double acc_bytes; /* bytes in the current measuring second */
} xfer;

typedef struct {
  char *arn;
  int64_t repl_size, repl_count;
  window fail_min; /* per second, last minute */
  window fail_hour; /* per minute, last hour */
  cb fail_total;
  lastmin lat[NSIZES];
  xfer lrg, sml;
} tstat;

typedef struct {
  char *bucket;
  tstat *t;
  size_t n;
  int64_t replica_size, replica_count;
  int64_t q_count, q_bytes; /* now */
  int64_t q_max_count, q_max_bytes;
  double q_avg_count, q_avg_bytes;
  uint64_t proxy[5][2]; /* get, head, put tagging, get tagging, remove tagging x total, failed */
} bstat;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static bstat *g_b;
static size_t g_nb;
static int64_t g_boot_sec;
/* node-wide */
static int64_t g_workers_curr, g_workers_max;
static double g_workers_avg;
static xfer g_lrg, g_sml;
static int64_t g_mrf_dropped_count, g_mrf_dropped_bytes, g_mrf_failed_last5;

static int64_t now_sec(void) { return (int64_t)time(NULL); }

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

void buckets_repl_stats_init(void) {
  pthread_mutex_lock(&g_mu);
  if (!g_boot_sec) g_boot_sec = now_sec();
  pthread_mutex_unlock(&g_mu);
}

static bstat *bucket_of(const char *bucket) {
  for (size_t i = 0; i < g_nb; i++)
    if (strcmp(g_b[i].bucket, bucket) == 0) return &g_b[i];
  g_b = buckets_xrealloc(g_b, (g_nb + 1) * sizeof(*g_b));
  bstat *b = &g_b[g_nb++];
  memset(b, 0, sizeof(*b));
  b->bucket = buckets_xstrdup(bucket);
  return b;
}

static tstat *target_of(bstat *b, const char *arn) {
  for (size_t i = 0; i < b->n; i++)
    if (strcmp(b->t[i].arn, arn) == 0) return &b->t[i];
  b->t = buckets_xrealloc(b->t, (b->n + 1) * sizeof(*b->t));
  tstat *t = &b->t[b->n++];
  memset(t, 0, sizeof(*t));
  t->arn = buckets_xstrdup(arn);
  return t;
}

static void window_forward(window *w, int64_t now) {
  if (w->last >= now) return;
  if (now - w->last >= 60) {
    memset(w->slot, 0, sizeof(w->slot));
  } else {
    for (int64_t t = w->last + 1; t <= now; t++) w->slot[t % 60] = (cb){0, 0};
  }
  w->last = now;
}

static void window_add(window *w, int64_t now, int64_t bytes) {
  window_forward(w, now);
  w->slot[now % 60].count++;
  w->slot[now % 60].bytes += bytes;
}

static cb window_total(window *w, int64_t now) {
  window_forward(w, now);
  cb out = {0, 0};
  for (int i = 0; i < 60; i++) out.count += w->slot[i].count, out.bytes += w->slot[i].bytes;
  return out;
}

static void lastmin_forward(lastmin *l, int64_t now) {
  if (l->last_sec >= now) return;
  if (now - l->last_sec >= 60) memset(l->totals, 0, sizeof(l->totals));
  else
    for (int64_t t = l->last_sec + 1; t <= now; t++) l->totals[t % 60] = (acc){0, 0, 0};
  l->last_sec = now;
}

static int size_tag(int64_t size) {
  if (size < 1024) return 0;
  if (size < 1024 * 1024) return 1;
  if (size < 10 * 1024 * 1024) return 2;
  if (size < 100 * 1024 * 1024) return 3;
  if (size < 1024LL * 1024 * 1024) return 4;
  return 5;
}

static const char *const k_size_tags[NSIZES] = {"LESS_THAN_1_KiB",   "LESS_THAN_1_MiB", "LESS_THAN_10_MiB",
                                                "LESS_THAN_100_MiB", "LESS_THAN_1_GiB", "GREATER_THAN_1_GiB"};

/* An exponentially weighted rate (MinIO's XferStats with its EWMA). */
static void xfer_add(xfer *x, int64_t bytes, int64_t dur_ns) {
  if (dur_ns <= 0) dur_ns = 1;
  double rate = (double)bytes / ((double)dur_ns / 1e9);
  x->curr = rate;
  x->avg = x->n ? 0.9 * x->avg + 0.1 * rate : rate;
  if (rate > x->peak) x->peak = rate;
  x->n++;
  x->last_ns = mono_ns();
}

void buckets_repl_stats_update(const char *bucket, const char *arn, bool completed, bool failed, int64_t size,
                               int64_t dur_ns) {
  if (!completed && !failed) return;
  pthread_mutex_lock(&g_mu);
  tstat *t = target_of(bucket_of(bucket), arn);
  int64_t now = now_sec();
  if (completed) {
    t->repl_size += size;
    t->repl_count++;
    if (dur_ns > 0) {
      lastmin *l = &t->lat[size_tag(size)];
      lastmin_forward(l, now);
      l->totals[now % 60].total += dur_ns;
      l->totals[now % 60].n++;
      l->totals[now % 60].size += size;
      bool large = size >= 128LL * 1024 * 1024;
      xfer_add(large ? &t->lrg : &t->sml, size, dur_ns);
      xfer_add(large ? &g_lrg : &g_sml, size, dur_ns);
    }
  } else {
    window_add(&t->fail_min, now, size);
    window_add(&t->fail_hour, now / 60, size);
    t->fail_total.count++;
    t->fail_total.bytes += size;
  }
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_replica(const char *bucket, int64_t size) {
  pthread_mutex_lock(&g_mu);
  bstat *b = bucket_of(bucket);
  b->replica_size += size;
  b->replica_count++;
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_queue(const char *bucket, int64_t size, int delta) {
  pthread_mutex_lock(&g_mu);
  bstat *b = bucket_of(bucket);
  b->q_count += delta;
  b->q_bytes += delta * size;
  if (b->q_count < 0) b->q_count = 0;
  if (b->q_bytes < 0) b->q_bytes = 0;
  if (b->q_count > b->q_max_count) b->q_max_count = b->q_count;
  if (b->q_bytes > b->q_max_bytes) b->q_max_bytes = b->q_bytes;
  b->q_avg_count = 0.9 * b->q_avg_count + 0.1 * (double)b->q_count;
  b->q_avg_bytes = 0.9 * b->q_avg_bytes + 0.1 * (double)b->q_bytes;
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_workers(int delta) {
  pthread_mutex_lock(&g_mu);
  g_workers_curr += delta;
  if (g_workers_curr < 0) g_workers_curr = 0;
  if (g_workers_curr > g_workers_max) g_workers_max = g_workers_curr;
  g_workers_avg = 0.9 * g_workers_avg + 0.1 * (double)g_workers_curr;
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_mrf_dropped(int64_t size) {
  pthread_mutex_lock(&g_mu);
  g_mrf_dropped_count++;
  g_mrf_dropped_bytes += size;
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_mrf_failed(int64_t n) {
  pthread_mutex_lock(&g_mu);
  g_mrf_failed_last5 = n;
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_proxy(const char *bucket, int api, bool failed) {
  if (api < 0 || api >= 5) return;
  pthread_mutex_lock(&g_mu);
  bstat *b = bucket_of(bucket);
  b->proxy[api][0]++;
  if (failed) b->proxy[api][1]++;
  pthread_mutex_unlock(&g_mu);
}

void buckets_repl_stats_delete_bucket(const char *bucket) {
  pthread_mutex_lock(&g_mu);
  for (size_t i = 0; i < g_nb; i++) {
    if (strcmp(g_b[i].bucket, bucket) != 0) continue;
    for (size_t k = 0; k < g_b[i].n; k++) free(g_b[i].t[k].arn);
    free(g_b[i].t);
    free(g_b[i].bucket);
    g_b[i] = g_b[--g_nb];
    break;
  }
  pthread_mutex_unlock(&g_mu);
}

/* ---- snapshots ---- */

bool buckets_repl_stats_get(const char *bucket, buckets_repl_bucket_stats *out) {
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&g_mu);
  bool found = false;
  int64_t now = now_sec();
  for (size_t i = 0; i < g_nb; i++) {
    bstat *b = &g_b[i];
    if (strcmp(b->bucket, bucket) != 0) continue;
    found = true;
    out->replica_size = b->replica_size;
    out->replica_count = b->replica_count;
    out->q_count = b->q_count, out->q_bytes = b->q_bytes;
    out->q_avg_count = b->q_avg_count, out->q_avg_bytes = b->q_avg_bytes;
    out->q_max_count = b->q_max_count, out->q_max_bytes = b->q_max_bytes;
    memcpy(out->proxy, b->proxy, sizeof(out->proxy));
    out->t = buckets_xcalloc(b->n + 1, sizeof(*out->t));
    out->n = b->n;
    for (size_t k = 0; k < b->n; k++) {
      tstat *t = &b->t[k];
      buckets_repl_target_stats *o = &out->t[k];
      snprintf(o->arn, sizeof(o->arn), "%s", t->arn);
      o->repl_size = t->repl_size;
      o->repl_count = t->repl_count;
      cb m = window_total(&t->fail_min, now), h = window_total(&t->fail_hour, now / 60);
      o->fail_min_count = m.count, o->fail_min_bytes = m.bytes;
      o->fail_hour_count = h.count, o->fail_hour_bytes = h.bytes;
      o->fail_total_count = t->fail_total.count, o->fail_total_bytes = t->fail_total.bytes;
      for (int s = 0; s < NSIZES; s++) {
        lastmin_forward(&t->lat[s], now);
        o->lat_last_sec[s] = t->lat[s].last_sec;
        for (int j = 0; j < 60; j++) {
          o->lat[s][j][0] = t->lat[s].totals[j].total;
          o->lat[s][j][1] = t->lat[s].totals[j].size;
          o->lat[s][j][2] = t->lat[s].totals[j].n;
        }
      }
      o->xfer[0][0] = t->lrg.curr, o->xfer[0][1] = t->lrg.avg, o->xfer[0][2] = t->lrg.peak;
      o->xfer[1][0] = t->sml.curr, o->xfer[1][1] = t->sml.avg, o->xfer[1][2] = t->sml.peak;
    }
  }
  pthread_mutex_unlock(&g_mu);
  return found;
}

void buckets_repl_bucket_stats_free(buckets_repl_bucket_stats *s) {
  free(s->t);
  memset(s, 0, sizeof(*s));
}

void buckets_repl_stats_node(buckets_repl_node_stats *out) {
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&g_mu);
  out->uptime = now_sec() - (g_boot_sec ? g_boot_sec : now_sec());
  out->workers_curr = g_workers_curr;
  out->workers_avg = g_workers_avg;
  out->workers_max = g_workers_max;
  out->xfer[0][0] = g_lrg.curr, out->xfer[0][1] = g_lrg.avg, out->xfer[0][2] = g_lrg.peak;
  out->xfer[1][0] = g_sml.curr, out->xfer[1][1] = g_sml.avg, out->xfer[1][2] = g_sml.peak;
  for (size_t i = 0; i < g_nb; i++) {
    out->q_count += g_b[i].q_count;
    out->q_bytes += g_b[i].q_bytes;
    out->q_avg_count += g_b[i].q_avg_count;
    out->q_avg_bytes += g_b[i].q_avg_bytes;
    out->q_max_count += g_b[i].q_max_count;
    out->q_max_bytes += g_b[i].q_max_bytes;
  }
  out->mrf_failed_last5 = g_mrf_failed_last5;
  out->mrf_dropped_count = g_mrf_dropped_count;
  out->mrf_dropped_bytes = g_mrf_dropped_bytes;
  pthread_mutex_unlock(&g_mu);
}

/* ---- JSON (GetBucketReplicationMetricsV2) ---- */

static void jcb(buckets_buf *b, const char *name, int64_t count, int64_t bytes) {
  buckets_buf_appendf(b, "\"%s\":{\"count\":%lld,\"bytes\":%lld}", name, (long long)count, (long long)bytes);
}

/* Go's strconv.FormatFloat(f, 'g', -1, 64) as encoding/json writes floats */
static void jfloat(buckets_buf *b, double v) {
  if (v == (double)(int64_t)v && v < 1e21 && v > -1e21) {
    buckets_buf_appendf(b, "%lld", (long long)v);
    return;
  }
  char s[64];
  for (int prec = 1; prec <= 17; prec++) {
    snprintf(s, sizeof(s), "%.*g", prec, v);
    if (strtod(s, NULL) == v) break;
  }
  buckets_buf_append_c(b, s);
}

static void jxfer(buckets_buf *b, const double x[3]) {
  buckets_buf_append_c(b, "{\"currRate\":");
  jfloat(b, x[0]);
  buckets_buf_append_c(b, ",\"avgRate\":");
  jfloat(b, x[1]);
  buckets_buf_append_c(b, ",\"peakRate\":");
  jfloat(b, x[2]);
  buckets_buf_append_c(b, ",\"n\":0}");
}

static void jsummary(buckets_buf *b, const double lrg[3], const double sml[3]) {
  double tot[3] = {lrg[0] + sml[0], lrg[1] + sml[1], lrg[2] > sml[2] ? lrg[2] : sml[2]};
  buckets_buf_append_c(b, "{\"Large\":");
  jxfer(b, lrg);
  buckets_buf_append_c(b, ",\"Small\":");
  jxfer(b, sml);
  buckets_buf_append_c(b, ",\"Total\":");
  jxfer(b, tot);
  buckets_buf_append_char(b, '}');
}

static void jtarget(buckets_buf *b, const buckets_repl_target_stats *t) {
  buckets_buf_appendf(b, "{\"completedReplicationSize\":%lld,\"replicaSize\":0,\"failed\":{", (long long)t->repl_size);
  jcb(b, "lastMinute", t->fail_min_count, t->fail_min_bytes);
  buckets_buf_append_char(b, ',');
  jcb(b, "lastHour", t->fail_hour_count, t->fail_hour_bytes);
  buckets_buf_append_char(b, ',');
  jcb(b, "totals", t->fail_total_count, t->fail_total_bytes);
  buckets_buf_appendf(b, "},\"replicationCount\":%lld,\"replicationLatency\":{\"UploadHistogram\":[",
                      (long long)t->repl_count);
  for (int s = 0; s < NSIZES; s++) {
    if (s) buckets_buf_append_char(b, ',');
    buckets_buf_append_c(b, "{\"Totals\":[");
    for (int j = 0; j < 60; j++) {
      if (j) buckets_buf_append_char(b, ',');
      buckets_buf_appendf(b, "{\"Total\":%lld,\"Size\":%lld,\"N\":%lld}", (long long)t->lat[s][j][0],
                          (long long)t->lat[s][j][1], (long long)t->lat[s][j][2]);
    }
    buckets_buf_appendf(b, "],\"LastSec\":%lld}", (long long)t->lat_last_sec[s]);
  }
  buckets_buf_append_c(b, "]},\"limitInBits\":0,\"currentBandwidth\":0,\"pendingReplicationSize\":0,"
                          "\"failedReplicationSize\":0,\"pendingReplicationCount\":0,\"failedReplicationCount\":0}");
}

static void jcurr(buckets_buf *b, const buckets_repl_bucket_stats *st) {
  buckets_buf_append_c(b, "{");
  int64_t rs = 0, rc = 0, fmc = 0, fmb = 0, fhc = 0, fhb = 0, ftc = 0, ftb = 0;
  if (st->n) {
    buckets_buf_append_c(b, "\"Stats\":{");
    for (size_t i = 0; i < st->n; i++) {
      if (i) buckets_buf_append_char(b, ',');
      buckets_json_go_string(b, st->t[i].arn, strlen(st->t[i].arn));
      buckets_buf_append_char(b, ':');
      jtarget(b, &st->t[i]);
      rs += st->t[i].repl_size, rc += st->t[i].repl_count;
      fmc += st->t[i].fail_min_count, fmb += st->t[i].fail_min_bytes;
      fhc += st->t[i].fail_hour_count, fhb += st->t[i].fail_hour_bytes;
      ftc += st->t[i].fail_total_count, ftb += st->t[i].fail_total_bytes;
    }
    buckets_buf_append_c(b, "},");
  }
  buckets_buf_appendf(b, "\"completedReplicationSize\":%lld,\"replicaSize\":%lld,\"failed\":{", (long long)rs,
                      (long long)st->replica_size);
  jcb(b, "lastMinute", fmc, fmb);
  buckets_buf_append_char(b, ',');
  jcb(b, "lastHour", fhc, fhb);
  buckets_buf_append_char(b, ',');
  jcb(b, "totals", ftc, ftb);
  buckets_buf_appendf(b, "},\"replicationCount\":%lld,\"replicaCount\":%lld,\"queued\":{", (long long)rc,
                      (long long)st->replica_count);
  jcb(b, "curr", st->q_count, st->q_bytes);
  buckets_buf_append_char(b, ',');
  jcb(b, "avg", (int64_t)st->q_avg_count, (int64_t)st->q_avg_bytes);
  buckets_buf_append_char(b, ',');
  jcb(b, "max", st->q_max_count, st->q_max_bytes);
  buckets_buf_append_c(b, "},\"pendingReplicationSize\":0,\"failedReplicationSize\":0,\"pendingReplicationCount\":0,"
                          "\"failedReplicationCount\":0}");
}

void buckets_repl_stats_json(const char *bucket, const char *node_name, bool v2, buckets_buf *b) {
  buckets_repl_bucket_stats st;
  buckets_repl_stats_get(bucket, &st);
  buckets_repl_node_stats ns;
  buckets_repl_stats_node(&ns);
  if (!v2) {
    jcurr(b, &st);
    buckets_buf_append_char(b, '\n');
    buckets_repl_bucket_stats_free(&st);
    return;
  }
  buckets_buf_appendf(b, "{\"uptime\":%lld,\"currStats\":", (long long)ns.uptime);
  jcurr(b, &st);
  buckets_buf_append_c(b, ",\"queueStats\":{\"nodes\":[{\"nodeName\":");
  buckets_json_go_string(b, node_name, strlen(node_name));
  buckets_buf_appendf(b, ",\"uptime\":%lld,\"activeWorkers\":{\"curr\":%lld,\"avg\":", (long long)ns.uptime,
                      (long long)ns.workers_curr);
  jfloat(b, (double)(float)ns.workers_avg);
  buckets_buf_appendf(b, ",\"max\":%lld},\"transferSummary\":", (long long)ns.workers_max);
  jsummary(b, ns.xfer[0], ns.xfer[1]);
  buckets_buf_append_c(b, ",\"tgtTransferStats\":{");
  for (size_t i = 0; i < st.n; i++) {
    if (i) buckets_buf_append_char(b, ',');
    buckets_json_go_string(b, st.t[i].arn, strlen(st.t[i].arn));
    buckets_buf_append_char(b, ':');
    jsummary(b, st.t[i].xfer[0], st.t[i].xfer[1]);
  }
  buckets_buf_append_c(b, "},\"queueStats\":{");
  jcb(b, "curr", st.q_count, st.q_bytes);
  buckets_buf_append_char(b, ',');
  jcb(b, "avg", (int64_t)st.q_avg_count, (int64_t)st.q_avg_bytes);
  buckets_buf_append_char(b, ',');
  jcb(b, "max", st.q_max_count, st.q_max_bytes);
  buckets_buf_appendf(b,
                      "},\"mrfStats\":{\"failedCount_last5min\":%lld,\"droppedCount_since_uptime\":%lld,"
                      "\"droppedBytes_since_uptime\":%lld}}],\"uptime\":%lld},",
                      (long long)ns.mrf_failed_last5, (long long)ns.mrf_dropped_count, (long long)ns.mrf_dropped_bytes,
                      (long long)ns.uptime);
  buckets_buf_appendf(b,
                      "\"proxyStats\":{\"putTaggingProxyTotal\":%llu,\"getTaggingProxyTotal\":%llu,"
                      "\"removeTaggingProxyTotal\":%llu,\"getProxyTotal\":%llu,\"headProxyTotal\":%llu,"
                      "\"putTaggingProxyFailed\":%llu,\"getTaggingProxyFailed\":%llu,\"removeTaggingProxyFailed\":%llu,"
                      "\"getProxyFailed\":%llu,\"headProxyFailed\":%llu}}\n",
                      (unsigned long long)st.proxy[2][0], (unsigned long long)st.proxy[3][0],
                      (unsigned long long)st.proxy[4][0], (unsigned long long)st.proxy[0][0],
                      (unsigned long long)st.proxy[1][0], (unsigned long long)st.proxy[2][1],
                      (unsigned long long)st.proxy[3][1], (unsigned long long)st.proxy[4][1],
                      (unsigned long long)st.proxy[0][1], (unsigned long long)st.proxy[1][1]);
  buckets_repl_bucket_stats_free(&st);
}

/* getUploadLatency: the last minute's average upload time (ms) by size */
void buckets_repl_stats_upload_latency(const buckets_repl_target_stats *t, const char **tags, uint64_t *ms) {
  for (int s = 0; s < NSIZES; s++) {
    int64_t total = 0, n = 0;
    for (int j = 0; j < 60; j++) total += t->lat[s][j][0], n += t->lat[s][j][2];
    tags[s] = k_size_tags[s];
    ms[s] = n >= 1 && total > 0 ? (uint64_t)(total / n / 1000000) : 0;
  }
}
