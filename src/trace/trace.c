/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "trace/trace.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/timefmt.h"

#define SUB_QUEUE_BYTES (64u << 20) /* a slow reader loses records rather than holding memory */

struct buckets_trace_sub {
  struct buckets_trace_sub *next;
  buckets_trace_opts o;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  buckets_buf pending;
  size_t pos;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static buckets_trace_sub *g_subs;
static _Atomic uint64_t g_wanted; /* union of the subscribers' types */

static void recompute(void) {
  uint64_t w = 0;
  for (buckets_trace_sub *s = g_subs; s; s = s->next) w |= s->o.types;
  atomic_store(&g_wanted, w);
}

static char g_node[256];
void buckets_trace_set_node(const char *node) { snprintf(g_node, sizeof(g_node), "%s", node ? node : ""); }
const char *buckets_trace_node(void) { return g_node; }

bool buckets_trace_wanted(uint64_t types) { return (atomic_load(&g_wanted) & types) != 0; }

/* shouldTrace */
static bool should_trace(const buckets_trace_opts *o, const buckets_trace_meta *m) {
  if (!(o->types & m->type)) return false;
  if (o->threshold_ns > 0 && m->dur_ns < o->threshold_ns) return false;
  bool internal = m->http && m->path && strncmp(m->path, "/minio/", 7) == 0;
  if (internal && !o->internal) return false;
  if (m->http && o->only_errors && m->status < 400) return false;
  return true;
}

void buckets_trace_publish(const buckets_trace_meta *m, const char *json, size_t n) {
  if (!buckets_trace_wanted(m->type)) return;
  pthread_mutex_lock(&g_mu);
  for (buckets_trace_sub *s = g_subs; s; s = s->next) {
    if (!should_trace(&s->o, m)) continue;
    pthread_mutex_lock(&s->mu);
    if (s->pending.len - s->pos + n < SUB_QUEUE_BYTES) {
      buckets_buf_append(&s->pending, json, n);
      buckets_buf_append_char(&s->pending, '\n');
      pthread_cond_broadcast(&s->cv);
    }
    pthread_mutex_unlock(&s->mu);
  }
  pthread_mutex_unlock(&g_mu);
}

buckets_trace_sub *buckets_trace_subscribe(const buckets_trace_opts *o) {
  buckets_trace_sub *s = buckets_xcalloc(1, sizeof(*s));
  s->o = *o;
  pthread_mutex_init(&s->mu, NULL);
  pthread_cond_init(&s->cv, NULL);
  pthread_mutex_lock(&g_mu);
  s->next = g_subs;
  g_subs = s;
  recompute();
  pthread_mutex_unlock(&g_mu);
  return s;
}

long buckets_trace_sub_read(void *ud, char *buf, size_t cap) {
  buckets_trace_sub *s = ud;
  pthread_mutex_lock(&s->mu);
  if (s->pos == s->pending.len) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 1;
    pthread_cond_timedwait(&s->cv, &s->mu, &until);
  }
  long k;
  if (s->pos < s->pending.len) {
    size_t avail = s->pending.len - s->pos;
    k = (long)(avail < cap ? avail : cap);
    memcpy(buf, s->pending.data + s->pos, (size_t)k);
    s->pos += (size_t)k;
    if (s->pos == s->pending.len) {
      buckets_buf_reset(&s->pending);
      s->pos = 0;
    }
  } else {
    buf[0] = ' '; /* keep-alive */
    k = 1;
  }
  pthread_mutex_unlock(&s->mu);
  return k;
}

void buckets_trace_sub_free(void *ud) {
  buckets_trace_sub *s = ud;
  if (!s) return;
  pthread_mutex_lock(&g_mu);
  for (buckets_trace_sub **p = &g_subs; *p; p = &(*p)->next) {
    if (*p == s) {
      *p = s->next;
      break;
    }
  }
  recompute();
  pthread_mutex_unlock(&g_mu);
  buckets_buf_free(&s->pending);
  pthread_cond_destroy(&s->cv);
  pthread_mutex_destroy(&s->mu);
  free(s);
}

bool buckets_trace_opts_parse(const buckets_trace_params *p, buckets_trace_opts *o) {
  static const struct {
    const char *q;
    uint64_t bit;
  } k[] = {{"s3", BUCKETS_TRACE_S3},
           {"internal", BUCKETS_TRACE_INTERNAL},
           {"storage", BUCKETS_TRACE_STORAGE},
           {"os", BUCKETS_TRACE_OS},
           {"scanner", BUCKETS_TRACE_SCANNER},
           {"decommission", BUCKETS_TRACE_DECOMMISSION},
           {"healing", BUCKETS_TRACE_HEALING},
           {"batch-replication", BUCKETS_TRACE_BATCH_REPLICATION},
           {"batch-keyrotation", BUCKETS_TRACE_BATCH_KEYROTATION},
           {"batch-expire", BUCKETS_TRACE_BATCH_EXPIRE},
           {"rebalance", BUCKETS_TRACE_REBALANCE},
           {"replication-resync", BUCKETS_TRACE_REPLICATION_RESYNC},
           {"bootstrap", BUCKETS_TRACE_BOOTSTRAP},
           {"ftp", BUCKETS_TRACE_FTP},
           {"ilm", BUCKETS_TRACE_ILM},
           {"kms", BUCKETS_TRACE_KMS},
           {"formatting", BUCKETS_TRACE_FORMATTING}};
  memset(o, 0, sizeof(*o));
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k); i++) {
    const char *v = p->get(p->ud, k[i].q);
    if (v && strcmp(v, "true") == 0) o->types |= k[i].bit;
  }
  const char *all = p->get(p->ud, "all");
  if (all && strcmp(all, "true") == 0)
    o->types |= BUCKETS_TRACE_S3 | BUCKETS_TRACE_INTERNAL | BUCKETS_TRACE_STORAGE | BUCKETS_TRACE_OS;
  o->internal = (o->types & BUCKETS_TRACE_INTERNAL) != 0;
  const char *err = p->get(p->ud, "err");
  o->only_errors = err && strcmp(err, "true") == 0;
  const char *th = p->get(p->ud, "threshold");
  return !(th && *th && !buckets_go_duration_parse(th, &o->threshold_ns));
}

void buckets_trace_sub_push(buckets_trace_sub *s, const char *line, size_t n) {
  pthread_mutex_lock(&s->mu);
  if (s->pending.len - s->pos + n < SUB_QUEUE_BYTES) {
    buckets_buf_append(&s->pending, line, n);
    buckets_buf_append_char(&s->pending, '\n');
    pthread_cond_broadcast(&s->cv);
  }
  pthread_mutex_unlock(&s->mu);
}
