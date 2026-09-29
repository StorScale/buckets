/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "logger/console.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/buf.h"
#include "core/common.h"

#define RING 10000 /* defaultLogBufferCount */

typedef struct {
  uint32_t mask;
  bool timed;
  char *node;
  char *json;
  size_t n;
} rec;

struct buckets_console_sub {
  struct buckets_console_sub *next;
  char *node;
  uint32_t mask;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  buckets_buf pending;
  size_t pos;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static rec g_ring[RING];
static size_t g_next, g_count;
static buckets_console_sub *g_subs;

uint32_t buckets_log_kind_mask(const char *k) {
  if (!k) return BUCKETS_LOGMASK_ALL;
  static const struct {
    const char *n;
    uint32_t m;
  } t[] = {{"MINIO", BUCKETS_LOGMASK_MINIO},     {"APPLICATION", BUCKETS_LOGMASK_APPLICATION},
           {"FATAL", BUCKETS_LOGMASK_FATAL},     {"WARNING", BUCKETS_LOGMASK_WARNING},
           {"ERROR", BUCKETS_LOGMASK_ERROR},     {"EVENT", BUCKETS_LOGMASK_EVENT},
           {"INFO", BUCKETS_LOGMASK_INFO}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(t); i++)
    if (strcasecmp(k, t[i].n) == 0) return t[i].m;
  return BUCKETS_LOGMASK_ALL;
}

/* Info.SendLog */
static bool wanted(uint32_t sub_mask, const char *sub_node, const rec *r) {
  if ((sub_mask & r->mask) != r->mask) return false;
  return !sub_node || !*sub_node || (strcasecmp(sub_node, r->node ? r->node : "") == 0 && r->timed);
}

static void push(buckets_console_sub *s, const rec *r) {
  buckets_buf_append(&s->pending, r->json, r->n);
  buckets_buf_append_char(&s->pending, '\n');
}

void buckets_console_add(uint32_t mask, bool timed, const char *node, const char *json, size_t n) {
  pthread_mutex_lock(&g_mu);
  rec *r = &g_ring[g_next];
  free(r->node);
  free(r->json);
  *r = (rec){mask, timed, buckets_xstrdup(node ? node : ""), buckets_xstrndup(json, n), n};
  g_next = (g_next + 1) % RING;
  if (g_count < RING) g_count++;
  for (buckets_console_sub *s = g_subs; s; s = s->next) {
    if (!wanted(s->mask, s->node, r)) continue;
    pthread_mutex_lock(&s->mu);
    if (s->pending.len - s->pos < (32u << 20)) push(s, r);
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
  }
  pthread_mutex_unlock(&g_mu);
}

buckets_console_sub *buckets_console_subscribe(const char *node, int last, uint32_t mask) {
  buckets_console_sub *s = buckets_xcalloc(1, sizeof(*s));
  s->node = node && *node ? buckets_xstrdup(node) : NULL;
  s->mask = mask ? mask : BUCKETS_LOGMASK_ALL;
  pthread_mutex_init(&s->mu, NULL);
  pthread_cond_init(&s->cv, NULL);
  if (last <= 0 || last > RING) last = RING;
  pthread_mutex_lock(&g_mu);
  /* the last `last` matching records, oldest first */
  size_t start = (g_next + RING - g_count) % RING, matched = 0;
  for (size_t i = 0; i < g_count; i++) matched += wanted(s->mask, s->node, &g_ring[(start + i) % RING]);
  size_t skip = matched > (size_t)last ? matched - (size_t)last : 0;
  for (size_t i = 0; i < g_count; i++) {
    const rec *r = &g_ring[(start + i) % RING];
    if (!wanted(s->mask, s->node, r)) continue;
    if (skip) {
      skip--;
      continue;
    }
    push(s, r);
  }
  s->next = g_subs;
  g_subs = s;
  pthread_mutex_unlock(&g_mu);
  return s;
}

long buckets_console_sub_read(void *ud, char *buf, size_t cap) {
  buckets_console_sub *s = ud;
  pthread_mutex_lock(&s->mu);
  if (s->pos == s->pending.len) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_nsec += 500000000L;
    if (until.tv_nsec >= 1000000000L) until.tv_sec++, until.tv_nsec -= 1000000000L;
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
    buf[0] = ' ';
    k = 1;
  }
  pthread_mutex_unlock(&s->mu);
  return k;
}

void buckets_console_sub_free(void *ud) {
  buckets_console_sub *s = ud;
  if (!s) return;
  pthread_mutex_lock(&g_mu);
  for (buckets_console_sub **p = &g_subs; *p; p = &(*p)->next) {
    if (*p == s) {
      *p = s->next;
      break;
    }
  }
  pthread_mutex_unlock(&g_mu);
  buckets_buf_free(&s->pending);
  pthread_cond_destroy(&s->cv);
  pthread_mutex_destroy(&s->mu);
  free(s->node);
  free(s);
}
