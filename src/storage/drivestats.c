/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/drivestats.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/common.h"

static const char *const k_names[BUCKETS_DOP__N] = {
    "MakeVol",    "StatVol", "DeleteVol",   "ListVols",       "ReadAll", "WriteAll", "CreateFile", "AppendFile",
    "Sync",       "OpenFile", "ReadFile",   "RenameData",     "Delete",  "ListDir",  "DiskInfo",   "StatInfoFile",
    "RenameFile"};

const char *buckets_drive_op_name(buckets_drive_op op) { return op < BUCKETS_DOP__N ? k_names[op] : ""; }

/* lastMinuteLatency: one slot per second of the last minute */
typedef struct {
  int64_t sec;
  uint64_t n, ns;
} slot;

typedef struct buckets_drive_stats {
  pthread_mutex_t mu;
  slot win[BUCKETS_DOP__N][60];
  uint64_t total[BUCKETS_DOP__N]; /* calls since start */
  _Atomic uint64_t err_avail, err_timeout;
  _Atomic int64_t waiting;
} dstats;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
typedef struct entry {
  struct entry *next;
  const buckets_drive *d;
  dstats *s;
} entry;
static entry *g_list;

/* The drive's statistics, created on first use (kept out of the drive
 * struct, which remote and local drives share by layout). */
static dstats *stats_of(const buckets_drive *d, bool create) {
  pthread_mutex_lock(&g_mu);
  entry *e = g_list;
  while (e && e->d != d) e = e->next;
  if (!e && create) {
    e = buckets_xcalloc(1, sizeof(*e));
    e->d = d;
    e->s = buckets_xcalloc(1, sizeof(*e->s));
    pthread_mutex_init(&e->s->mu, NULL);
    e->next = g_list;
    g_list = e;
  }
  dstats *s = e ? e->s : NULL;
  pthread_mutex_unlock(&g_mu);
  return s;
}

static int64_t now_sec(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec;
}

void buckets_drive_stats_begin(buckets_drive *d) { atomic_fetch_add(&stats_of(d, true)->waiting, 1); }

void buckets_drive_stats_end(buckets_drive *d, buckets_drive_op op, int64_t ns, buckets_drive_err err) {
  dstats *s = stats_of(d, true);
  atomic_fetch_sub(&s->waiting, 1);
  if (err == BUCKETS_DRIVE_ERR_IO || err == BUCKETS_DRIVE_ERR_OFFLINE) atomic_fetch_add(&s->err_avail, 1);
  if (op >= BUCKETS_DOP__N) return;
  int64_t sec = now_sec();
  pthread_mutex_lock(&s->mu);
  slot *sl = &s->win[op][sec % 60];
  if (sl->sec != sec) *sl = (slot){sec, 0, 0};
  sl->n++;
  sl->ns += ns > 0 ? (uint64_t)ns : 0;
  s->total[op]++;
  pthread_mutex_unlock(&s->mu);
}

void buckets_drive_stats_free(buckets_drive *d) {
  pthread_mutex_lock(&g_mu);
  for (entry **p = &g_list; *p; p = &(*p)->next) {
    if ((*p)->d == d) {
      entry *e = *p;
      *p = e->next;
      pthread_mutex_destroy(&e->s->mu);
      free(e->s);
      free(e);
      break;
    }
  }
  pthread_mutex_unlock(&g_mu);
}

void buckets_drive_stats_get(buckets_drive *d, buckets_drive_stats_view *out) {
  memset(out, 0, sizeof(*out));
  dstats *s = stats_of(d, false);
  if (!s) return;
  out->errors_availability = atomic_load(&s->err_avail);
  out->errors_timeout = atomic_load(&s->err_timeout);
  out->waiting = atomic_load(&s->waiting);
  int64_t sec = now_sec();
  pthread_mutex_lock(&s->mu);
  for (int op = 0; op < BUCKETS_DOP__N; op++) {
    uint64_t n = 0, ns = 0;
    for (int i = 0; i < 60; i++) {
      const slot *sl = &s->win[op][i];
      if (sl->n && sec - sl->sec < 60) n += sl->n, ns += sl->ns;
    }
    out->count[op] = n;
    out->total[op] = s->total[op];
    out->acc_ns[op] = ns;
    out->avg_us[op] = n ? (double)ns / (double)n / 1000.0 : 0;
  }
  pthread_mutex_unlock(&s->mu);
}
