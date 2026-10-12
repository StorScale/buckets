/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/rpcstats.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_OPS 64

typedef struct {
  char op[32];
  _Atomic uint64_t calls, ns;
} slot;

typedef struct {
  slot slots[MAX_OPS];
  _Atomic size_t n; /* slots[0..n) are named */
  pthread_mutex_t mu;
} table;

static table tables[3] = {{.mu = PTHREAD_MUTEX_INITIALIZER}, {.mu = PTHREAD_MUTEX_INITIALIZER},
                          {.mu = PTHREAD_MUTEX_INITIALIZER}};

int64_t buckets_rpcstats_now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static slot *find(table *t, const char *op) {
  size_t n = atomic_load_explicit(&t->n, memory_order_acquire);
  for (size_t i = 0; i < n; i++) {
    if (strcmp(t->slots[i].op, op) == 0) return &t->slots[i];
  }
  return NULL;
}

void buckets_rpcstats_add(buckets_rpc_side side, const char *kind, const char *name, int64_t ns) {
  table *t = &tables[side];
  char op[32];
  snprintf(op, sizeof(op), "%s/%s", kind, name);
  slot *s = find(t, op);
  if (!s) {
    pthread_mutex_lock(&t->mu);
    s = find(t, op);
    size_t n = atomic_load(&t->n);
    if (!s && n < MAX_OPS) {
      s = &t->slots[n];
      memcpy(s->op, op, sizeof(op));
      atomic_store_explicit(&t->n, n + 1, memory_order_release);
    }
    pthread_mutex_unlock(&t->mu);
    if (!s) return; /* full: unknown names from peers are not worth a lock */
  }
  atomic_fetch_add_explicit(&s->calls, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->ns, (uint64_t)(ns > 0 ? ns : 0), memory_order_relaxed);
}

void buckets_rpcstats_each(buckets_rpc_side side, void (*fn)(void *ud, const buckets_rpcstat *st), void *ud) {
  table *t = &tables[side];
  size_t n = atomic_load_explicit(&t->n, memory_order_acquire);
  for (size_t i = 0; i < n; i++) {
    buckets_rpcstat st = {t->slots[i].op, atomic_load_explicit(&t->slots[i].calls, memory_order_relaxed),
                          atomic_load_explicit(&t->slots[i].ns, memory_order_relaxed)};
    fn(ud, &st);
  }
}
