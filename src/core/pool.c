/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/pool.h"

#include <pthread.h>
#include <stdlib.h>

#include "core/common.h"

typedef struct batch {
  buckets_par_fn fn;
  void *ctx;
  size_t n, next, remaining;
  bool detached; /* heap-allocated by buckets_pool_submit; freed when done */
  pthread_cond_t *done; /* buckets_parallel's caller waits on it (its own, not a shared one) */
  struct batch *prev, *nextb; /* queue links while indexes are left to hand out */
} batch;

struct buckets_pool {
  pthread_mutex_t mu;
  pthread_cond_t work; /* a batch was queued, or stop */
  batch *head, *tail;
  int idle; /* workers waiting on work */
  bool stop;
  int nthreads;
  pthread_t *threads;
};

static void unlink_batch(buckets_pool *p, batch *b) {
  if (b->prev) b->prev->nextb = b->nextb;
  else p->head = b->nextb;
  if (b->nextb) b->nextb->prev = b->prev;
  else p->tail = b->prev;
  b->prev = b->nextb = NULL;
}

/* Hands out the next index of b (lock held); dequeues b once exhausted. */
static size_t take(buckets_pool *p, batch *b) {
  size_t i = b->next++;
  if (b->next == b->n) unlink_batch(p, b);
  return i;
}

static void finish(buckets_pool *p, batch *b) {
  if (--b->remaining) return;
  (void)p;
  if (b->detached) free(b);
  else pthread_cond_signal(b->done);
}

static void *worker(void *arg) {
  buckets_pool *p = arg;
  pthread_mutex_lock(&p->mu);
  for (;;) {
    while (!p->head && !p->stop) {
      p->idle++;
      pthread_cond_wait(&p->work, &p->mu);
      p->idle--;
    }
    if (!p->head) break;
    batch *b = p->head;
    size_t i = take(p, b);
    pthread_mutex_unlock(&p->mu);
    b->fn(b->ctx, i);
    pthread_mutex_lock(&p->mu);
    finish(p, b);
  }
  pthread_mutex_unlock(&p->mu);
  return NULL;
}

buckets_pool *buckets_pool_new(int nthreads) {
  buckets_pool *p = buckets_xcalloc(1, sizeof(*p));
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->work, NULL);
  p->threads = buckets_xcalloc((size_t)(nthreads > 0 ? nthreads : 1), sizeof(pthread_t));
  for (int t = 0; t < nthreads; t++) {
    if (pthread_create(&p->threads[t], NULL, worker, p) != 0) break;
    p->nthreads++;
  }
  return p;
}

void buckets_pool_free(buckets_pool *p) {
  if (!p) return;
  pthread_mutex_lock(&p->mu);
  p->stop = true;
  pthread_cond_broadcast(&p->work);
  pthread_mutex_unlock(&p->mu);
  for (int t = 0; t < p->nthreads; t++) pthread_join(p->threads[t], NULL);
  pthread_cond_destroy(&p->work);
  pthread_mutex_destroy(&p->mu);
  free(p->threads);
  free(p);
}

void buckets_parallel(buckets_pool *p, size_t n, buckets_par_fn fn, void *ctx) {
  if (!p || p->nthreads == 0 || n <= 1) {
    for (size_t i = 0; i < n; i++) fn(ctx, i);
    return;
  }
  pthread_cond_t done;
  pthread_cond_init(&done, NULL);
  batch b = {.fn = fn, .ctx = ctx, .n = n, .remaining = n, .done = &done};
  pthread_mutex_lock(&p->mu);
  b.prev = p->tail;
  if (p->tail) p->tail->nextb = &b;
  else p->head = &b;
  p->tail = &b;
  /* Wake as many workers as there are indexes besides the caller's own, not
   * every idle one: the rest would only fight over the lock. */
  for (size_t k = 1; k < n && (int)k <= p->idle; k++) pthread_cond_signal(&p->work);
  while (b.next < b.n) {
    size_t i = take(p, &b);
    pthread_mutex_unlock(&p->mu);
    fn(ctx, i);
    pthread_mutex_lock(&p->mu);
    finish(p, &b);
  }
  while (b.remaining) pthread_cond_wait(&done, &p->mu);
  pthread_mutex_unlock(&p->mu);
  pthread_cond_destroy(&done);
}

void buckets_pool_submit(buckets_pool *p, buckets_par_fn fn, void *ctx) {
  if (!p || p->nthreads == 0) {
    fn(ctx, 0);
    return;
  }
  batch *b = buckets_xcalloc(1, sizeof(*b));
  *b = (batch){.fn = fn, .ctx = ctx, .n = 1, .remaining = 1, .detached = true};
  pthread_mutex_lock(&p->mu);
  b->prev = p->tail;
  if (p->tail) p->tail->nextb = b;
  else p->head = b;
  p->tail = b;
  pthread_cond_signal(&p->work);
  pthread_mutex_unlock(&p->mu);
}

static buckets_pool *g_io;

void buckets_io_pool_set(buckets_pool *p) { g_io = p; }
buckets_pool *buckets_io_pool(void) { return g_io; }
void buckets_io_parallel(size_t n, buckets_par_fn fn, void *ctx) { buckets_parallel(g_io, n, fn, ctx); }
