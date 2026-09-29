/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/wpool.h"

#include <stdlib.h>
#include <string.h>

#include "core/common.h"

static void *wpool_main(void *arg) {
  buckets_wpool *p = arg;
  pthread_mutex_lock(&p->mu);
  for (;;) {
    while (!p->head && !p->closing) pthread_cond_wait(&p->cv, &p->mu);
    if (!p->head) break;
    buckets_wpool_task *t = p->head;
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

void buckets_wpool_init(buckets_wpool *p, int n) {
  memset(p, 0, sizeof(*p));
  if (n < 1) n = 1;
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->cv, NULL);
  p->limit = n;
  p->threads = buckets_xcalloc((size_t)n, sizeof(pthread_t));
  for (int i = 0; i < n; i++)
    if (pthread_create(&p->threads[i], NULL, wpool_main, p) == 0) p->nthreads++;
}

void buckets_wpool_go(buckets_wpool *p, void (*fn)(void *), void *arg) {
  buckets_wpool_task *t = buckets_xcalloc(1, sizeof(*t));
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

void buckets_wpool_wait(buckets_wpool *p) {
  pthread_mutex_lock(&p->mu);
  while (p->busy || p->queued) pthread_cond_wait(&p->cv, &p->mu);
  pthread_mutex_unlock(&p->mu);
}

void buckets_wpool_close(buckets_wpool *p) {
  pthread_mutex_lock(&p->mu);
  p->closing = true;
  pthread_cond_broadcast(&p->cv);
  pthread_mutex_unlock(&p->mu);
  for (int i = 0; i < p->nthreads; i++) pthread_join(p->threads[i], NULL);
  free(p->threads);
  pthread_mutex_destroy(&p->mu);
  pthread_cond_destroy(&p->cv);
}
