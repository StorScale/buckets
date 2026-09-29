/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_WPOOL_H
#define BUCKETS_CORE_WPOOL_H

#include <pthread.h>
#include <stdbool.h>

/* A fixed set of worker threads fed one task at a time (minio/pkg workers:
 * Take/Give/Wait): buckets_wpool_go blocks while every worker is busy. */

typedef struct buckets_wpool_task {
  struct buckets_wpool_task *next;
  void (*fn)(void *);
  void *arg;
} buckets_wpool_task;

typedef struct {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  buckets_wpool_task *head, *tail;
  int busy, nthreads, queued, limit;
  bool closing;
  pthread_t *threads;
} buckets_wpool;

void buckets_wpool_init(buckets_wpool *p, int n);
/* Waits for a free worker, then runs fn(arg) on it. */
void buckets_wpool_go(buckets_wpool *p, void (*fn)(void *), void *arg);
/* Waits until every task has run. */
void buckets_wpool_wait(buckets_wpool *p);
void buckets_wpool_close(buckets_wpool *p);

#endif
