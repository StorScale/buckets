/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "object/nslock.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "core/buf.h"

#define NBUCKETS 1024

/* A resource's local state, shared by everyone holding or waiting for it. */
typedef struct slot slot;
struct slot {
  buckets_nslock *t;
  struct slot *next; /* hash chain */
  char *key;
  size_t refs;        /* holders + waiters; the entry lives while > 0 */
  int readers;        /* holding read */
  bool writer;        /* holding write */
  int waiting_writers;
  pthread_cond_t cv;
};

struct buckets_nslock {
  pthread_mutex_t mu;
  slot *tab[NBUCKETS];
  void *(*dist_lock)(void *ud, const char *resource, bool write, int timeout_ms);
  void (*dist_unlock)(void *ud, void *handle);
  void *dist_ud;
};

/* One acquisition: the local slot plus, when distributed, the cluster lock. */
struct buckets_nslock_entry {
  slot *s;
  bool write;
  void *dist;
};

void buckets_nslock_set_backend(buckets_nslock *t, void *(*lock)(void *, const char *, bool, int),
                                void (*unlock)(void *, void *), void *ud) {
  t->dist_lock = lock;
  t->dist_unlock = unlock;
  t->dist_ud = ud;
}

static size_t hash(const char *s) {
  size_t h = 1469598103934665603ull; /* FNV-1a */
  for (; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211ull;
  return h % NBUCKETS;
}

buckets_nslock *buckets_nslock_new(void) {
  buckets_nslock *t = buckets_xcalloc(1, sizeof(*t));
  pthread_mutex_init(&t->mu, NULL);
  return t;
}

void buckets_nslock_free(buckets_nslock *t) {
  if (!t) return;
  for (size_t i = 0; i < NBUCKETS; i++) {
    for (slot *e = t->tab[i], *next; e; e = next) {
      next = e->next;
      pthread_cond_destroy(&e->cv);
      free(e->key);
      free(e);
    }
  }
  pthread_mutex_destroy(&t->mu);
  free(t);
}

static void put_ref(slot *e) {
  buckets_nslock *t = e->t;
  if (--e->refs) return;
  slot **pp = &t->tab[hash(e->key)];
  while (*pp != e) pp = &(*pp)->next;
  *pp = e->next;
  pthread_cond_destroy(&e->cv);
  free(e->key);
  free(e);
}

static slot *slot_lock(buckets_nslock *t, const char *key, bool write, int timeout_ms) {
  buckets_buf k = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&k, key);
  size_t h = hash(k.data);
  struct timeval now;
  gettimeofday(&now, NULL);
  int64_t ns = (int64_t)now.tv_usec * 1000 + (int64_t)timeout_ms * 1000000;
  struct timespec deadline = {now.tv_sec + (time_t)(ns / 1000000000), (long)(ns % 1000000000)};

  pthread_mutex_lock(&t->mu);
  slot *e = t->tab[h];
  while (e && strcmp(e->key, k.data) != 0) e = e->next;
  if (!e) {
    e = buckets_xcalloc(1, sizeof(*e));
    e->t = t;
    e->key = buckets_xstrdup(k.data);
    pthread_cond_init(&e->cv, NULL);
    e->next = t->tab[h];
    t->tab[h] = e;
  }
  buckets_buf_free(&k);
  e->refs++;
  bool ok = true;
  if (write) {
    e->waiting_writers++;
    while ((e->writer || e->readers) && ok) ok = pthread_cond_timedwait(&e->cv, &t->mu, &deadline) != ETIMEDOUT;
    e->waiting_writers--;
    if (ok || !(e->writer || e->readers)) {
      e->writer = true;
      ok = true;
    }
  } else {
    while ((e->writer || e->waiting_writers) && ok) ok = pthread_cond_timedwait(&e->cv, &t->mu, &deadline) != ETIMEDOUT;
    if (ok || !(e->writer || e->waiting_writers)) {
      e->readers++;
      ok = true;
    }
  }
  if (!ok) {
    /* A writer that gave up may have been what held readers back. */
    if (write) pthread_cond_broadcast(&e->cv);
    put_ref(e);
    e = NULL;
  }
  pthread_mutex_unlock(&t->mu);
  return e;
}

static void slot_unlock(slot *e, bool write) {
  buckets_nslock *t = e->t;
  pthread_mutex_lock(&t->mu);
  if (write) e->writer = false;
  else e->readers--;
  pthread_cond_broadcast(&e->cv);
  put_ref(e);
  pthread_mutex_unlock(&t->mu);
}

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

buckets_nslock_entry *buckets_nslock_lock(buckets_nslock *t, const char *vol, const char *path, bool write,
                                          int timeout_ms) {
  buckets_buf key = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&key, "%s/%s", vol, path);
  int64_t start = mono_ms();
  /* Local first: threads of this node queue here instead of hammering the
   * cluster's lock servers. */
  slot *s = slot_lock(t, key.data, write, timeout_ms);
  buckets_nslock_entry *h = NULL;
  if (s) {
    void *dist = NULL;
    int left = timeout_ms - (int)(mono_ms() - start);
    if (t->dist_lock && !(dist = t->dist_lock(t->dist_ud, key.data, write, left > 0 ? left : 0))) {
      slot_unlock(s, write);
    } else {
      h = buckets_xcalloc(1, sizeof(*h));
      h->s = s;
      h->write = write;
      h->dist = dist;
    }
  }
  buckets_buf_free(&key);
  return h;
}

void buckets_nslock_unlock(buckets_nslock_entry *h) {
  if (!h) return;
  buckets_nslock *t = h->s->t;
  if (h->dist) t->dist_unlock(t->dist_ud, h->dist);
  slot_unlock(h->s, h->write);
  free(h);
}
