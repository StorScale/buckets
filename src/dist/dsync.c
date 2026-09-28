/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/dsync.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/log.h"
#include "core/pool.h"
#include "core/query.h"
#include "core/uuid.h"
#include "dist/internode.h"

#define VALIDITY_MS 60000
#define REFRESH_MS 10000
#define PEER_BACKOFF_MS 1000
#define NBUCKETS 1024

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- lock server --------------------------------------------------------------- */

typedef struct {
  char uid[BUCKETS_UUID_STR_LEN + 1];
  int64_t refreshed_ms;
} holder;

typedef struct lentry {
  struct lentry *next;
  char *resource;
  bool write;
  holder *h;
  size_t n;
} lentry;

struct buckets_lock_server {
  pthread_mutex_t mu;
  lentry *tab[NBUCKETS];
};

static size_t lhash(const char *s) {
  size_t h = 1469598103934665603ull;
  for (; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211ull;
  return h % NBUCKETS;
}

buckets_lock_server *buckets_lock_server_new(void) {
  buckets_lock_server *s = buckets_xcalloc(1, sizeof(*s));
  pthread_mutex_init(&s->mu, NULL);
  return s;
}

void buckets_lock_server_free(buckets_lock_server *s) {
  if (!s) return;
  for (size_t i = 0; i < NBUCKETS; i++) {
    for (lentry *e = s->tab[i], *next; e; e = next) {
      next = e->next;
      free(e->resource);
      free(e->h);
      free(e);
    }
  }
  pthread_mutex_destroy(&s->mu);
  free(s);
}

/* Finds (optionally creating) a resource's entry, dropping expired holders. */
static lentry *lookup(buckets_lock_server *s, const char *res, bool create) {
  lentry **pp = &s->tab[lhash(res)];
  for (; *pp; pp = &(*pp)->next) {
    if (strcmp((*pp)->resource, res) == 0) break;
  }
  lentry *e = *pp;
  if (e) {
    int64_t now = now_ms();
    size_t k = 0;
    for (size_t i = 0; i < e->n; i++) {
      if (now - e->h[i].refreshed_ms < VALIDITY_MS) e->h[k++] = e->h[i];
      else buckets_log_warn("lock on %s held by %s expired unrefreshed", res, e->h[i].uid);
    }
    e->n = k;
  }
  if (e && e->n == 0 && !create) {
    *pp = e->next;
    free(e->resource);
    free(e->h);
    free(e);
    return NULL;
  }
  if (!e && create) {
    e = buckets_xcalloc(1, sizeof(*e));
    e->resource = buckets_xstrdup(res);
    e->next = s->tab[lhash(res)];
    s->tab[lhash(res)] = e;
  }
  return e;
}

static bool srv_lock(buckets_lock_server *s, const char *res, const char *uid, bool write) {
  pthread_mutex_lock(&s->mu);
  lentry *e = lookup(s, res, true);
  bool ok = false;
  for (size_t i = 0; i < e->n; i++) {
    if (strcmp(e->h[i].uid, uid) == 0) ok = true; /* a retried request */
  }
  if (!ok && (e->n == 0 || (!write && !e->write))) {
    e->h = buckets_xrealloc(e->h, (e->n + 1) * sizeof(holder));
    snprintf(e->h[e->n].uid, sizeof(e->h[e->n].uid), "%s", uid);
    e->h[e->n].refreshed_ms = now_ms();
    e->n++;
    e->write = write;
    ok = true;
  }
  if (e->n == 0) lookup(s, res, false); /* drop the empty entry */
  pthread_mutex_unlock(&s->mu);
  return ok;
}

/* unlock or refresh: returns whether uid held res. */
static bool srv_touch(buckets_lock_server *s, const char *res, const char *uid, bool release) {
  pthread_mutex_lock(&s->mu);
  lentry *e = lookup(s, res, false);
  bool held = false;
  for (size_t i = 0; e && i < e->n; i++) {
    if (strcmp(e->h[i].uid, uid) != 0) continue;
    held = true;
    if (release) e->h[i] = e->h[--e->n];
    else e->h[i].refreshed_ms = now_ms();
    break;
  }
  if (e && e->n == 0) lookup(s, res, false);
  pthread_mutex_unlock(&s->mu);
  return held;
}

size_t buckets_lock_server_held(buckets_lock_server *s) {
  size_t n = 0;
  pthread_mutex_lock(&s->mu);
  for (size_t i = 0; i < NBUCKETS; i++) {
    for (lentry *e = s->tab[i]; e; e = e->next) n += e->n > 0;
  }
  pthread_mutex_unlock(&s->mu);
  return n;
}

void buckets_lock_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_lock_server *s = ud;
  if (!buckets_internode_verify(req)) {
    resp->status = 403;
    return;
  }
  const size_t pl = strlen(BUCKETS_INTERNODE_PREFIX "lock/");
  char op[16];
  snprintf(op, sizeof(op), "%.*s", (int)(req->path.n > pl ? req->path.n - pl : 0), req->path.p + pl);
  buckets_query q;
  buckets_query_parse(req->query, &q);
  const char *res = buckets_query_get(&q, "res"), *uid = buckets_query_get(&q, "uid");
  const char *w = buckets_query_get(&q, "write");
  bool ok = false;
  if (!res || !uid) resp->status = 400;
  else if (strcmp(op, "lock") == 0) ok = srv_lock(s, res, uid, w && strcmp(w, "1") == 0);
  else if (strcmp(op, "unlock") == 0) ok = srv_touch(s, res, uid, true) || true;
  else if (strcmp(op, "refresh") == 0) ok = srv_touch(s, res, uid, false);
  else resp->status = 400;
  if (resp->status == 200 && !ok) resp->status = 409;
  buckets_query_free(&q);
}

/* ---- client -------------------------------------------------------------------- */

typedef struct dlock {
  struct dlock *prev, *next;
  char *resource;
  char uid[BUCKETS_UUID_STR_LEN + 1];
  bool write;
} dlock;

struct buckets_dsync {
  buckets_http_client **peers;
  size_t npeers;
  _Atomic int64_t *peer_down_until;
  buckets_lock_server *local;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  dlock *held;
  bool stop;
  pthread_t refresher;
};

typedef struct {
  buckets_dsync *d;
  const char *op, *resource, *uid;
  bool write;
  bool ok[64];
  bool down[64]; /* no answer: the node is unreachable */
} fan;

/* Node 0 is this node's own lock server; 1..npeers are the peers. */
static void fan_one(void *ctx, size_t i) {
  fan *f = ctx;
  buckets_dsync *d = f->d;
  if (i == 0) {
    if (strcmp(f->op, "lock") == 0) f->ok[0] = srv_lock(d->local, f->resource, f->uid, f->write);
    else f->ok[0] = srv_touch(d->local, f->resource, f->uid, strcmp(f->op, "unlock") == 0);
    return;
  }
  size_t p = i - 1;
  f->ok[i] = false;
  f->down[i] = false;
  if (atomic_load(&d->peer_down_until[p]) > now_ms()) {
    f->down[i] = true;
    return;
  }
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&t, BUCKETS_INTERNODE_PREFIX "lock/%s?res=", f->op);
  buckets_url_encode(&t, f->resource, false);
  buckets_buf_appendf(&t, "&uid=%s&write=%d", f->uid, f->write ? 1 : 0);
  char auth[96];
  buckets_internode_sign("POST", t.data, auth);
  buckets_http_kv h[] = {{BUCKETS_INTERNODE_AUTH, auth}};
  buckets_http_result r;
  if (buckets_http_client_do(d->peers[p], "POST", t.data, h, 1, NULL, 0, &r)) {
    f->ok[i] = r.status == 200;
    buckets_http_result_free(&r);
  } else {
    f->down[i] = true;
    atomic_store(&d->peer_down_until[p], now_ms() + PEER_BACKOFF_MS);
  }
  buckets_buf_free(&t);
}

static size_t nodes(const buckets_dsync *d) { return d->npeers + 1; }

static size_t quorum(const buckets_dsync *d, bool write) {
  size_t n = nodes(d), tol = n / 2, q = n - tol;
  if (write && q == tol) q++;
  return q;
}

static size_t run(buckets_dsync *d, fan *f) {
  buckets_io_parallel(nodes(d), fan_one, f);
  size_t ok = 0;
  for (size_t i = 0; i < nodes(d); i++) ok += f->ok[i];
  return ok;
}

static void *refresh_loop(void *arg) {
  buckets_dsync *d = arg;
  pthread_mutex_lock(&d->mu);
  while (!d->stop) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += REFRESH_MS / 1000;
    pthread_cond_timedwait(&d->cv, &d->mu, &ts);
    if (d->stop) break;
    /* Snapshot, then refresh without holding the list lock. */
    size_t n = 0;
    for (dlock *l = d->held; l; l = l->next) n++;
    dlock *snap = buckets_xcalloc(n ? n : 1, sizeof(dlock));
    size_t k = 0;
    for (dlock *l = d->held; l; l = l->next) {
      snap[k] = *l;
      snap[k].resource = buckets_xstrdup(l->resource);
      k++;
    }
    pthread_mutex_unlock(&d->mu);
    for (size_t i = 0; i < k; i++) {
      fan f = {.d = d, .op = "refresh", .resource = snap[i].resource, .uid = snap[i].uid, .write = snap[i].write};
      if (run(d, &f) < quorum(d, snap[i].write)) {
        buckets_log_warn("distributed lock on %s lost its quorum while held", snap[i].resource);
      }
      free(snap[i].resource);
    }
    free(snap);
    pthread_mutex_lock(&d->mu);
  }
  pthread_mutex_unlock(&d->mu);
  return NULL;
}

buckets_dsync *buckets_dsync_new(buckets_http_client *const *peers, size_t npeers, buckets_lock_server *local) {
  if (npeers + 1 > 64) buckets_fatal("dsync supports at most 64 nodes");
  buckets_dsync *d = buckets_xcalloc(1, sizeof(*d));
  d->peers = buckets_xcalloc(npeers ? npeers : 1, sizeof(*d->peers));
  memcpy(d->peers, peers, npeers * sizeof(*peers));
  d->npeers = npeers;
  d->peer_down_until = buckets_xcalloc(npeers ? npeers : 1, sizeof(*d->peer_down_until));
  d->local = local;
  pthread_mutex_init(&d->mu, NULL);
  pthread_cond_init(&d->cv, NULL);
  if (pthread_create(&d->refresher, NULL, refresh_loop, d) != 0) buckets_fatal("start lock refresher");
  return d;
}

void buckets_dsync_free(buckets_dsync *d) {
  if (!d) return;
  pthread_mutex_lock(&d->mu);
  d->stop = true;
  pthread_cond_broadcast(&d->cv);
  pthread_mutex_unlock(&d->mu);
  pthread_join(d->refresher, NULL);
  while (d->held) {
    dlock *l = d->held;
    d->held = l->next;
    free(l->resource);
    free(l);
  }
  pthread_cond_destroy(&d->cv);
  pthread_mutex_destroy(&d->mu);
  free((void *)d->peer_down_until);
  free(d->peers);
  free(d);
}

void *buckets_dsync_lock(buckets_dsync *d, const char *resource, bool write, int timeout_ms) {
  dlock *l = buckets_xcalloc(1, sizeof(*l));
  l->resource = buckets_xstrdup(resource);
  l->write = write;
  buckets_uuid_v4(l->uid);
  int64_t deadline = now_ms() + timeout_ms;
  size_t need = quorum(d, write);
  for (unsigned attempt = 0;; attempt++) {
    fan f = {.d = d, .op = "lock", .resource = resource, .uid = l->uid, .write = write};
    if (run(d, &f) >= need) break;
    size_t reachable = 0;
    for (size_t i = 0; i < nodes(d); i++) reachable += !f.down[i];
    /* Release partial grants so competing clients can make progress. */
    fan u = {.d = d, .op = "unlock", .resource = resource, .uid = l->uid, .write = write};
    run(d, &u);
    /* With too many lock servers down no retry can reach quorum: fail now
     * rather than hold the request for the whole timeout. */
    if (now_ms() >= deadline || reachable < need) {
      if (reachable < need) {
        buckets_log_warn("lock on %s needs %zu of %zu nodes but only %zu answer", resource, need, nodes(d), reachable);
      }
      free(l->resource);
      free(l);
      return NULL;
    }
    uint32_t r;
    buckets_random_bytes(&r, sizeof(r));
    int64_t cap = BUCKETS_MIN(250, 10 << BUCKETS_MIN(attempt, 5u));
    struct timespec ts = {0, (long)(r % (uint32_t)cap + 1) * 1000000L};
    nanosleep(&ts, NULL);
  }
  pthread_mutex_lock(&d->mu);
  l->next = d->held;
  if (d->held) d->held->prev = l;
  d->held = l;
  pthread_mutex_unlock(&d->mu);
  return l;
}

void buckets_dsync_unlock(buckets_dsync *d, void *handle) {
  dlock *l = handle;
  if (!l) return;
  pthread_mutex_lock(&d->mu);
  if (l->prev) l->prev->next = l->next;
  else d->held = l->next;
  if (l->next) l->next->prev = l->prev;
  pthread_mutex_unlock(&d->mu);
  fan u = {.d = d, .op = "unlock", .resource = l->resource, .uid = l->uid, .write = l->write};
  run(d, &u);
  free(l->resource);
  free(l);
}
