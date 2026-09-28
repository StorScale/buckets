/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/peer.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/log.h"
#include "core/query.h"
#include "dist/internode.h"

#define PEER_BACKOFF_MS 5000

typedef struct note {
  char *target;
  struct note *next;
} note;

/* Notifications go out from a worker thread, so callers never block on a
 * peer (and never hold their own locks across a round trip to a server
 * that may be waiting on them). */
struct buckets_peer_sys {
  buckets_http_client **peers;
  size_t n;
  _Atomic long long *down_until;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  note *head, *tail;
  bool stop;
  pthread_t worker;
};

static long long now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void broadcast(buckets_peer_sys *p, const char *target);

static void *worker_main(void *arg) {
  buckets_peer_sys *p = arg;
  pthread_mutex_lock(&p->mu);
  for (;;) {
    while (!p->head && !p->stop) pthread_cond_wait(&p->cv, &p->mu);
    if (!p->head) break;
    note *nt = p->head;
    p->head = nt->next;
    if (!p->head) p->tail = NULL;
    pthread_mutex_unlock(&p->mu);
    broadcast(p, nt->target);
    free(nt->target);
    free(nt);
    pthread_mutex_lock(&p->mu);
  }
  pthread_mutex_unlock(&p->mu);
  return NULL;
}

buckets_peer_sys *buckets_peer_sys_new(buckets_http_client *const *peers, size_t n) {
  buckets_peer_sys *p = buckets_xcalloc(1, sizeof(*p));
  p->peers = buckets_xcalloc(n ? n : 1, sizeof(*p->peers));
  memcpy(p->peers, peers, n * sizeof(*peers));
  p->n = n;
  p->down_until = buckets_xcalloc(n ? n : 1, sizeof(*p->down_until));
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->cv, NULL);
  if (pthread_create(&p->worker, NULL, worker_main, p) != 0) abort();
  return p;
}

/* Delivers what is queued, then stops. */
void buckets_peer_sys_free(buckets_peer_sys *p) {
  if (!p) return;
  pthread_mutex_lock(&p->mu);
  p->stop = true;
  pthread_cond_signal(&p->cv);
  pthread_mutex_unlock(&p->mu);
  pthread_join(p->worker, NULL);
  pthread_mutex_destroy(&p->mu);
  pthread_cond_destroy(&p->cv);
  free(p->peers);
  free((void *)p->down_until);
  free(p);
}

static void enqueue(buckets_peer_sys *p, buckets_buf *target) {
  note *nt = buckets_xcalloc(1, sizeof(*nt));
  nt->target = buckets_buf_detach(target);
  pthread_mutex_lock(&p->mu);
  if (p->tail) p->tail->next = nt;
  else p->head = nt;
  p->tail = nt;
  pthread_cond_signal(&p->cv);
  pthread_mutex_unlock(&p->mu);
}

static void broadcast(buckets_peer_sys *p, const char *target) {
  char auth[96];
  buckets_internode_sign("POST", target, auth);
  buckets_http_kv h[] = {{BUCKETS_INTERNODE_AUTH, auth}};
  for (size_t i = 0; i < p->n; i++) {
    if (atomic_load(&p->down_until[i]) > now_ms()) continue;
    buckets_http_result r;
    if (!buckets_http_client_do(p->peers[i], "POST", target, h, 1, NULL, 0, &r)) {
      atomic_store(&p->down_until[i], now_ms() + PEER_BACKOFF_MS);
      buckets_log_warn("peer %s: notification %s failed", buckets_http_client_host(p->peers[i]), target);
      continue;
    }
    if (r.status != 200) buckets_log_warn("peer %s: notification answered %d", buckets_http_client_host(p->peers[i]), r.status);
    buckets_http_result_free(&r);
  }
}

void buckets_peer_notify_iam(buckets_peer_sys *p, const char *kind, const char *name) {
  if (!p || !p->n) return;
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/iam?kind=");
  buckets_url_encode(&t, kind, false);
  buckets_buf_append_c(&t, "&name=");
  buckets_url_encode(&t, name, false);
  enqueue(p, &t);
}

void buckets_peer_notify_bucket(buckets_peer_sys *p, const char *bucket) {
  if (!p || !p->n) return;
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/bucket-meta?bucket=");
  buckets_url_encode(&t, bucket, false);
  enqueue(p, &t);
}

bool buckets_peer_node_online(buckets_peer_sys *p, const char *node) {
  if (!p) return false;
  for (size_t i = 0; i < p->n; i++) {
    char key[300];
    snprintf(key, sizeof(key), "%s:%d", buckets_http_client_host(p->peers[i]), buckets_http_client_port(p->peers[i]));
    if (strcmp(key, node) == 0) return atomic_load(&p->down_until[i]) <= now_ms();
  }
  return false;
}

typedef struct {
  buckets_peer_sys *p;
  size_t i;
  buckets_peer_info *out;
} info_job;

static void *info_main(void *arg) {
  info_job *j = arg;
  buckets_peer_sys *p = j->p;
  const char *target = BUCKETS_INTERNODE_PREFIX "peer/serverinfo";
  if (atomic_load(&p->down_until[j->i]) > now_ms()) return NULL;
  char auth[96];
  buckets_internode_sign("GET", target, auth);
  buckets_http_kv h[] = {{BUCKETS_INTERNODE_AUTH, auth}};
  buckets_http_result r;
  if (!buckets_http_client_do(p->peers[j->i], "GET", target, h, 1, NULL, 0, &r)) {
    atomic_store(&p->down_until[j->i], now_ms() + PEER_BACKOFF_MS);
    return NULL;
  }
  if (r.status == 200) j->out->json = buckets_buf_detach(&r.body);
  buckets_http_result_free(&r);
  return NULL;
}

buckets_peer_info *buckets_peer_server_info(buckets_peer_sys *p, size_t *n) {
  *n = p ? p->n : 0;
  if (!*n) return NULL;
  buckets_peer_info *out = buckets_xcalloc(p->n, sizeof(*out));
  info_job *jobs = buckets_xcalloc(p->n, sizeof(*jobs));
  pthread_t *th = buckets_xcalloc(p->n, sizeof(*th));
  bool *started = buckets_xcalloc(p->n, sizeof(*started));
  for (size_t i = 0; i < p->n; i++) {
    buckets_buf node = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&node, "%s:%d", buckets_http_client_host(p->peers[i]), buckets_http_client_port(p->peers[i]));
    out[i].node = buckets_buf_detach(&node);
    jobs[i] = (info_job){p, i, &out[i]};
    started[i] = pthread_create(&th[i], NULL, info_main, &jobs[i]) == 0;
    if (!started[i]) info_main(&jobs[i]);
  }
  for (size_t i = 0; i < p->n; i++) {
    if (started[i]) pthread_join(th[i], NULL);
  }
  free(started);
  free(th);
  free(jobs);
  return out;
}

void buckets_peer_info_free(buckets_peer_info *info, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(info[i].node);
    free(info[i].json);
  }
  free(info);
}

void buckets_peer_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  const buckets_peer_handlers *h = ud;
  if (!buckets_internode_verify(req)) {
    resp->status = 403;
    return;
  }
  buckets_query q = {0};
  if (!buckets_query_parse(req->query, &q)) {
    buckets_query_free(&q);
    resp->status = 400;
    return;
  }
  buckets_str path = req->path;
  const char *kind = buckets_query_get(&q, "kind"), *name = buckets_query_get(&q, "name");
  const char *bucket = buckets_query_get(&q, "bucket");
  resp->status = 200;
  if (buckets_str_eq_c(path, BUCKETS_INTERNODE_PREFIX "peer/iam") && kind && name) {
    if (h->iam) h->iam(h->ud, kind, name);
  } else if (buckets_str_eq_c(path, BUCKETS_INTERNODE_PREFIX "peer/bucket-meta") && bucket) {
    if (h->bucket) h->bucket(h->ud, bucket);
  } else if (buckets_str_eq_c(path, BUCKETS_INTERNODE_PREFIX "peer/serverinfo") && h->server_info) {
    char *json = h->server_info(h->ud);
    buckets_http_resp_header(resp, "Content-Type", "application/json");
    buckets_buf_append_c(&resp->body, json);
    free(json);
  } else {
    resp->status = 404;
  }
  buckets_query_free(&q);
}
