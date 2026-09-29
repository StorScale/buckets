/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "admin/jobstream.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/common.h"

struct buckets_jobstream {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  pthread_t thread;
  buckets_job_fn fn;
  void *ud;
  void (*ud_free)(void *);
  buckets_buf out;       /* emitted, not yet written */
  size_t pos;
  buckets_buf keepalive; /* repeated while idle (empty: none) */
  int keepalive_ms;
  bool done, cancelled;
};

static void *run(void *arg) {
  buckets_jobstream *j = arg;
  j->fn(j, j->ud);
  pthread_mutex_lock(&j->mu);
  j->done = true;
  pthread_cond_broadcast(&j->cv);
  pthread_mutex_unlock(&j->mu);
  return NULL;
}

void buckets_jobstream_emit(buckets_jobstream *j, const char *data, size_t n) {
  pthread_mutex_lock(&j->mu);
  buckets_buf_append(&j->out, data, n);
  pthread_cond_broadcast(&j->cv);
  pthread_mutex_unlock(&j->mu);
}

void buckets_jobstream_set_keepalive(buckets_jobstream *j, const char *data, size_t n) {
  pthread_mutex_lock(&j->mu);
  buckets_buf_reset(&j->keepalive);
  buckets_buf_append(&j->keepalive, data, n);
  pthread_mutex_unlock(&j->mu);
}

bool buckets_jobstream_cancelled(buckets_jobstream *j) {
  pthread_mutex_lock(&j->mu);
  bool c = j->cancelled;
  pthread_mutex_unlock(&j->mu);
  return c;
}

static long js_read(void *ud, char *buf, size_t cap) {
  buckets_jobstream *j = ud;
  pthread_mutex_lock(&j->mu);
  while (j->pos == j->out.len) {
    buckets_buf_reset(&j->out);
    j->pos = 0;
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += j->keepalive_ms / 1000;
    until.tv_nsec += (long)(j->keepalive_ms % 1000) * 1000000L;
    if (until.tv_nsec >= 1000000000L) until.tv_sec++, until.tv_nsec -= 1000000000L;
    bool timed_out = false;
    while (!j->out.len && !j->done && !timed_out)
      timed_out = pthread_cond_timedwait(&j->cv, &j->mu, &until) != 0;
    if (!j->out.len && j->done) {
      pthread_mutex_unlock(&j->mu);
      return 0;
    }
    /* idle: the keepalive, if there is one (otherwise wait again) */
    if (!j->out.len && j->keepalive.len) buckets_buf_append(&j->out, j->keepalive.data, j->keepalive.len);
  }
  size_t k = j->out.len - j->pos;
  if (k > cap) k = cap;
  memcpy(buf, j->out.data + j->pos, k);
  j->pos += k;
  pthread_mutex_unlock(&j->mu);
  return (long)k;
}

static void js_free(void *ud) {
  buckets_jobstream *j = ud;
  pthread_mutex_lock(&j->mu);
  j->cancelled = true;
  pthread_mutex_unlock(&j->mu);
  pthread_join(j->thread, NULL);
  if (j->ud_free) j->ud_free(j->ud);
  buckets_buf_free(&j->out);
  buckets_buf_free(&j->keepalive);
  pthread_cond_destroy(&j->cv);
  pthread_mutex_destroy(&j->mu);
  free(j);
}

void buckets_jobstream_start(buckets_http_response *resp, buckets_job_fn fn, void *ud, void (*ud_free)(void *),
                             int keepalive_ms, const char *keepalive) {
  buckets_jobstream *j = buckets_xcalloc(1, sizeof(*j));
  pthread_mutex_init(&j->mu, NULL);
  pthread_cond_init(&j->cv, NULL);
  j->fn = fn;
  j->ud = ud;
  j->ud_free = ud_free;
  j->keepalive_ms = keepalive_ms > 0 ? keepalive_ms : 1000;
  if (keepalive) buckets_buf_append_c(&j->keepalive, keepalive);
  if (pthread_create(&j->thread, NULL, run, j) != 0) buckets_fatal("start admin job");
  resp->status = 200;
  resp->chunked = true;
  resp->stream = js_read;
  resp->stream_ud = j;
  resp->stream_free = js_free;
}
