/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/peerstream.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/common.h"
#include "dist/internode.h"

typedef struct {
  struct buckets_peer_relay *r;
  buckets_http_client *peer;
  pthread_t th;
  bool started;
} reader;

struct buckets_peer_relay {
  _Atomic bool stop;
  char *target;
  buckets_peer_line_fn sink;
  void *ud;
  reader *readers;
  size_t n;
};

static void *reader_main(void *arg) {
  reader *rd = arg;
  buckets_peer_relay *r = rd->r;
  while (!atomic_load(&r->stop)) {
    char auth[96];
    buckets_internode_sign("GET", r->target, auth);
    buckets_http_kv h[] = {{BUCKETS_INTERNODE_AUTH, auth}};
    int status = 0;
    buckets_buf hdrs = BUCKETS_BUF_INIT;
    buckets_http_stream *s = buckets_http_client_open(rd->peer, "GET", r->target, h, 1, NULL, NULL, 0, &status, &hdrs);
    buckets_buf_free(&hdrs);
    if (!s || status != 200) {
      if (s) buckets_http_stream_free(s);
      for (int i = 0; i < 10 && !atomic_load(&r->stop); i++) usleep(100000); /* the peer is down: retry */
      continue;
    }
    buckets_buf line = BUCKETS_BUF_INIT;
    char buf[16384];
    long k;
    while (!atomic_load(&r->stop) && (k = buckets_http_stream_read(s, buf, sizeof(buf))) > 0) {
      for (long i = 0; i < k; i++) {
        if (buf[i] == '\n') {
          if (line.len) r->sink(r->ud, line.data, line.len);
          buckets_buf_reset(&line);
        } else if (!(buf[i] == ' ' && !line.len)) { /* keep-alive spaces between records */
          buckets_buf_append_char(&line, buf[i]);
        }
      }
    }
    buckets_buf_free(&line);
    buckets_http_stream_free(s);
  }
  return NULL;
}

buckets_peer_relay *buckets_peer_relay_start(buckets_http_client *const *peers, size_t n, const char *target,
                                             buckets_peer_line_fn sink, void *ud) {
  buckets_peer_relay *r = buckets_xcalloc(1, sizeof(*r));
  r->target = buckets_xstrdup(target);
  r->sink = sink;
  r->ud = ud;
  r->n = n;
  r->readers = buckets_xcalloc(n ? n : 1, sizeof(*r->readers));
  for (size_t i = 0; i < n; i++) {
    r->readers[i] = (reader){r, peers[i], 0, false};
    r->readers[i].started = pthread_create(&r->readers[i].th, NULL, reader_main, &r->readers[i]) == 0;
  }
  return r;
}

void buckets_peer_relay_stop(buckets_peer_relay *r) {
  if (!r) return;
  atomic_store(&r->stop, true);
  for (size_t i = 0; i < r->n; i++)
    if (r->readers[i].started) pthread_join(r->readers[i].th, NULL);
  free(r->readers);
  free(r->target);
  free(r);
}
