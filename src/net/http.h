/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_HTTP_H
#define BUCKETS_NET_HTTP_H

#include "core/buf.h"
#include "core/loop.h"
#include "core/pool.h"
#include "net/tls.h"
#include "core/str.h"

#define BUCKETS_HTTP_MAX_HEADERS 128

typedef struct {
  buckets_str name;
  buckets_str value;
} buckets_http_header;

/* A fully received request. All slices point into connection-owned memory and
 * are valid only for the duration of the handler call.
 *
 * Small bodies (<= mem_body_limit) are in memory in `body`. Larger bodies
 * with a Content-Length are streamed: the handler starts once the headers are
 * in and reads the body as it arrives (`pipe`, with backpressure on the
 * socket). Without worker threads, or with chunked transfer encoding, large
 * bodies are spooled to an unlinked temp file (body_fd >= 0). Use
 * buckets_http_body_read() to consume any kind, sequentially. */
typedef struct {
  buckets_str method;
  buckets_str target; /* raw request-target, e.g. "/bucket/key?uploads" */
  buckets_str path;   /* raw (percent-encoded) path portion of target */
  buckets_str query;  /* raw query string without the leading '?' */
  buckets_http_header headers[BUCKETS_HTTP_MAX_HEADERS];
  size_t nheaders;
  buckets_str body;
  int body_fd;       /* -1 when the body is in memory */
  int64_t body_len;  /* total body bytes in either representation */
  bool keep_alive;
  bool secure; /* arrived over TLS */
  /* The TLS client's certificates (see buckets_tls_peer_chain), or NULL. */
  const buckets_buf *peer_certs;
  size_t npeer_certs;
  /* Set for large bodies streamed to the handler while they arrive (it runs
   * before the body is complete); read it with buckets_http_body_read. */
  struct buckets_body_pipe *pipe;
  const char *remote_addr;
} buckets_http_request;

/* Case-insensitive header lookup. Returns a slice with p == NULL when absent. */
buckets_str buckets_http_header_get(const buckets_http_request *req, const char *name);

/* Sequential reader over a request body, whichever way it is stored. */
typedef struct {
  const buckets_http_request *req;
  int64_t off;
} buckets_http_body_cursor;

/* Returns bytes read, 0 at end of body, -1 on I/O error or when the client
 * went away mid-body. May block while a streamed body is still arriving. */
long buckets_http_body_read(buckets_http_body_cursor *c, void *buf, size_t n);

/* Streaming response body: called whenever the socket can take more data.
 * Returns bytes written into buf, 0 when finished, -1 on error (the
 * connection is then closed, since headers are already on the wire). */
typedef long (*buckets_http_body_fn)(void *ud, char *buf, size_t cap);

typedef struct {
  int status;
  buckets_buf headers; /* serialized "Name: value\r\n" lines */
  buckets_buf body;
  bool head_only;          /* HEAD response: send Content-Length, omit body */
  long long content_length; /* -1: use body.len; required with a stream */
  buckets_http_body_fn stream; /* optional; replaces `body` */
  void *stream_ud;
  void (*stream_free)(void *ud); /* called once the stream is done or abandoned */
} buckets_http_response;

void buckets_http_resp_header(buckets_http_response *resp, const char *name, const char *value);
void buckets_http_resp_headerf(buckets_http_response *resp, const char *name, const char *fmt, ...)
    BUCKETS_PRINTF(3, 4);
const char *buckets_http_status_text(int status);

typedef void (*buckets_http_handler)(const buckets_http_request *req, buckets_http_response *resp,
                                     void *ud);

/* Requests whose path starts with prefix go to their own handler and worker
 * pool (internode RPC must never queue behind client requests). */
typedef struct {
  const char *prefix;
  buckets_http_handler handler;
  void *ud;
  buckets_pool *workers; /* NULL: inline on the loop thread */
} buckets_http_route;

#define BUCKETS_HTTP_MAX_ROUTES 16

typedef struct {
  const char *host; /* NULL or "" binds all interfaces */
  int port;
  int64_t max_body;       /* largest accepted request body */
  size_t mem_body_limit;  /* bodies up to this size stay in memory */
  const char *spool_dir;  /* where larger bodies are spooled */
  int idle_timeout_sec;
  int write_timeout_sec; /* close a response that makes no progress this long (default 60) */
  const char *server_header; /* value of the Server response header */
  /* Runs handlers and response-stream pulls, so the loop thread only moves
   * bytes. NULL runs them inline on the loop thread. Must outlive the server's
   * connections: free the pool (draining it) before the server. */
  buckets_pool *workers;
  /* Serve HTTPS with these certificates (reloaded when they change); NULL
   * serves plain HTTP. Owned by the caller. */
  buckets_tls *tls;
  buckets_http_route routes[BUCKETS_HTTP_MAX_ROUTES];
  size_t nroutes;
} buckets_http_config;

typedef struct buckets_http_server buckets_http_server;

buckets_http_server *buckets_http_server_start(buckets_loop *loop, const buckets_http_config *cfg,
                                               buckets_http_handler handler, void *ud);
/* Stops accepting and closes idle connections; in-flight responses finish. */
void buckets_http_server_shutdown(buckets_http_server *srv);
size_t buckets_http_server_connections(const buckets_http_server *srv);
int buckets_http_server_port(const buckets_http_server *srv);
void buckets_http_server_free(buckets_http_server *srv);

#endif
