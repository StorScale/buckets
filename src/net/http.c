/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <llhttp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
#include "core/timefmt.h"

#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

enum { HDR_NONE, HDR_FIELD, HDR_VALUE };

typedef struct {
  size_t name_off, name_len, value_off, value_len;
} hdr_span;

typedef struct conn {
  struct buckets_http_server *srv;
  struct conn *prev, *next;
  int fd;
  llhttp_t parser;
  buckets_buf in;
  buckets_buf out;
  size_t out_off;
  /* request being accumulated */
  buckets_buf method, url, hdr, body;
  int body_fd;      /* spool file, or -1 */
  int64_t body_len;
  /* response body still being streamed */
  buckets_http_body_fn stream;
  long (*stream_view)(void *ud, const void **data);
  void (*stream_consume)(void *ud, size_t n);
  void *stream_ud;
  void (*stream_free)(void *);
  bool stream_close_after; /* close the connection when the stream ends */
  bool chunked;            /* frame the stream as chunked transfer coding */
  hdr_span spans[BUCKETS_HTTP_MAX_HEADERS];
  size_t nspans;
  int last;
  bool too_many_headers;
  bool too_large;
  bool closing;  /* close once out is flushed */
  bool peer_eof; /* client half-closed; answer what we have, then close */
  /* A handler or stream pull runs on a worker: the loop leaves the connection
   * alone (unwatched, never closed) until the worker posts back. */
  bool busy;
  /* With workers, a response stream is run on one: it pulls each chunk and
   * sends it itself, so the bytes stay on one thread (and in its caches),
   * until the socket is full, the stream ends, or it yields. Meanwhile the
   * loop leaves the connection alone; a close is deferred until it is back. */
  bool fill_inflight, close_pending;
  int stream_result; /* the worker's outcome (stream_run), read by the loop */
  buckets_tls_conn *tls;
  buckets_buf peer_certs; /* the TLS client's certificates, read once after the handshake */
  size_t npeer_certs;
  bool peer_loaded;
  /* A streamed request body: the handler already runs and reads it from pipe. */
  struct buckets_body_pipe *pipe;
  bool chunked_stream; /* ... chunked, of unknown length */
  bool read_paused;  /* pipe full: parsing and reading stop until it drains */
  bool backpressure; /* on_body asked to pause (vs. message complete) */
  bool discarding;   /* the handler finished early: drop the rest of the body */
  bool dead;         /* failed while a handler ran: close once it returns */
  bool write_wants_read; /* TLS: a send is blocked until the socket is readable */
  bool read_wants_write; /* TLS: a receive is blocked until it is writable */
  struct reactor *r; /* the loop thread that owns it */
  time_t last_active;
  time_t last_write; /* the last time response bytes left, or a write began */
  char remote[INET6_ADDRSTRLEN + 8];
} conn;

/* A loop thread and the connections it owns. The first is the caller's
 * loop, which also accepts; accepted connections are dealt round-robin. */
typedef struct reactor {
  buckets_http_server *srv;
  buckets_loop *loop;
  pthread_t thread;
  bool started;
  conn *conns;
} reactor;

struct buckets_http_server {
  buckets_http_config cfg;
  buckets_http_handler handler;
  void *ud;
  int listen_fd;
  int port;
  llhttp_settings_t settings;
  reactor *rs;
  size_t nrs, next_rs;
  atomic_size_t nconns;
  atomic_bool shutting_down;
  unsigned ticks;
};

static void conn_io(buckets_loop *loop, int fd, unsigned events, void *ud);
static bool conn_process(conn *c);
static void conn_read(conn *c);

/* ---- transport: plain TCP or TLS ------------------------------------------ */

/* >0 bytes, 0 at EOF, or BUCKETS_TLS_ERROR / _WANT_READ / _WANT_WRITE. */
static long conn_recv(conn *c, void *buf, size_t n) {
  if (c->tls) return buckets_tls_recv(c->tls, buf, n);
  for (;;) {
    ssize_t r = recv(c->fd, buf, n, 0);
    if (r >= 0) return (long)r;
    if (errno == EINTR) continue;
    return errno == EAGAIN || errno == EWOULDBLOCK ? BUCKETS_TLS_WANT_READ : BUCKETS_TLS_ERROR;
  }
}

static long conn_send(conn *c, const void *buf, size_t n) {
  if (c->tls) return buckets_tls_send(c->tls, buf, n);
  for (;;) {
    ssize_t r = send(c->fd, buf, n, SEND_FLAGS);
    if (r > 0) return (long)r;
    if (r < 0 && errno == EINTR) continue;
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? BUCKETS_TLS_WANT_WRITE : BUCKETS_TLS_ERROR;
  }
}

/* ---- response helpers ---------------------------------------------------- */

void buckets_http_resp_header(buckets_http_response *resp, const char *name, const char *value) {
  buckets_buf_appendf(&resp->headers, "%s: %s\r\n", name, value);
}

void buckets_http_resp_header_set(buckets_http_response *resp, const char *name, const char *value) {
  buckets_http_resp_header_del(resp, name);
  buckets_http_resp_header(resp, name, value);
}

void buckets_http_resp_header_del(buckets_http_response *resp, const char *name) {
  /* Drop the "name:" lines (case-insensitive). */
  buckets_buf kept = BUCKETS_BUF_INIT;
  size_t nl = strlen(name);
  const char *p = resp->headers.data, *end = p + resp->headers.len;
  while (p && p < end) {
    const char *eol = memchr(p, '\n', (size_t)(end - p));
    const char *next = eol ? eol + 1 : end;
    if (!((size_t)(next - p) > nl && p[nl] == ':' && strncasecmp(p, name, nl) == 0))
      buckets_buf_append(&kept, p, (size_t)(next - p));
    p = next;
  }
  buckets_buf_reset(&resp->headers);
  if (kept.len) buckets_buf_append(&resp->headers, kept.data, kept.len);
  buckets_buf_free(&kept);
}

void buckets_http_resp_headerf(buckets_http_response *resp, const char *name, const char *fmt, ...) {
  char val[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(val, sizeof(val), fmt, ap);
  va_end(ap);
  buckets_http_resp_header(resp, name, val);
}

const char *buckets_http_status_text(int status) {
  switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Request Entity Too Large";
    case 416: return "Requested Range Not Satisfiable";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default: return "Unknown";
  }
}

/* ---- streamed bodies ----------------------------------------------------- */

#define PIPE_HIGH (8u * 1024 * 1024) /* pause reading the socket above this */
#define PIPE_LOW (2u * 1024 * 1024)  /* and resume below this */
#define DISCARD_LIMIT (4LL * 1024 * 1024)

typedef struct buckets_body_pipe {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  buckets_buf buf;
  size_t off; /* read position in buf */
  bool done, failed, reader_gone;
  bool producer_paused, resume_posted;
  buckets_loop *loop;
  struct conn *c;
} body_pipe;

static void pipe_resume_cb(buckets_loop *loop, void *ud);

static body_pipe *pipe_new(buckets_loop *loop, struct conn *c) {
  body_pipe *p = buckets_xcalloc(1, sizeof(*p));
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->cv, NULL);
  p->loop = loop;
  p->c = c;
  return p;
}

static void pipe_free(body_pipe *p) {
  if (!p) return;
  pthread_cond_destroy(&p->cv);
  pthread_mutex_destroy(&p->mu);
  buckets_buf_free(&p->buf);
  free(p);
}

/* Producer (loop thread). Returns true when the reader wants no more input
 * for now (pause), false to keep going. */
static bool pipe_put(body_pipe *p, const char *data, size_t n) {
  pthread_mutex_lock(&p->mu);
  bool pause = false;
  if (!p->reader_gone) {
    buckets_buf_append(&p->buf, data, n);
    pthread_cond_signal(&p->cv);
    if (p->buf.len - p->off > PIPE_HIGH) pause = p->producer_paused = true;
  }
  pthread_mutex_unlock(&p->mu);
  return pause;
}

static void pipe_end(body_pipe *p, bool failed) {
  pthread_mutex_lock(&p->mu);
  p->done = true;
  p->failed |= failed;
  pthread_cond_broadcast(&p->cv);
  pthread_mutex_unlock(&p->mu);
}

/* Consumer (handler thread). */
static long pipe_read(body_pipe *p, void *out, size_t n) {
  pthread_mutex_lock(&p->mu);
  while (p->buf.len == p->off && !p->done) pthread_cond_wait(&p->cv, &p->mu);
  size_t avail = p->buf.len - p->off;
  long got = -1;
  if (avail) {
    got = (long)BUCKETS_MIN(n, avail);
    memcpy(out, p->buf.data + p->off, (size_t)got);
    p->off += (size_t)got;
    if (p->off == p->buf.len) {
      buckets_buf_reset(&p->buf);
      p->off = 0;
    } else if (p->off > PIPE_HIGH / 2) {
      buckets_buf_consume(&p->buf, p->off);
      p->off = 0;
    }
    if (p->producer_paused && !p->resume_posted && p->buf.len - p->off < PIPE_LOW) {
      p->resume_posted = true;
      buckets_loop_post(p->loop, pipe_resume_cb, p->c);
    }
  } else if (!p->failed) {
    got = 0;
  }
  pthread_mutex_unlock(&p->mu);
  return got;
}

long buckets_http_body_read(buckets_http_body_cursor *c, void *buf, size_t n) {
  const buckets_http_request *req = c->req;
  if (req->body_len < 0 && req->pipe) { /* chunked, streamed: until it ends */
    long r = pipe_read(req->pipe, buf, n);
    if (r > 0) c->off += r;
    return r;
  }
  if (c->off >= req->body_len) return 0;
  if (req->pipe) {
    long r = pipe_read(req->pipe, buf, (size_t)BUCKETS_MIN((int64_t)n, req->body_len - c->off));
    if (r == 0) return -1; /* the body ended short of Content-Length */
    if (r > 0) c->off += r;
    return r;
  }
  size_t want = (size_t)BUCKETS_MIN((int64_t)n, req->body_len - c->off);
  if (req->body_fd < 0) {
    memcpy(buf, req->body.p + c->off, want);
    c->off += (int64_t)want;
    return (long)want;
  }
  ssize_t r;
  do {
    r = pread(req->body_fd, buf, want, (off_t)c->off);
  } while (r < 0 && errno == EINTR);
  if (r <= 0) return -1; /* the spool file is shorter than recorded: I/O error */
  c->off += r;
  return (long)r;
}

buckets_str buckets_http_header_get(const buckets_http_request *req, const char *name) {
  for (size_t i = 0; i < req->nheaders; i++) {
    if (buckets_str_ieq_c(req->headers[i].name, name)) return req->headers[i].value;
  }
  return BUCKETS_STR_NULL;
}

/* ---- connection lifecycle ------------------------------------------------ */

static void request_reset(conn *c) {
  if (c->body_fd >= 0) close(c->body_fd);
  c->body_fd = -1;
  c->body_len = 0;
  buckets_buf_reset(&c->method);
  buckets_buf_reset(&c->url);
  buckets_buf_reset(&c->hdr);
  buckets_buf_reset(&c->body);
  c->nspans = 0;
  c->last = HDR_NONE;
  c->too_many_headers = false;
  c->too_large = false;
}

static void stream_end(conn *c) {
  if (c->stream_free) c->stream_free(c->stream_ud);
  c->stream = NULL;
  c->stream_view = NULL;
  c->stream_consume = NULL;
  c->stream_ud = NULL;
  c->stream_free = NULL;
}

static void conn_close(conn *c) {
  reactor *r = c->r;
  if (c->fill_inflight) { /* a worker is still reading the stream: close when it is back */
    c->close_pending = true;
    buckets_loop_unwatch(r->loop, c->fd);
    return;
  }
  stream_end(c);
  if (c->body_fd >= 0) close(c->body_fd);
  buckets_loop_unwatch(r->loop, c->fd);
  buckets_tls_conn_free(c->tls);
  buckets_buf_free(&c->peer_certs);
  c->npeer_certs = 0;
  c->peer_loaded = false;
  close(c->fd);
  if (c->prev) c->prev->next = c->next;
  else r->conns = c->next;
  if (c->next) c->next->prev = c->prev;
  atomic_fetch_sub(&c->srv->nconns, 1);
  buckets_buf_free(&c->in);
  buckets_buf_free(&c->out);
  buckets_buf_free(&c->method);
  buckets_buf_free(&c->url);
  buckets_buf_free(&c->hdr);
  buckets_buf_free(&c->body);
  free(c);
}

static void set_busy(conn *c);

/* Like conn_close, but a connection whose handler is still reading its body
 * cannot be freed yet: fail the body and close once the handler returns. */
static void conn_abort(conn *c) {
  if (!c->pipe) {
    conn_close(c);
    return;
  }
  pipe_end(c->pipe, true);
  c->dead = true;
  set_busy(c);
}

/* Writes as much of c->out as the socket takes. Returns false if the
 * connection was closed. */
static void start_stream(conn *c);

#define STREAM_CHUNK (256 * 1024)
#define CHUNK_HDR 18 /* "<hex size>\r\n", at most 16 digits */

/* Installs a pulled stream chunk into c->out. Returns -1 if the connection
 * was closed, 0 when the stream ended, 1 when there is data to send. */
static int take_chunk(conn *c, long got) {
  if (got < 0) {
    conn_close(c); /* mid-body failure: the client sees a short response */
    return -1;
  }
  if (got == 0) {
    stream_end(c);
    if (c->stream_close_after) c->closing = true;
    if (c->chunked) { /* the last chunk */
      c->chunked = false;
      buckets_buf_reset(&c->out);
      buckets_buf_append_c(&c->out, "0\r\n\r\n");
      c->out_off = 0;
      return 1;
    }
    return 0;
  }
  if (c->chunked) { /* the data sits at CHUNK_HDR: its size line goes just before it */
    char hdr[CHUNK_HDR + 1];
    int h = snprintf(hdr, sizeof(hdr), "%lx\r\n", got);
    memcpy(c->out.data + CHUNK_HDR - h, hdr, (size_t)h);
    memcpy(c->out.data + CHUNK_HDR + got, "\r\n", 2);
    c->out_off = (size_t)(CHUNK_HDR - h);
    c->out.len = (size_t)(CHUNK_HDR + got + 2);
    c->out.data[c->out.len] = '\0';
    return 1;
  }
  c->out.len = (size_t)got;
  c->out.data[c->out.len] = '\0';
  return 1;
}

/* Pulls the next stream chunk into buf (leaving room for chunk framing).
 * Streams of unknown length (listen, trace, logs) end when the server
 * shuts down, so draining does not wait for them. */
static long pull_stream(conn *c, buckets_buf *buf) {
  if (c->chunked && c->srv->shutting_down) return 0;
  if (!c->chunked) return c->stream(c->stream_ud, buf->data, buf->cap - 1);
  return c->stream(c->stream_ud, buf->data + CHUNK_HDR, buf->cap - 1 - CHUNK_HDR - 2);
}

static bool conn_flush(conn *c) {
  if (c->stream && c->srv->cfg.workers) { /* a worker sends it (the headers too) */
    if (!c->fill_inflight) start_stream(c);
    return true;
  }
  for (;;) {
    if (c->out_off >= c->out.len) {
      if (!c->stream) break;
      buckets_buf_reset(&c->out);
      c->out_off = 0;
      buckets_buf_reserve(&c->out, STREAM_CHUNK);
      int r = take_chunk(c, pull_stream(c, &c->out));
      if (r < 0) return false;
      if (r == 0) break;
      continue;
    }
    long n = conn_send(c, c->out.data + c->out_off, c->out.len - c->out_off);
    if (n > 0) {
      c->out_off += (size_t)n;
      c->last_write = time(NULL);
      continue;
    }
    if (n == BUCKETS_TLS_WANT_WRITE || n == BUCKETS_TLS_WANT_READ) {
      c->write_wants_read = n == BUCKETS_TLS_WANT_READ;
      buckets_loop_watch(c->r->loop, c->fd, c->write_wants_read ? BUCKETS_EV_READ : BUCKETS_EV_WRITE, conn_io, c);
      return true;
    }
    conn_close(c);
    return false;
  }
  buckets_buf_reset(&c->out);
  c->out_off = 0;
  if (c->closing) {
    conn_close(c);
    return false;
  }
  /* After EOF there is nothing left to read; don't poll a readable-forever fd. */
  buckets_loop_watch(c->r->loop, c->fd, c->peer_eof ? 0 : BUCKETS_EV_READ, conn_io, c);
  return true;
}

static bool conn_writing(const conn *c) { return c->out_off < c->out.len || c->stream != NULL; }

/* Best-effort write that never closes the connection; safe inside parser
 * callbacks. Whatever is left is sent by the next conn_flush(). */
static void conn_send_some(conn *c) {
  while (c->out_off < c->out.len) {
    long n = conn_send(c, c->out.data + c->out_off, c->out.len - c->out_off);
    if (n <= 0) return;
    c->out_off += (size_t)n;
    c->last_write = time(NULL);
  }
  buckets_buf_reset(&c->out);
  c->out_off = 0;
}

static void write_response(conn *c, buckets_http_response *resp, bool keep_alive) {
  buckets_http_server *srv = c->srv;
  char date[BUCKETS_TIME_HTTP_LEN + 1];
  buckets_time_http(time(NULL), date);
  c->last_write = time(NULL); /* the stall clock starts with each response */
  long long clen = resp->content_length >= 0 ? resp->content_length : (long long)resp->body.len;
  bool chunked = resp->chunked && resp->stream && !resp->head_only;
  buckets_buf_appendf(&c->out, "HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\n", resp->status,
                      buckets_http_status_text(resp->status), srv->cfg.server_header, date);
  if (chunked) buckets_buf_append_c(&c->out, "Transfer-Encoding: chunked\r\n");
  /* net/http: no length on the statuses that have no body */
  else if (resp->status >= 200 && resp->status != 204 && resp->status != 304)
    buckets_buf_appendf(&c->out, "Content-Length: %lld\r\n", clen);
  if (!keep_alive) buckets_buf_append_c(&c->out, "Connection: close\r\n");
  buckets_buf_append(&c->out, resp->headers.data, resp->headers.len);
  buckets_buf_append(&c->out, "\r\n", 2);
  if (resp->stream) {
    if (resp->head_only) {
      if (resp->stream_free) resp->stream_free(resp->stream_ud);
    } else {
      c->stream = resp->stream;
      c->stream_ud = resp->stream_ud;
      c->stream_view = resp->stream_view;
      c->stream_consume = resp->stream_consume;
      c->stream_free = resp->stream_free;
      c->chunked = chunked;
    }
    resp->stream = NULL;
    return;
  }
  if (!resp->head_only) buckets_buf_append(&c->out, resp->body.data, resp->body.len);
}

static void send_error_and_close(conn *c, int status) {
  buckets_http_response resp = {.status = status, .content_length = -1};
  write_response(c, &resp, false);
  buckets_buf_free(&resp.headers);
  c->closing = true;
  conn_flush(c);
}

/* Splits the request-target into path and query. */
static void split_target(buckets_str target, buckets_str *path, buckets_str *query) {
  buckets_str_cut(target, '?', path, query);
}

/* ---- worker hand-off ------------------------------------------------------ */

static void set_busy(conn *c) {
  c->busy = true;
  buckets_loop_unwatch(c->r->loop, c->fd); /* even HUP/ERR: nothing may close it now */
}

/* Back on the loop thread after a worker finished: resume sending, then
 * any pipelined requests. */
/* TLS may hold decrypted input the socket will never signal again. */
static void drain_pending(conn *c) {
  if (c->tls && !c->busy && !c->fill_inflight && !c->closing && !c->peer_eof && !conn_writing(c) &&
      buckets_tls_pending(c->tls)) {
    conn_read(c);
  }
}

static void resume(conn *c) {
  c->busy = false;
  if (conn_flush(c) && conn_process(c)) drain_pending(c);
}

/* ---- response streams on a worker -------------------------------------- */

enum { SR_DONE, SR_BLOCKED, SR_YIELD, SR_ERROR };
/* Bytes a worker sends before it gives the connection back (and its thread
 * to others). */
#define STREAM_YIELD (4 * 1024 * 1024)

/* On the worker that owns c: pull and send until the socket is full
 * (SR_BLOCKED), the stream has been sent (SR_DONE), it yields (SR_YIELD) or
 * something fails (SR_ERROR). take_chunk's work, minus what only the loop may
 * do (closing, watching). */
static int stream_run(conn *c) {
  for (size_t sent = 0;;) {
    if (c->out_off >= c->out.len && c->stream && c->stream_view && !c->chunked) {
      /* straight from the stream's own buffer: no copy into out */
      if (sent >= STREAM_YIELD) return SR_YIELD;
      const void *p;
      long k = c->stream_view(c->stream_ud, &p);
      if (k < 0) return SR_ERROR;
      if (k > 0) {
        long n = conn_send(c, p, (size_t)k);
        if (n > 0) {
          c->stream_consume(c->stream_ud, (size_t)n);
          sent += (size_t)n;
          c->last_write = time(NULL);
          continue;
        }
        if (n == BUCKETS_TLS_WANT_WRITE || n == BUCKETS_TLS_WANT_READ) {
          c->write_wants_read = n == BUCKETS_TLS_WANT_READ;
          return SR_BLOCKED;
        }
        return SR_ERROR;
      }
      stream_end(c);
      if (c->stream_close_after) c->closing = true;
      buckets_buf_reset(&c->out);
      c->out_off = 0;
      return SR_DONE;
    }
    if (c->out_off < c->out.len) {
      long n = conn_send(c, c->out.data + c->out_off, c->out.len - c->out_off);
      if (n > 0) {
        c->out_off += (size_t)n;
        sent += (size_t)n;
        c->last_write = time(NULL);
        continue;
      }
      if (n == BUCKETS_TLS_WANT_WRITE || n == BUCKETS_TLS_WANT_READ) {
        c->write_wants_read = n == BUCKETS_TLS_WANT_READ;
        return SR_BLOCKED;
      }
      return SR_ERROR;
    }
    if (!c->stream) return SR_DONE;
    if (sent >= STREAM_YIELD) return SR_YIELD;
    buckets_buf_reset(&c->out);
    c->out_off = 0;
    buckets_buf_reserve(&c->out, STREAM_CHUNK);
    long got = pull_stream(c, &c->out);
    if (got < 0) return SR_ERROR; /* mid-body failure: the client sees a short response */
    if (got == 0) {
      stream_end(c);
      if (c->stream_close_after) c->closing = true;
      if (c->chunked) { /* the last chunk */
        c->chunked = false;
        buckets_buf_reset(&c->out);
        buckets_buf_append_c(&c->out, "0\r\n\r\n");
        continue;
      }
      buckets_buf_reset(&c->out);
      return SR_DONE;
    }
    if (c->chunked) {
      char hdr[CHUNK_HDR + 1];
      int h = snprintf(hdr, sizeof(hdr), "%lx\r\n", got);
      memcpy(c->out.data + CHUNK_HDR - h, hdr, (size_t)h);
      memcpy(c->out.data + CHUNK_HDR + got, "\r\n", 2);
      c->out_off = (size_t)(CHUNK_HDR - h);
      c->out.len = (size_t)(CHUNK_HDR + got + 2);
    } else {
      c->out.len = (size_t)got;
    }
  }
}

static void stream_done(buckets_loop *loop, void *ud) {
  conn *c = ud;
  (void)loop;
  c->fill_inflight = false;
  if (c->close_pending || c->stream_result == SR_ERROR) {
    conn_close(c);
    return;
  }
  if (c->stream_result == SR_BLOCKED) { /* resumed by conn_io once the socket takes more */
    buckets_loop_watch(c->r->loop, c->fd, c->write_wants_read ? BUCKETS_EV_READ : BUCKETS_EV_WRITE, conn_io, c);
    return;
  }
  /* SR_YIELD runs again (behind other work); SR_DONE finishes the response
   * and serves any pipelined requests. */
  if (conn_flush(c) && conn_process(c)) drain_pending(c);
}

static void stream_task(void *ud, size_t i) {
  conn *c = ud;
  (void)i;
  c->stream_result = stream_run(c);
  buckets_loop_post(c->r->loop, stream_done, c);
}

static void start_stream(conn *c) {
  c->fill_inflight = true;
  buckets_loop_watch(c->r->loop, c->fd, 0, conn_io, c); /* the worker owns it now */
  buckets_pool_submit(c->srv->cfg.workers, stream_task, c);
}

typedef struct {
  conn *c;
  buckets_http_handler handler;
  void *ud;
  buckets_http_request req;
  buckets_http_response resp;
} job;

static void finish_request(conn *c, buckets_http_request *req, buckets_http_response *resp) {
  write_response(c, resp, req->keep_alive);
  buckets_buf_free(&resp->headers);
  buckets_buf_free(&resp->body);
  if (!req->keep_alive) {
    if (c->stream) c->stream_close_after = true;
    else c->closing = true;
  }
  request_reset(c);
}

static void job_done(buckets_loop *loop, void *ud) {
  job *j = ud;
  conn *c = j->c;
  (void)loop;
  body_pipe *p = j->req.pipe;
  if (p) {
    c->pipe = NULL;
    if (c->dead) { /* the client went away mid-body */
      buckets_buf_free(&j->resp.headers);
      buckets_buf_free(&j->resp.body);
      if (j->resp.stream_free) j->resp.stream_free(j->resp.stream_ud);
      free(j);
      pipe_free(p);
      c->busy = false;
      conn_close(c);
      return;
    }
    pthread_mutex_lock(&p->mu);
    bool done = p->done;
    p->reader_gone = true;
    pthread_mutex_unlock(&p->mu);
    if (!done) {
      /* Answered before the body was in (an error, typically): skip the rest
       * of it to keep the connection, unless that is too much to read. */
      if ((int64_t)c->parser.content_length > DISCARD_LIMIT) j->req.keep_alive = false; /* bytes still to come */
      else c->discarding = true;
      if (c->read_paused) {
        c->read_paused = false;
        llhttp_resume(&c->parser);
      }
    }
    pipe_free(p);
  }
  finish_request(c, &j->req, &j->resp);
  free(j);
  resume(c);
}

static void job_task(void *ud, size_t i) {
  job *j = ud;
  (void)i;
  reactor *r = j->c->r;
  j->handler(&j->req, &j->resp, j->ud);
  buckets_loop_post(r->loop, job_done, j);
}

/* streamed: the body is still arriving (c->pipe); the loop keeps reading. */
static void dispatch_request_mode(conn *c, bool streamed) {
  buckets_http_server *srv = c->srv;
  job *j = buckets_xcalloc(1, sizeof(*j));
  j->c = c;
  buckets_http_request *rq = &j->req;
  rq->method = buckets_buf_str(&c->method);
  rq->target = buckets_buf_str(&c->url);
  split_target(rq->target, &rq->path, &rq->query);
  for (size_t i = 0; i < c->nspans; i++) {
    rq->headers[i].name = (buckets_str){c->hdr.data + c->spans[i].name_off, c->spans[i].name_len};
    rq->headers[i].value =
        buckets_str_trim((buckets_str){c->hdr.data + c->spans[i].value_off, c->spans[i].value_len});
  }
  rq->nheaders = c->nspans;
  rq->body = buckets_buf_str(&c->body);
  rq->body_fd = c->body_fd;
  rq->body_len = c->body_fd >= 0 ? c->body_len : (int64_t)c->body.len;
  rq->keep_alive = llhttp_should_keep_alive(&c->parser) && !srv->shutting_down;
  rq->remote_addr = c->remote;
  rq->secure = c->tls != NULL;
  if (c->tls && !c->peer_loaded) {
    c->npeer_certs = buckets_tls_peer_chain(c->tls, &c->peer_certs);
    c->peer_loaded = true;
  }
  rq->peer_certs = c->npeer_certs ? &c->peer_certs : NULL;
  rq->npeer_certs = c->npeer_certs;
  if (streamed) {
    rq->pipe = c->pipe;
    rq->body_fd = -1;
    rq->body_len = c->chunked_stream ? -1 : (int64_t)c->parser.content_length;
  }
  j->resp = (buckets_http_response){.status = 200, .content_length = -1};
  j->resp.head_only = buckets_str_eq_c(rq->method, "HEAD");
  j->handler = srv->handler;
  j->ud = srv->ud;
  buckets_pool *workers = srv->cfg.workers;
  for (size_t i = 0; i < srv->cfg.nroutes; i++) {
    const buckets_http_route *r = &srv->cfg.routes[i];
    size_t pl = strlen(r->prefix);
    if (rq->path.n >= pl && memcmp(rq->path.p, r->prefix, pl) == 0) {
      j->handler = r->handler;
      j->ud = r->ud;
      workers = r->workers;
      break;
    }
  }
  if (streamed) {
    buckets_pool_submit(workers ? workers : srv->cfg.workers, job_task, j);
    return;
  }
  if (workers) {
    set_busy(c);
    buckets_pool_submit(workers, job_task, j);
    return;
  }
  j->handler(rq, &j->resp, j->ud);
  finish_request(c, rq, &j->resp);
  free(j);
}

static void dispatch_request(conn *c) { dispatch_request_mode(c, false); }

/* Backpressure released: the handler drained the pipe below the low mark. */
static void pipe_resume_cb(buckets_loop *loop, void *ud) {
  conn *c = ud;
  (void)loop;
  if (c->pipe) {
    pthread_mutex_lock(&c->pipe->mu);
    c->pipe->producer_paused = false;
    c->pipe->resume_posted = false;
    pthread_mutex_unlock(&c->pipe->mu);
  }
  if (!c->read_paused || c->busy) return;
  c->read_paused = false;
  llhttp_resume(&c->parser);
  buckets_loop_watch(c->r->loop, c->fd, BUCKETS_EV_READ, conn_io, c);
  if (conn_process(c)) drain_pending(c);
}

/* Feeds buffered input to the parser, dispatching complete requests one at a
 * time. Stops while a response is still being written (pipelining backpressure). */
static bool conn_process(conn *c) {
  if (c->busy || c->read_paused || c->fill_inflight) return true;
  /* fill_inflight: a worker took the response stream on (inside the loop too) */
  while (c->in.len > 0 && !c->fill_inflight && !conn_writing(c) && !c->closing) {
    llhttp_errno_t err = llhttp_execute(&c->parser, c->in.data, c->in.len);
    if (err == HPE_OK) {
      buckets_buf_reset(&c->in);
      break;
    }
    if (err == HPE_PAUSED) {
      const char *pos = llhttp_get_error_pos(&c->parser);
      buckets_buf_consume(&c->in, (size_t)(pos - c->in.data));
      if (c->backpressure) { /* the pipe is full: stop until the handler drains it */
        c->backpressure = false;
        c->read_paused = true;
        buckets_loop_watch(c->r->loop, c->fd, 0, conn_io, c);
        return true;
      }
      if (c->pipe) { /* a streamed body is complete; its handler is running */
        pipe_end(c->pipe, false);
        llhttp_resume(&c->parser);
        set_busy(c); /* job_done takes over */
        return true;
      }
      if (c->discarding) { /* the unwanted rest of an answered request */
        c->discarding = false;
        request_reset(c);
        llhttp_resume(&c->parser);
        continue;
      }
      dispatch_request(c);
      llhttp_resume(&c->parser);
      if (c->busy) return true; /* job_done resumes */
      if (!conn_flush(c)) return false;
      continue;
    }
    send_error_and_close(c, c->too_large ? 413 : 400);
    return false;
  }
  if (c->peer_eof) {
    if (c->pipe) { /* EOF in the middle of a streamed body */
      conn_abort(c);
      return false;
    }
    if (!conn_writing(c)) {
      conn_close(c);
      return false;
    }
    /* Close after the last response, unless pipelined requests are still
     * queued behind this write (the WRITE path resumes processing them). */
    if (c->in.len == 0) c->closing = true;
  }
  return true;
}

/* Reads until the transport would block, parsing (and spooling bodies) every
 * megabyte so a fast client cannot make us buffer without bound. */
static void conn_read(conn *c) {
  for (;;) {
    buckets_buf_reserve(&c->in, 64 * 1024);
    long n = conn_recv(c, c->in.data + c->in.len, c->in.cap - c->in.len - 1);
    if (n > 0) {
      c->in.len += (size_t)n;
      c->in.data[c->in.len] = '\0';
      if (c->in.len > 1024 * 1024) {
        if (!conn_process(c)) return;
        if (c->busy || c->read_paused || conn_writing(c) || c->closing) return; /* resumed later */
      }
      continue;
    }
    if (n == BUCKETS_TLS_WANT_READ) break;
    if (n == BUCKETS_TLS_WANT_WRITE) { /* TLS handshake output is blocked */
      c->read_wants_write = true;
      buckets_loop_watch(c->r->loop, c->fd, BUCKETS_EV_READ | BUCKETS_EV_WRITE, conn_io, c);
      break;
    }
    if (n < 0) { /* reset or error: nobody is listening for responses */
      conn_abort(c);
      return;
    }
    /* Orderly EOF: requests may already be buffered, so answer them first. */
    c->peer_eof = true;
    buckets_loop_watch(c->r->loop, c->fd, conn_writing(c) ? BUCKETS_EV_WRITE : 0, conn_io, c);
    break;
  }
  conn_process(c);
}

static void conn_io(buckets_loop *loop, int fd, unsigned events, void *ud) {
  conn *c = ud;
  (void)loop;
  (void)fd;
  c->last_active = time(NULL);
  if (c->busy || c->fill_inflight) return; /* a worker owns it: events queued before it did are stale */
  if (c->read_paused) { /* waiting for the handler to drain the body pipe */
    if (events & BUCKETS_EV_ERROR) conn_abort(c);
    return;
  }
  bool retry_read = c->read_wants_write && (events & BUCKETS_EV_WRITE);
  if (retry_read) c->read_wants_write = false;
  if (((events & BUCKETS_EV_WRITE) && !retry_read) || (c->write_wants_read && (events & BUCKETS_EV_READ))) {
    c->write_wants_read = false;
    if (!conn_flush(c)) return;
    if (conn_process(c)) drain_pending(c);
    return;
  }
  if (c->peer_eof) return;
  if (!(events & BUCKETS_EV_READ) && !retry_read) return;
  conn_read(c);
}

/* ---- llhttp callbacks ---------------------------------------------------- */

static int on_method(llhttp_t *p, const char *at, size_t n) {
  buckets_buf_append(&((conn *)p->data)->method, at, n);
  return 0;
}

static int on_url(llhttp_t *p, const char *at, size_t n) {
  buckets_buf_append(&((conn *)p->data)->url, at, n);
  return 0;
}

static int on_header_field(llhttp_t *p, const char *at, size_t n) {
  conn *c = p->data;
  if (c->last != HDR_FIELD) {
    if (c->nspans == BUCKETS_HTTP_MAX_HEADERS) {
      c->too_many_headers = true;
      return -1;
    }
    c->spans[c->nspans++] = (hdr_span){c->hdr.len, 0, 0, 0};
  }
  buckets_buf_append(&c->hdr, at, n);
  c->spans[c->nspans - 1].name_len += n;
  c->last = HDR_FIELD;
  return 0;
}

static int on_header_value(llhttp_t *p, const char *at, size_t n) {
  conn *c = p->data;
  if (c->nspans == 0) return -1;
  hdr_span *s = &c->spans[c->nspans - 1];
  if (c->last != HDR_VALUE) s->value_off = c->hdr.len;
  buckets_buf_append(&c->hdr, at, n);
  s->value_len += n;
  c->last = HDR_VALUE;
  return 0;
}

static int open_spool(const char *dir) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/body-XXXXXX", dir && *dir ? dir : "/tmp");
  int fd = mkstemp(path);
  if (fd < 0) return -1;
  unlink(path); /* anonymous: disappears with the descriptor */
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  return fd;
}

static int on_headers_complete(llhttp_t *p) {
  conn *c = p->data;
  const buckets_http_config *cfg = &c->srv->cfg;
  bool has_len = (p->flags & F_CONTENT_LENGTH) != 0;
  if (has_len && p->content_length > (uint64_t)cfg->max_body) {
    c->too_large = true;
    return -1;
  }
  bool big = has_len && p->content_length > cfg->mem_body_limit;
  bool stream = big && !(p->flags & F_CHUNKED) && cfg->workers;
  bool chunked_stream = false;
  if ((p->flags & F_CHUNKED) && cfg->workers && cfg->stream_chunked) {
    buckets_str target = buckets_buf_str(&c->url), path, query;
    split_target(target, &path, &query);
    chunked_stream = stream = cfg->stream_chunked(path);
  }
  c->chunked_stream = chunked_stream;
  if (!stream && ((p->flags & F_CHUNKED) || big)) {
    c->body_fd = open_spool(cfg->spool_dir);
    if (c->body_fd < 0) {
      buckets_log_error("spool request body in %s: %s", cfg->spool_dir, strerror(errno));
      return -1;
    }
  }
  for (size_t i = 0; i < c->nspans; i++) {
    buckets_str name = {c->hdr.data + c->spans[i].name_off, c->spans[i].name_len};
    buckets_str value = {c->hdr.data + c->spans[i].value_off, c->spans[i].value_len};
    if (buckets_str_ieq_c(name, "expect") && buckets_str_ieq_c(buckets_str_trim(value), "100-continue")) {
      buckets_buf_append_c(&c->out, "HTTP/1.1 100 Continue\r\n\r\n");
      conn_send_some(c);
    }
  }
  if (stream) { /* the handler starts now and reads the body as it arrives */
    c->pipe = pipe_new(c->r->loop, c);
    dispatch_request_mode(c, true);
  }
  return 0;
}

static int on_body(llhttp_t *p, const char *at, size_t n) {
  conn *c = p->data;
  if (c->discarding) return 0;
  if (c->pipe) {
    if (pipe_put(c->pipe, at, n)) {
      c->backpressure = true;
      return HPE_PAUSED;
    }
    return 0;
  }
  int64_t have = c->body_fd >= 0 ? c->body_len : (int64_t)c->body.len;
  if (have + (int64_t)n > c->srv->cfg.max_body) {
    c->too_large = true;
    return -1;
  }
  if (c->body_fd < 0) {
    buckets_buf_append(&c->body, at, n);
    return 0;
  }
  /* Synchronous spool write; moves to the disk thread pool with the object layer. */
  while (n) {
    ssize_t w = write(c->body_fd, at, n);
    if (w < 0 && errno == EINTR) continue;
    if (w < 0) return -1;
    at += w;
    n -= (size_t)w;
    c->body_len += w;
  }
  return 0;
}

static int on_message_complete(llhttp_t *p) { return HPE_PAUSED; }

/* ---- accept / listen ----------------------------------------------------- */

/* On the connection's own loop thread. */
static void adopt(buckets_loop *loop, void *ud) {
  conn *c = ud;
  reactor *r = c->r;
  c->next = r->conns;
  if (r->conns) r->conns->prev = c;
  r->conns = c;
  if (buckets_loop_watch(loop, c->fd, BUCKETS_EV_READ, conn_io, c) != 0) conn_close(c);
}

static void on_accept(buckets_loop *loop, int fd, unsigned events, void *ud) {
  buckets_http_server *srv = ud;
  for (;;) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int cfd = accept(fd, (struct sockaddr *)&ss, &sl);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      if (errno != EAGAIN && errno != EWOULDBLOCK) buckets_log_warn("accept: %s", strerror(errno));
      return;
    }
    fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);
    fcntl(cfd, F_SETFD, FD_CLOEXEC);
    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    conn *c = buckets_xcalloc(1, sizeof(*c));
    c->srv = srv;
    c->fd = cfd;
    c->body_fd = -1;
    c->last_active = time(NULL);
    if (ss.ss_family == AF_INET6) {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, c->remote, sizeof(c->remote));
    } else if (ss.ss_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, c->remote, sizeof(c->remote));
    }
    if (srv->cfg.tls && !(c->tls = buckets_tls_accept(srv->cfg.tls, cfd))) {
      close(cfd);
      free(c);
      continue;
    }
    llhttp_init(&c->parser, HTTP_REQUEST, &srv->settings);
    c->parser.data = c;
    c->r = &srv->rs[srv->next_rs++ % srv->nrs];
    atomic_fetch_add(&srv->nconns, 1);
    if (c->r->loop == loop) adopt(loop, c);
    else buckets_loop_post(c->r->loop, adopt, c);
  }
}

static int try_bind(const struct addrinfo *ai) {
  int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) return -1;
  int one = 1, zero = 0;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (ai->ai_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
  if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 1024) == 0) return fd;
  close(fd);
  return -1;
}

static int listen_socket(const char *host, int port, int *bound_port) {
  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%d", port);
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  int rc = getaddrinfo(host && *host ? host : NULL, portstr, &hints, &res);
  if (rc != 0) {
    buckets_log_error("resolve %s:%d: %s", host ? host : "", port, gai_strerror(rc));
    return -1;
  }
  /* Prefer a dual-stack IPv6 socket when binding all interfaces. */
  struct addrinfo *pick = res;
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET6) {
      pick = ai;
      break;
    }
  }
  int fd = try_bind(pick);
  for (struct addrinfo *ai = res; fd < 0 && ai; ai = ai->ai_next) {
    if (ai != pick) fd = try_bind(ai);
  }
  freeaddrinfo(res);
  if (fd < 0) {
    buckets_log_error("listen on %s:%d: %s", host ? host : "*", port, strerror(errno));
    return -1;
  }
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  struct sockaddr_storage ss;
  socklen_t sl = sizeof(ss);
  getsockname(fd, (struct sockaddr *)&ss, &sl);
  *bound_port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                               : ((struct sockaddr_in *)&ss)->sin_port);
  return fd;
}

static void on_tick(reactor *r) {
  buckets_http_server *srv = r->srv;
  time_t now = time(NULL);
  if (r == srv->rs && srv->cfg.tls && ++srv->ticks % 5 == 0) buckets_tls_reload(srv->cfg.tls);
  for (conn *c = r->conns, *next; c; c = next) {
    next = c->next;
    if (c->fill_inflight) continue; /* a worker owns it (and waits on our own data don't count) */
    bool idle = !c->busy && !c->pipe && !c->read_paused && c->in.len == 0 && !conn_writing(c);
    if (idle && (srv->shutting_down || now - c->last_active > srv->cfg.idle_timeout_sec)) {
      conn_close(c);
      continue;
    }
    /* A client that stops reading a response would otherwise hold its
     * stream (and the object's read lock) forever. Waits for our own data
     * (a stream fill) do not count. */
    if (!c->busy && conn_writing(c) &&
        now - (c->last_write ? c->last_write : c->last_active) > srv->cfg.write_timeout_sec) {
      buckets_log_warn("closing %s: response stalled for %ds", c->remote, srv->cfg.write_timeout_sec);
      conn_close(c);
    }
  }
}

static void tick_cb(buckets_loop *loop, void *ud) { on_tick(ud); }

static void stop_cb(buckets_loop *loop, void *ud) { buckets_loop_stop(loop); }

static void *reactor_main(void *ud) {
  reactor *r = ud;
  buckets_loop_run(r->loop);
  return NULL;
}

buckets_http_server *buckets_http_server_start(buckets_loop *loop, const buckets_http_config *cfg,
                                               buckets_http_handler handler, void *ud) {
  buckets_http_server *srv = buckets_xcalloc(1, sizeof(*srv));
  srv->cfg = *cfg;
  if (!srv->cfg.server_header) srv->cfg.server_header = "Buckets";
  if (srv->cfg.idle_timeout_sec <= 0) srv->cfg.idle_timeout_sec = 30;
  if (srv->cfg.write_timeout_sec <= 0) srv->cfg.write_timeout_sec = 60;
  if (srv->cfg.mem_body_limit == 0) srv->cfg.mem_body_limit = 1024 * 1024;
  srv->handler = handler;
  srv->ud = ud;
  llhttp_settings_init(&srv->settings);
  srv->settings.on_method = on_method;
  srv->settings.on_url = on_url;
  srv->settings.on_header_field = on_header_field;
  srv->settings.on_header_value = on_header_value;
  srv->settings.on_headers_complete = on_headers_complete;
  srv->settings.on_body = on_body;
  srv->settings.on_message_complete = on_message_complete;

  srv->listen_fd = listen_socket(cfg->host, cfg->port, &srv->port);
  if (srv->listen_fd < 0) {
    free(srv);
    return NULL;
  }
  srv->nrs = cfg->reactors > 1 ? (size_t)cfg->reactors : 1;
  srv->rs = buckets_xcalloc(srv->nrs, sizeof(*srv->rs));
  for (size_t i = 0; i < srv->nrs; i++) {
    reactor *r = &srv->rs[i];
    r->srv = srv;
    r->loop = i == 0 ? loop : buckets_loop_new();
    buckets_loop_add_tick(r->loop, tick_cb, r);
    if (i > 0 && !(r->started = pthread_create(&r->thread, NULL, reactor_main, r) == 0)) {
      buckets_log_error("http: starting loop thread %zu: %s", i, strerror(errno));
      buckets_loop_free(r->loop);
      srv->nrs = i;
      break;
    }
  }
  buckets_loop_watch(loop, srv->listen_fd, BUCKETS_EV_READ, on_accept, srv);
  return srv;
}

void buckets_http_server_shutdown(buckets_http_server *srv) {
  if (atomic_exchange(&srv->shutting_down, true)) return;
  if (srv->listen_fd >= 0) {
    buckets_loop_unwatch(srv->rs[0].loop, srv->listen_fd);
    close(srv->listen_fd);
    srv->listen_fd = -1;
  }
  on_tick(&srv->rs[0]);
  for (size_t i = 1; i < srv->nrs; i++) buckets_loop_post(srv->rs[i].loop, tick_cb, &srv->rs[i]);
}

size_t buckets_http_server_connections(const buckets_http_server *srv) { return atomic_load(&srv->nconns); }

int buckets_http_server_port(const buckets_http_server *srv) { return srv->port; }

void buckets_http_server_free(buckets_http_server *srv) {
  if (!srv) return;
  /* The worker pools are gone by now: a fill still marked in flight will
   * never come back (its completion is never run), so close regardless. */
  for (size_t i = 1; i < srv->nrs; i++) {
    buckets_loop_post(srv->rs[i].loop, stop_cb, NULL);
    pthread_join(srv->rs[i].thread, NULL);
  }
  for (size_t i = 0; i < srv->nrs; i++) {
    reactor *r = &srv->rs[i];
    while (r->conns) {
      r->conns->fill_inflight = false;
      conn_close(r->conns);
    }
    if (i > 0) buckets_loop_free(r->loop);
  }
  if (srv->listen_fd >= 0) close(srv->listen_fd);
  free(srv->rs);
  free(srv);
}
