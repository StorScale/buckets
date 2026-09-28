/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <llhttp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  void *stream_ud;
  void (*stream_free)(void *);
  bool stream_close_after; /* close the connection when the stream ends */
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
  long fill_got;
  time_t last_active;
  char remote[INET6_ADDRSTRLEN + 8];
} conn;

struct buckets_http_server {
  buckets_loop *loop;
  buckets_http_config cfg;
  buckets_http_handler handler;
  void *ud;
  int listen_fd;
  int port;
  llhttp_settings_t settings;
  conn *conns;
  size_t nconns;
  bool shutting_down;
};

static void conn_io(buckets_loop *loop, int fd, unsigned events, void *ud);
static bool conn_process(conn *c);

/* ---- response helpers ---------------------------------------------------- */

void buckets_http_resp_header(buckets_http_response *resp, const char *name, const char *value) {
  buckets_buf_appendf(&resp->headers, "%s: %s\r\n", name, value);
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

long buckets_http_body_read(buckets_http_body_cursor *c, void *buf, size_t n) {
  const buckets_http_request *req = c->req;
  if (c->off >= req->body_len) return 0;
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
  c->stream_ud = NULL;
  c->stream_free = NULL;
}

static void conn_close(conn *c) {
  buckets_http_server *srv = c->srv;
  stream_end(c);
  if (c->body_fd >= 0) close(c->body_fd);
  buckets_loop_unwatch(srv->loop, c->fd);
  close(c->fd);
  if (c->prev) c->prev->next = c->next;
  else srv->conns = c->next;
  if (c->next) c->next->prev = c->prev;
  srv->nconns--;
  buckets_buf_free(&c->in);
  buckets_buf_free(&c->out);
  buckets_buf_free(&c->method);
  buckets_buf_free(&c->url);
  buckets_buf_free(&c->hdr);
  buckets_buf_free(&c->body);
  free(c);
}

/* Writes as much of c->out as the socket takes. Returns false if the
 * connection was closed. */
static void start_fill(conn *c);

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
    return 0;
  }
  c->out.len = (size_t)got;
  c->out.data[c->out.len] = '\0';
  return 1;
}

static bool conn_flush(conn *c) {
  for (;;) {
    if (c->out_off >= c->out.len) {
      if (!c->stream) break;
      buckets_buf_reset(&c->out);
      c->out_off = 0;
      buckets_buf_reserve(&c->out, 256 * 1024);
      if (c->srv->cfg.workers) {
        start_fill(c);
        return true;
      }
      int r = take_chunk(c, c->stream(c->stream_ud, c->out.data, c->out.cap - 1));
      if (r < 0) return false;
      if (r == 0) break;
      continue;
    }
    ssize_t n = send(c->fd, c->out.data + c->out_off, c->out.len - c->out_off, SEND_FLAGS);
    if (n > 0) {
      c->out_off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      buckets_loop_watch(c->srv->loop, c->fd, BUCKETS_EV_WRITE, conn_io, c);
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
  buckets_loop_watch(c->srv->loop, c->fd, c->peer_eof ? 0 : BUCKETS_EV_READ, conn_io, c);
  return true;
}

static bool conn_writing(const conn *c) { return c->out_off < c->out.len || c->stream != NULL; }

/* Best-effort write that never closes the connection; safe inside parser
 * callbacks. Whatever is left is sent by the next conn_flush(). */
static void conn_send_some(conn *c) {
  while (c->out_off < c->out.len) {
    ssize_t n = send(c->fd, c->out.data + c->out_off, c->out.len - c->out_off, SEND_FLAGS);
    if (n > 0) {
      c->out_off += (size_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      return;
    }
  }
  buckets_buf_reset(&c->out);
  c->out_off = 0;
}

static void write_response(conn *c, buckets_http_response *resp, bool keep_alive) {
  buckets_http_server *srv = c->srv;
  char date[BUCKETS_TIME_HTTP_LEN + 1];
  buckets_time_http(time(NULL), date);
  long long clen = resp->content_length >= 0 ? resp->content_length : (long long)resp->body.len;
  buckets_buf_appendf(&c->out, "HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\nContent-Length: %lld\r\n",
                      resp->status, buckets_http_status_text(resp->status), srv->cfg.server_header,
                      date, clen);
  if (!keep_alive) buckets_buf_append_c(&c->out, "Connection: close\r\n");
  buckets_buf_append(&c->out, resp->headers.data, resp->headers.len);
  buckets_buf_append(&c->out, "\r\n", 2);
  if (resp->stream) {
    if (resp->head_only) {
      if (resp->stream_free) resp->stream_free(resp->stream_ud);
    } else {
      c->stream = resp->stream;
      c->stream_ud = resp->stream_ud;
      c->stream_free = resp->stream_free;
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
  buckets_loop_unwatch(c->srv->loop, c->fd); /* even HUP/ERR: nothing may close it now */
}

/* Back on the loop thread after a worker finished: resume sending, then
 * any pipelined requests. */
static void resume(conn *c) {
  c->busy = false;
  if (conn_flush(c)) conn_process(c);
}

static void fill_done(buckets_loop *loop, void *ud) {
  conn *c = ud;
  (void)loop;
  c->busy = false;
  if (take_chunk(c, c->fill_got) < 0) return;
  resume(c);
}

static void fill_task(void *ud, size_t i) {
  conn *c = ud;
  (void)i;
  c->fill_got = c->stream(c->stream_ud, c->out.data, c->out.cap - 1);
  buckets_loop_post(c->srv->loop, fill_done, c);
}

static void start_fill(conn *c) {
  set_busy(c);
  buckets_pool_submit(c->srv->cfg.workers, fill_task, c);
}

typedef struct {
  conn *c;
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
  finish_request(c, &j->req, &j->resp);
  free(j);
  resume(c);
}

static void job_task(void *ud, size_t i) {
  job *j = ud;
  (void)i;
  buckets_http_server *srv = j->c->srv;
  srv->handler(&j->req, &j->resp, srv->ud);
  buckets_loop_post(srv->loop, job_done, j);
}

static void dispatch_request(conn *c) {
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
  j->resp = (buckets_http_response){.status = 200, .content_length = -1};
  j->resp.head_only = buckets_str_eq_c(rq->method, "HEAD");
  if (srv->cfg.workers) {
    set_busy(c);
    buckets_pool_submit(srv->cfg.workers, job_task, j);
    return;
  }
  srv->handler(rq, &j->resp, srv->ud);
  finish_request(c, rq, &j->resp);
  free(j);
}

/* Feeds buffered input to the parser, dispatching complete requests one at a
 * time. Stops while a response is still being written (pipelining backpressure). */
static bool conn_process(conn *c) {
  if (c->busy) return true;
  while (c->in.len > 0 && !conn_writing(c) && !c->closing) {
    llhttp_errno_t err = llhttp_execute(&c->parser, c->in.data, c->in.len);
    if (err == HPE_OK) {
      buckets_buf_reset(&c->in);
      break;
    }
    if (err == HPE_PAUSED) {
      const char *pos = llhttp_get_error_pos(&c->parser);
      buckets_buf_consume(&c->in, (size_t)(pos - c->in.data));
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

static void conn_io(buckets_loop *loop, int fd, unsigned events, void *ud) {
  conn *c = ud;
  c->last_active = time(NULL);
  if (events & BUCKETS_EV_WRITE) {
    if (!conn_flush(c)) return;
    conn_process(c);
    return;
  }
  if (c->peer_eof) return;
  if (!(events & BUCKETS_EV_READ)) return;
  for (;;) {
    buckets_buf_reserve(&c->in, 64 * 1024);
    ssize_t n = recv(c->fd, c->in.data + c->in.len, c->in.cap - c->in.len - 1, 0);
    if (n > 0) {
      c->in.len += (size_t)n;
      c->in.data[c->in.len] = '\0';
      if (c->in.len > 1024 * 1024) break; /* parse (and spool) before buffering more */
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
    if (n < 0) { /* reset or error: nobody is listening for responses */
      conn_close(c);
      return;
    }
    /* Orderly EOF: requests may already be buffered, so answer them first. */
    c->peer_eof = true;
    buckets_loop_watch(c->srv->loop, c->fd, conn_writing(c) ? BUCKETS_EV_WRITE : 0, conn_io, c);
    break;
  }
  conn_process(c);
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
  if ((p->flags & F_CHUNKED) || (has_len && p->content_length > cfg->mem_body_limit)) {
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
  return 0;
}

static int on_body(llhttp_t *p, const char *at, size_t n) {
  conn *c = p->data;
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
    llhttp_init(&c->parser, HTTP_REQUEST, &srv->settings);
    c->parser.data = c;
    c->next = srv->conns;
    if (srv->conns) srv->conns->prev = c;
    srv->conns = c;
    srv->nconns++;
    if (buckets_loop_watch(loop, cfd, BUCKETS_EV_READ, conn_io, c) != 0) conn_close(c);
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

static void on_tick(buckets_http_server *srv) {
  time_t now = time(NULL);
  for (conn *c = srv->conns, *next; c; c = next) {
    next = c->next;
    bool idle = !c->busy && c->in.len == 0 && !conn_writing(c);
    if (idle && (srv->shutting_down || now - c->last_active > srv->cfg.idle_timeout_sec)) conn_close(c);
  }
}

static void tick_cb(buckets_loop *loop, void *ud) { on_tick(ud); }

buckets_http_server *buckets_http_server_start(buckets_loop *loop, const buckets_http_config *cfg,
                                               buckets_http_handler handler, void *ud) {
  buckets_http_server *srv = buckets_xcalloc(1, sizeof(*srv));
  srv->loop = loop;
  srv->cfg = *cfg;
  if (!srv->cfg.server_header) srv->cfg.server_header = "Buckets";
  if (srv->cfg.idle_timeout_sec <= 0) srv->cfg.idle_timeout_sec = 30;
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
  buckets_loop_watch(loop, srv->listen_fd, BUCKETS_EV_READ, on_accept, srv);
  buckets_loop_add_tick(loop, tick_cb, srv);
  return srv;
}

void buckets_http_server_shutdown(buckets_http_server *srv) {
  if (srv->shutting_down) return;
  srv->shutting_down = true;
  if (srv->listen_fd >= 0) {
    buckets_loop_unwatch(srv->loop, srv->listen_fd);
    close(srv->listen_fd);
    srv->listen_fd = -1;
  }
  on_tick(srv);
}

size_t buckets_http_server_connections(const buckets_http_server *srv) { return srv->nconns; }

int buckets_http_server_port(const buckets_http_server *srv) { return srv->port; }

void buckets_http_server_free(buckets_http_server *srv) {
  if (!srv) return;
  while (srv->conns) conn_close(srv->conns);
  if (srv->listen_fd >= 0) close(srv->listen_fd);
  free(srv);
}
