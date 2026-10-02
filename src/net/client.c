/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/client.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/log.h"

#define MAX_IDLE 64
#define MAX_HEADER_BYTES (64 * 1024)

struct buckets_http_client;
typedef struct {
  int fd;
  buckets_tls_conn *tls;
  struct buckets_http_client *c; /* for its traffic counters */
} hconn;

struct buckets_http_client {
  char *host;
  int port;
  buckets_tls_client *tls;
  int timeout_ms;
  pthread_mutex_t mu;
  hconn idle[MAX_IDLE];
  size_t nidle;
  _Atomic uint64_t sent, received, errors, dials, dial_errors, dial_ns, requests;
  _Atomic int64_t streams, last_connect_ns;
  char dial_err[200]; /* the last failed dial, as Go's net.Dial reports it */
};

buckets_http_client *buckets_http_client_new(const char *host, int port, buckets_tls_client *tls, int timeout_ms) {
  buckets_http_client *c = buckets_xcalloc(1, sizeof(*c));
  c->host = buckets_xstrdup(host);
  c->port = port;
  c->tls = tls;
  c->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;
  pthread_mutex_init(&c->mu, NULL);
  return c;
}

static void hconn_close(hconn *h) {
  buckets_tls_conn_free(h->tls);
  if (h->fd >= 0) close(h->fd);
  h->fd = -1;
  h->tls = NULL;
}

void buckets_http_client_reset(buckets_http_client *c) {
  pthread_mutex_lock(&c->mu);
  for (size_t i = 0; i < c->nidle; i++) hconn_close(&c->idle[i]);
  c->nidle = 0;
  pthread_mutex_unlock(&c->mu);
}

void buckets_http_client_free(buckets_http_client *c) {
  if (!c) return;
  buckets_http_client_reset(c);
  pthread_mutex_destroy(&c->mu);
  free(c->host);
  free(c);
}

const char *buckets_http_client_dial_error(const buckets_http_client *c) { return c->dial_err; }

const char *buckets_http_client_host(const buckets_http_client *c) { return c->host; }
int buckets_http_client_port(const buckets_http_client *c) { return c->port; }

/* 0, or the errno of the failure (ETIMEDOUT when the timeout passed). */
static int connect_timeout(int fd, const struct sockaddr *sa, socklen_t sl, int timeout_ms) {
  int flags = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  int rc = connect(fd, sa, sl), e = rc == 0 ? 0 : errno;
  if (rc != 0 && e == EINPROGRESS) {
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    e = ETIMEDOUT;
    if (poll(&p, 1, timeout_ms) == 1) {
      int err = 0;
      socklen_t el = sizeof(err);
      getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
      e = err;
    }
  }
  fcntl(fd, F_SETFL, flags);
  return e;
}

static bool dial(buckets_http_client *c, hconn *out) {
  char port[16];
  snprintf(port, sizeof(port), "%d", c->port);
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  atomic_fetch_add(&c->dials, 1);
  char hp[300];
  snprintf(hp, sizeof(hp), strchr(c->host, ':') ? "[%s]:%d" : "%s:%d", c->host, c->port);
  if (getaddrinfo(c->host, port, &hints, &res) != 0) {
    atomic_fetch_add(&c->dial_errors, 1);
    snprintf(c->dial_err, sizeof(c->dial_err), "dial tcp: lookup %s: no such host", c->host);
    return false;
  }
  int fd = -1, e = 0;
  for (struct addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if ((e = connect_timeout(fd, ai->ai_addr, ai->ai_addrlen, c->timeout_ms)) != 0) {
      close(fd);
      fd = -1;
    }
  }
  if (fd < 0)
    snprintf(c->dial_err, sizeof(c->dial_err), e == ETIMEDOUT ? "dial tcp %s: i/o timeout" : "dial tcp %s: connect: %s", hp,
             e == ECONNREFUSED ? "connection refused" : strerror(e));
  freeaddrinfo(res);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  atomic_fetch_add(&c->dial_ns, (uint64_t)((t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec)));
  if (fd < 0) {
    atomic_fetch_add(&c->dial_errors, 1);
    return false;
  }
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  struct timeval tv = {c->timeout_ms / 1000, (c->timeout_ms % 1000) * 1000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  out->fd = fd;
  out->tls = NULL;
  out->c = c;
  if (c->tls && !(out->tls = buckets_tls_connect(c->tls, fd, c->host))) {
    close(fd);
    return false;
  }
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  atomic_store(&c->last_connect_ns, (int64_t)now.tv_sec * 1000000000LL + now.tv_nsec);
  return true;
}

#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

static bool send_all(hconn *h, const void *data, size_t n) {
  const char *p = data;
  while (n) {
    long w;
    if (h->tls) {
      w = buckets_tls_send(h->tls, p, n);
    } else {
      w = send(h->fd, p, n, SEND_FLAGS);
      if (w < 0 && errno == EINTR) continue;
    }
    if (w <= 0) return false;
    if (h->c) atomic_fetch_add(&h->c->sent, (uint64_t)w);
    p += w;
    n -= (size_t)w;
  }
  return true;
}

static long recv_some(hconn *h, void *buf, size_t n) {
  for (;;) {
    long r = h->tls ? buckets_tls_recv(h->tls, buf, n) : recv(h->fd, buf, n, 0);
    if (r < 0 && !h->tls && errno == EINTR) continue;
    if (r > 0 && h->c) atomic_fetch_add(&h->c->received, (uint64_t)r);
    return r;
  }
}

const char *buckets_http_result_header(const buckets_http_result *r, const char *name, size_t *len) {
  return buckets_http_headers_get(&r->headers, name, len);
}

const char *buckets_http_headers_get(const buckets_buf *headers, const char *name, size_t *len) {
  size_t nl = strlen(name);
  const char *p = headers->data, *end = p ? p + headers->len : NULL;
  while (p && p < end) {
    const char *eol = memchr(p, '\n', (size_t)(end - p));
    if (!eol) eol = end;
    if ((size_t)(eol - p) > nl && p[nl] == ':' && strncasecmp(p, name, nl) == 0) {
      const char *v = p + nl + 1;
      while (v < eol && *v == ' ') v++;
      const char *ve = eol;
      while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ')) ve--;
      if (len) *len = (size_t)(ve - v);
      return v;
    }
    p = eol + 1;
  }
  return NULL;
}

void buckets_http_result_free(buckets_http_result *r) {
  buckets_buf_free(&r->headers);
  buckets_buf_free(&r->body);
  memset(r, 0, sizeof(*r));
}

/* Returns 1 on success, 0 on a failure before any response byte (retryable),
 * -1 on a later failure. *reusable says whether the connection may go back
 * to the pool. */
static int exchange(hconn *h, const buckets_buf *head, const void *body, size_t blen, buckets_http_result *res,
                    bool *reusable) {
  *reusable = false;
  if (!send_all(h, head->data, head->len) || (blen && !send_all(h, body, blen))) return 0;
  buckets_buf in = BUCKETS_BUF_INIT;
  size_t hend = 0;
  while (!hend) {
    if (in.len > MAX_HEADER_BYTES) goto bad;
    buckets_buf_reserve(&in, 16384);
    long r = recv_some(h, in.data + in.len, in.cap - in.len - 1);
    if (r <= 0) {
      int rc = in.len ? -1 : 0;
      buckets_buf_free(&in);
      return rc;
    }
    in.len += (size_t)r;
    in.data[in.len] = '\0';
    char *e = strstr(in.data, "\r\n\r\n");
    if (e) hend = (size_t)(e - in.data) + 4;
  }
  int status = 0;
  if (sscanf(in.data, "HTTP/1.%*d %d", &status) != 1) goto bad;
  const char *eol = strstr(in.data, "\r\n");
  res->status = status;
  buckets_buf_append(&res->headers, eol + 2, hend - (size_t)(eol + 2 - in.data));
  size_t te_len;
  const char *te = buckets_http_result_header(res, "Transfer-Encoding", &te_len);
  if (te && te_len >= 7 && strncasecmp(te + te_len - 7, "chunked", 7) == 0) {
    /* Chunked body: <hex size>\r\n<data>\r\n ... 0\r\n[trailers]\r\n */
    buckets_buf raw = BUCKETS_BUF_INIT;
    buckets_buf_append(&raw, in.data + hend, in.len - hend);
    buckets_buf_free(&in);
    size_t pos = 0;
    for (;;) {
      char *nl;
      while (!(nl = raw.len > pos ? memmem(raw.data + pos, raw.len - pos, "\r\n", 2) : NULL)) {
        buckets_buf_reserve(&raw, 65536);
        long r = recv_some(h, raw.data + raw.len, raw.cap - raw.len - 1);
        if (r <= 0) goto chunk_bad;
        raw.len += (size_t)r;
      }
      unsigned long long sz = strtoull(raw.data + pos, NULL, 16);
      size_t data_at = (size_t)(nl - raw.data) + 2;
      if (sz == 0) { /* last chunk; drain the (empty) trailer section */
        pos = data_at;
        while (!(raw.len >= pos + 2 && memmem(raw.data + pos, raw.len - pos, "\r\n", 2))) {
          buckets_buf_reserve(&raw, 1024);
          long r = recv_some(h, raw.data + raw.len, raw.cap - raw.len - 1);
          if (r <= 0) goto chunk_bad;
          raw.len += (size_t)r;
        }
        break;
      }
      while (raw.len < data_at + sz + 2) {
        buckets_buf_reserve(&raw, (size_t)sz + 2);
        long r = recv_some(h, raw.data + raw.len, raw.cap - raw.len - 1);
        if (r <= 0) goto chunk_bad;
        raw.len += (size_t)r;
      }
      buckets_buf_append(&res->body, raw.data + data_at, (size_t)sz);
      pos = data_at + (size_t)sz + 2;
    }
    buckets_buf_free(&raw);
    if (res->body.data) res->body.data[res->body.len] = '\0';
    *reusable = false; /* simplest: never reuse after a chunked body */
    return 1;
  chunk_bad:
    buckets_buf_free(&raw);
    return -1;
  }
  size_t cl_len;
  /* no body by definition (RFC 9112 6.3) */
  if (res->status == 204 || res->status == 304 || (res->status >= 100 && res->status < 200)) {
    buckets_buf_free(&in);
    *reusable = true;
    return 1;
  }
  const char *cl = buckets_http_result_header(res, "Content-Length", &cl_len);
  if (!cl) { /* the body runs to the connection's close */
    buckets_buf_append(&res->body, in.data + hend, in.len - hend);
    buckets_buf_free(&in);
    char tmp[16384];
    for (long r; (r = recv_some(h, tmp, sizeof(tmp))) > 0;) buckets_buf_append(&res->body, tmp, (size_t)r);
    if (res->body.data) res->body.data[res->body.len] = '\0';
    *reusable = false;
    return 1;
  }
  long long want = strtoll(cl, NULL, 10);
  if (want < 0) goto bad;
  size_t have = in.len - hend;
  buckets_buf_reserve(&res->body, (size_t)want);
  buckets_buf_append(&res->body, in.data + hend, BUCKETS_MIN(have, (size_t)want));
  buckets_buf_free(&in);
  while ((long long)res->body.len < want) {
    long r = recv_some(h, res->body.data + res->body.len, (size_t)want - res->body.len);
    if (r <= 0) return -1;
    res->body.len += (size_t)r;
  }
  if (res->body.data) res->body.data[res->body.len] = '\0';
  size_t conn_len;
  const char *conn = buckets_http_result_header(res, "Connection", &conn_len);
  *reusable = !(conn && conn_len == 5 && strncasecmp(conn, "close", 5) == 0) && have <= (size_t)want;
  return 1;
bad:
  buckets_buf_free(&in);
  return -1;
}

bool buckets_http_client_do(buckets_http_client *c, const char *method, const char *target, const buckets_http_kv *hdrs,
                            size_t nhdrs, const void *body, size_t body_len, buckets_http_result *res) {
  memset(res, 0, sizeof(*res));
  atomic_fetch_add(&c->requests, 1);
  buckets_buf head = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&head, "%s %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %zu\r\n", method, target, c->host,
                      c->port, body_len);
  for (size_t i = 0; i < nhdrs; i++) buckets_buf_appendf(&head, "%s: %s\r\n", hdrs[i].name, hdrs[i].value);
  buckets_buf_append(&head, "\r\n", 2);
  bool ok = false;
  for (int attempt = 0; attempt < 2 && !ok; attempt++) {
    hconn h = {.fd = -1};
    bool pooled = false;
    pthread_mutex_lock(&c->mu);
    if (attempt == 0 && c->nidle) {
      h = c->idle[--c->nidle];
      pooled = true;
    }
    pthread_mutex_unlock(&c->mu);
    if (!pooled && !dial(c, &h)) break;
    bool reusable;
    int rc = exchange(&h, &head, body, body_len, res, &reusable);
    if (rc == 1) {
      ok = true;
      pthread_mutex_lock(&c->mu);
      if (reusable && c->nidle < MAX_IDLE) c->idle[c->nidle++] = h, h.fd = -1, h.tls = NULL;
      pthread_mutex_unlock(&c->mu);
    }
    hconn_close(&h);
    if (!ok) {
      buckets_http_result_free(res);
      if (rc != 0 || !pooled) break; /* only a stale pooled connection is retried */
    }
  }
  buckets_buf_free(&head);
  if (!ok) atomic_fetch_add(&c->errors, 1);
  return ok;
}

void buckets_http_client_stats_get(buckets_http_client *c, buckets_http_client_stats *out) {
  out->sent = atomic_load(&c->sent);
  out->received = atomic_load(&c->received);
  out->errors = atomic_load(&c->errors);
  out->dials = atomic_load(&c->dials);
  out->dial_errors = atomic_load(&c->dial_errors);
  out->dial_ns = atomic_load(&c->dial_ns);
  out->requests = atomic_load(&c->requests);
  out->streams = atomic_load(&c->streams);
  out->last_connect_ns = atomic_load(&c->last_connect_ns);
}

/* ---- streaming ------------------------------------------------------------ */

struct buckets_http_stream {
  buckets_http_client *c;
  hconn h;
  buckets_buf in; /* bytes received past the headers, not yet returned */
  size_t in_pos;
  bool chunked, close_delimited, done, failed, reusable;
  int64_t remaining; /* Content-Length bytes (or bytes of the current chunk) left */
  int64_t length;
};

/* Buffered byte source over the connection. */
static bool stream_fill(buckets_http_stream *s) {
  if (s->in_pos == s->in.len) {
    buckets_buf_reset(&s->in);
    s->in_pos = 0;
  }
  buckets_buf_reserve(&s->in, 65536);
  long r = recv_some(&s->h, s->in.data + s->in.len, s->in.cap - s->in.len - 1);
  if (r <= 0) return false;
  s->in.len += (size_t)r;
  return true;
}

/* A CRLF-terminated line from the buffer (without the CRLF). */
static bool stream_line(buckets_http_stream *s, char *out, size_t cap) {
  for (;;) {
    const char *base = s->in.data + s->in_pos;
    size_t avail = s->in.len - s->in_pos;
    const char *nl = avail ? memmem(base, avail, "\r\n", 2) : NULL;
    if (nl) {
      size_t n = (size_t)(nl - base);
      if (n >= cap) return false;
      memcpy(out, base, n);
      out[n] = '\0';
      s->in_pos += n + 2;
      return true;
    }
    if (avail > 4096 || !stream_fill(s)) return false;
  }
}

buckets_http_stream *buckets_http_client_open(buckets_http_client *c, const char *method, const char *target,
                                              const buckets_http_kv *hdrs, size_t nhdrs, buckets_http_read_fn rd,
                                              void *rd_ud, int64_t body_len, int *status, buckets_buf *headers) {
  buckets_buf head = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&head, "%s %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %lld\r\n", method, target, c->host,
                      c->port, (long long)(body_len > 0 ? body_len : 0));
  for (size_t i = 0; i < nhdrs; i++) buckets_buf_appendf(&head, "%s: %s\r\n", hdrs[i].name, hdrs[i].value);
  buckets_buf_append(&head, "\r\n", 2);
  buckets_http_stream *s = buckets_xcalloc(1, sizeof(*s));
  atomic_fetch_add(&c->requests, 1);
  s->c = c;
  s->h.fd = -1;
  /* A body that cannot be replayed only goes out on a fresh connection. */
  bool pooled = false;
  if (body_len <= 0) {
    pthread_mutex_lock(&c->mu);
    if (c->nidle) {
      s->h = c->idle[--c->nidle];
      pooled = true;
    }
    pthread_mutex_unlock(&c->mu);
  }
  for (int attempt = 0; attempt < 2; attempt++) {
    if (!pooled && !dial(c, &s->h)) goto fail;
    bool sent = send_all(&s->h, head.data, head.len);
    for (int64_t left = body_len; sent && left > 0;) {
      char buf[65536];
      long n = rd(rd_ud, buf, (size_t)BUCKETS_MIN(left, (int64_t)sizeof(buf)));
      if (n <= 0) goto fail; /* the source ended early */
      sent = send_all(&s->h, buf, (size_t)n);
      left -= n;
    }
    /* status line and headers */
    size_t hend = 0;
    while (sent && !hend) {
      if (s->in.len > MAX_HEADER_BYTES || !stream_fill(s)) break;
      s->in.data[s->in.len] = '\0';
      char *e = strstr(s->in.data, "\r\n\r\n");
      if (e) hend = (size_t)(e - s->in.data) + 4;
    }
    if (!hend) {
      bool retry = pooled && s->in.len == 0; /* a stale keep-alive connection */
      hconn_close(&s->h);
      buckets_buf_reset(&s->in);
      if (!retry) goto fail;
      pooled = false;
      continue;
    }
    if (sscanf(s->in.data, "HTTP/1.%*d %d", status) != 1) goto fail;
    const char *eol = strstr(s->in.data, "\r\n");
    buckets_buf_reset(headers);
    buckets_buf_append(headers, eol + 2, hend - (size_t)(eol + 2 - s->in.data) - 2);
    s->in_pos = hend;
    size_t n;
    const char *te = buckets_http_headers_get(headers, "Transfer-Encoding", &n);
    const char *cl = buckets_http_headers_get(headers, "Content-Length", NULL);
    const char *conn = buckets_http_headers_get(headers, "Connection", &n);
    bool conn_close = conn && n == 5 && strncasecmp(conn, "close", 5) == 0;
    s->length = -1;
    if (te && strstr(te, "chunked")) {
      s->chunked = true;
    } else if (cl) {
      s->remaining = s->length = strtoll(cl, NULL, 10);
    } else if (strcasecmp(method, "HEAD") == 0 || *status == 204 || *status == 304) {
      s->remaining = 0;
    } else {
      s->close_delimited = true;
    }
    if (strcasecmp(method, "HEAD") == 0) s->remaining = 0, s->chunked = s->close_delimited = false;
    s->reusable = !conn_close && !s->close_delimited;
    if (!s->chunked && !s->close_delimited && s->remaining == 0) s->done = true;
    buckets_buf_free(&head);
    atomic_fetch_add(&c->streams, 1);
    return s;
  }
fail:
  buckets_buf_free(&head);
  hconn_close(&s->h);
  buckets_buf_free(&s->in);
  free(s);
  return NULL;
}

int64_t buckets_http_stream_length(const buckets_http_stream *s) { return s->length; }

long buckets_http_stream_read(void *ud, void *buf, size_t n) {
  buckets_http_stream *s = ud;
  if (s->failed) return -1;
  while (!s->done) {
    if (s->chunked && s->remaining == 0) {
      char line[128];
      if (!stream_line(s, line, sizeof(line))) goto fail;
      if (!*line) continue; /* the CRLF after a chunk's data */
      s->remaining = (int64_t)strtoull(line, NULL, 16);
      if (s->remaining == 0) { /* last chunk: skip trailers up to the empty line */
        while (stream_line(s, line, sizeof(line)) && *line) {
        }
        s->done = true;
        break;
      }
    }
    if (s->in_pos == s->in.len) {
      if (!stream_fill(s)) {
        if (s->close_delimited) {
          s->done = true;
          break;
        }
        goto fail;
      }
      continue;
    }
    size_t k = s->in.len - s->in_pos;
    if (k > n) k = n;
    if (!s->close_delimited && (int64_t)k > s->remaining) k = (size_t)s->remaining;
    memcpy(buf, s->in.data + s->in_pos, k);
    s->in_pos += k;
    if (!s->close_delimited) s->remaining -= (int64_t)k;
    if (!s->chunked && !s->close_delimited && s->remaining == 0) s->done = true;
    return (long)k;
  }
  return 0;
fail:
  s->failed = true;
  return -1;
}

void buckets_http_stream_free(void *ud) {
  buckets_http_stream *s = ud;
  if (!s) return;
  atomic_fetch_sub(&s->c->streams, 1);
  bool clean = s->done && !s->failed && s->reusable && s->in_pos == s->in.len;
  if (clean) {
    pthread_mutex_lock(&s->c->mu);
    if (s->c->nidle < MAX_IDLE) s->c->idle[s->c->nidle++] = s->h, s->h.fd = -1, s->h.tls = NULL;
    pthread_mutex_unlock(&s->c->mu);
  }
  hconn_close(&s->h);
  buckets_buf_free(&s->in);
  free(s);
}
