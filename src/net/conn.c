/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/conn.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/common.h"

struct buckets_conn {
  int fd;
  buckets_tls_conn *tls;
  char rbuf[16384];
  size_t rpos, rlen;
};

static void set_timeouts(int fd, int timeout_ms) {
  struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

buckets_conn *buckets_conn_dial(const char *host, int port, buckets_tls_client *tls, int timeout_ms, char *err,
                                size_t errlen) {
  char ps[16], hp[300];
  snprintf(ps, sizeof(ps), "%d", port);
  snprintf(hp, sizeof(hp), strchr(host, ':') ? "[%s]:%d" : "%s:%d", host, port);
  struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res;
  int gai = getaddrinfo(host, ps, &hints, &res);
  if (gai != 0) {
    snprintf(err, errlen, "dial tcp: lookup %s: no such host", host);
    return NULL;
  }
  int fd = -1, last = ECONNREFUSED;
  for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next) {
    fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (fd < 0) continue;
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(fd, a->ai_addr, a->ai_addrlen);
    if (rc < 0 && errno == EINPROGRESS) {
      struct pollfd pfd = {fd, POLLOUT, 0};
      int e = 0;
      socklen_t el = sizeof(e);
      int pr = poll(&pfd, 1, timeout_ms);
      if (pr == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el) == 0 && e == 0) rc = 0;
      else last = pr == 0 ? ETIMEDOUT : e ? e : errno;
    } else if (rc < 0) {
      last = errno;
    }
    fcntl(fd, F_SETFL, fl);
    if (rc != 0) {
      close(fd);
      fd = -1;
    }
  }
  freeaddrinfo(res);
  if (fd < 0) {
    snprintf(err, errlen, last == ETIMEDOUT ? "dial tcp %s: i/o timeout" : "dial tcp %s: connect: %s", hp,
             last == ECONNREFUSED ? "connection refused" : strerror(last));
    return NULL;
  }
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  set_timeouts(fd, timeout_ms);
  buckets_conn *c = buckets_xcalloc(1, sizeof(*c));
  c->fd = fd;
  if (tls && !buckets_conn_start_tls(c, tls, host)) {
    snprintf(err, errlen, "tls: handshake with %s failed", hp);
    buckets_conn_close(c);
    return NULL;
  }
  return c;
}

bool buckets_conn_start_tls(buckets_conn *c, buckets_tls_client *tls, const char *host) {
  c->tls = buckets_tls_connect(tls, c->fd, host);
  return c->tls != NULL;
}

void buckets_conn_close(buckets_conn *c) {
  if (!c) return;
  if (c->tls) buckets_tls_conn_free(c->tls);
  if (c->fd >= 0) close(c->fd);
  free(c);
}

void buckets_conn_set_timeout(buckets_conn *c, int timeout_ms) { set_timeouts(c->fd, timeout_ms); }

bool buckets_conn_write(buckets_conn *c, const void *data, size_t n) {
  const char *p = data;
  while (n) {
    long k;
    if (c->tls) k = buckets_tls_send(c->tls, p, n);
    else {
#ifdef MSG_NOSIGNAL
      k = send(c->fd, p, n, MSG_NOSIGNAL);
#else
      k = send(c->fd, p, n, 0);
#endif
      if (k < 0 && errno == EINTR) continue;
    }
    if (k <= 0) return false;
    p += k;
    n -= (size_t)k;
  }
  return true;
}

static bool fill(buckets_conn *c) {
  if (c->rpos < c->rlen) return true;
  c->rpos = c->rlen = 0;
  for (;;) {
    long k = c->tls ? buckets_tls_recv(c->tls, c->rbuf, sizeof(c->rbuf)) : recv(c->fd, c->rbuf, sizeof(c->rbuf), 0);
    if (k < 0 && !c->tls && errno == EINTR) continue;
    if (k <= 0) return false;
    c->rlen = (size_t)k;
    return true;
  }
}

bool buckets_conn_read_full(buckets_conn *c, void *out, size_t n) {
  char *o = out;
  while (n) {
    if (!fill(c)) return false;
    size_t k = BUCKETS_MIN(n, c->rlen - c->rpos);
    memcpy(o, c->rbuf + c->rpos, k);
    c->rpos += k;
    o += k;
    n -= k;
  }
  return true;
}

bool buckets_conn_read_line(buckets_conn *c, buckets_buf *line) {
  buckets_buf_reset(line);
  for (;;) {
    if (!fill(c)) return false;
    char *nl = memchr(c->rbuf + c->rpos, '\n', c->rlen - c->rpos);
    size_t k = nl ? (size_t)(nl - (c->rbuf + c->rpos)) : c->rlen - c->rpos;
    buckets_buf_append(line, c->rbuf + c->rpos, k);
    c->rpos += k;
    if (nl) {
      c->rpos++;
      if (line->len && line->data[line->len - 1] == '\r') line->data[--line->len] = '\0';
      return true;
    }
  }
}

size_t buckets_conn_buffered(const buckets_conn *c) { return c->rlen - c->rpos; }

bool buckets_conn_broken(buckets_conn *c) {
  if (c->rpos < c->rlen) return false;
  struct pollfd pfd = {c->fd, POLLIN, 0};
  if (poll(&pfd, 1, 0) != 1) return false;
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return true;
  if (c->tls) return false; /* TLS records may be pending: let the next read tell */
  char b;
  long k = recv(c->fd, &b, 1, MSG_PEEK);
  return k <= 0;
}

int buckets_conn_readable(buckets_conn *c, int timeout_ms) {
  if (c->rpos < c->rlen || (c->tls && buckets_tls_pending(c->tls))) return 1;
  struct pollfd pfd = {c->fd, POLLIN, 0};
  int r = poll(&pfd, 1, timeout_ms);
  if (r < 0) return -1;
  if (r == 0) return 0;
  return (pfd.revents & (POLLERR | POLLNVAL)) ? -1 : 1;
}
