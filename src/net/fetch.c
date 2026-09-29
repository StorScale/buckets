/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/fetch.h"

#include "core/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The host, port and request target of an http(s) URL. */
static bool split_url(const char *url, bool *secure, char *host, size_t hcap, int *port, char *target, size_t tcap,
                      char *err, size_t errlen) {
  *secure = strncmp(url, "https://", 8) == 0;
  if (!*secure && strncmp(url, "http://", 7) != 0) {
    snprintf(err, errlen, "unsupported URL %s", url);
    return false;
  }
  const char *h = url + (*secure ? 8 : 7);
  size_t hl = strcspn(h, "/?#");
  *port = *secure ? 443 : 80;
  if (hl >= hcap) {
    snprintf(err, errlen, "URL host too long");
    return false;
  }
  if (*h == '[') { /* [v6]:port */
    const char *rb = memchr(h, ']', hl);
    if (!rb) {
      snprintf(err, errlen, "malformed URL %s", url);
      return false;
    }
    snprintf(host, hcap, "%.*s", (int)(rb - h - 1), h + 1);
    if (rb[1] == ':') *port = atoi(rb + 2);
  } else {
    const char *colon = memchr(h, ':', hl);
    snprintf(host, hcap, "%.*s", colon ? (int)(colon - h) : (int)hl, h);
    if (colon) *port = atoi(colon + 1);
  }
  const char *path = h + hl;
  snprintf(target, tcap, "%s%s", *path == '/' ? "" : "/", *path == '#' ? "" : path);
  char *hash = strchr(target, '#');
  if (hash) *hash = '\0';
  return true;
}

bool buckets_fetch(const char *method, const char *url, const char *ca_file, const buckets_http_kv *hdrs, size_t nhdrs,
                   const void *body, size_t len, int timeout_ms, buckets_http_result *out, char *err, size_t errlen) {
  bool secure;
  char host[256], target[4096];
  int port;
  if (!split_url(url, &secure, host, sizeof(host), &port, target, sizeof(target), err, errlen)) return false;
  buckets_tls_client *tls = NULL;
  if (secure && !(tls = buckets_tls_client_new(ca_file, err, errlen))) return false;
  buckets_http_client *c = buckets_http_client_new(host, port, tls, timeout_ms > 0 ? timeout_ms : 10000);
  bool ok = buckets_http_client_do(c, method, target, hdrs, nhdrs, body, len, out);
  if (!ok) {
    const char *de = buckets_http_client_dial_error(c);
    if (*de) snprintf(err, errlen, "%s", de);
    else snprintf(err, errlen, "%s %s: connection failed", method, url);
  }
  buckets_http_client_free(c);
  buckets_tls_client_free(tls);
  return ok;
}

struct buckets_fetch_stream {
  buckets_tls_client *tls;
  buckets_http_client *c;
  buckets_http_stream *st;
  const uint8_t *body;
  size_t len, pos;
};

static long body_read(void *ud, void *buf, size_t n) {
  buckets_fetch_stream *f = ud;
  size_t k = f->len - f->pos < n ? f->len - f->pos : n;
  memcpy(buf, f->body + f->pos, k);
  f->pos += k;
  return (long)k;
}

buckets_fetch_stream *buckets_fetch_open(const char *method, const char *url, const char *ca_file,
                                         const buckets_http_kv *hdrs, size_t nhdrs, const void *body, size_t len,
                                         int timeout_ms, int *status, buckets_buf *headers, char *err, size_t errlen) {
  bool secure;
  char host[256], target[4096];
  int port;
  if (!split_url(url, &secure, host, sizeof(host), &port, target, sizeof(target), err, errlen)) return NULL;
  buckets_fetch_stream *f = buckets_xcalloc(1, sizeof(*f));
  if (secure && !(f->tls = buckets_tls_client_new(ca_file, err, errlen))) {
    free(f);
    return NULL;
  }
  f->c = buckets_http_client_new(host, port, f->tls, timeout_ms > 0 ? timeout_ms : 10000);
  f->body = body;
  f->len = len;
  f->st = buckets_http_client_open(f->c, method, target, hdrs, nhdrs, len ? body_read : NULL, f, (int64_t)len, status,
                                   headers);
  if (!f->st) {
    const char *de = buckets_http_client_dial_error(f->c);
    if (*de) snprintf(err, errlen, "%s", de);
    else snprintf(err, errlen, "%s %s: connection failed", method, url);
    buckets_fetch_close(f);
    return NULL;
  }
  f->body = NULL; /* sent */
  return f;
}

long buckets_fetch_read(void *ud, void *buf, size_t n) { return buckets_http_stream_read(((buckets_fetch_stream *)ud)->st, buf, n); }

void buckets_fetch_close(void *ud) {
  buckets_fetch_stream *f = ud;
  if (!f) return;
  if (f->st) buckets_http_stream_free(f->st);
  buckets_http_client_free(f->c);
  buckets_tls_client_free(f->tls);
  free(f);
}
