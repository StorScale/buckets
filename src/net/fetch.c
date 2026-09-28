/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/fetch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool buckets_fetch(const char *method, const char *url, const char *ca_file, const buckets_http_kv *hdrs, size_t nhdrs,
                   const void *body, size_t len, int timeout_ms, buckets_http_result *out, char *err, size_t errlen) {
  bool secure = strncmp(url, "https://", 8) == 0;
  if (!secure && strncmp(url, "http://", 7) != 0) {
    snprintf(err, errlen, "unsupported URL %s", url);
    return false;
  }
  const char *h = url + (secure ? 8 : 7);
  size_t hl = strcspn(h, "/?#");
  char host[256];
  int port = secure ? 443 : 80;
  if (hl >= sizeof(host)) {
    snprintf(err, errlen, "URL host too long");
    return false;
  }
  if (*h == '[') { /* [v6]:port */
    const char *rb = memchr(h, ']', hl);
    if (!rb) {
      snprintf(err, errlen, "malformed URL %s", url);
      return false;
    }
    snprintf(host, sizeof(host), "%.*s", (int)(rb - h - 1), h + 1);
    if (rb[1] == ':') port = atoi(rb + 2);
  } else {
    const char *colon = memchr(h, ':', hl);
    snprintf(host, sizeof(host), "%.*s", colon ? (int)(colon - h) : (int)hl, h);
    if (colon) port = atoi(colon + 1);
  }
  const char *path = h + hl;
  char target[4096];
  snprintf(target, sizeof(target), "%s%s", *path == '/' ? "" : "/", *path == '#' ? "" : path);
  char *hash = strchr(target, '#');
  if (hash) *hash = '\0';
  buckets_tls_client *tls = NULL;
  if (secure && !(tls = buckets_tls_client_new(ca_file, err, errlen))) return false;
  buckets_http_client *c = buckets_http_client_new(host, port, tls, timeout_ms > 0 ? timeout_ms : 10000);
  bool ok = buckets_http_client_do(c, method, target, hdrs, nhdrs, body, len, out);
  if (!ok) snprintf(err, errlen, "%s %s: connection failed", method, url);
  buckets_http_client_free(c);
  buckets_tls_client_free(tls);
  return ok;
}
