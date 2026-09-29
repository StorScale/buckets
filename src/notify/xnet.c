/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "notify/xnet.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool addr_err(char *err, size_t errlen, const char *addr, const char *why) {
  snprintf(err, errlen, "address %s: %s", addr, why);
  return false;
}

bool buckets_go_split_host_port(const char *hp, char *host, size_t hcap, char *port, size_t pcap, char *err,
                                size_t errlen) {
  size_t n = strlen(hp);
  const char *last = strrchr(hp, ':');
  if (!last) return addr_err(err, errlen, hp, "missing port in address");
  size_t i = (size_t)(last - hp), j = 0, k = 0;
  const char *h;
  size_t hl;
  if (hp[0] == '[') {
    const char *end = strchr(hp, ']');
    if (!end) return addr_err(err, errlen, hp, "missing ']' in address");
    size_t e = (size_t)(end - hp);
    if (e + 1 == n) return addr_err(err, errlen, hp, "missing port in address");
    if (e + 1 != i) {
      if (hp[e + 1] == ':') return addr_err(err, errlen, hp, "too many colons in address");
      return addr_err(err, errlen, hp, "missing port in address");
    }
    h = hp + 1, hl = e - 1;
    if (memchr(h, ':', hl) == NULL) { /* fine: IPv4 or a name in brackets */
    }
    j = 1, k = e + 1;
  } else {
    h = hp, hl = i;
    if (memchr(h, ':', hl)) return addr_err(err, errlen, hp, "too many colons in address");
  }
  if (strchr(hp + j, '[')) return addr_err(err, errlen, hp, "unexpected '[' in address");
  if (strchr(hp + k, ']')) return addr_err(err, errlen, hp, "unexpected ']' in address");
  snprintf(host, hcap, "%.*s", (int)hl, h);
  snprintf(port, pcap, "%s", hp + i + 1);
  return true;
}

static bool label_ok(const char *l, size_t n) {
  if (n < 1 || n > 63) return false;
  if (!isalnum((unsigned char)l[0]) || !isalnum((unsigned char)l[n - 1])) return false;
  for (size_t i = 0; i < n; i++)
    if (!isalnum((unsigned char)l[i]) && l[i] != '-') return false;
  return true;
}

static bool valid_host(const char *h) {
  if (!*h) return true;
  unsigned char buf[16];
  if (inet_pton(AF_INET, h, buf) == 1 || inet_pton(AF_INET6, h, buf) == 1) return true;
  size_t n = strlen(h);
  if (n > 253) return false;
  for (const char *p = h;;) {
    const char *dot = strchr(p, '.');
    size_t ln = dot ? (size_t)(dot - p) : strlen(p);
    if (!dot) return label_ok(p, ln) || (ln == 0 && p != h); /* a trailing '.' is allowed */
    if (!label_ok(p, ln)) return false;
    p = dot + 1;
    if (!*p) return true;
  }
}

bool buckets_xnet_parse_host(const char *s, buckets_xnet_host *h, char *err, size_t errlen) {
  memset(h, 0, sizeof(*h));
  if (!*s) {
    snprintf(err, errlen, "invalid argument");
    return false;
  }
  char host[300], port[64], serr[400];
  if (buckets_go_split_host_port(s, host, sizeof(host), port, sizeof(port), serr, sizeof(serr))) {
    if (strcmp(port, "https") == 0) h->port = 443;
    else if (strcmp(port, "http") == 0) h->port = 80;
    else {
      char *end;
      long v = strtol(port, &end, 10);
      if (!*port || *end) {
        snprintf(err, errlen, "invalid port number");
        return false;
      }
      if (v < 0 || v > 65535) {
        snprintf(err, errlen, "port must be between 0 to 65535");
        return false;
      }
      h->port = (int)v;
    }
    h->port_set = true;
  } else if (strstr(serr, "missing port in address")) {
    snprintf(host, sizeof(host), "%s", s);
  } else {
    snprintf(err, errlen, "%s", serr);
    return false;
  }
  size_t hl = strlen(host);
  if (hl && host[hl - 1] == ']') { /* trimIPv6 */
    if (host[0] != '[') {
      snprintf(err, errlen, "missing '[' in host");
      return false;
    }
    memmove(host, host + 1, hl - 2);
    host[hl - 2] = '\0';
  }
  char trimmed[300];
  snprintf(trimmed, sizeof(trimmed), "%s", host);
  char *pct = strrchr(trimmed, '%');
  if (pct) *pct = '\0';
  if (!valid_host(trimmed)) {
    snprintf(err, errlen, "invalid hostname");
    return false;
  }
  snprintf(h->name, sizeof(h->name), "%s", host);
  return true;
}

void buckets_xnet_host_string(const buckets_xnet_host *h, char *out, size_t cap) {
  if (!h->port_set) snprintf(out, cap, "%s", h->name);
  else snprintf(out, cap, strchr(h->name, ':') ? "[%s]:%d" : "%s:%d", h->name, h->port);
}
