/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/endpoint.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

bool buckets_endpoint_parse(const char *s, int default_port, buckets_endpoint *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  const char *rest;
  if (strncasecmp(s, "http://", 7) == 0) {
    rest = s + 7;
  } else if (strncasecmp(s, "https://", 8) == 0) {
    rest = s + 8;
    out->secure = true;
  } else {
    snprintf(err, errlen, "%s: endpoints must be http:// or https:// URLs", s);
    return false;
  }
  const char *slash = strchr(rest, '/');
  if (!slash || !slash[1]) {
    snprintf(err, errlen, "%s: missing drive path", s);
    return false;
  }
  char hostport[512];
  snprintf(hostport, sizeof(hostport), "%.*s", (int)(slash - rest), rest);
  char *h = hostport, *colon;
  if (*h == '[') { /* [ipv6]:port */
    char *close = strchr(h, ']');
    if (!close) {
      snprintf(err, errlen, "%s: bad IPv6 host", s);
      return false;
    }
    *close = '\0';
    colon = close[1] == ':' ? close + 1 : NULL;
    h++;
  } else {
    colon = strrchr(h, ':');
    if (colon) *colon = '\0';
  }
  out->port = default_port;
  if (colon) {
    char *end;
    long p = strtol(colon + 1, &end, 10);
    if (*end || p <= 0 || p > 65535) {
      snprintf(err, errlen, "%s: bad port", s);
      return false;
    }
    out->port = (int)p;
  }
  if (!*h) {
    snprintf(err, errlen, "%s: missing host", s);
    return false;
  }
  out->host = buckets_xstrdup(h);
  out->path = buckets_xstrdup(slash);
  out->url = buckets_xstrdup(s);
  return true;
}

void buckets_endpoint_free(buckets_endpoint *e) {
  free(e->url);
  free(e->host);
  free(e->path);
  memset(e, 0, sizeof(*e));
}

static bool same_addr(const struct sockaddr *a, const struct sockaddr *b) {
  if (a->sa_family != b->sa_family) return false;
  if (a->sa_family == AF_INET) {
    struct sockaddr_in x, y;
    memcpy(&x, a, sizeof(x));
    memcpy(&y, b, sizeof(y));
    return x.sin_addr.s_addr == y.sin_addr.s_addr;
  }
  if (a->sa_family == AF_INET6) {
    struct sockaddr_in6 x, y;
    memcpy(&x, a, sizeof(x));
    memcpy(&y, b, sizeof(y));
    return memcmp(&x.sin6_addr, &y.sin6_addr, 16) == 0;
  }
  return false;
}

bool buckets_host_is_local(const char *host) {
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, NULL, &hints, &res) != 0) return false;
  struct ifaddrs *ifs = NULL;
  bool local = false;
  if (getifaddrs(&ifs) == 0) {
    for (struct addrinfo *ai = res; ai && !local; ai = ai->ai_next) {
      for (struct ifaddrs *i = ifs; i && !local; i = i->ifa_next) {
        if (i->ifa_addr && same_addr(ai->ai_addr, i->ifa_addr)) local = true;
      }
    }
    freeifaddrs(ifs);
  }
  freeaddrinfo(res);
  return local;
}

/* A StatefulSet pod's endpoint is "<pod>.<service>.<ns>.svc...": its first
 * label is the pod's hostname. Matching on it works before cluster DNS has
 * published the pod's address. */
static bool host_is_me(const char *host) {
  char me[256];
  if (gethostname(me, sizeof(me)) != 0) return false;
  me[sizeof(me) - 1] = '\0';
  size_t n = strlen(me);
  if (!n) return false;
  if (strcasecmp(host, me) == 0) return true;
  return strncasecmp(host, me, n) == 0 && host[n] == '.';
}

void buckets_endpoint_resolve_local(buckets_endpoint *e, int server_port) {
  e->local = e->port == server_port && (host_is_me(e->host) || buckets_host_is_local(e->host));
}
