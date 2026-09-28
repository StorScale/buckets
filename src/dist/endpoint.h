/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_ENDPOINT_H
#define BUCKETS_DIST_ENDPOINT_H

#include "core/common.h"

/* A drive given as a URL: http(s)://host[:port]/path. Replaces MinIO's
 * cmd/endpoint.go. An endpoint is local when its port is this server's and
 * its host resolves to one of this machine's addresses, so a test cluster
 * can run on one machine with a port per node. */
typedef struct {
  char *url;
  bool secure;
  char *host;
  int port;
  char *path;
  bool local;
} buckets_endpoint;

/* default_port applies when the URL has none (MinIO uses the server port). */
bool buckets_endpoint_parse(const char *s, int default_port, buckets_endpoint *out, char *err, size_t errlen);
void buckets_endpoint_free(buckets_endpoint *e);
/* Sets e->local against this server's listen port. */
void buckets_endpoint_resolve_local(buckets_endpoint *e, int server_port);
bool buckets_host_is_local(const char *host);

#endif
