/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NOTIFY_XNET_H
#define BUCKETS_NOTIFY_XNET_H

#include <stdbool.h>
#include <stddef.h>

/* minio/pkg net.Host and ParseHost (the addresses of Redis, NSQ and other
 * targets): Go's net.SplitHostPort, then a hostname or IP check, with Go's
 * error messages. */
typedef struct {
  char name[256];
  int port;
  bool port_set;
} buckets_xnet_host;

bool buckets_xnet_parse_host(const char *s, buckets_xnet_host *h, char *err, size_t errlen);
/* Host.String: name, or JoinHostPort(name, port) when the port is set. */
void buckets_xnet_host_string(const buckets_xnet_host *h, char *out, size_t cap);

/* Go's net.SplitHostPort; false with Go's error ("address x: missing port in
 * address", ...). */
bool buckets_go_split_host_port(const char *hostport, char *host, size_t hcap, char *port, size_t pcap, char *err,
                                size_t errlen);

#endif
