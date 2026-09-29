/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_PEERSTREAM_H
#define BUCKETS_DIST_PEERSTREAM_H

#include <stddef.h>

#include "net/client.h"

/* Streams of records (JSON lines) from peers, e.g. their traces and logs
 * for mc admin trace and logs: one reader per peer hands every record to
 * sink until stopped. Peers keep their streams alive with spaces at least
 * every second, so a stop takes effect within about a second. */

typedef void (*buckets_peer_line_fn)(void *ud, const char *line, size_t n);
typedef struct buckets_peer_relay buckets_peer_relay;

/* target: an internode path with query (signed as internode requests are). */
buckets_peer_relay *buckets_peer_relay_start(buckets_http_client *const *peers, size_t n, const char *target,
                                             buckets_peer_line_fn sink, void *ud);
void buckets_peer_relay_stop(buckets_peer_relay *r);

#endif
