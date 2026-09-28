/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_PEER_H
#define BUCKETS_DIST_PEER_H

#include "net/client.h"
#include "net/http.h"

/* Peer notifications (MinIO's NotificationSys for IAM and bucket
 * metadata): after a change, every other server is told to reload the
 * item, so a user created on one server can sign in on the next request to
 * another. Best effort: servers that are down reload everything when they
 * start, and IAM and bucket metadata are also refreshed periodically. */
typedef struct buckets_peer_sys buckets_peer_sys;

buckets_peer_sys *buckets_peer_sys_new(buckets_http_client *const *peers, size_t n);
void buckets_peer_sys_free(buckets_peer_sys *p);

/* Tells every peer to reload one IAM item (see buckets_iam_notify_fn). */
void buckets_peer_notify_iam(buckets_peer_sys *p, const char *kind, const char *name);
/* Tells every peer to drop its cached metadata for a bucket. */
void buckets_peer_notify_bucket(buckets_peer_sys *p, const char *bucket);

/* The receiving side, under BUCKETS_INTERNODE_PREFIX "peer/". */
typedef struct {
  void (*iam)(void *ud, const char *kind, const char *name);
  void (*bucket)(void *ud, const char *bucket);
  void *ud;
} buckets_peer_handlers;
void buckets_peer_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

#endif
