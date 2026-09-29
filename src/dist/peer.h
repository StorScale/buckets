/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_PEER_H
#define BUCKETS_DIST_PEER_H

#include "net/client.h"
#include "net/http.h"
#include "core/query.h"

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

/* Whether a peer ("host:port") answered recently (false while backing off). */
bool buckets_peer_node_online(buckets_peer_sys *p, const char *node);

/* Each peer's madmin.ServerProperties JSON (NULL where unreachable), in
 * peer order; nodes[i] is "host:port". Queried in parallel. */
typedef struct {
  char *node;
  char *json;
} buckets_peer_info;
buckets_peer_info *buckets_peer_server_info(buckets_peer_sys *p, size_t *n);
void buckets_peer_info_free(buckets_peer_info *info, size_t n);
/* The clients to every peer (the internode traffic counters). */
buckets_http_client *const *buckets_peer_clients(buckets_peer_sys *p, size_t *n);
/* Each peer's node metrics (MinIO's peerMetricsGroups) as Prometheus text
 * in json, NULL where unreachable. */
buckets_peer_info *buckets_peer_metrics(buckets_peer_sys *p, size_t *n);
/* Each peer's last-day tier stats (GetLastDayTierStats), NULL where unreachable. */
buckets_peer_info *buckets_peer_tier_stats(buckets_peer_sys *p, size_t *n);
/* A request to one node ("host:port"), POSTed and signed; false when it
 * could not be reached. */
bool buckets_peer_call(buckets_peer_sys *p, const char *node, const char *target, int *status, buckets_buf *body);
/* Each peer's batch job metrics, NULL where unreachable. */
buckets_peer_info *buckets_peer_batch_metrics(buckets_peer_sys *p, size_t *n);

/* The receiving side, under BUCKETS_INTERNODE_PREFIX "peer/". */
typedef struct {
  void (*iam)(void *ud, const char *kind, const char *name);
  void (*bucket)(void *ud, const char *bucket);
  char *(*server_info)(void *ud); /* JSON, malloc'd */
  char *(*metrics)(void *ud);     /* this node's metrics as Prometheus text, malloc'd */
  /* this node's events for a listener (bucket, prefix, suffix, events in
   * q), streamed into resp; false: a bad request */
  bool (*listen)(void *ud, const buckets_query *q, buckets_http_response *resp);
  void *ud;
  char *(*tier_stats)(void *ud); /* this node's last-day transitions (JSON), malloc'd */
  char *(*batch_metrics)(void *ud); /* this node's batch job metrics (JSON object by job ID), malloc'd */
  /* a decommission or rebalance operation this node runs (q: op and its
   * arguments): the admin API's answer, status and JSON body */
  void (*datamove)(void *ud, const buckets_query *q, int *status, buckets_buf *body);
  /* an admin operation on state this node holds (q: op and its arguments,
   * e.g. a heal sequence's status): status and JSON body */
  void (*admin)(void *ud, const buckets_query *q, int *status, buckets_buf *body);
} buckets_peer_handlers;
void buckets_peer_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

#endif
