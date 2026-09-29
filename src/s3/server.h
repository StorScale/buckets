/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SERVER_H
#define BUCKETS_S3_SERVER_H

#include <pthread.h>
#include <stdatomic.h>

#include "core/query.h"
#include "iam/iam.h"
#include "net/http.h"
#include "object/object.h"

/* The S3 API front end: health probes, request authentication and routing.
 * Replaces MinIO's cmd/api-router.go + generic-handlers.go + auth-handler.go. */
typedef struct buckets_s3_server {
  buckets_objlayer *_Atomic layer; /* NULL until bootstrap finishes */
  const char *root_user;
  const char *root_password;
  const char *region; /* "" accepts any region in signatures */
  buckets_iam *iam;   /* credentials and policies (root-only until started) */
  struct buckets_metasys *meta; /* bucket metadata cache, once the layer is up */
  int meta_ttl_ms;              /* its snapshot lifetime (0: until invalidated) */
  struct buckets_peer_sys *peers; /* other servers, told about IAM and bucket changes */
  struct buckets_cluster_info *cluster; /* nodes and drive endpoints, for the admin API */
  struct buckets_config_sys *config;    /* the server configuration, once loaded */
  pthread_mutex_t oidc_mu;
  struct buckets_openid *openid; /* identity_openid providers (guarded by oidc_mu) */
  struct buckets_plugins *plugins; /* policy/identity plugins (guarded by oidc_mu) */
  struct buckets_ldapidp *ldap;    /* identity_ldap, fixed once IAM starts (guarded by oidc_mu) */
  const char *ca_path;             /* extra trusted CAs (certs/CAs), or NULL */
  pthread_mutex_t freeze_mu; /* mc admin service freeze: S3 requests wait while freeze_cnt > 0 */
  pthread_cond_t freeze_cv;
  int freeze_cnt;
  /* restart / stop the process (set by main), after the response is sent */
  void (*service)(void *ud, const char *action);
  void *service_ud;
  /* A bucket's size in bytes from the latest data usage (0 when unknown),
   * for hard quotas; NULL until the scanner provides one. */
  uint64_t (*bucket_usage)(void *ud, const char *bucket);
  void *bucket_usage_ud;
  struct buckets_usage_cache_s *usage; /* the stored data usage (scanner/usage.h), once the layer is up */
  struct buckets_kms *kms;             /* SSE-S3/SSE-KMS keys, or NULL when no KMS is configured */
  struct buckets_repl *repl;           /* bucket replication (targets and workers), once the layer is up */
  struct buckets_tiering *tiering;     /* transitions and remote reads, once the layer is up */
  struct buckets_tiers *tiers;         /* remote tiers (tier-config.bin), once the layer is up */
  struct buckets_batch *batch;         /* batch jobs, once the layer is up */
  struct buckets_datamove *datamove;   /* decommission and rebalance, once the layer is up */
  struct buckets_sr *sr;               /* site replication (always set; enabled by its state) */
  /* Background threads (IAM start and refresh, LDAP sync), stopped and
   * joined by buckets_s3_server_stop before the object layer is freed. */
  pthread_mutex_t bg_mu;
  pthread_cond_t bg_cv;
  bool bg_stop;
  pthread_t iam_thread, ldap_thread;
  bool iam_thread_started, ldap_thread_started;
  char host_id[65];   /* x-amz-id-2 */
  struct buckets_notifier *notifier; /* event notification targets and listeners */
  struct buckets_logger *logger;     /* audit and server log targets */
  int requests_max;                  /* API workers (the X-Ratelimit-* headers; 0: none) */
  char endpoint[256];  /* this server's URL, for x-minio-origin-endpoint */
  _Atomic uint64_t request_seq;
  struct buckets_scanner *_Atomic scanner; /* the data scanner, once started (for its metrics) */
  struct buckets_healer *_Atomic healer;   /* MRF and drive healing, once started (for its metrics) */
  struct buckets_lock_server *lock_server; /* this node's dsync locks (distributed), for metrics */
  struct buckets_tls_client *internode_tls; /* for connections to peers of our own (netperf), NULL: plain */
  struct buckets_http_client **internode;  /* clients to the other nodes (their traffic), and how many */
  size_t ninternode;
  _Atomic uint64_t ilm_actions[9];       /* their outcomes, by lifecycle action (bucket/lifecycle.h) */
  pthread_t metrics_thread;              /* samples the host for the resource metrics */
  bool metrics_thread_started;
} buckets_s3_server;

void buckets_s3_server_init(buckets_s3_server *s, buckets_objlayer *layer, const char *root_user,
                            const char *root_password, const char *region);
/* Publishes the object layer once bootstrap is done; until then S3 requests
 * get 503 XMinioServerNotInitialized and readiness probes fail. */
void buckets_s3_server_set_layer(buckets_s3_server *s, buckets_objlayer *layer);
void buckets_s3_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);
/* Stops the background threads; call once requests have drained and
 * before freeing the object layer. */
void buckets_s3_server_stop(buckets_s3_server *s);
/* Closes the notification and log targets (MQTT brokers get a DISCONNECT,
 * connections close); after everything that sends events has stopped. */
void buckets_s3_server_close_targets(buckets_s3_server *s);
/* The data scanner's hooks: cycle length from `scanner speed`, bucket
 * versioning from the metadata cache. */
void buckets_s3_scanner_hooks(buckets_s3_server *s, void *hooks /* buckets_scanner_hooks */);
/* Applies peers' notifications (the ud of buckets_peer_server_handle). */
void buckets_s3_peer_iam(void *server, const char *kind, const char *name);
void buckets_s3_peer_bucket(void *server, const char *bucket);
char *buckets_s3_peer_server_info(void *server);
char *buckets_s3_peer_tier_stats(void *server);
char *buckets_s3_peer_batch_metrics(void *server);
void buckets_s3_peer_datamove(void *server, const buckets_query *q, int *status, buckets_buf *body);
void buckets_s3_peer_admin(void *server, const buckets_http_request *req, const buckets_query *q,
                           buckets_http_response *resp);
/* Which versions of one key (newest first) lifecycle would delete now. */
void buckets_s3_lifecycle_due(buckets_s3_server *s, const char *bucket, const buckets_object_info *v, size_t n,
                              bool *due);
/* This node's contribution to the cluster metrics (Prometheus text). */
char *buckets_s3_peer_metrics(void *server);
/* A peer's listener on this node's events (see buckets_peer_handlers.listen). */
bool buckets_s3_peer_listen(void *server, const buckets_query *q, buckets_http_response *resp);
/* The current OpenID providers (a reference to release), or NULL. */
struct buckets_openid *buckets_s3_openid(buckets_s3_server *s);
/* The current plugins (a reference to release), or NULL. */
struct buckets_plugins *buckets_s3_plugins(buckets_s3_server *s);
/* A service action (restart, stop, freeze, unfreeze) on this server; with
 * local, peers are told as well. */
void buckets_s3_service(buckets_s3_server *s, const char *action, bool local);

/* The LDAP identity provider (a reference to release), or NULL. */
struct buckets_ldapidp *buckets_s3_ldap(buckets_s3_server *s);

/* A configuration object under .minio.sys (path relative to it), written
 * SSE-S3-encrypted when a KMS is configured, as MinIO saves tier-config.bin;
 * reading decrypts either kind. */
bool buckets_s3_config_write(buckets_s3_server *s, const char *path, const void *data, size_t n);
buckets_obj_err buckets_s3_config_read(buckets_s3_server *s, const char *path, buckets_buf *out);

#endif
