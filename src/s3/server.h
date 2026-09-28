/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SERVER_H
#define BUCKETS_S3_SERVER_H

#include <pthread.h>
#include <stdatomic.h>

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
  /* Background threads (IAM start and refresh, LDAP sync), stopped and
   * joined by buckets_s3_server_stop before the object layer is freed. */
  pthread_mutex_t bg_mu;
  pthread_cond_t bg_cv;
  bool bg_stop;
  pthread_t iam_thread, ldap_thread;
  bool iam_thread_started, ldap_thread_started;
  char host_id[65];   /* x-amz-id-2 */
  _Atomic uint64_t request_seq;
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
/* The data scanner's hooks: cycle length from `scanner speed`, bucket
 * versioning from the metadata cache. */
void buckets_s3_scanner_hooks(buckets_s3_server *s, void *hooks /* buckets_scanner_hooks */);
/* Applies peers' notifications (the ud of buckets_peer_server_handle). */
void buckets_s3_peer_iam(void *server, const char *kind, const char *name);
void buckets_s3_peer_bucket(void *server, const char *bucket);
char *buckets_s3_peer_server_info(void *server);
/* The current OpenID providers (a reference to release), or NULL. */
struct buckets_openid *buckets_s3_openid(buckets_s3_server *s);
/* The current plugins (a reference to release), or NULL. */
struct buckets_plugins *buckets_s3_plugins(buckets_s3_server *s);
/* A service action (restart, stop, freeze, unfreeze) on this server; with
 * local, peers are told as well. */
void buckets_s3_service(buckets_s3_server *s, const char *action, bool local);

/* The LDAP identity provider (a reference to release), or NULL. */
struct buckets_ldapidp *buckets_s3_ldap(buckets_s3_server *s);

#endif
