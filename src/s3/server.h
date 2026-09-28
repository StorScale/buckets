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
  char host_id[65];   /* x-amz-id-2 */
  _Atomic uint64_t request_seq;
} buckets_s3_server;

void buckets_s3_server_init(buckets_s3_server *s, buckets_objlayer *layer, const char *root_user,
                            const char *root_password, const char *region);
/* Publishes the object layer once bootstrap is done; until then S3 requests
 * get 503 XMinioServerNotInitialized and readiness probes fail. */
void buckets_s3_server_set_layer(buckets_s3_server *s, buckets_objlayer *layer);
void buckets_s3_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);
/* Applies peers' notifications (the ud of buckets_peer_server_handle). */
void buckets_s3_peer_iam(void *server, const char *kind, const char *name);
void buckets_s3_peer_bucket(void *server, const char *bucket);
char *buckets_s3_peer_server_info(void *server);
/* The current OpenID providers (a reference to release), or NULL. */
struct buckets_openid *buckets_s3_openid(buckets_s3_server *s);
/* The current plugins (a reference to release), or NULL. */
struct buckets_plugins *buckets_s3_plugins(buckets_s3_server *s);

#endif
