/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SERVER_H
#define BUCKETS_S3_SERVER_H

#include <stdatomic.h>

#include "iam/iam.h"
#include "net/http.h"
#include "object/object.h"

/* The S3 API front end: health probes, request authentication and routing.
 * Replaces MinIO's cmd/api-router.go + generic-handlers.go + auth-handler.go. */
typedef struct {
  buckets_objlayer *_Atomic layer; /* NULL until bootstrap finishes */
  const char *root_user;
  const char *root_password;
  const char *region; /* "" accepts any region in signatures */
  buckets_iam *iam;   /* credentials and policies (root-only until started) */
  struct buckets_metasys *meta; /* bucket metadata cache, once the layer is up */
  int meta_ttl_ms;              /* its snapshot lifetime (0: until invalidated) */
  char host_id[65];   /* x-amz-id-2 */
  _Atomic uint64_t request_seq;
} buckets_s3_server;

void buckets_s3_server_init(buckets_s3_server *s, buckets_objlayer *layer, const char *root_user,
                            const char *root_password, const char *region);
/* Publishes the object layer once bootstrap is done; until then S3 requests
 * get 503 XMinioServerNotInitialized and readiness probes fail. */
void buckets_s3_server_set_layer(buckets_s3_server *s, buckets_objlayer *layer);
void buckets_s3_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

#endif
