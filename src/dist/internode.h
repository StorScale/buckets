/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_INTERNODE_H
#define BUCKETS_DIST_INTERNODE_H

#include "net/http.h"

/* Internode RPC: HTTP/1.1 on the S3 port under this prefix, keep-alive
 * pooled, TLS when the endpoints are https://. Our own protocol -- not
 * MinIO's grid -- so Buckets and MinIO nodes cannot be mixed in one cluster.
 *
 * Every request carries X-Buckets-Internode: <unix-seconds>:<hex HMAC-SHA256>
 * over "<seconds>\n<method>\n<target>", keyed by a hash of the root
 * credentials, which all nodes share (as in MinIO). Requests more than 15
 * minutes off are refused. */
#define BUCKETS_INTERNODE_PREFIX "/buckets/internode/v1/"
#define BUCKETS_INTERNODE_AUTH "X-Buckets-Internode"
#define BUCKETS_INTERNODE_ERR "X-Buckets-Err"

void buckets_internode_set_secret(const char *root_user, const char *root_password);
/* out receives the header value. */
void buckets_internode_sign(const char *method, const char *target, char out[96]);
bool buckets_internode_verify(const buckets_http_request *req);

#endif
