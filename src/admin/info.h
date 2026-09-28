/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_ADMIN_INFO_H
#define BUCKETS_ADMIN_INFO_H

#include <stddef.h>
#include <time.h>

#include "core/common.h"

/* The deployment's shape, as the admin API reports it (MinIO's
 * globalEndpoints): every node and every drive endpoint. */
typedef struct {
  char *endpoint; /* the URL in a cluster, else the path */
  char *path;
  char *node; /* host:port */
  bool local;
  size_t pool;
} buckets_info_endpoint;

typedef struct buckets_cluster_info {
  char *self; /* this node's host:port */
  bool secure;
  char **nodes; /* every node, this one included */
  size_t nnodes;
  buckets_info_endpoint *eps;
  size_t neps;
  time_t started;
  bool distributed;
} buckets_cluster_info;

void buckets_cluster_info_free(buckets_cluster_info *ci);

struct buckets_s3_server;
/* madmin.ServerProperties for this node (its own drives), as JSON. */
char *buckets_admin_local_server_json(struct buckets_s3_server *s);

#endif
