/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_IAM_H
#define BUCKETS_OPERATOR_IAM_H

#include "reconcile.h"
#include "s3client.h"

/* Applies every BucketsPolicy, BucketsUser and Bucket to its cluster
 * (clusters: the BucketsCluster list's items). BucketsUser and
 * BucketsPolicy carry a finalizer, so deleting them removes the user or
 * policy from the cluster; deleting a Bucket leaves the bucket and its data. */
void op_reconcile_iam(op_ctx *o, yyjson_val *clusters);

/* A BucketsCluster's admin API, as root (its credentials Secret). NULL and
 * why on failure; free with op_cluster_admin_free. */
typedef struct op_admin op_admin;
op_admin *op_cluster_admin(op_ctx *o, yyjson_val *bc, char *err, size_t errlen);
struct s3c *op_admin_client(op_admin *a);
void op_cluster_admin_free(op_admin *a);

#endif
