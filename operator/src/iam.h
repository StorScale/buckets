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

/* Where a BucketsCluster's S3 API is, and its root credentials (freed by the caller). */
bool op_cluster_peer(op_ctx *o, yyjson_val *bc, char *url, size_t cap, char **ak, char **sk, char *err, size_t errlen);
/* A Secret's two keys, decoded (freed by the caller); false unless both are there. */
bool op_secret_pair(op_ctx *o, const char *ns, const char *secret, const char *k1, const char *k2, char **v1, char **v2);
/* How often applied resources are read back and put right (BUCKETS_OPERATOR_DRIFT_MS, 10 minutes). */
long long op_drift_interval_ms(void);
/* The BucketsCluster ns/name among clusters, or NULL. */
yyjson_val *op_find_cluster(yyjson_val *clusters, const char *ns, const char *name);

#endif
