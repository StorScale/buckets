/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_IAM_H
#define BUCKETS_OPERATOR_IAM_H

#include "reconcile.h"

/* Applies every BucketsPolicy, BucketsUser and Bucket to its cluster
 * (clusters: the BucketsCluster list's items). BucketsUser and
 * BucketsPolicy carry a finalizer, so deleting them removes the user or
 * policy from the cluster; deleting a Bucket leaves the bucket and its data. */
void op_reconcile_iam(op_ctx *o, yyjson_val *clusters);

#endif
