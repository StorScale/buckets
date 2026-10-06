/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_SITEREPLICATION_H
#define BUCKETS_OPERATOR_SITEREPLICATION_H

#include "reconcile.h"

/* Applies every BucketsSiteReplication (clusters: the BucketsCluster list's items). */
void op_reconcile_site_replication(op_ctx *o, yyjson_val *clusters);

#endif
