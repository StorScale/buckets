/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_RECONCILE_H
#define BUCKETS_OPERATOR_RECONCILE_H

#include "kube.h"

typedef struct {
  kube *k;
  const char *namespace;      /* watch only this namespace; NULL = all */
  const char *cluster_domain; /* cluster DNS suffix, default cluster.local */
} op_ctx;

/* One level-triggered pass over every BucketsCluster (and the IAM kinds). */
void op_reconcile_all(op_ctx *o);

#endif
