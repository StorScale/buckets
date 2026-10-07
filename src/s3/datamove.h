/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_DATAMOVE_H
#define BUCKETS_S3_DATAMOVE_H

#include <stdbool.h>

#include "core/buf.h"
#include "core/query.h"

/* Pool decommission and rebalance (MinIO's
 * cmd/erasure-server-pool-decom.go and erasure-server-pool-rebalance.go):
 * objects move out of a pool being retired, or out of pools fuller than the
 * rest, version by version, keeping their IDs, times and metadata. Progress
 * is kept as MinIO keeps it: .minio.sys/pool.bin in every pool and
 * .minio.sys/rebalance.bin in the first, both in MinIO's msgp. */

struct buckets_s3_server;
typedef struct buckets_datamove buckets_datamove;

buckets_datamove *buckets_datamove_new(struct buckets_s3_server *s);
void buckets_datamove_stop(buckets_datamove *d);
/* Stops it, then frees it. */
void buckets_datamove_free(buckets_datamove *d);

/* The admin API's operations: op is "decom-start", "decom-cancel",
 * "decom-status", "pools-list", "rebal-start", "rebal-status" or
 * "rebal-stop", with the request's query (pool, by-id). The result is the
 * HTTP status with either the response body or an error code and message.
 * Unless forwarded, an operation that belongs to another node is sent there. */
typedef struct {
  int status;
  char code[64];
  char message[512];
  buckets_buf body;
} buckets_datamove_result;
void buckets_datamove_op(buckets_datamove *d, const char *op, const buckets_query *q, bool forwarded,
                         buckets_datamove_result *out);

/* Peer notifications: pool.bin or rebalance.bin changed (start: resume
 * the local pools' rebalance), or rebalance stopped. */
void buckets_datamove_reload_pool_meta(buckets_datamove *d);
void buckets_datamove_reload_rebalance(buckets_datamove *d, bool start);
void buckets_datamove_stop_rebalance(buckets_datamove *d);

#endif
