/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_METRICS_H
#define BUCKETS_S3_METRICS_H

#include <stdbool.h>

#include "core/buf.h"
#include "metrics/expo.h"
#include "s3/server.h"

/* /minio/v2/metrics/<which> (cluster, node, bucket, resource) into out, as
 * Prometheus text; false for an unknown endpoint. */
bool buckets_metrics_v2(buckets_s3_server *s, const char *which, buckets_buf *out);
/* /minio/metrics/v3<path>; false when no metric group serves path. */
bool buckets_metrics_v3(buckets_s3_server *s, const char *path, buckets_buf *out);
/* Samples the host for the resource endpoint (at start, then every minute). */
void buckets_metrics_resource_collect(buckets_s3_server *s);
/* The Go collector's families, from the C runtime. */
void buckets_metrics_go_collector(buckets_expo *e);

#endif
