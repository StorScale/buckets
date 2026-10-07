/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_BATCH_H
#define BUCKETS_S3_BATCH_H

#include <stdbool.h>

#include "batch/job.h"
#include "core/buf.h"

/* Batch jobs (MinIO's cmd/batch-*.go): replicate (to or from a remote
 * MinIO/Buckets or S3 endpoint), keyrotate (re-seal SSE-S3/SSE-KMS object
 * keys) and expire. Jobs are kept in .minio.sys/batch-jobs/<id> and their
 * progress in .minio.sys/batch-jobs/reports/<id>/, as MinIO keeps them, so
 * either server lists and describes the other's jobs. */

struct buckets_s3_server;
typedef struct buckets_batch buckets_batch;

buckets_batch *buckets_batch_new(struct buckets_s3_server *s);
void buckets_batch_stop(buckets_batch *b);
/* Stops it, then frees it. */
void buckets_batch_free(buckets_batch *b);

/* StartBatchJob: validates and saves the job (which the call takes), then
 * runs it. On success out gets madmin.BatchJobResult JSON; on failure e. */
bool buckets_batch_start(buckets_batch *b, buckets_batch_job *job, const char *user, buckets_buf *out,
                         buckets_batch_err *e);
/* CancelBatchJob: stops the job (on whichever node runs it) and removes
 * its definition. */
void buckets_batch_cancel(buckets_batch *b, const char *id, bool broadcast);
/* ListBatchJobs (madmin.ListBatchJobsResult JSON), jobs of one type or all. */
void buckets_batch_list(buckets_batch *b, const char *type, buckets_buf *out);
/* BatchJobStatus / DescribeBatchJob: false when there is no such job
 * (other errors in e). */
bool buckets_batch_status(buckets_batch *b, const char *id, buckets_buf *out, buckets_batch_err *e);
bool buckets_batch_describe(buckets_batch *b, const char *id, buckets_buf *out);
/* This node's job metrics (batchJobMetrics.report): a madmin.JobMetric JSON
 * object per job ("id":{...}), for id or every job. */
void buckets_batch_metrics_json(buckets_batch *b, const char *id, buckets_buf *out);
/* The same, one entry per running or recent job, for Prometheus: type,
 * bucket, job ID, objects, objects failed. */
typedef struct {
  char type[16], bucket[256], id[128];
  double objects, failed;
} buckets_batch_metric;
size_t buckets_batch_metrics(buckets_batch *b, buckets_batch_metric **out);

#endif
