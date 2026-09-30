/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Batch jobs (MinIO's StartBatchJob, ListBatchJobs, BatchJobStatus,
 * DescribeBatchJob and CancelBatchJob) and the realtime metrics stream
 * (MetricsHandler) that mc batch status follows. */
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "core/timefmt.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "s3/batch.h"
#include "trace/trace.h"

#define MAX_JOB_SIZE (4 * 1024 * 1024)

static void batch_error(s3_ctx *c, const buckets_batch_err *e) {
  if (!e->code) {
    buckets_admin_custom_error(c, 400, "XMinioAdminInvalidArgument", "Invalid arguments specified.");
  } else if (e->internal) {
    char msg[1024];
    snprintf(msg, sizeof(msg), "We encountered an internal error, please try again.: cause(%s)", e->desc);
    buckets_admin_custom_error(c, 500, "InternalError", msg);
  } else {
    buckets_admin_custom_error(c, e->status, e->code, e->desc);
  }
}

static void no_such_job(s3_ctx *c) {
  buckets_admin_custom_error(c, 404, "XMinioAdminNoSuchJob", "The specified job does not exist.");
}

static bool ready(s3_ctx *c) {
  if (c->s->batch) return true;
  buckets_admin_custom_error(c, 503, "XMinioServerNotInitialized", "Server not initialized, please try again.");
  return false;
}

void buckets_admin_batch_start(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:StartBatchJob") || !ready(c)) return;
  buckets_s3_error re = buckets_s3_read_doc(c);
  if (re) {
    buckets_admin_error(c, re);
    return;
  }
  if (c->doc.len > MAX_JOB_SIZE) {
    buckets_admin_custom_error(c, 400, "InvalidRequest", "input provided exceeds the hard limit");
    return;
  }
  const char *user = c->ident ? (c->ident->parent && *c->ident->parent ? c->ident->parent : c->ident->access_key) : "";
  buckets_batch_job job;
  char *err = NULL;
  if (!buckets_batch_job_parse(c->doc.data ? c->doc.data : "", c->doc.len, &job, &err)) {
    buckets_batch_err e = {.code = "InternalError", .internal = true, .status = 500};
    snprintf(e.desc, sizeof(e.desc), "%s", err);
    free(err);
    batch_error(c, &e);
    return;
  }
  buckets_batch_err e = {0};
  buckets_buf out = BUCKETS_BUF_INIT;
  if (!buckets_batch_start(c->s->batch, &job, user, &out, &e)) {
    buckets_batch_job_free(&job);
    buckets_buf_free(&out);
    batch_error(c, &e);
    return;
  }
  buckets_batch_job_free(&job);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, out.data, out.len);
  buckets_buf_free(&out);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

void buckets_admin_batch_list(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListBatchJobs") || !ready(c)) return;
  buckets_buf_reset(&c->resp->body);
  buckets_batch_list(c->s->batch, buckets_query_get(&c->q, "jobType"), &c->resp->body);
  buckets_buf_append_c(&c->resp->body, "\n"); /* json.Encoder */
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
  c->resp->status = 200;
}

void buckets_admin_batch_status(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListBatchJobs") || !ready(c)) return;
  const char *id = buckets_query_get(&c->q, "jobId");
  if (!id || !*id) {
    buckets_admin_custom_error(c, 400, "XMinioAdminInvalidArgument", "Invalid arguments specified.");
    return;
  }
  buckets_batch_err e = {0};
  buckets_buf out = BUCKETS_BUF_INIT;
  if (!buckets_batch_status(c->s->batch, id, &out, &e)) {
    buckets_buf_free(&out);
    no_such_job(c);
    return;
  }
  if (e.status) {
    buckets_buf_free(&out);
    batch_error(c, &e);
    return;
  }
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, out.data, out.len);
  buckets_buf_free(&out);
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
  c->resp->status = 200;
}

void buckets_admin_batch_describe(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:DescribeBatchJob") || !ready(c)) return;
  const char *id = buckets_query_get(&c->q, "jobId");
  if (!id || !*id) {
    buckets_admin_custom_error(c, 400, "XMinioAdminInvalidArgument", "Invalid arguments specified.");
    return;
  }
  buckets_buf out = BUCKETS_BUF_INIT;
  if (!buckets_batch_describe(c->s->batch, id, &out)) {
    buckets_buf_free(&out);
    no_such_job(c);
    return;
  }
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, out.data, out.len);
  buckets_buf_free(&out);
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
  c->resp->status = 200;
}

void buckets_admin_batch_cancel(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:CancelBatchJob") || !ready(c)) return;
  const char *id = buckets_query_get(&c->q, "id");
  if (!id || !*id) {
    buckets_admin_custom_error(c, 400, "XMinioAdminInvalidArgument", "Invalid arguments specified.");
    return;
  }
  buckets_batch_cancel(c->s->batch, id, true);
  buckets_buf_reset(&c->resp->body);
  c->resp->status = 204;
}
