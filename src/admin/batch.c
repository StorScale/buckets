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

/* ---- realtime metrics (madmin.RealtimeMetrics records, one per interval) ---- */

#define METRICS_BATCH_JOBS (1u << 3)

typedef struct {
  buckets_s3_server *s;
  uint64_t types;
  char *job_id;
  int n;
  int64_t interval_ns;
  bool first;
  buckets_buf pending;
  size_t pos;
} mstream;

static void mstream_free(void *ud) {
  mstream *m = ud;
  if (!m) return;
  free(m->job_id);
  buckets_buf_free(&m->pending);
  free(m);
}

/* The batch jobs of this node and every peer, by job ID (later ones win). */
static void batch_jobs_json(mstream *m, buckets_buf *out) {
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *jobs = yyjson_mut_obj(doc);
  size_t np = 0;
  buckets_peer_info *pi = buckets_peer_batch_metrics(m->s->peers, &np);
  buckets_buf local = BUCKETS_BUF_INIT;
  buckets_batch_metrics_json(m->s->batch, m->job_id, &local);
  const char *srcs[65];
  size_t nsrc = 0;
  srcs[nsrc++] = local.data;
  for (size_t i = 0; i < np && nsrc < 65; i++)
    if (pi[i].json) srcs[nsrc++] = pi[i].json;
  for (size_t i = 0; i < nsrc; i++) {
    yyjson_doc *d = yyjson_read(srcs[i], strlen(srcs[i]), 0);
    yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
    yyjson_obj_iter it = yyjson_obj_iter_with(root);
    yyjson_val *k;
    while (yyjson_is_obj(root) && (k = yyjson_obj_iter_next(&it))) {
      const char *id = yyjson_get_str(k);
      if (m->job_id && *m->job_id && strcmp(id, m->job_id) != 0) continue;
      yyjson_mut_val *key = yyjson_mut_strcpy(doc, id);
      yyjson_mut_obj_remove(jobs, key);
      yyjson_mut_obj_add(jobs, key, yyjson_val_mut_copy(doc, yyjson_obj_iter_get_val(k)));
    }
    yyjson_doc_free(d);
  }
  buckets_peer_info_free(pi, np);
  buckets_buf_free(&local);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  char when[64];
  buckets_time_rfc3339_nano(ts.tv_sec, ts.tv_nsec, when);
  size_t len;
  char *j = yyjson_mut_val_write(jobs, 0, &len);
  buckets_buf_appendf(out, "\"batchJobs\":{\"collected\":\"%s\",\"Jobs\":%s}", when, j ? j : "{}");
  free(j);
  yyjson_mut_doc_free(doc);
}

static void record(mstream *m, buckets_buf *out) {
  const char *node = buckets_trace_node();
  buckets_buf_append_c(out, "{\"hosts\":[");
  buckets_json_go_string(out, node, strlen(node));
  buckets_buf_append_c(out, "],\"aggregated\":{");
  if (m->types & METRICS_BATCH_JOBS) batch_jobs_json(m, out);
  buckets_buf_appendf(out, "},\"final\":%s}\n", m->n <= 1 ? "true" : "false");
}

static long mstream_read(void *ud, char *buf, size_t cap) {
  mstream *m = ud;
  if (m->pos == m->pending.len) {
    if (m->n <= 0) return 0;
    buckets_buf_reset(&m->pending);
    m->pos = 0;
    if (!m->first) {
      struct timespec ts = {m->interval_ns / 1000000000LL, m->interval_ns % 1000000000LL};
      nanosleep(&ts, NULL);
    }
    m->first = false;
    record(m, &m->pending);
    m->n--;
  }
  size_t k = m->pending.len - m->pos;
  if (k > cap) k = cap;
  memcpy(buf, m->pending.data + m->pos, k);
  m->pos += k;
  return (long)k;
}

void buckets_admin_metrics(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ServerInfo") || !ready(c)) return;
  mstream *m = buckets_xcalloc(1, sizeof(*m));
  m->s = c->s;
  m->first = true;
  const char *iv = buckets_query_get(&c->q, "interval");
  int64_t ns = 0;
  if (!iv || !buckets_go_duration_parse(iv, &ns) || ns < 1000000000LL) ns = 1000000000LL;
  m->interval_ns = ns;
  const char *nv = buckets_query_get(&c->q, "n");
  long n = nv ? strtol(nv, NULL, 10) : 0;
  m->n = n > 0 && n < INT_MAX ? (int)n : INT_MAX;
  const char *tv = buckets_query_get(&c->q, "types");
  uint64_t types = tv ? strtoull(tv, NULL, 10) : 0;
  m->types = types ? types : UINT64_MAX;
  const char *id = buckets_query_get(&c->q, "by-jobID");
  m->job_id = id && *id ? buckets_xstrdup(id) : NULL;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
  c->resp->chunked = true;
  c->resp->stream = mstream_read;
  c->resp->stream_ud = m;
  c->resp->stream_free = mstream_free;
}
