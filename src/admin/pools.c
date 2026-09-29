/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin decommission and mc admin rebalance (MinIO's
 * cmd/admin-handlers-pools.go). */
#include <stdio.h>
#include <string.h>

#include "admin/admin.h"
#include "s3/datamove.h"

static void run(s3_ctx *c, const char *op, bool info_or_decom) {
  static const char *const info_decom[] = {"admin:ServerInfo", "admin:Decommission"};
  bool ok = info_or_decom ? buckets_admin_authorize_any(c, info_decom, 2)
                          : buckets_admin_authorize(c, strncmp(op, "rebal", 5) == 0 ? "admin:Rebalance" : "admin:Decommission");
  if (!ok) return;
  if (!c->s->datamove) {
    buckets_admin_custom_error(c, 503, "XMinioServerNotInitialized", "Server not initialized, please try again.");
    return;
  }
  buckets_datamove_result r;
  buckets_datamove_op(c->s->datamove, op, &c->q, false, &r);
  if (r.status >= 300) {
    buckets_admin_custom_error(c, r.status, r.code, r.message);
  } else {
    buckets_buf_reset(&c->resp->body);
    buckets_buf_append(&c->resp->body, r.body.data, r.body.len);
    if (r.body.len) buckets_http_resp_header(c->resp, "Content-Type", "application/json");
    c->resp->status = r.status;
  }
  buckets_buf_free(&r.body);
}

void buckets_admin_pools_list(s3_ctx *c) { run(c, "pools-list", true); }
void buckets_admin_pools_status(s3_ctx *c) { run(c, "decom-status", true); }
void buckets_admin_decommission(s3_ctx *c) { run(c, "decom-start", false); }
void buckets_admin_decommission_cancel(s3_ctx *c) { run(c, "decom-cancel", false); }
void buckets_admin_rebalance_start(s3_ctx *c) { run(c, "rebal-start", false); }
void buckets_admin_rebalance_status(s3_ctx *c) { run(c, "rebal-status", false); }
void buckets_admin_rebalance_stop(s3_ctx *c) { run(c, "rebal-stop", false); }
