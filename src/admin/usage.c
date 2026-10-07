/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The usage and chargeback reports' data (docs/design/usage-reports.md), Buckets extensions to the admin API:
 *   GET    /minio/admin/v3/buckets/usage?from=YYYY-MM-DD&to=YYYY-MM-DD   admin:DataUsageInfo
 *          (buckets_usage_report: per bucket and per team, with the rates; from and to default to this
 *          month so far)
 *   PUT    /minio/admin/v3/buckets/usage-rates   {"currency", "storageGbMonth", ...}   admin:ConfigUpdate
 *   DELETE /minio/admin/v3/buckets/usage-rates                                        admin:ConfigUpdate
 * Teams are today's, from the policies, as the Teams page shows them. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "iam/teams.h"
#include "object/sysconfig.h"
#include "usage/store.h"

/* The teams in the server's policies, into d. */
static yyjson_mut_val *teams_now(s3_ctx *c, yyjson_mut_doc *d) {
  buckets_iam_policy_doc *docs;
  size_t n;
  buckets_iam_list_policies(c->s->iam, &docs, &n);
  yyjson_mut_doc *pd = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(pd);
  yyjson_mut_doc_set_root(pd, root);
  for (size_t i = 0; i < n; i++) {
    if (strncmp(docs[i].name, "team-", 5) != 0) continue; /* only a team's can be one */
    yyjson_doc *p = yyjson_read(docs[i].json, strlen(docs[i].json), 0);
    if (p)
      yyjson_mut_obj_add(root, yyjson_mut_strcpy(pd, docs[i].name),
                         yyjson_val_mut_copy(pd, yyjson_doc_get_root(p)));
    yyjson_doc_free(p);
  }
  buckets_iam_policy_doc_free(docs, n);
  free(docs);
  yyjson_doc *policies = yyjson_mut_doc_imut_copy(pd, NULL);
  yyjson_mut_doc_free(pd);
  yyjson_mut_val *teams = buckets_teams_from_policies(d, yyjson_doc_get_root(policies));
  yyjson_doc_free(policies);
  return teams;
}

static void reply_json(s3_ctx *c, const buckets_buf *j) {
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, j->data ? j->data : "", j->len);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

void buckets_admin_usage(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:DataUsageInfo")) return;
  char today[11], first[11];
  buckets_usage_today(today);
  snprintf(first, sizeof(first), "%.8s01", today);
  const char *from = buckets_query_get(&c->q, "from"), *to = buckets_query_get(&c->q, "to");
  if (!from || !*from) from = first;
  if (!to || !*to) to = today;

  yyjson_mut_doc *td = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(td, teams_now(c, td));
  yyjson_doc *teams = yyjson_mut_doc_imut_copy(td, NULL);
  yyjson_mut_doc_free(td);
  buckets_buf rb = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  yyjson_doc *rates =
      buckets_sysconfig_read(c->s->layer, BUCKETS_USAGE_RATES_PATH, &rb, NULL) == BUCKETS_OBJ_OK
          ? yyjson_read(rb.data, rb.len, 0)
          : NULL;
  buckets_usage_source src = buckets_usage_store_source(c->s->layer);
  char err[256];
  if (buckets_usage_report(&src, from, to, yyjson_doc_get_root(teams), yyjson_doc_get_root(rates), &out, err,
                           sizeof(err)))
    reply_json(c, &out);
  else
    buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, err);
  yyjson_doc_free(teams);
  yyjson_doc_free(rates);
  buckets_buf_free(&rb);
  buckets_buf_free(&out);
}

void buckets_admin_usage_rates_set(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ConfigUpdate")) return;
  if (c->req->body_len > 4096) {
    buckets_admin_error(c, BUCKETS_ERR_ENTITY_TOO_LARGE);
    return;
  }
  buckets_s3_error re = buckets_s3_read_doc(c);
  if (re) {
    buckets_admin_error(c, re);
    return;
  }
  yyjson_doc *d = yyjson_read(c->doc.data ? c->doc.data : "", c->doc.len, 0);
  char err[256];
  if (!d) snprintf(err, sizeof(err), "the rates are a JSON object");
  if (!d || !buckets_usage_rates_check(yyjson_doc_get_root(d), err, sizeof(err))) {
    yyjson_doc_free(d);
    buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, err);
    return;
  }
  /* stored as checked: only the known fields */
  static const char *const keep[] = {"currency",   "storageGbMonth", "outGb",       "inGb",
                                     "per10kRead", "per10kWrite",    "per10kDelete"};
  yyjson_mut_doc *m = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(m);
  yyjson_mut_doc_set_root(m, root);
  for (size_t i = 0; i < sizeof(keep) / sizeof(keep[0]); i++) {
    yyjson_val *v = yyjson_obj_get(yyjson_doc_get_root(d), keep[i]);
    if (v) yyjson_mut_obj_add(root, yyjson_mut_str(m, keep[i]), yyjson_val_mut_copy(m, v));
  }
  size_t len;
  char *j = yyjson_mut_write(m, 0, &len);
  buckets_obj_err e = buckets_sysconfig_write(c->s->layer, BUCKETS_USAGE_RATES_PATH, j, len);
  free(j);
  yyjson_mut_doc_free(m);
  yyjson_doc_free(d);
  if (e)
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
  else
    c->resp->status = 200;
}

void buckets_admin_usage_rates_delete(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ConfigUpdate")) return;
  buckets_obj_err e = buckets_sysconfig_delete(c->s->layer, BUCKETS_USAGE_RATES_PATH);
  if (e && e != BUCKETS_OBJ_ERR_NO_SUCH_KEY)
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
  else
    c->resp->status = 200;
}
