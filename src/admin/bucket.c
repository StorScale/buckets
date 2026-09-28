/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket admin APIs (MinIO's admin-bucket-handlers.go): quotas; and the
 * scanner's data usage (DataUsageInfoHandler). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "admin/admin.h"
#include "bucket/metasys.h"
#include "bucket/quota.h"
#include "object/sysconfig.h"
#include "scanner/usage.h"

/* vars["bucket"] after pathClean, and GetBucketInfo on it. */
static const char *admin_bucket(s3_ctx *c) {
  const char *b = buckets_query_get(&c->q, "bucket");
  if (!b) b = "";
  /* errors name the bucket, not the admin path */
  free(c->err_bucket);
  free(c->err_object);
  c->err_bucket = buckets_xstrdup(b);
  c->err_object = buckets_xstrdup("");
  buckets_obj_err err = buckets_obj_stat_bucket(c->s->layer, b);
  if (err) {
    buckets_admin_error(c, buckets_s3_obj_error(err));
    return NULL;
  }
  return b;
}

void buckets_admin_set_bucket_quota(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetBucketQuota")) return;
  const char *bucket = admin_bucket(c);
  if (!bucket) return;
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  buckets_quota q;
  char err[512];
  if (!buckets_quota_parse(c->doc.data ? c->doc.data : "", c->doc.len, &q, err, sizeof(err))) {
    /* writeErrorResponse(toAPIError(err)): an XML internal error */
    char msg[700];
    snprintf(msg, sizeof(msg), "%s: cause(%s)", buckets_s3_error_get(BUCKETS_ERR_INTERNAL_ERROR)->message, err);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, msg);
    return;
  }
  /* MinIO stores the document as sent. */
  if (!buckets_metasys_update(c->s->meta, bucket, BUCKETS_BCFG_QUOTA, c->doc.data, c->doc.len)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
}

void buckets_admin_get_bucket_quota(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:GetBucketQuota")) return;
  const char *bucket = admin_bucket(c);
  if (!bucket) return;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  if (!st->exists) {
    buckets_bucket_state_release(st);
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_NO_SUCH_QUOTA_CONFIGURATION);
    return;
  }
  buckets_quota none = {0};
  buckets_quota_json(st->has_quota ? &st->quota : &none, &c->resp->body); /* an empty quota when unset */
  buckets_bucket_state_release(st);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

void buckets_admin_data_usage_info(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:DataUsageInfo")) return;
  /* loadDataUsageFromBackend, then the backup */
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_obj_err err = buckets_sysconfig_read(c->s->layer, BUCKETS_USAGE_PATH, &b, NULL);
  if (err) err = buckets_sysconfig_read(c->s->layer, BUCKETS_USAGE_PATH ".bkp", &b, NULL);
  buckets_data_usage u;
  if (!err && buckets_data_usage_parse(b.data, b.len, &u)) {
    buckets_data_usage_json(&u, &c->resp->body);
    buckets_data_usage_free(&u);
  } else {
    /* DataUsageInfo{}: nothing scanned yet */
    buckets_buf_append_c(&c->resp->body,
                         "{\"lastUpdate\":\"0001-01-01T00:00:00Z\",\"objectsCount\":0,\"versionsCount\":0,"
                         "\"deleteMarkersCount\":0,\"objectsTotalSize\":0,\"objectsReplicationInfo\":null,"
                         "\"bucketsCount\":0,\"bucketsUsageInfo\":null,\"bucketsSizes\":null}");
  }
  buckets_buf_free(&b);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}
