/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket lifecycle configuration (MinIO's bucket-lifecycle-handlers.go) and
 * the x-amz-expiration prediction header. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bucket/lifecycle.h"
#include "bucket/metasys.h"
#include "core/timefmt.h"
#include "s3/internal.h"
#include "s3/xml.h"

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* toAPIError for lifecycle parse and validation errors. */
static void write_lc_error(s3_ctx *c, const buckets_lc_error *e) {
  char msg[400];
  switch (e->code) {
  case BUCKETS_LC_ERR_INVALID: buckets_s3_write_custom_error(c, 400, "InvalidArgument", e->msg); break;
  case BUCKETS_LC_ERR_RANGE: buckets_s3_write_custom_error(c, 400, "BadRequest", e->msg); break;
  case BUCKETS_LC_ERR_MALFORMED: buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML); break;
  case BUCKETS_LC_ERR_STORAGE_CLASS: buckets_s3_write_error(c, BUCKETS_ERR_INVALID_STORAGE_CLASS); break;
  default:
    snprintf(msg, sizeof(msg), "%s: cause(%s)", buckets_s3_error_get(BUCKETS_ERR_INTERNAL_ERROR)->message, e->msg);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, msg);
  }
}

/* No remote tiers yet: every transition storage class is unknown. */
static bool tier_valid(void *ud, const char *tier) {
  (void)ud, (void)tier;
  return false;
}

void buckets_s3_put_bucket_lifecycle(s3_ctx *c) {
  buckets_s3_error derr = buckets_s3_read_checked_doc(c); /* validateLengthAndChecksum */
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  buckets_lifecycle lc;
  buckets_lc_error e;
  if (!buckets_lifecycle_parse(c->doc.data ? c->doc.data : "", c->doc.len, true, &lc, &e)) {
    buckets_bucket_state_release(st);
    write_lc_error(c, &e);
    return;
  }
  if (!buckets_lifecycle_validate(&lc, st->lock_enabled, tier_valid, NULL, &e)) {
    buckets_bucket_state_release(st);
    buckets_lifecycle_free(&lc);
    write_lc_error(c, &e);
    return;
  }
  /* ExpiryUpdatedAt: when this configuration expires anything, or a rule
   * that did is gone or no longer does. */
  bool removed = false;
  for (size_t i = 0; st->has_lifecycle && i < st->lifecycle.n && !removed; i++) {
    const buckets_lc_rule *old = &st->lifecycle.rules[i];
    if (!buckets_lc_rule_has_expiry(old)) continue;
    const buckets_lc_rule *upd = NULL;
    for (size_t j = 0; j < lc.n; j++) {
      if (strcmp(lc.rules[j].id, old->id) == 0) upd = &lc.rules[j]; /* the map keeps the last */
    }
    removed = !upd || !buckets_lc_rule_has_expiry(upd);
  }
  buckets_bucket_state_release(st);
  if (buckets_lifecycle_has_expiry(&lc) || removed) lc.expiry_updated_ns = now_ns();
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_lifecycle_xml(&lc, true, &x);
  buckets_lifecycle_free(&lc);
  bool ok = buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_LIFECYCLE, x.data, x.len);
  buckets_buf_free(&x);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
}

void buckets_s3_get_bucket_lifecycle(s3_ctx *c) {
  bool with_updated_at = false;
  const char *w = buckets_query_get(&c->q, "withUpdatedAt");
  if (w && *w) {
    static const char *const t[] = {"1", "t", "T", "TRUE", "true", "True"};
    static const char *const f[] = {"0", "f", "F", "FALSE", "false", "False"};
    bool known = false;
    for (size_t i = 0; i < 6; i++) {
      if (strcmp(w, t[i]) == 0) known = with_updated_at = true;
      if (strcmp(w, f[i]) == 0) known = true;
    }
    if (!known) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_LIFECYCLE_QUERY_PARAMETER);
      return;
    }
  }
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (!st->has_lifecycle) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_LIFECYCLE_CONFIGURATION);
    return;
  }
  buckets_lifecycle_xml(&st->lifecycle, false, &c->resp->body);
  if (with_updated_at) {
    const buckets_gotime *u = &st->meta.updated[BUCKETS_BCFG_LIFECYCLE];
    char ts[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(u->sec * 1000000000LL + u->nsec, ts);
    buckets_http_resp_header(c->resp, "X-Minio-LifecycleConfig-UpdatedAt", ts);
  }
  buckets_bucket_state_release(st);
  buckets_s3_write_xml(c, 200);
}

void buckets_s3_delete_bucket_lifecycle(s3_ctx *c) {
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_LIFECYCLE, NULL, 0)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 204;
}

static bool lc_obj(const buckets_object_info *oi, buckets_lc_obj *o) {
  memset(o, 0, sizeof(*o));
  o->name = oi->name;
  o->user_tags = buckets_object_meta(oi, "X-Amz-Tagging");
  o->mod_time_ns = oi->mod_time_ns;
  o->size = oi->size;
  o->version_id = oi->version_id;
  o->is_latest = oi->is_latest;
  o->delete_marker = oi->delete_marker;
  o->num_versions = oi->num_versions;
  o->successor_mod_time_ns = oi->successor_mod_time_ns;
  return true;
}

void buckets_s3_expiration_header(s3_ctx *c, const buckets_object_info *oi) {
  if (!c->s->meta || !oi->name) return;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (st->has_lifecycle) {
    buckets_lc_obj o;
    lc_obj(oi, &o);
    /* ObjectInfo.VersionID is "" for the null version */
    if (strcmp(o.version_id, "null") == 0) o.version_id = "";
    char v[512];
    const char *h = buckets_lifecycle_prediction(&st->lifecycle, &o, v, sizeof(v));
    if (h) buckets_http_resp_header(c->resp, h, v);
  }
  buckets_bucket_state_release(st);
}
