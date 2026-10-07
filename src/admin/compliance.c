/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The compliance reports' data (docs/design/compliance-reports.md), a Buckets
 * extension to the admin API: GET /minio/admin/v3/buckets/compliance, with
 * admin:DataUsageInfo. Each bucket's retention and encryption settings, read
 * now, beside the counts the scanner stored at its last complete cycle
 * (scanner/compliance.h):
 *
 *   {"scannedAt": unix seconds (0: no cycle yet),
 *    "kms": {"configured", "online"},
 *    "buckets": [{"name", "versioning": "Enabled" | "Suspended" | "Off",
 *                 "objectLock": {"enabled", "mode": "GOVERNANCE" | "COMPLIANCE" | "", "days", "years"},
 *                 "lifecycleExpires": whether an enabled rule deletes versions,
 *                 "encryption": {"algorithm": "SSE-S3" | "SSE-KMS" | "", "keyId",
 *                                "keyStatus": "ok" | "missing" | "error" | "no-kms" | ""},
 *                 "counts": {"sseS3", "sseKms", "sseC", "unencrypted", "governance", "compliance",
 *                            "legalHold": {"versions", "bytes"}, "latestRetainUntil"} | null}]} */
#include "scanner/compliance.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "bucket/metasys.h"
#include "kms/kms.h"
#include "object/sysconfig.h"

/* Whether an enabled lifecycle rule deletes versions (not only delete markers or uploads). */
static bool lifecycle_expires(const buckets_bucket_state *st) {
  if (!st->has_lifecycle) return false;
  for (size_t i = 0; i < st->lifecycle.n; i++) {
    const buckets_lc_rule *r = &st->lifecycle.rules[i];
    if (!r->status || strcmp(r->status, "Enabled") != 0) continue;
    if ((r->exp_set && (r->exp_days || r->exp_date)) || (r->exp_all_set && r->exp_all) || r->nve_set)
      return true;
  }
  return false;
}

typedef struct {
  char *key;
  const char *status;
} key_seen;

/* A key's status, asked of the KMS once per request: a data key generated under it, as setting it as a
 * bucket's default does. */
static const char *key_status(buckets_kms *kms, const char *key, key_seen **seen, size_t *nseen) {
  if (!kms) return "no-kms";
  for (size_t i = 0; i < *nseen; i++)
    if (strcmp((*seen)[i].key, key) == 0) return (*seen)[i].status;
  uint8_t plain[32];
  char id[256];
  buckets_buf ct = BUCKETS_BUF_INIT;
  buckets_kms_err e = buckets_kms_generate(kms, key, "{\"MinIO admin API\":\"ServerInfoHandler\"}", plain,
                                           &ct, id, sizeof(id));
  memset(plain, 0, sizeof(plain));
  buckets_buf_free(&ct);
  const char *st = e == BUCKETS_KMS_OK ? "ok" : e == BUCKETS_KMS_ERR_KEY_NOT_FOUND ? "missing" : "error";
  *seen = buckets_xrealloc(*seen, (*nseen + 1) * sizeof(**seen));
  (*seen)[(*nseen)++] = (key_seen){buckets_xstrdup(key), st};
  return st;
}

static void put_count(yyjson_mut_doc *d, yyjson_mut_val *o, const char *k,
                      const buckets_compliance_count *c) {
  yyjson_mut_val *x = yyjson_mut_obj_add_obj(d, o, k);
  yyjson_mut_obj_add_uint(d, x, "versions", c->versions);
  yyjson_mut_obj_add_uint(d, x, "bytes", c->bytes);
}

void buckets_admin_compliance(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:DataUsageInfo")) return;
  buckets_buf stored = BUCKETS_BUF_INIT;
  if (buckets_sysconfig_read(c->s->layer, BUCKETS_COMPLIANCE_PATH, &stored, NULL) != BUCKETS_OBJ_OK)
    buckets_buf_reset(&stored);
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(c->s->layer, &bk, &nb) != BUCKETS_OBJ_OK) {
    buckets_buf_free(&stored);
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  buckets_kms *kms = c->s->kms;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  int64_t scanned_at = 0;
  buckets_compliance_counts ignore;
  buckets_compliance_lookup(stored.data, stored.len, "", &ignore, &scanned_at);
  yyjson_mut_obj_add_sint(d, root, "scannedAt", scanned_at);
  yyjson_mut_val *k = yyjson_mut_obj_add_obj(d, root, "kms");
  yyjson_mut_obj_add_bool(d, k, "configured", kms != NULL);
  yyjson_mut_obj_add_bool(d, k, "online", kms && buckets_kms_online(kms));
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, root, "buckets");
  key_seen *seen = NULL;
  size_t nseen = 0;
  for (size_t i = 0; i < nb; i++) {
    const char *name = bk[i].name;
    buckets_bucket_state *st = buckets_metasys_get(c->s->meta, name);
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "name", name);
    yyjson_mut_obj_add_str(d, o, "versioning",
                           st->versioning.status == BUCKETS_VERSIONING_ENABLED     ? "Enabled"
                           : st->versioning.status == BUCKETS_VERSIONING_SUSPENDED ? "Suspended"
                                                                                   : "Off");
    yyjson_mut_val *lk = yyjson_mut_obj_add_obj(d, o, "objectLock");
    yyjson_mut_obj_add_bool(d, lk, "enabled", st->lock_enabled);
    yyjson_mut_obj_add_str(d, lk, "mode",
                           st->object_lock.mode == BUCKETS_RET_COMPLIANCE   ? "COMPLIANCE"
                           : st->object_lock.mode == BUCKETS_RET_GOVERNANCE ? "GOVERNANCE"
                                                                            : "");
    yyjson_mut_obj_add_uint(d, lk, "days", st->object_lock.days);
    yyjson_mut_obj_add_uint(d, lk, "years", st->object_lock.years);
    yyjson_mut_obj_add_bool(d, o, "lifecycleExpires", lifecycle_expires(st));
    yyjson_mut_val *en = yyjson_mut_obj_add_obj(d, o, "encryption");
    const char *alg = !st->has_sse                                ? ""
                      : strcmp(st->sse.algorithm, "aws:kms") == 0 ? "SSE-KMS"
                      : strcmp(st->sse.algorithm, "AES256") == 0  ? "SSE-S3"
                                                                  : "";
    yyjson_mut_obj_add_str(d, en, "algorithm", alg);
    const char *key = strcmp(alg, "SSE-KMS") == 0 ? st->sse.key_id : kms ? buckets_kms_default_key(kms) : "";
    yyjson_mut_obj_add_strcpy(d, en, "keyId", *alg ? (key ? key : "") : "");
    yyjson_mut_obj_add_str(d, en, "keyStatus", *alg ? key_status(kms, key ? key : "", &seen, &nseen) : "");
    buckets_bucket_state_release(st);
    buckets_compliance_counts cc;
    int64_t at;
    if (buckets_compliance_lookup(stored.data, stored.len, name, &cc, &at)) {
      yyjson_mut_val *co = yyjson_mut_obj_add_obj(d, o, "counts");
      put_count(d, co, "sseS3", &cc.sse_s3);
      put_count(d, co, "sseKms", &cc.sse_kms);
      put_count(d, co, "sseC", &cc.sse_c);
      put_count(d, co, "unencrypted", &cc.plain);
      put_count(d, co, "governance", &cc.governance);
      put_count(d, co, "compliance", &cc.compliance);
      put_count(d, co, "legalHold", &cc.legal_hold);
      yyjson_mut_obj_add_sint(d, co, "latestRetainUntil", cc.latest_until);
    } else {
      yyjson_mut_obj_add_null(d, o, "counts"); /* made since the last cycle */
    }
  }
  for (size_t i = 0; i < nseen; i++) free(seen[i].key);
  free(seen);
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  if (j) buckets_buf_append(&c->resp->body, j, len);
  free(j);
  yyjson_mut_doc_free(d);
  buckets_bucket_info_free(bk, nb);
  buckets_buf_free(&stored);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}
