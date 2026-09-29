/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Remote tiers (MinIO's cmd/tier-handlers.go): mc admin tier add|edit|ls|rm|check|info. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "admin/admin.h"
#include "crypto/madmin.h"
#include "tier/tier.h"

/* The tier name after /tier/ in the path. */
static char *tier_name(s3_ctx *c) {
  buckets_str p = c->req->path;
  const char *prefix = "/minio/admin/v3/tier/";
  size_t n = strlen(prefix);
  if (p.n <= n) return buckets_xstrdup("");
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append(&b, p.p + n, p.n - n);
  return buckets_buf_detach(&b);
}

static bool qtrue(s3_ctx *c, const char *k) {
  const char *v = buckets_query_get(&c->q, k);
  return v && (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "t") == 0 || strcmp(v, "T") == 0 ||
               strcmp(v, "TRUE") == 0 || strcmp(v, "True") == 0);
}

static void fail(s3_ctx *c, const buckets_tier_err *e) {
  buckets_admin_custom_error(c, e->status, e->code, e->message);
}

static bool decrypted_body(s3_ctx *c, buckets_buf *out) {
  buckets_s3_error de = buckets_s3_read_doc(c);
  if (de) {
    buckets_admin_error(c, de);
    return false;
  }
  if (!buckets_madmin_decrypt(c->ident->secret_key, c->doc.data ? c->doc.data : "", c->doc.len, out)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON);
    return false;
  }
  return true;
}

void buckets_admin_tier_add(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetTier")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!decrypted_body(c, &b)) return;
  buckets_tier_err e;
  if (buckets_tiers_add(c->s->tiers, b.data ? b.data : "", b.len, qtrue(c, "force"), &e)) c->resp->status = 204;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_tier_edit(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetTier")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!decrypted_body(c, &b)) return;
  char *name = tier_name(c);
  buckets_tier_err e;
  if (buckets_tiers_edit(c->s->tiers, name, b.data ? b.data : "", b.len, &e)) c->resp->status = 204;
  else fail(c, &e);
  free(name);
  buckets_buf_free(&b);
}

void buckets_admin_tier_list(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListTier")) return;
  buckets_buf_reset(&c->resp->body);
  buckets_tiers_list_json(c->s->tiers, &c->resp->body);
  /* time.Time.String() of the last refresh */
  int64_t ns = buckets_tiers_refreshed_at(c->s->tiers);
  time_t sec = (time_t)(ns / 1000000000LL);
  struct tm tm;
  gmtime_r(&sec, &tm);
  char ts[96], frac[16] = "";
  if (ns % 1000000000LL) {
    snprintf(frac, sizeof(frac), ".%09lld", (long long)(ns % 1000000000LL));
    size_t k = strlen(frac);
    while (frac[k - 1] == '0') frac[--k] = '\0';
  }
  snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d%s +0000 UTC", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, frac);
  buckets_http_resp_header(c->resp, "X-MinIO-TierCfg-RefreshedAt", ts);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

void buckets_admin_tier_remove(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetTier")) return;
  char *name = tier_name(c);
  buckets_tier_err e;
  if (buckets_tiers_remove(c->s->tiers, name, qtrue(c, "force"), &e)) c->resp->status = 204;
  else fail(c, &e);
  free(name);
}

void buckets_admin_tier_verify(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListTier")) return;
  char *name = tier_name(c);
  buckets_tier_err e;
  if (buckets_tiers_verify(c->s->tiers, name, &e)) c->resp->status = 204;
  else fail(c, &e);
  free(name);
}

/* TierStats: the tiers' usage from the scanner's data usage (step in progress:
 * configured tiers with the transitioned data counted so far). */
void buckets_admin_tier_stats(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListTier")) return;
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append_c(&c->resp->body, "null");
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}
