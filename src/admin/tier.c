/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Remote tiers (MinIO's cmd/tier-handlers.go): mc admin tier add|edit|ls|rm|check|info. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "admin/admin.h"
#include "core/timefmt.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "object/sysconfig.h"
#include "s3/tiering.h"
#include "scanner/usage.h"
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
    buckets_admin_decrypt_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON, NULL);
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
typedef struct {
  const char *name, *type;
  const buckets_tier_usage *u;
  const buckets_tier_day *day;
} tier_info;

/* internal (the hot tier's classes) first, then by name */
static int cmp_info(const void *a, const void *b) {
  const tier_info *x = a, *y = b;
  bool xi = !strcmp(x->type, "internal"), yi = !strcmp(y->type, "internal");
  if (xi != yi) return xi ? -1 : 1;
  return strcmp(x->name, y->name);
}

static void stats_json(buckets_buf *b, uint64_t size, uint64_t versions, uint64_t objects) {
  buckets_buf_appendf(b, "{\"totalSize\":%llu,\"numVersions\":%llu,\"numObjects\":%llu}", (unsigned long long)size,
                      (unsigned long long)versions, (unsigned long long)objects);
}

/* TierStatsHandler: the stored usage's tierStats (as []madmin.TierInfo)
 * with every node's last-day transitions. */
void buckets_admin_tier_stats(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListTier")) return;
  buckets_s3_server *s = c->s;
  buckets_data_usage u = {0};
  buckets_buf raw = BUCKETS_BUF_INIT;
  if (buckets_sysconfig_read(s->layer, BUCKETS_USAGE_PATH, &raw, NULL) == BUCKETS_OBJ_OK)
    buckets_data_usage_parse(raw.data, raw.len, &u);
  buckets_buf_free(&raw);
  buckets_tier_day *days;
  size_t ndays = buckets_tiering_day_stats(s->tiering, &days);
  size_t np = 0;
  buckets_peer_info *pi = buckets_peer_tier_stats(s->peers, &np);
  for (size_t i = 0; i < np; i++)
    if (pi[i].json) buckets_tier_days_merge_json(&days, &ndays, pi[i].json);
  buckets_peer_info_free(pi, np);

  buckets_buf *b = &c->resp->body;
  buckets_buf_reset(b);
  if (!u.ntiers || buckets_tiers_empty(s->tiers)) {
    buckets_buf_append_c(b, "null");
  } else {
    tier_info *ti = buckets_xcalloc(u.ntiers, sizeof(*ti));
    for (size_t i = 0; i < u.ntiers; i++) {
      ti[i] = (tier_info){u.tiers[i].name, buckets_tiers_type(s->tiers, u.tiers[i].name), &u.tiers[i], NULL};
      for (size_t d = 0; d < ndays; d++)
        if (!strcmp(days[d].tier, ti[i].name)) ti[i].day = &days[d];
    }
    qsort(ti, u.ntiers, sizeof(*ti), cmp_info);
    buckets_buf_append_c(b, "[");
    for (size_t i = 0; i < u.ntiers; i++) {
      buckets_buf_append_c(b, i ? ",{\"Name\":" : "{\"Name\":");
      buckets_json_go_string(b, ti[i].name, strlen(ti[i].name));
      buckets_buf_appendf(b, ",\"Type\":\"%s\",\"Stats\":", ti[i].type);
      stats_json(b, ti[i].u->size, ti[i].u->versions, ti[i].u->objects);
      buckets_buf_append_c(b, ",\"DailyStats\":{\"Bins\":[");
      for (int h = 0; h < 24; h++) {
        if (h) buckets_buf_append_c(b, ",");
        const buckets_tier_stat *st = ti[i].day ? &ti[i].day->bins[h] : NULL;
        stats_json(b, st ? st->size : 0, st ? st->versions : 0, st ? st->objects : 0);
      }
      char ts[64] = "0001-01-01T00:00:00Z";
      if (ti[i].day && ti[i].day->updated_ns)
        buckets_time_rfc3339_nano(ti[i].day->updated_ns / 1000000000LL, (long)(ti[i].day->updated_ns % 1000000000LL),
                                  ts);
      buckets_buf_appendf(b, "],\"UpdatedAt\":\"%s\"}}", ts);
    }
    buckets_buf_append_c(b, "]");
    free(ti);
  }
  free(days);
  buckets_data_usage_free(&u);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}
