/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The audit log viewer's data (docs/design/audit-log.md), a Buckets extension to the admin API:
 *   GET /minio/admin/v3/buckets/audit?from=&to=&user=&accessKey=&bucket=&prefix=&api=&kind=&status=&ip=&limit=&cursor=
 *       admin:ServerInfo
 *   -> {"enabled", "entries": [audit entries as MinIO writes them, plus "node"] (newest first),
 *       "cursor": the next page's (or null), "coverage": [{"node", "oldest", "dropped"}]}
 * from and to are RFC 3339 times (to: now; from: an hour before to). Every server is asked for its own entries
 * (the peer op "audit"), and the answers merged by time. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "audit/store.h"
#include "core/timefmt.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "notify/event.h"

#define MAX_LIMIT 1000

static const char *const k_filters[][2] = {
    {"user", "user"}, {"accessKey", "accessKey"}, {"bucket", "bucket"}, {"prefix", "prefix"},
    {"api", "api"},   {"kind", "kind"},           {"status", "status"}, {"ip", "ip"}};

static int64_t parse_time(const char *s) {
  long long sec;
  long nsec;
  if (!s || !*s) return 0;
  if (buckets_time_parse_rfc3339(s, &sec, &nsec)) return (int64_t)sec * 1000000000LL + nsec;
  return -1;
}

/* The query from the request's parameters; false (and why) when they are wrong. */
static bool query_of(const buckets_query *qs, buckets_audit_query *q, char *err, size_t errlen) {
  memset(q, 0, sizeof(*q));
  int64_t now = (int64_t)time(NULL) * 1000000000LL;
  q->to_ns = parse_time(buckets_query_get(qs, "to"));
  q->from_ns = parse_time(buckets_query_get(qs, "from"));
  if (q->to_ns < 0 || q->from_ns < 0) {
    snprintf(err, errlen, "from and to are RFC 3339 times, such as 2026-10-07T10:00:00Z");
    return false;
  }
  if (!q->to_ns) q->to_ns = now;
  if (!q->from_ns) q->from_ns = q->to_ns - 3600LL * 1000000000LL;
  if (q->from_ns > q->to_ns) {
    snprintf(err, errlen, "from is after to");
    return false;
  }
  const char *c = buckets_query_get(qs, "cursor");
  q->before_ns = c && *c ? strtoll(c, NULL, 10) : 0;
  q->user = buckets_query_get(qs, "user");
  q->access_key = buckets_query_get(qs, "accessKey");
  q->bucket = buckets_query_get(qs, "bucket");
  q->prefix = buckets_query_get(qs, "prefix");
  q->api = buckets_query_get(qs, "api");
  q->kind = buckets_query_get(qs, "kind");
  q->status = buckets_query_get(qs, "status");
  q->ip = buckets_query_get(qs, "ip");
  const char *l = buckets_query_get(qs, "limit");
  long lim = l && *l ? strtol(l, NULL, 10) : 100;
  q->limit = (size_t)(lim < 1 ? 1 : lim > MAX_LIMIT ? MAX_LIMIT : lim);
  if (q->kind && *q->kind && strcmp(q->kind, "read") && strcmp(q->kind, "write") &&
      strcmp(q->kind, "delete") && strcmp(q->kind, "admin") && strcmp(q->kind, "system")) {
    snprintf(err, errlen, "kind is read, write, delete, admin or system");
    return false;
  }
  if (q->status && *q->status && strcmp(q->status, "ok") && strcmp(q->status, "denied") &&
      strcmp(q->status, "failed")) {
    snprintf(err, errlen, "status is ok, denied or failed");
    return false;
  }
  return true;
}

/* This server's answer: {"node", "enabled", "entries", "oldest", "dropped"}. */
static void local_answer(buckets_s3_server *s, const buckets_audit_query *q, buckets_buf *out) {
  const char *node = s->cluster && s->cluster->self ? s->cluster->self : "";
  buckets_buf_append_c(out, "{\"node\":");
  buckets_json_go_string(out, node, strlen(node));
  if (!s->audit_store) {
    buckets_buf_append_c(out, ",\"enabled\":false,\"entries\":[],\"oldest\":0,\"dropped\":0}");
    return;
  }
  buckets_buf_append_c(out, ",\"enabled\":true,\"entries\":");
  int64_t oldest = 0;
  buckets_audit_query_dir(buckets_audit_store_root(s->audit_store), q, out, &oldest);
  buckets_buf_appendf(out, ",\"oldest\":%lld,\"dropped\":%llu}", (long long)oldest,
                      (unsigned long long)buckets_audit_store_dropped(s->audit_store));
}

bool buckets_admin_audit_peer(buckets_s3_server *s, const char *op, const buckets_query *qs,
                              buckets_http_response *resp) {
  if (strcmp(op, "audit") != 0) return false;
  buckets_audit_query q;
  char err[200];
  if (!query_of(qs, &q, err, sizeof(err))) {
    resp->status = 400;
    return true;
  }
  local_answer(s, &q, &resp->body);
  resp->status = 200;
  return true;
}

static void query_param(buckets_buf *t, const char *k, const char *v) {
  if (!v || !*v) return;
  buckets_buf_appendf(t, "&%s=", k);
  for (const unsigned char *p = (const unsigned char *)v; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
        strchr("-_.~", *p))
      buckets_buf_append_char(t, (char)*p);
    else
      buckets_buf_appendf(t, "%%%02X", *p);
  }
}

typedef struct {
  yyjson_val *e;
  int64_t t;
  const char *node;
} merged;

static int merged_cmp(const void *a, const void *b) { /* newest first */
  int64_t x = ((const merged *)a)->t, y = ((const merged *)b)->t;
  return x < y ? 1 : x > y ? -1 : 0;
}

void buckets_admin_audit(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ServerInfo")) return;
  buckets_audit_query q;
  char err[200];
  if (!query_of(&c->q, &q, err, sizeof(err))) {
    buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, err);
    return;
  }
  buckets_s3_server *s = c->s;
  size_t nnodes = s->cluster && s->cluster->nnodes ? s->cluster->nnodes : 1;
  const char *self = s->cluster && s->cluster->self ? s->cluster->self : "";
  yyjson_doc **answers = buckets_xcalloc(nnodes, sizeof(*answers));
  for (size_t i = 0; i < nnodes; i++) {
    const char *node = s->cluster && s->cluster->nnodes ? s->cluster->nodes[i] : self;
    buckets_buf body = BUCKETS_BUF_INIT;
    if (!strcmp(node, self) || !s->peers) {
      local_answer(s, &q, &body);
    } else { /* the same query, of that server */
      buckets_buf t = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/admin?op=audit");
      buckets_buf_appendf(&t, "&limit=%zu", q.limit);
      char ts[64];
      buckets_time_rfc3339_nano((long long)(q.from_ns / 1000000000LL), (long)(q.from_ns % 1000000000LL), ts);
      query_param(&t, "from", ts);
      buckets_time_rfc3339_nano((long long)(q.to_ns / 1000000000LL), (long)(q.to_ns % 1000000000LL), ts);
      query_param(&t, "to", ts);
      if (q.before_ns) buckets_buf_appendf(&t, "&cursor=%lld", (long long)q.before_ns);
      for (size_t f = 0; f < sizeof(k_filters) / sizeof(k_filters[0]); f++)
        query_param(&t, k_filters[f][1], buckets_query_get(&c->q, k_filters[f][0]));
      int status = 0;
      if (!buckets_peer_call(s->peers, node, t.data, &status, &body) || status != 200)
        buckets_buf_reset(&body);
      buckets_buf_free(&t);
    }
    answers[i] = body.len ? yyjson_read(body.data, body.len, 0) : NULL;
    buckets_buf_free(&body);
  }
  /* merged by time, the page's worth */
  merged *all = NULL;
  size_t nall = 0;
  bool enabled = false;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *cov = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < nnodes; i++) {
    yyjson_val *a = yyjson_doc_get_root(answers[i]);
    const char *node = s->cluster && s->cluster->nnodes ? s->cluster->nodes[i] : self;
    yyjson_mut_val *cv = yyjson_mut_arr_add_obj(d, cov);
    yyjson_mut_obj_add_strcpy(d, cv, "node", node);
    if (!a) {
      yyjson_mut_obj_add_bool(d, cv, "reachable", false);
      continue;
    }
    enabled |= yyjson_get_bool(yyjson_obj_get(a, "enabled"));
    yyjson_mut_obj_add_bool(d, cv, "reachable", true);
    yyjson_mut_obj_add_bool(d, cv, "enabled", yyjson_get_bool(yyjson_obj_get(a, "enabled")));
    yyjson_mut_obj_add_sint(d, cv, "oldest", yyjson_get_sint(yyjson_obj_get(a, "oldest")) / 1000000000LL);
    yyjson_mut_obj_add_uint(d, cv, "dropped", yyjson_get_uint(yyjson_obj_get(a, "dropped")));
    size_t j, jm;
    yyjson_val *e;
    yyjson_arr_foreach(yyjson_obj_get(a, "entries"), j, jm, e) {
      all = buckets_xrealloc(all, (nall + 1) * sizeof(*all));
      all[nall++] = (merged){e, buckets_audit_time_ns(e), node};
    }
  }
  if (nall) qsort(all, nall, sizeof(*all), merged_cmp);
  yyjson_mut_obj_add_bool(d, root, "enabled", enabled);
  yyjson_mut_val *entries = yyjson_mut_obj_add_arr(d, root, "entries");
  size_t take = nall < q.limit ? nall : q.limit;
  for (size_t i = 0; i < take; i++) {
    yyjson_mut_val *m = yyjson_val_mut_copy(d, all[i].e);
    yyjson_mut_obj_add_strcpy(d, m, "node", all[i].node);
    yyjson_mut_arr_append(entries, m);
  }
  /* more may follow when a page was filled: the next starts below the last time given */
  if (take == q.limit && take) {
    char cur[32];
    snprintf(cur, sizeof(cur), "%lld", (long long)all[take - 1].t);
    yyjson_mut_obj_add_strcpy(d, root, "cursor", cur);
  } else {
    yyjson_mut_obj_add_null(d, root, "cursor");
  }
  yyjson_mut_obj_add_val(d, root, "coverage", cov);
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  if (j) buckets_buf_append(&c->resp->body, j, len);
  free(j);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
  free(all);
  yyjson_mut_doc_free(d);
  for (size_t i = 0; i < nnodes; i++) yyjson_doc_free(answers[i]);
  free(answers);
}
