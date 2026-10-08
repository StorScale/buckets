/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket remote targets (MinIO's admin-bucket-handlers.go: SetRemoteTarget,
 * ListRemoteTargets, RemoveRemoteTarget, and BucketTargetSys.SetTarget /
 * RemoveTarget in bucket-targets.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "bucket/metasys.h"
#include "crypto/madmin.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "s3/replicate.h"
#include "siterepl/siterepl.h"

static const char *bucket_param(s3_ctx *c, bool check) {
  const char *b = buckets_query_get(&c->q, "bucket");
  if (!b) b = "";
  free(c->err_bucket);
  free(c->err_object);
  c->err_bucket = buckets_xstrdup(b);
  c->err_object = buckets_xstrdup("");
  if (!check) return b;
  buckets_obj_err err = buckets_obj_stat_bucket(c->s->layer, b);
  if (err) {
    buckets_admin_error(c, buckets_s3_obj_error(err));
    return NULL;
  }
  return b;
}

static void with_err(s3_ctx *c, buckets_s3_error e, const char *detail) {
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  char msg[1200];
  if (detail) snprintf(msg, sizeof(msg), "%s (%s)", info->message, detail);
  else snprintf(msg, sizeof(msg), "%s", info->message);
  buckets_admin_error_msg(c, e, msg);
}

static void reply_json(s3_ctx *c, const char *data, size_t n) {
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, data, n);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

/* The URL string madmin compares targets by (scheme://endpoint). */
static void target_url(const buckets_bucket_target *t, char *out, size_t cap) {
  snprintf(out, cap, "%s://%s", t->secure ? "https" : "http", t->endpoint);
}

/* A connection failure (RemoteTargetConnectionErr) as the API reports it. */
static void conn_error(s3_ctx *c, const buckets_bucket_target *t, const char *err) {
  char d[1024];
  snprintf(d, sizeof(d), "Remote service endpoint offline, target bucket: %s or remote service credentials: %s invalid \n\t%s",
           t->target_bucket, t->access_key, err);
  with_err(c, BUCKETS_ERR_REPLICATION_REMOTE_CONNECTION_ERROR, d);
}

/* BucketTargetSys.SetTarget's checks of the remote end. */
static bool check_target_ex(s3_ctx *c, const char *bucket, const buckets_bucket_target *t, bool update,
                            bool check_source);
static bool check_target(s3_ctx *c, const char *bucket, const buckets_bucket_target *t, bool update) {
  return check_target_ex(c, bucket, t, update, true);
}

/* check_source false: the source's versioning isn't checked (the console's test offers to turn it on). */
static bool check_target_ex(s3_ctx *c, const char *bucket, const buckets_bucket_target *t, bool update,
                            bool check_source) {
  if (strcmp(t->type, "replication") != 0 && !update) {
    buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_ARN_TYPE_INVALID);
    return false;
  }
  buckets_s3c *cl = buckets_repl_client_for(c->s->repl, t);
  buckets_s3c_result res;
  bool ok = true;
  bool found = buckets_s3c_do(cl, "HEAD", t->target_bucket, NULL, NULL, NULL, 0, NULL, 0, &res);
  if (!found) {
    if (res.status == 404 && !res.network) buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    else conn_error(c, t, buckets_s3c_error(&res));
    ok = false;
  }
  buckets_s3c_result_free(&res);
  if (ok && strcmp(t->type, "replication") == 0) {
    buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
    bool versioned = st->versioning.status == BUCKETS_VERSIONING_ENABLED || !check_source;
    buckets_bucket_state_release(st);
    if (!versioned) {
      buckets_admin_error(c, BUCKETS_ERR_REPLICATION_SOURCE_NOT_VERSIONED_ERROR);
      ok = false;
    } else if (!buckets_s3c_do(cl, "GET", t->target_bucket, NULL, "versioning=", NULL, 0, NULL, 0, &res)) {
      conn_error(c, t, buckets_s3c_error(&res));
      buckets_s3c_result_free(&res);
      ok = false;
    } else {
      bool enabled = res.body.data && strstr(res.body.data, "<Status>Enabled</Status>");
      buckets_s3c_result_free(&res);
      if (!enabled) {
        buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_VERSIONED_ERROR);
        ok = false;
      }
    }
  }
  if (ok) { /* a MinIO-style server, alive */
    if (!buckets_s3c_health(cl, "live", 3000, &res)) {
      conn_error(c, t, res.status ? "Health check timed out after 3 seconds" : buckets_s3c_error(&res));
      ok = false;
    }
    buckets_s3c_result_free(&res);
  }
  buckets_s3c_free(cl);
  return ok;
}

static void save_targets(s3_ctx *c, const char *bucket, const buckets_bucket_targets *ts) {
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_bucket_targets_json(ts, &j);
  bool ok = buckets_metasys_update_targets(c->s->meta, bucket, j.data, j.len);
  buckets_buf_free(&j);
  if (!ok) buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
}

void buckets_admin_set_remote_target(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetBucketTarget")) return;
  const char *bucket = bucket_param(c, true);
  if (!bucket) return;
  bool update = buckets_query_get(&c->q, "update") && strcmp(buckets_query_get(&c->q, "update"), "true") == 0;
  buckets_s3_error de = buckets_s3_read_doc(c);
  if (de) {
    buckets_admin_error(c, de);
    return;
  }
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (!buckets_madmin_decrypt(c->ident->secret_key, c->doc.data, c->doc.len, &plain)) {
    buckets_buf_free(&plain);
    buckets_admin_decrypt_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON, NULL);
    return;
  }
  buckets_bucket_target t;
  char err[512];
  bool parsed = buckets_bucket_target_parse(plain.data ? plain.data : "", plain.len, &t, err, sizeof(err));
  buckets_buf_free(&plain);
  if (!parsed) {
    buckets_bucket_target_free(&t);
    with_err(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON, err);
    return;
  }
  if (strcmp(t.target_bucket, bucket) == 0 && buckets_s3_is_local_endpoint(c->s, t.endpoint)) {
    buckets_bucket_target_free(&t);
    buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_IDENTICAL_TO_SOURCE);
    return;
  }
  if (buckets_sr_enabled(c->s->sr) && !update) {
    buckets_bucket_target_free(&t);
    buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_DENY_ADD_ERROR);
    return;
  }
  free(t.source_bucket);
  t.source_bucket = buckets_xstrdup(bucket);
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  buckets_bucket_targets ts = {0};
  ts.t = buckets_xcalloc(st->targets.n + 1, sizeof(*ts.t));
  for (size_t i = 0; i < st->targets.n; i++) buckets_bucket_target_copy(&ts.t[ts.n++], &st->targets.t[i]);
  buckets_bucket_state_release(st);
  if (!update) {
    /* getRemoteARN: the ARN of an identical target, or a new one */
    char url[400], turl[400];
    target_url(&t, url, sizeof(url));
    for (size_t i = 0; i < ts.n; i++) {
      target_url(&ts.t[i], turl, sizeof(turl));
      if (strcmp(ts.t[i].type, t.type) == 0 && strcmp(ts.t[i].target_bucket, t.target_bucket) == 0 &&
          strcmp(url, turl) == 0 && strcmp(ts.t[i].access_key, t.access_key) == 0) {
        buckets_buf out = BUCKETS_BUF_INIT;
        buckets_json_go_string(&out, ts.t[i].arn, strlen(ts.t[i].arn));
        reply_json(c, out.data, out.len);
        buckets_buf_free(&out);
        buckets_bucket_target_free(&t);
        buckets_bucket_targets_free(&ts);
        return;
      }
    }
    if (strcmp(t.type, "replication") != 0) {
      buckets_bucket_target_free(&t);
      buckets_bucket_targets_free(&ts);
      buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON);
      return;
    }
    char arn[600];
    buckets_arn_generate(t.type, t.region, NULL, t.target_bucket, arn, sizeof(arn));
    free(t.arn);
    t.arn = buckets_xstrdup(arn);
  } else {
    /* overlay the updates on the stored target */
    buckets_bucket_target *cur = NULL;
    for (size_t i = 0; i < ts.n; i++)
      if (strcmp(ts.t[i].arn, t.arn) == 0) cur = &ts.t[i];
    if (!*t.arn || !cur) {
      buckets_bucket_target_free(&t);
      buckets_bucket_targets_free(&ts);
      buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
      return;
    }
    buckets_bucket_target nt;
    buckets_bucket_target_copy(&nt, cur);
#define OP(name) (buckets_query_get(&c->q, name) && strcmp(buckets_query_get(&c->q, name), "true") == 0)
#define SWAPS(f)          \
  do {                    \
    free(nt.f);           \
    nt.f = buckets_xstrdup(t.f); \
  } while (0)
    if (OP("creds") && !buckets_sr_enabled(c->s->sr)) { /* the site replicator's credentials stay */
      SWAPS(access_key);
      SWAPS(secret_key);
      SWAPS(session_token);
      SWAPS(target_bucket);
      SWAPS(endpoint);
      nt.secure = t.secure;
    }
    if (OP("sync")) nt.replication_sync = t.replication_sync;
    if (OP("proxy")) nt.disable_proxy = t.disable_proxy;
    if (OP("path")) SWAPS(path);
    if (OP("bandwidth")) nt.bandwidth_limit = t.bandwidth_limit;
    if (OP("healthcheck")) nt.health_check_ns = t.health_check_ns;
#undef OP
#undef SWAPS
    buckets_bucket_target_free(&t);
    t = nt;
  }
  if (t.bandwidth_limit > 0 && t.bandwidth_limit < 100LL * 1000 * 1000) {
    buckets_bucket_target_free(&t);
    buckets_bucket_targets_free(&ts);
    buckets_admin_error(c, BUCKETS_ERR_REPLICATION_BANDWIDTH_LIMIT_ERROR);
    return;
  }
  if (!check_target(c, bucket, &t, update)) {
    buckets_bucket_target_free(&t);
    buckets_bucket_targets_free(&ts);
    return;
  }
  bool found = false;
  for (size_t i = 0; i < ts.n; i++) {
    if (strcmp(ts.t[i].type, t.type) != 0) continue;
    if (strcmp(ts.t[i].arn, t.arn) == 0) {
      if (!update) {
        buckets_bucket_target_free(&t);
        buckets_bucket_targets_free(&ts);
        buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_ALREADY_EXISTS);
        return;
      }
      buckets_bucket_target_free(&ts.t[i]);
      buckets_bucket_target_copy(&ts.t[i], &t);
      found = true;
      continue;
    }
    if (strcmp(ts.t[i].endpoint, t.endpoint) == 0) {
      buckets_bucket_target_free(&t);
      buckets_bucket_targets_free(&ts);
      buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_ALREADY_EXISTS);
      return;
    }
  }
  if (!found && !update) {
    ts.t = buckets_xrealloc(ts.t, (ts.n + 1) * sizeof(*ts.t));
    buckets_bucket_target_copy(&ts.t[ts.n++], &t);
  }
  /* what is stored: no health (ListBucketTargets holds the configured targets) */
  save_targets(c, bucket, &ts);
  buckets_bucket_targets_free(&ts);
  if (c->resp->status >= 400) {
    buckets_bucket_target_free(&t);
    return;
  }
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_json_go_string(&out, t.arn, strlen(t.arn));
  reply_json(c, out.data, out.len);
  buckets_buf_free(&out);
  buckets_bucket_target_free(&t);
}

static void list_append(s3_ctx *c, buckets_buf *b, const buckets_bucket_target *t, const char *type, bool *first) {
  if (*type && strcmp(t->type, type) != 0) return;
  buckets_bucket_target copy;
  buckets_bucket_target_copy(&copy, t);
  buckets_repl_health_fill(c->s->repl, &copy);
  if (!*first) buckets_buf_append_char(b, ',');
  *first = false;
  buckets_bucket_target_json(&copy, true, b);
  buckets_bucket_target_free(&copy);
}

void buckets_admin_list_remote_targets(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:GetBucketTarget")) return;
  const char *bucket = bucket_param(c, false);
  const char *type = buckets_query_get(&c->q, "type");
  if (!type) type = "";
  buckets_buf b = BUCKETS_BUF_INIT;
  bool first = true;
  if (*bucket) {
    if (!bucket_param(c, true)) return;
    buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
    if (!st->meta.config[BUCKETS_BCFG_TARGETS].len) {
      buckets_bucket_state_release(st);
      buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
      return;
    }
    buckets_buf_append_char(&b, '[');
    for (size_t i = 0; i < st->targets.n; i++) list_append(c, &b, &st->targets.t[i], type, &first);
    buckets_bucket_state_release(st);
  } else {
    buckets_buf_append_char(&b, '[');
    buckets_bucket_info *bl = NULL;
    size_t nb = 0;
    if (buckets_obj_list_buckets(c->s->layer, &bl, &nb) == BUCKETS_OBJ_OK) {
      for (size_t k = 0; k < nb; k++) {
        buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bl[k].name);
        for (size_t i = 0; i < st->targets.n; i++) list_append(c, &b, &st->targets.t[i], type, &first);
        buckets_bucket_state_release(st);
      }
      buckets_bucket_info_free(bl, nb);
    }
  }
  if (first) { /* json.Marshal of a nil slice */
    buckets_buf_reset(&b);
    buckets_buf_append_c(&b, "null");
  } else {
    buckets_buf_append_char(&b, ']');
  }
  reply_json(c, b.data, b.len);
  buckets_buf_free(&b);
}

void buckets_admin_remove_remote_target(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetBucketTarget")) return;
  const char *bucket = bucket_param(c, true);
  if (!bucket) return;
  const char *arn = buckets_query_get(&c->q, "arn");
  buckets_arn a;
  if (!arn || !*arn || !buckets_arn_parse(arn, &a)) {
    buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_ARN_INVALID);
    return;
  }
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  if (strcmp(a.type, "replication") == 0 && st->has_replication) {
    buckets_repl_obj o = {.op = BUCKETS_REPL_ALL};
    char **arns = NULL;
    size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
    bool used = false;
    for (size_t i = 0; i < na; i++) used |= strcmp(arns[i], arn) == 0 || strcmp(st->replication.role, arn) == 0;
    buckets_replication_arns_free(arns, na);
    bool known = false;
    for (size_t i = 0; i < st->targets.n; i++) known |= strcmp(st->targets.t[i].arn, arn) == 0;
    if (used && known) {
      buckets_bucket_state_release(st);
      buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_REMOVE_DISALLOWED);
      return;
    }
  }
  if (!st->meta.config[BUCKETS_BCFG_TARGETS].len) {
    buckets_bucket_state_release(st);
    buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    return;
  }
  buckets_bucket_targets ts = {0};
  ts.t = buckets_xcalloc(st->targets.n + 1, sizeof(*ts.t));
  bool found = false;
  for (size_t i = 0; i < st->targets.n; i++) {
    if (strcmp(st->targets.t[i].arn, arn) == 0) {
      found = true;
      continue;
    }
    buckets_bucket_target_copy(&ts.t[ts.n++], &st->targets.t[i]);
  }
  buckets_bucket_state_release(st);
  if (!found) {
    buckets_bucket_targets_free(&ts);
    buckets_admin_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    return;
  }
  save_targets(c, bucket, &ts);
  buckets_bucket_targets_free(&ts);
  if (c->resp->status < 400) c->resp->status = 204;
}

/* ---- mc replicate diff / backlog ---- */

void buckets_admin_replication_diff(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ReplicationDiff")) return;
  const char *bucket = bucket_param(c, true);
  if (!bucket) return;
  const char *arn = buckets_query_get(&c->q, "arn");
  const char *v = buckets_query_get(&c->q, "verbose");
  const char *prefix = buckets_query_get(&c->q, "prefix");
  if (arn && *arn) {
    buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
    bool known = false;
    for (size_t i = 0; i < st->targets.n; i++) known |= strcmp(st->targets.t[i].arn, arn) == 0;
    buckets_bucket_state_release(st);
    if (!known) {
      char d[600];
      snprintf(d, sizeof(d), "invalid arn : '%s'", arn);
      with_err(c, BUCKETS_ERR_INVALID_REQUEST, d);
      return;
    }
  }
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  bool has = st->has_replication;
  bool had_targets = st->meta.config[BUCKETS_BCFG_TARGETS].len > 0;
  buckets_bucket_state_release(st);
  if (!has) {
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_CONFIGURATION_NOT_FOUND_ERROR);
    return;
  }
  if (!had_targets) {
    buckets_s3_write_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    return;
  }
  buckets_repl_diff(c->s, bucket, prefix, arn, v && strcmp(v, "true") == 0, &c->resp->body);
  c->resp->status = 200;
}

void buckets_admin_replication_mrf(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ReplicationDiff")) return;
  const char *bucket = bucket_param(c, false);
  if (*bucket && !bucket_param(c, true)) return;
  const char *ep = c->s->endpoint, *h = strstr(ep, "://");
  buckets_repl_mrf_json(c->s->repl, bucket, h ? h + 3 : ep, &c->resp->body);
  c->resp->status = 200;
}

/* ---- Buckets' own: the console's replication editor (docs/design/lifecycle-replication-editor.md) ---- */

/* POST buckets/replication-test?bucket= (admin:SetBucketTarget), body: a madmin-encrypted target as
 * SetRemoteTarget takes it. The checks SetRemoteTarget makes of the remote end (the bucket there, its versioning,
 * the credentials, a live server), with nothing saved -> {"ok": true, "sourceVersioned"}. */
void buckets_admin_replication_test(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SetBucketTarget")) return;
  const char *bucket = bucket_param(c, true);
  if (!bucket) return;
  buckets_s3_error de = buckets_s3_read_doc(c);
  if (de) {
    buckets_admin_error(c, de);
    return;
  }
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (!buckets_madmin_decrypt(c->ident->secret_key, c->doc.data, c->doc.len, &plain)) {
    buckets_buf_free(&plain);
    buckets_admin_decrypt_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON, NULL);
    return;
  }
  buckets_bucket_target t;
  char err[512];
  bool parsed = buckets_bucket_target_parse(plain.data ? plain.data : "", plain.len, &t, err, sizeof(err));
  memset(plain.data, 0, plain.len); /* the secret */
  buckets_buf_free(&plain);
  if (!parsed) {
    buckets_bucket_target_free(&t);
    with_err(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON, err);
    return;
  }
  if (strcmp(t.target_bucket, bucket) == 0 && buckets_s3_is_local_endpoint(c->s, t.endpoint)) {
    buckets_bucket_target_free(&t);
    buckets_admin_error(c, BUCKETS_ERR_BUCKET_REMOTE_IDENTICAL_TO_SOURCE);
    return;
  }
  bool ok = check_target_ex(c, bucket, &t, false, false);
  buckets_bucket_target_free(&t);
  if (!ok) return;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  bool versioned = st->versioning.status == BUCKETS_VERSIONING_ENABLED;
  buckets_bucket_state_release(st);
  char out[64];
  int n = snprintf(out, sizeof(out), "{\"ok\":true,\"sourceVersioned\":%s}", versioned ? "true" : "false");
  reply_json(c, out, (size_t)n);
}

/* This node's replication counts since it started, for one bucket or every bucket that replicates:
 * {"<bucket>": {"q": [objects, bytes], "t": {"<arn>": [replicated, failedLastHour, failedSinceStart]}}} */
static void stats_json(buckets_s3_server *s, const char *only, buckets_buf *b) {
  buckets_bucket_info *bl = NULL;
  size_t nb = 0;
  if (!*only) buckets_obj_list_buckets(s->layer, &bl, &nb);
  buckets_buf_append_char(b, '{');
  bool first = true;
  for (size_t k = 0; k < (*only ? 1 : nb); k++) {
    const char *bucket = *only ? only : bl[k].name;
    buckets_repl_bucket_stats rs;
    if (!buckets_repl_stats_get(bucket, &rs)) continue;
    if (!first) buckets_buf_append_char(b, ',');
    first = false;
    buckets_json_go_string(b, bucket, strlen(bucket));
    buckets_buf_appendf(b, ":{\"q\":[%lld,%lld],\"t\":{", (long long)rs.q_count, (long long)rs.q_bytes);
    for (size_t i = 0; i < rs.n; i++) {
      if (i) buckets_buf_append_char(b, ',');
      buckets_json_go_string(b, rs.t[i].arn, strlen(rs.t[i].arn));
      buckets_buf_appendf(b, ":[%lld,%lld,%lld]", (long long)rs.t[i].repl_count, (long long)rs.t[i].fail_hour_count,
                          (long long)rs.t[i].fail_total_count);
    }
    buckets_buf_append_c(b, "}}");
    buckets_repl_bucket_stats_free(&rs);
  }
  buckets_buf_append_char(b, '}');
  buckets_bucket_info_free(bl, nb);
}

bool buckets_admin_replication_peer(buckets_s3_server *s, const char *op, const buckets_query *q,
                                    buckets_http_response *resp) {
  if (strcmp(op, "replication-stats") != 0) return false;
  const char *b = buckets_query_get(q, "bucket");
  stats_json(s, b ? b : "", &resp->body);
  resp->status = 200;
  return true;
}

static void add_counts(yyjson_val *node, const char *bucket, const char *arn, long long *q, long long *t) {
  yyjson_val *bk = yyjson_obj_get(node, bucket);
  if (!bk) return;
  if (q) {
    yyjson_val *qa = yyjson_obj_get(bk, "q");
    q[0] += yyjson_get_sint(yyjson_arr_get(qa, 0));
    q[1] += yyjson_get_sint(yyjson_arr_get(qa, 1));
  }
  if (arn) {
    yyjson_val *ta = yyjson_obj_get(yyjson_obj_get(bk, "t"), arn);
    for (size_t i = 0; i < 3; i++) t[i] += yyjson_get_sint(yyjson_arr_get(ta, i));
  }
}

/* GET buckets/replication[?bucket=]: each bucket that replicates (or the one asked for), its rules, its targets
 * with their health, and the counts every server keeps added up. One bucket: s3:GetReplicationConfiguration on it;
 * every bucket: admin:GetBucketTarget. */
void buckets_admin_replication(s3_ctx *c) {
  const char *only = buckets_query_get(&c->q, "bucket");
  if (!only) only = "";
  static const char *const act[] = {"s3:GetReplicationConfiguration"};
  if (*only ? !buckets_admin_authorize_bucket(c, only, act, 1) : !buckets_admin_authorize(c, "admin:GetBucketTarget"))
    return;
  if (*only && !bucket_param(c, true)) return;
  buckets_s3_server *s = c->s;
  /* every server's counts */
  size_t nnodes = s->cluster && s->cluster->nnodes ? s->cluster->nnodes : 1;
  const char *self = s->cluster && s->cluster->self ? s->cluster->self : "";
  yyjson_doc **counts = buckets_xcalloc(nnodes, sizeof(*counts));
  for (size_t i = 0; i < nnodes; i++) {
    const char *node = s->cluster && s->cluster->nnodes ? s->cluster->nodes[i] : self;
    buckets_buf body = BUCKETS_BUF_INIT;
    if (!strcmp(node, self) || !s->peers) {
      stats_json(s, only, &body);
    } else {
      buckets_buf t = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/admin?op=replication-stats");
      if (*only) {
        buckets_buf_append_c(&t, "&bucket=");
        buckets_buf_append_c(&t, only); /* bucket names need no escaping */
      }
      int status = 0;
      if (!buckets_peer_call(s->peers, node, t.data, &status, &body) || status != 200) buckets_buf_reset(&body);
      buckets_buf_free(&t);
    }
    counts[i] = body.len ? yyjson_read(body.data, body.len, 0) : NULL;
    buckets_buf_free(&body);
  }
  buckets_bucket_info *bl = NULL;
  size_t nb = 0;
  if (!*only) buckets_obj_list_buckets(s->layer, &bl, &nb);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  bool sr = buckets_sr_enabled(s->sr);
  yyjson_mut_obj_add_bool(d, root, "siteReplication", sr);
  size_t reachable = 0;
  for (size_t i = 0; i < nnodes; i++) reachable += counts[i] != NULL;
  yyjson_mut_obj_add_uint(d, root, "servers", nnodes);
  yyjson_mut_obj_add_uint(d, root, "serversAnswering", reachable);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, root, "buckets");
  for (size_t k = 0; k < (*only ? 1 : nb); k++) {
    const char *bucket = *only ? only : bl[k].name;
    buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
    if (!*only && !st->has_replication && !st->targets.n) {
      buckets_bucket_state_release(st);
      continue;
    }
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "bucket", bucket);
    yyjson_mut_obj_add_bool(d, o, "versioned", st->versioning.status == BUCKETS_VERSIONING_ENABLED);
    yyjson_mut_obj_add_bool(d, o, "configured", st->has_replication);
    long long q[2] = {0, 0};
    for (size_t i = 0; i < nnodes; i++) add_counts(yyjson_doc_get_root(counts[i]), bucket, NULL, q, NULL);
    yyjson_mut_val *pend = yyjson_mut_obj_add_obj(d, o, "pending");
    yyjson_mut_obj_add_int(d, pend, "objects", q[0]);
    yyjson_mut_obj_add_int(d, pend, "bytes", q[1]);
    yyjson_mut_val *ta = yyjson_mut_obj_add_arr(d, o, "targets");
    for (size_t i = 0; i < st->targets.n; i++) {
      if (strcmp(st->targets.t[i].type, "replication") != 0) continue;
      buckets_bucket_target copy;
      buckets_bucket_target_copy(&copy, &st->targets.t[i]);
      buckets_repl_health_fill(s->repl, &copy);
      yyjson_mut_val *t = yyjson_mut_arr_add_obj(d, ta);
      yyjson_mut_obj_add_strcpy(d, t, "arn", copy.arn);
      yyjson_mut_obj_add_strcpy(d, t, "endpoint", copy.endpoint);
      yyjson_mut_obj_add_bool(d, t, "secure", copy.secure);
      yyjson_mut_obj_add_strcpy(d, t, "bucket", copy.target_bucket);
      yyjson_mut_obj_add_strcpy(d, t, "accessKey", copy.access_key ? copy.access_key : "");
      yyjson_mut_obj_add_bool(d, t, "online", copy.online);
      yyjson_mut_obj_add_int(d, t, "lastOnline", copy.last_online_sec > 0 ? copy.last_online_sec : 0);
      yyjson_mut_obj_add_int(d, t, "offlineCount", copy.offline_count);
      yyjson_mut_obj_add_int(d, t, "latencyMs", copy.lat_avg / 1000000);
      yyjson_mut_obj_add_int(d, t, "bandwidthLimit", copy.bandwidth_limit);
      yyjson_mut_obj_add_bool(d, t, "sync", copy.replication_sync);
      long long n3[3] = {0, 0, 0};
      for (size_t j = 0; j < nnodes; j++) add_counts(yyjson_doc_get_root(counts[j]), bucket, copy.arn, NULL, n3);
      yyjson_mut_obj_add_int(d, t, "replicated", n3[0]);
      yyjson_mut_obj_add_int(d, t, "failedLastHour", n3[1]);
      yyjson_mut_obj_add_int(d, t, "failedSinceStart", n3[2]);
      buckets_bucket_target_free(&copy);
    }
    yyjson_mut_val *ra = yyjson_mut_obj_add_arr(d, o, "rules");
    for (size_t i = 0; st->has_replication && i < st->replication.n; i++) {
      const buckets_repl_rule *r = &st->replication.rules[i];
      yyjson_mut_val *x = yyjson_mut_arr_add_obj(d, ra);
      yyjson_mut_obj_add_strcpy(d, x, "id", r->id ? r->id : "");
      yyjson_mut_obj_add_strcpy(d, x, "status", r->status ? r->status : "");
      yyjson_mut_obj_add_strcpy(d, x, "arn", r->dest_arn ? r->dest_arn : "");
    }
    buckets_bucket_state_release(st);
  }
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  reply_json(c, j ? j : "{}", j ? len : 2);
  free(j);
  yyjson_mut_doc_free(d);
  buckets_bucket_info_free(bl, nb);
  for (size_t i = 0; i < nnodes; i++) yyjson_doc_free(counts[i]);
  free(counts);
}
