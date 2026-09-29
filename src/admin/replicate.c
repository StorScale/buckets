/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket remote targets (MinIO's admin-bucket-handlers.go: SetRemoteTarget,
 * ListRemoteTargets, RemoveRemoteTarget, and BucketTargetSys.SetTarget /
 * RemoveTarget in bucket-targets.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "admin/admin.h"
#include "bucket/metasys.h"
#include "crypto/madmin.h"
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
static bool check_target(s3_ctx *c, const char *bucket, const buckets_bucket_target *t, bool update) {
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
    bool versioned = st->versioning.status == BUCKETS_VERSIONING_ENABLED;
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
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON);
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
