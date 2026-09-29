/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/plugins.h"

#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "crypto/base64.h"
#include "net/fetch.h"

/* serviceRTTMinuteStats: one whole minute of identity plugin calls */
typedef struct {
  int64_t minute; /* unix minute */
  uint64_t ok, failed;
  double rtt_sum_ms, rtt_max_ms;
} rtt_minute;

struct buckets_plugins {
  _Atomic int refs;
  char *authz_url, *authz_token;
  char *idp_url, *idp_token, *idp_role_policy, *idp_role_arn;
  pthread_mutex_t mu; /* the identity plugin's call statistics */
  rtt_minute current, last_full;
  int64_t last_success_ns, last_failure_ns;
};

static int64_t wall_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* accumRequestRTT */
static void accum_rtt(buckets_plugins *p, int64_t start_ns, double rtt_ms, bool ok) {
  pthread_mutex_lock(&p->mu);
  if (ok && start_ns > p->last_success_ns) p->last_success_ns = start_ns;
  if (!ok && start_ns > p->last_failure_ns) p->last_failure_ns = start_ns;
  int64_t minute = start_ns / 60000000000LL;
  if (minute > p->current.minute) {
    p->last_full = p->current;
    p->current = (rtt_minute){.minute = minute};
  }
  rtt_minute *e = minute == p->current.minute ? &p->current : minute == p->last_full.minute ? &p->last_full : NULL;
  if (e) {
    if (ok) {
      e->ok++;
      e->rtt_sum_ms += rtt_ms;
      if (rtt_ms > e->rtt_max_ms) e->rtt_max_ms = rtt_ms;
    } else {
      e->failed++;
    }
  }
  pthread_mutex_unlock(&p->mu);
}

void buckets_idp_plugin_metrics_get(buckets_plugins *p, buckets_idp_plugin_metrics *out) {
  memset(out, 0, sizeof(*out));
  if (!buckets_idp_plugin_enabled(p)) return;
  pthread_mutex_lock(&p->mu);
  int64_t now = wall_ns();
  out->last_reachable_secs = (double)(now - p->last_success_ns) / 1e9;
  out->last_unreachable_secs = (double)(now - p->last_failure_ns) / 1e9;
  out->total_requests = p->last_full.ok + p->last_full.failed;
  out->failed_requests = p->last_full.failed;
  out->avg_rtt_ms = p->last_full.ok ? p->last_full.rtt_sum_ms / (double)p->last_full.ok : 0;
  out->max_rtt_ms = p->last_full.rtt_max_ms;
  pthread_mutex_unlock(&p->mu);
}

buckets_plugins *buckets_plugins_ref(buckets_plugins *p) {
  if (p) atomic_fetch_add(&p->refs, 1);
  return p;
}

void buckets_plugins_release(buckets_plugins *p) {
  if (!p || atomic_fetch_sub(&p->refs, 1) != 1) return;
  free(p->authz_url);
  free(p->authz_token);
  free(p->idp_url);
  free(p->idp_token);
  free(p->idp_role_policy);
  free(p->idp_role_arn);
  pthread_mutex_destroy(&p->mu);
  free(p);
}

static char *nz(char *s) {
  if (s && !*s) {
    free(s);
    return NULL;
  }
  return s;
}

static bool valid_http_url(const char *u) { return strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0; }

/* Args.Validate: an empty POST must get an answer (any status). */
static bool probe_url(const char *url, const char *token, char *err, size_t errlen) {
  buckets_http_kv h[2] = {{"Content-Type", "application/json"}};
  size_t nh = 1;
  if (token && *token) h[nh++] = (buckets_http_kv){"Authorization", token};
  buckets_http_result r;
  if (!buckets_fetch("POST", url, NULL, h, nh, "", 0, 10000, &r, err, errlen)) return false;
  buckets_http_result_free(&r);
  return true;
}

buckets_plugins *buckets_plugins_build(const buckets_config *cfg, const char *region, bool probe, char *err,
                                       size_t errlen) {
  buckets_plugins *p = buckets_xcalloc(1, sizeof(*p));
  pthread_mutex_init(&p->mu, NULL);
  atomic_init(&p->refs, 1);
  p->authz_url = nz(buckets_config_get(cfg, "policy_plugin", NULL, "url"));
  p->authz_token = nz(buckets_config_get(cfg, "policy_plugin", NULL, "auth_token"));
  if (!p->authz_url) { /* the deprecated OPA sub-system maps onto the plugin */
    p->authz_url = nz(buckets_config_get(cfg, "policy_opa", NULL, "url"));
    p->authz_token = nz(buckets_config_get(cfg, "policy_opa", NULL, "auth_token"));
  }
  p->idp_url = nz(buckets_config_get(cfg, "identity_plugin", NULL, "url"));
  p->idp_token = nz(buckets_config_get(cfg, "identity_plugin", NULL, "auth_token"));
  bool ok = true;
  if (p->authz_url && !valid_http_url(p->authz_url)) {
    snprintf(err, errlen, "unexpected scheme found %s", p->authz_url);
    ok = false;
  }
  if (ok && p->authz_url && probe) ok = probe_url(p->authz_url, p->authz_token, err, errlen);
  if (ok && p->idp_url) {
    if (!valid_http_url(p->idp_url)) {
      snprintf(err, errlen, "unexpected scheme found %s", p->idp_url);
      ok = false;
    }
    p->idp_role_policy = nz(buckets_config_get(cfg, "identity_plugin", NULL, "role_policy"));
    if (ok && !p->idp_role_policy) {
      snprintf(err, errlen, "A role policy must be specified for Identity Management Plugin");
      ok = false;
    }
    char *role_id = nz(buckets_config_get(cfg, "identity_plugin", NULL, "role_id"));
    char rid[128] = "idmp-";
    if (ok && !role_id) {
      unsigned char sum[SHA_DIGEST_LENGTH];
      SHA1((const unsigned char *)p->idp_url, strlen(p->idp_url), sum);
      buckets_base64url_raw_encode(sum, sizeof(sum), rid + 5);
    } else if (ok) {
      for (const char *c = role_id; *c && ok; c++) {
        if (!(*c == '_' || *c == '-' || (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9'))) {
          snprintf(err, errlen, "Role ID must match the regexp `^[a-zA-Z0-9_-]+$`");
          ok = false;
        }
      }
      snprintf(rid + 5, sizeof(rid) - 5, "%s", role_id);
    }
    free(role_id);
    if (ok) {
      char arn[256];
      snprintf(arn, sizeof(arn), "arn:minio:iam:%s::role/%s", region ? region : "", rid);
      p->idp_role_arn = buckets_xstrdup(arn);
    }
    if (ok && probe) ok = probe_url(p->idp_url, p->idp_token, err, errlen);
  }
  if (!ok) {
    buckets_plugins_release(p);
    return NULL;
  }
  return p;
}

bool buckets_authz_plugin_enabled(const buckets_plugins *p) { return p && p->authz_url; }
bool buckets_idp_plugin_enabled(const buckets_plugins *p) { return p && p->idp_url; }
const char *buckets_idp_plugin_role_arn(const buckets_plugins *p) { return p ? p->idp_role_arn : NULL; }
const char *buckets_idp_plugin_role_policy(const buckets_plugins *p) { return p ? p->idp_role_policy : NULL; }

bool buckets_authz_plugin_allowed(buckets_plugins *p, const char *account, char *const *groups, size_t ngroups,
                                  bool owner, const buckets_policy_args *a, const char *claims_json) {
  if (!buckets_authz_plugin_enabled(p)) return false;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_val *in = yyjson_mut_obj_add_obj(d, root, "input");
  yyjson_mut_obj_add_strcpy(d, in, "account", account ? account : "");
  if (ngroups) {
    yyjson_mut_val *g = yyjson_mut_obj_add_arr(d, in, "groups");
    for (size_t i = 0; i < ngroups; i++) yyjson_mut_arr_add_strcpy(d, g, groups[i]);
  } else {
    yyjson_mut_obj_add_null(d, in, "groups");
  }
  yyjson_mut_obj_add_strcpy(d, in, "action", a->action);
  yyjson_mut_obj_add_str(d, in, "originalAction", "");
  yyjson_mut_obj_add_strcpy(d, in, "bucket", a->bucket ? a->bucket : "");
  yyjson_mut_val *conds = yyjson_mut_obj_add_obj(d, in, "conditions");
  for (size_t i = 0; i < a->nconds; i++) {
    yyjson_mut_val *vals = yyjson_mut_arr(d);
    for (size_t k = 0; k < a->conds[i].n; k++) yyjson_mut_arr_add_strcpy(d, vals, a->conds[i].values[k]);
    yyjson_mut_obj_add(conds, yyjson_mut_strcpy(d, a->conds[i].key), vals);
  }
  yyjson_mut_obj_add_bool(d, in, "owner", owner);
  yyjson_mut_obj_add_strcpy(d, in, "object", a->object ? a->object : "");
  yyjson_doc *cd = claims_json ? yyjson_read(claims_json, strlen(claims_json), 0) : NULL;
  if (cd) yyjson_mut_obj_add_val(d, in, "claims", yyjson_val_mut_copy(d, yyjson_doc_get_root(cd)));
  else yyjson_mut_obj_add_null(d, in, "claims");
  yyjson_doc_free(cd);
  yyjson_mut_obj_add_bool(d, in, "denyOnly", a->deny_only);
  size_t len;
  char *body = yyjson_mut_write(d, 0, &len);
  yyjson_mut_doc_free(d);
  buckets_http_kv h[2] = {{"Content-Type", "application/json"}};
  size_t nh = 1;
  if (p->authz_token) h[nh++] = (buckets_http_kv){"Authorization", p->authz_token};
  buckets_http_result r;
  char err[256];
  bool allowed = false;
  if (buckets_fetch("POST", p->authz_url, NULL, h, nh, body, len, 60000, &r, err, sizeof(err))) {
    yyjson_doc *rd = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    yyjson_val *res = rd ? yyjson_obj_get(yyjson_doc_get_root(rd), "result") : NULL;
    /* {"result": bool} or {"result": {"allow": bool}} */
    if (yyjson_is_bool(res)) allowed = yyjson_get_bool(res);
    else if (yyjson_is_obj(res)) allowed = yyjson_get_bool(yyjson_obj_get(res, "allow"));
    yyjson_doc_free(rd);
    buckets_http_result_free(&r);
  }
  free(body);
  return allowed;
}

void buckets_idp_result_free(buckets_idp_result *r) {
  free(r->user);
  free(r->reason);
  yyjson_doc_free(r->claims);
  memset(r, 0, sizeof(*r));
}

bool buckets_idp_plugin_authenticate(buckets_plugins *p, const char *role_arn, const char *token,
                                     buckets_idp_result *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (!buckets_idp_plugin_enabled(p) || !role_arn || strcmp(role_arn, p->idp_role_arn) != 0) {
    snprintf(err, errlen, "Invalid role ARN value: %s", role_arn ? role_arn : "");
    return false;
  }
  buckets_buf url = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&url, p->idp_url);
  buckets_buf_append_c(&url, strchr(p->idp_url, '?') ? "&token=" : "?token=");
  buckets_url_encode(&url, token, false);
  buckets_http_kv h[1];
  size_t nh = 0;
  if (p->idp_token) h[nh++] = (buckets_http_kv){"Authorization", p->idp_token};
  buckets_http_result r;
  int64_t t0 = wall_ns();
  bool ok = buckets_fetch("POST", url.data, NULL, h, nh, NULL, 0, 5000, &r, err, errlen);
  accum_rtt(p, t0, (double)(wall_ns() - t0) / 1e6, ok);
  buckets_buf_free(&url);
  if (!ok) return false;
  yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
  yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
  ok = false;
  if (r.status == 200 && root) {
    long long mv = yyjson_get_sint(yyjson_obj_get(root, "maxValiditySeconds"));
    if (yyjson_is_uint(yyjson_obj_get(root, "maxValiditySeconds"))) mv = (long long)yyjson_get_uint(yyjson_obj_get(root, "maxValiditySeconds"));
    if (mv < 900 || mv > 365LL * 24 * 3600) {
      snprintf(err, errlen, "Plugin returned an invalid validity duration (%lld) - should be between 900 and 31536000", mv);
    } else {
      const char *user = yyjson_get_str(yyjson_obj_get(root, "user"));
      out->user = buckets_xstrdup(user ? user : "");
      out->max_validity = (int)mv;
      yyjson_val *cl = yyjson_obj_get(root, "claims");
      if (yyjson_is_obj(cl)) {
        char *cj = yyjson_val_write(cl, 0, NULL);
        out->claims = yyjson_read(cj, strlen(cj), 0);
        free(cj);
      }
      ok = true;
    }
  } else if (r.status == 403 && root) {
    const char *reason = yyjson_get_str(yyjson_obj_get(root, "reason"));
    out->reason = buckets_xstrdup(reason ? reason : "");
    ok = true;
  } else {
    snprintf(err, errlen, r.status == 200 || r.status == 403 ? "malformed response from auth plugin"
                                                             : "Invalid status code %d from auth plugin", r.status);
  }
  yyjson_doc_free(d);
  buckets_http_result_free(&r);
  return ok;
}
