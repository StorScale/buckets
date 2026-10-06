/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "monitoring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/log.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/jwt.h"
#include "iam.h"
#include "kms.h"
#include "s3client.h"

#define POLICY "buckets-prometheus"
/* admin:Prometheus only, in the form of MinIO's own diagnostics policy */
static const char k_policy[] = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                               "\"Action\":[\"admin:Prometheus\"],\"Resource\":[\"arn:aws:s3:::*\"]}]}";

static void status(yyjson_mut_doc *d, yyjson_mut_val *mon, const char *phase, const char *message) {
  yyjson_mut_obj_add_str(d, mon, "phase", phase);
  if (message && *message) yyjson_mut_obj_add_strcpy(d, mon, "message", message);
}

void op_prometheus_token(const char *ak, const char *sk, long long now, buckets_buf *out) {
  char claims[512];
  int n = snprintf(claims, sizeof(claims), "{\"exp\":%lld,\"sub\":\"%s\",\"iss\":\"prometheus\"}",
                   now + 100LL * 365 * 86400, ak);
  buckets_jwt_sign(claims, (size_t)n, sk, out);
}

/* Whether the Prometheus Operator's API serves ServiceMonitors. */
static bool installed(op_ctx *o) {
  yyjson_doc *api = NULL;
  int st = kube_get(o->k, BC_MONITORING_API, &api);
  bool ok = false;
  size_t i, max;
  yyjson_val *r;
  if (st == 200) {
    yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(api), "resources"), i, max, r) {
      const char *n = yyjson_get_str(yyjson_obj_get(r, "name"));
      ok = ok || (n && strcmp(n, "servicemonitors") == 0);
    }
  }
  yyjson_doc_free(api);
  return ok;
}

static void admin_refusal(const char *what, int st, const buckets_buf *body, char *err, size_t errlen) {
  yyjson_doc *j = body->len ? yyjson_read(body->data, body->len, 0) : NULL;
  const char *m = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(j), "Message"));
  if (m && *m) snprintf(err, errlen, "%s: %s", what, m);
  else if (st == 0) snprintf(err, errlen, "%s: the servers cannot be reached", what);
  else snprintf(err, errlen, "%s: the servers answered %d", what, st);
  yyjson_doc_free(j);
}

/* The metrics user with secret sk and only the buckets-prometheus policy; with check, only when it is missing.
 * False and why on failure. */
static bool ensure_user(op_ctx *o, yyjson_val *bc, const char *ak, const char *sk, bool check, char *err,
                        size_t errlen) {
  op_admin *a = op_cluster_admin(o, bc, err, errlen);
  if (!a) return false;
  struct s3c *c = op_admin_client(a);
  buckets_buf q = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  bool ok = true;
  buckets_buf_append_c(&q, "accessKey=");
  buckets_url_encode(&q, ak, false);
  if (check) {
    int st = s3c_admin(c, "GET", "user-info", q.data, NULL, 0, false, false, &body);
    yyjson_doc *ui = st == 200 ? yyjson_read(body.data, body.len, 0) : NULL;
    const char *pol = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ui), "policyName"));
    const char *stt = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ui), "status"));
    bool fine = pol && strcmp(pol, POLICY) == 0 && stt && strcmp(stt, "enabled") == 0;
    yyjson_doc_free(ui);
    if (fine) goto out;
    if (st != 200 && st != 404) {
      char code[64];
      s3c_error_code(&body, code, sizeof(code));
      if (strcmp(code, "XMinioAdminNoSuchUser") != 0) {
        admin_refusal("Checking the metrics user", st, &body, err, errlen);
        ok = false;
        goto out;
      }
    }
  }
  buckets_buf_reset(&body);
  char pq[64];
  snprintf(pq, sizeof(pq), "name=%s", POLICY);
  int st = s3c_admin(c, "PUT", "add-canned-policy", pq, k_policy, strlen(k_policy), false, false, &body);
  if (st / 100 != 2) {
    admin_refusal("Creating the buckets-prometheus policy", st, &body, err, errlen);
    ok = false;
    goto out;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "secretKey", sk);
  yyjson_mut_obj_add_str(d, root, "status", "enabled");
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  buckets_buf_reset(&body);
  st = s3c_admin(c, "PUT", "add-user", q.data, json, n, true, false, &body);
  memset(json, 0, n);
  free(json);
  if (st / 100 != 2) {
    admin_refusal("Creating the metrics user", st, &body, err, errlen);
    ok = false;
    goto out;
  }
  buckets_buf_reset(&q);
  buckets_buf_appendf(&q, "policyName=%s&userOrGroup=", POLICY);
  buckets_url_encode(&q, ak, false);
  buckets_buf_append_c(&q, "&isGroup=false");
  buckets_buf_reset(&body);
  st = s3c_admin(c, "PUT", "set-user-or-group-policy", q.data, NULL, 0, false, false, &body);
  if (st / 100 != 2) {
    admin_refusal("Giving the metrics user its policy", st, &body, err, errlen);
    ok = false;
  }
out:
  buckets_buf_free(&q);
  buckets_buf_free(&body);
  op_cluster_admin_free(a);
  return ok;
}

/* The key of a TLS Secret holding the CA to check its certificate with: ca.crt, or the certificate itself
 * when self-signed. */
static const char *ca_key_of(op_ctx *o, const bc_spec *s, const char *secret) {
  char *ca = op_secret_text(o, s, secret, "ca.crt");
  bool has = ca && *ca;
  free(ca);
  return has ? "ca.crt" : "tls.crt";
}

/* Applies obj (freeing it); false and why on failure. */
static bool apply(op_ctx *o, bc_object obj, const char *what, char *err, size_t errlen) {
  yyjson_doc *resp = NULL;
  int st = kube_apply(o->k, obj.path, obj.doc, &resp);
  if (st / 100 != 2) snprintf(err, errlen, "%s cannot be written (%d): %s", what, st, kube_error_message(resp));
  yyjson_doc_free(resp);
  free(obj.path); /* bc_objects_free would free an array */
  yyjson_mut_doc_free(obj.doc);
  return st / 100 == 2;
}

static void delete_console_monitor(op_ctx *o, const bc_spec *s) {
  char name[160];
  bc_console_service_monitor_name(s, name, sizeof(name));
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, BC_MONITORING_API "/namespaces/%s/servicemonitors/%s", s->ns, name);
  kube_delete(o->k, p.data);
  buckets_buf_free(&p);
}

static void wipe_free(char *p) {
  if (p) memset(p, 0, strlen(p));
  free(p);
}

void op_monitoring_reconcile(op_ctx *o, yyjson_val *bc, const bc_spec *s, yyjson_mut_doc *d, yyjson_mut_val *mon) {
  buckets_buf smpath = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&smpath, BC_MONITORING_API "/namespaces/%s/servicemonitors/%s", s->ns, s->name);
  bool api = installed(o);
  if (s->monitoring.enabled == 0) {
    if (api) {
      int st = kube_delete(o->k, smpath.data);
      if (st / 100 == 2) buckets_log_info("%s/%s: monitoring off: deleted its ServiceMonitor", s->ns, s->name);
      delete_console_monitor(o, s);
    }
    status(d, mon, "Disabled", "spec.monitoring.enabled is false.");
    goto done;
  }
  if (!api) {
    status(d, mon, "NotInstalled",
           "The Prometheus Operator is not installed: scrape the servers as docs/monitoring.md shows.");
    goto done;
  }
  char name[160], err[1024] = "";
  bc_prometheus_secret_name(s, name, sizeof(name));
  char *ak = op_secret_text(o, s, name, "accessKey"), *sk = op_secret_text(o, s, name, "secretKey");
  char *tok = op_secret_text(o, s, name, "token");
  bool fresh = !ak || !sk || !tok || !*ak || !*sk || !*tok;
  if (fresh) {
    wipe_free(ak), wipe_free(sk), wipe_free(tok);
    char a[160];
    snprintf(a, sizeof(a), "%s-prometheus", s->name);
    ak = buckets_xstrdup(a);
    unsigned char r[30];
    buckets_random(r, sizeof(r));
    sk = buckets_xcalloc(64, 1);
    buckets_base64url_raw_encode(r, sizeof(r), sk);
    buckets_buf t = BUCKETS_BUF_INIT;
    op_prometheus_token(ak, sk, (long long)time(NULL), &t);
    tok = t.data;
  }
  if (!ensure_user(o, bc, ak, sk, !fresh, err, sizeof(err))) {
    buckets_log_warn("%s/%s: monitoring: %s", s->ns, s->name, err);
    status(d, mon, "Error", err);
    goto creds;
  }
  if (fresh) {
    yyjson_mut_doc *sec = bc_prometheus_secret(s, ak, sk, tok);
    buckets_buf path = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "/api/v1/namespaces/%s/secrets/%s", s->ns, name);
    yyjson_doc *resp = NULL;
    int st = kube_apply(o->k, path.data, sec, &resp);
    if (st / 100 != 2) {
      snprintf(err, sizeof(err), "Secret %s cannot be written (%d): %s", name, st, kube_error_message(resp));
      status(d, mon, "Error", err);
    }
    yyjson_doc_free(resp);
    yyjson_mut_doc_free(sec);
    buckets_buf_free(&path);
    if (st / 100 != 2) goto creds;
    buckets_log_info("%s/%s: monitoring: metrics user %s and its token Secret %s", s->ns, s->name, ak, name);
  }
  {
    const char *srv_tls = s->tls_secret ? (s->ca_secret ? s->ca_secret : s->tls_secret) : NULL;
    bool ok = apply(o, bc_service_monitor(s, srv_tls ? ca_key_of(o, s, srv_tls) : "ca.crt"), "The ServiceMonitor", err,
                    sizeof(err));
    if (ok && s->console.enabled) {
      const char *ct = s->console.tls_secret;
      ok = apply(o, bc_console_service_monitor(s, ct ? ca_key_of(o, s, ct) : "ca.crt"), "The console's ServiceMonitor",
                 err, sizeof(err));
    } else if (ok) {
      delete_console_monitor(o, s);
    }
    if (!ok) {
      status(d, mon, "Error", err);
    } else {
      char msg[300];
      snprintf(msg, sizeof(msg), "Prometheus scrapes every server%s through ServiceMonitor %s%s.",
               s->console.enabled ? " and the console" : "", s->name, s->console.enabled ? " and its -console one" : "");
      status(d, mon, "Ready", msg);
    }
  }
creds:
  wipe_free(ak), wipe_free(sk), wipe_free(tok);
done:
  buckets_buf_free(&smpath);
}
