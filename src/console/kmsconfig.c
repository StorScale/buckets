/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "console/kmsconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <yyjson.h>

#include "core/buf.h"
#include "core/log.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "k8s/kube.h"
#include "kms/kesutil.h"

#define GROUP_PATH "/apis/buckets.io/v1alpha1"
#define TEST_ANNOTATION "buckets.io/kms-test"
#define MAX_BODY (256 * 1024)

struct buckets_console_kms {
  kube *k;
  char *cluster, *ns;
};

buckets_console_kms *buckets_console_kms_new(void) {
  const char *cluster = getenv("BUCKETS_CONSOLE_CLUSTER"), *ns = getenv("BUCKETS_CONSOLE_NAMESPACE");
  if (!cluster || !*cluster || !ns || !*ns) return NULL;
  char err[256];
  kube *k = kube_from_env(err, sizeof(err));
  if (!k) {
    buckets_log_warn("console: KMS settings unavailable: Kubernetes API: %s", err);
    return NULL;
  }
  kube_set_field_manager(k, "buckets-console");
  buckets_console_kms *m = buckets_xcalloc(1, sizeof(*m));
  m->k = k;
  m->cluster = buckets_xstrdup(cluster);
  m->ns = buckets_xstrdup(ns);
  return m;
}

void buckets_console_kms_free(buckets_console_kms *m) {
  if (!m) return;
  kube_free(m->k);
  free(m->cluster);
  free(m->ns);
  free(m);
}

/* ---- replies ------------------------------------------------------------------- */

static void reply(buckets_http_response *resp, int status, yyjson_mut_doc *d) {
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

static void fail(buckets_http_response *resp, int status, const char *code, const char *message) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "code", code);
  yyjson_mut_obj_add_strcpy(d, o, "message", message);
  reply(resp, status, d);
}

/* ---- the cluster and its Secrets ---------------------------------------------------- */

static void cluster_path(const buckets_console_kms *m, buckets_buf *p) {
  buckets_buf_appendf(p, GROUP_PATH "/namespaces/%s/bucketsclusters/%s", m->ns, m->cluster);
}
static void secret_path(const buckets_console_kms *m, const char *suffix, buckets_buf *p) {
  buckets_buf_appendf(p, "/api/v1/namespaces/%s/secrets/%s%s", m->ns, m->cluster, suffix);
}

/* data[key] of a Secret, decoded and parsed as JSON; NULL if absent. */
static yyjson_doc *secret_json(yyjson_val *secret, const char *key) {
  const char *b64 = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(secret, "data"), key));
  if (!b64) return NULL;
  size_t n = strlen(b64);
  char *raw = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64_decode(b64, n, (uint8_t *)raw);
  yyjson_doc *d = k > 0 ? yyjson_read(raw, (size_t)k, 0) : NULL;
  OPENSSL_cleanse(raw, n * 3 / 4 + 4);
  free(raw);
  return d;
}

/* GETs one of the cluster's KMS Secrets. */
static int get_secret(buckets_console_kms *m, const char *suffix, yyjson_doc **out) {
  buckets_buf p = BUCKETS_BUF_INIT;
  secret_path(m, suffix, &p);
  int st = kube_get(m->k, p.data, out);
  buckets_buf_free(&p);
  return st;
}

/* Replaces one of the cluster's KMS Secrets' contents with key = json. */
static int put_secret(buckets_console_kms *m, const char *suffix, yyjson_val *current, const char *key, const char *json) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "apiVersion", "v1");
  yyjson_mut_obj_add_str(d, o, "kind", "Secret");
  yyjson_mut_val *meta = yyjson_val_mut_copy(d, yyjson_obj_get(current, "metadata")); /* resourceVersion: no lost update */
  yyjson_mut_obj_add_val(d, o, "metadata", meta);
  yyjson_mut_obj_add_str(d, o, "type", "Opaque");
  yyjson_mut_obj_add_strcpy(d, yyjson_mut_obj_add_obj(d, o, "stringData"), key, json);
  buckets_buf p = BUCKETS_BUF_INIT;
  secret_path(m, suffix, &p);
  yyjson_doc *resp = NULL;
  int st = kube_update(m->k, p.data, d, &resp);
  if (st / 100 != 2) buckets_log_warn("console: updating %s: %d %s", p.data, st, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&p);
  yyjson_mut_doc_free(d);
  return st;
}

static int patch_cluster(buckets_console_kms *m, yyjson_mut_doc *patch) {
  buckets_buf p = BUCKETS_BUF_INIT;
  cluster_path(m, &p);
  yyjson_doc *resp = NULL;
  int st = kube_merge_patch(m->k, p.data, patch, &resp);
  if (st / 100 != 2) buckets_log_warn("console: patching %s: %d %s", p.data, st, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&p);
  return st;
}

/* ---- GET ------------------------------------------------------------------------- */

static void handle_get(buckets_console_kms *m, buckets_http_response *resp) {
  buckets_buf p = BUCKETS_BUF_INIT;
  cluster_path(m, &p);
  yyjson_doc *bc = NULL;
  int st = kube_get(m->k, p.data, &bc);
  buckets_buf_free(&p);
  if (st != 200) {
    yyjson_doc_free(bc);
    char msg[200];
    snprintf(msg, sizeof(msg), "Reading BucketsCluster %s/%s failed (%d).", m->ns, m->cluster, st);
    fail(resp, 502, "KubernetesError", msg);
    return;
  }
  yyjson_val *root = yyjson_doc_get_root(bc);
  yyjson_val *kes = yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(root, "spec"), "kms"), "kes");
  yyjson_doc *sec = NULL;
  get_secret(m, "-kms", &sec);
  yyjson_doc *settings = secret_json(yyjson_doc_get_root(sec), "settings.json");

  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_bool(d, o, "managed", true);
  yyjson_mut_obj_add_strcpy(d, o, "cluster", m->cluster);
  yyjson_mut_obj_add_strcpy(d, o, "namespace", m->ns);
  char sa[160]; /* the account a Vault Kubernetes role names: spec.kms.kes's, else the servers' own */
  const char *sa_set = yyjson_get_str(yyjson_obj_get(kes, "serviceAccountName"));
  const char *kes_name = yyjson_get_str(yyjson_obj_get(kes, "name"));
  if (sa_set && *sa_set) snprintf(sa, sizeof(sa), "%s", sa_set);
  else if (kes_name && *kes_name) snprintf(sa, sizeof(sa), "%s", kes_name);
  else snprintf(sa, sizeof(sa), "%s-kes", m->cluster);
  yyjson_mut_obj_add_strcpy(d, o, "kesServiceAccount", sa);
  yyjson_mut_obj_add_bool(d, o, "enabled", yyjson_is_obj(kes));
  const char *key = yyjson_get_str(yyjson_obj_get(kes, "keyName"));
  yyjson_mut_obj_add_strcpy(d, o, "keyName", key && *key ? key : "buckets-default");
  if (settings) {
    yyjson_mut_obj_add_val(d, o, "settings", buckets_kes_settings_redacted(d, yyjson_doc_get_root(settings)));
    char desc[300];
    buckets_kes_settings_describe(yyjson_doc_get_root(settings), desc, sizeof(desc));
    yyjson_mut_obj_add_strcpy(d, o, "description", desc);
  } else {
    yyjson_mut_obj_add_null(d, o, "settings");
  }
  yyjson_val *status = yyjson_obj_get(yyjson_obj_get(root, "status"), "kms");
  if (status) yyjson_mut_obj_add_val(d, o, "status", yyjson_val_mut_copy(d, status));
  else yyjson_mut_obj_add_obj(d, o, "status");
  reply(resp, 200, d);
  yyjson_doc_free(settings);
  yyjson_doc_free(sec);
  yyjson_doc_free(bc);
}

/* ---- POST test ---------------------------------------------------------------------- */

static void handle_test(buckets_console_kms *m, yyjson_val *body, buckets_http_response *resp) {
  yyjson_val *in = yyjson_obj_get(body, "settings");
  const char *key = yyjson_get_str(yyjson_obj_get(body, "keyName"));
  if (!yyjson_is_obj(in)) {
    fail(resp, 400, "InvalidSettings", "Choose where keys are kept.");
    return;
  }
  if (!key || !*key || strlen(key) > 200 || strpbrk(key, "/\\* ")) {
    fail(resp, 400, "InvalidSettings", "Name the default key: letters, digits, '-' and '_', no spaces or slashes.");
    return;
  }
  /* secrets not typed again come from the saved settings */
  yyjson_doc *live = NULL;
  int st = get_secret(m, "-kms", &live);
  yyjson_doc *saved = st == 200 ? secret_json(yyjson_doc_get_root(live), "settings.json") : NULL;
  yyjson_doc_free(live);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *settings = yyjson_val_mut_copy(d, in);
  if (saved) buckets_kes_settings_keep_secrets(d, settings, yyjson_doc_get_root(saved));
  yyjson_mut_obj_remove_key(settings, "secretsSet");
  yyjson_doc_free(saved);

  /* the operator checks them again; here, a person learns of a mistake at once */
  yyjson_mut_doc *probe = yyjson_mut_doc_new(NULL);
  yyjson_doc *sdoc = yyjson_mut_val_imut_copy(settings, NULL);
  char err[300];
  bool ok = buckets_kes_keystore(probe, yyjson_doc_get_root(sdoc), "/ca.pem", err, sizeof(err)) != NULL;
  yyjson_doc_free(sdoc);
  yyjson_mut_doc_free(probe);
  if (!ok) {
    yyjson_mut_doc_free(d);
    fail(resp, 400, "InvalidSettings", err);
    return;
  }
  char id[40];
  buckets_uuid_v4(id);
  yyjson_mut_val *cand = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, cand);
  yyjson_mut_obj_add_strcpy(d, cand, "testId", id);
  yyjson_mut_obj_add_val(d, cand, "settings", settings);
  yyjson_mut_obj_add_strcpy(d, cand, "keyName", key);
  yyjson_mut_obj_add_bool(d, cand, "createKey", yyjson_get_bool(yyjson_obj_get(body, "createKey")));
  yyjson_mut_val *req = yyjson_mut_obj_add_arr(d, cand, "requiredKeys");
  size_t i, max;
  yyjson_val *rk;
  yyjson_arr_foreach(yyjson_obj_get(body, "requiredKeys"), i, max, rk) {
    if (yyjson_is_str(rk) && yyjson_get_len(rk) < 256) yyjson_mut_arr_add_strcpy(d, req, yyjson_get_str(rk));
  }
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);

  yyjson_doc *cur = NULL;
  st = get_secret(m, "-kms-candidate", &cur);
  if (st == 200) st = put_secret(m, "-kms-candidate", yyjson_doc_get_root(cur), "candidate.json", json);
  yyjson_doc_free(cur);
  OPENSSL_cleanse(json, n);
  free(json);
  if (st / 100 != 2) {
    char msg[200];
    snprintf(msg, sizeof(msg), "Saving the settings to test failed (%d): is buckets-operator running?", st);
    fail(resp, 502, "KubernetesError", msg);
    return;
  }
  /* the operator starts the trial when the annotation names a new one */
  yyjson_mut_doc *patch = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *pr = yyjson_mut_obj(patch);
  yyjson_mut_doc_set_root(patch, pr);
  yyjson_mut_val *ann = yyjson_mut_obj_add_obj(patch, yyjson_mut_obj_add_obj(patch, pr, "metadata"), "annotations");
  yyjson_mut_obj_add_strcpy(patch, ann, TEST_ANNOTATION, id);
  st = patch_cluster(m, patch);
  yyjson_mut_doc_free(patch);
  if (st / 100 != 2) {
    fail(resp, 502, "KubernetesError", "Starting the test failed: the console may not update its BucketsCluster.");
    return;
  }
  buckets_log_info("console: testing new KMS settings (%s)", id);
  yyjson_mut_doc *r = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *ro = yyjson_mut_obj(r);
  yyjson_mut_doc_set_root(r, ro);
  yyjson_mut_obj_add_strcpy(r, ro, "testId", id);
  reply(resp, 202, r);
}

/* ---- POST apply --------------------------------------------------------------------- */

static void handle_apply(buckets_console_kms *m, yyjson_val *body, buckets_http_response *resp) {
  const char *id = yyjson_get_str(yyjson_obj_get(body, "testId"));
  if (!id || !*id) {
    fail(resp, 400, "InvalidRequest", "testId is required");
    return;
  }
  buckets_buf p = BUCKETS_BUF_INIT;
  cluster_path(m, &p);
  yyjson_doc *bc = NULL;
  int st = kube_get(m->k, p.data, &bc);
  buckets_buf_free(&p);
  yyjson_val *test = yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(bc), "status"), "kms"), "test");
  const char *tid = yyjson_get_str(yyjson_obj_get(test, "id")), *phase = yyjson_get_str(yyjson_obj_get(test, "phase"));
  bool passed = st == 200 && tid && strcmp(tid, id) == 0 && phase && strcmp(phase, "Passed") == 0;
  yyjson_doc_free(bc);
  if (!passed) {
    fail(resp, 409, "NotTested", "These settings have not passed a test: test them first.");
    return;
  }
  yyjson_doc *cur = NULL;
  st = get_secret(m, "-kms-candidate", &cur);
  yyjson_doc *cand = st == 200 ? secret_json(yyjson_doc_get_root(cur), "candidate.json") : NULL;
  yyjson_doc_free(cur);
  yyjson_val *cr = yyjson_doc_get_root(cand);
  const char *cid = yyjson_get_str(yyjson_obj_get(cr, "testId"));
  if (!cid || strcmp(cid, id) != 0) {
    yyjson_doc_free(cand);
    fail(resp, 409, "NotTested", "The settings changed since they were tested: test them again.");
    return;
  }
  size_t n;
  char *json = yyjson_val_write(yyjson_obj_get(cr, "settings"), 0, &n);
  yyjson_doc *live = NULL;
  st = get_secret(m, "-kms", &live);
  if (st == 200) st = put_secret(m, "-kms", yyjson_doc_get_root(live), "settings.json", json);
  yyjson_doc_free(live);
  OPENSSL_cleanse(json, n);
  free(json);
  if (st / 100 != 2) {
    yyjson_doc_free(cand);
    fail(resp, 502, "KubernetesError", "Saving the settings failed.");
    return;
  }
  /* spec.kms.kes turns KES on (if it was not) with the tested default key */
  yyjson_mut_doc *patch = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *pr = yyjson_mut_obj(patch);
  yyjson_mut_doc_set_root(patch, pr);
  yyjson_mut_val *kes = yyjson_mut_obj_add_obj(
      patch, yyjson_mut_obj_add_obj(patch, yyjson_mut_obj_add_obj(patch, pr, "spec"), "kms"), "kes");
  yyjson_mut_obj_add_strcpy(patch, kes, "keyName", yyjson_get_str(yyjson_obj_get(cr, "keyName")));
  st = patch_cluster(m, patch);
  yyjson_mut_doc_free(patch);
  yyjson_doc_free(cand);
  if (st / 100 != 2) {
    fail(resp, 502, "KubernetesError", "Turning on KES failed: the console may not update its BucketsCluster.");
    return;
  }
  buckets_log_info("console: applied KMS settings (%s)", id);
  yyjson_mut_doc *r = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *ro = yyjson_mut_obj(r);
  yyjson_mut_doc_set_root(r, ro);
  yyjson_mut_obj_add_bool(r, ro, "applied", true);
  reply(resp, 200, r);
}

void buckets_console_kms_handle(buckets_console_kms *m, const buckets_http_request *req, const char *sub,
                                buckets_http_response *resp) {
  bool get = buckets_str_eq_c(req->method, "GET"), post = buckets_str_eq_c(req->method, "POST");
  if (!*sub && get) {
    if (!m) {
      yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
      yyjson_mut_val *o = yyjson_mut_obj(d);
      yyjson_mut_doc_set_root(d, o);
      yyjson_mut_obj_add_bool(d, o, "managed", false);
      reply(resp, 200, d);
      return;
    }
    handle_get(m, resp);
    return;
  }
  if (!post || (strcmp(sub, "/test") != 0 && strcmp(sub, "/apply") != 0)) {
    fail(resp, 404, "NotFound", "unknown API");
    return;
  }
  if (!m) {
    fail(resp, 501, "NotImplemented", "The KMS is configured on the servers here, not in the console.");
    return;
  }
  if (req->body_len > MAX_BODY || req->body_fd >= 0 || req->pipe) {
    fail(resp, 400, "InvalidRequest", "request too large");
    return;
  }
  yyjson_doc *d = yyjson_read(req->body.p ? req->body.p : "", req->body.n, 0);
  yyjson_val *body = yyjson_doc_get_root(d);
  if (!yyjson_is_obj(body)) fail(resp, 400, "InvalidRequest", "a JSON object is expected");
  else if (strcmp(sub, "/test") == 0) handle_test(m, body, resp);
  else handle_apply(m, body, resp);
  yyjson_doc_free(d);
}

/* ---- Buckets declared as resources ------------------------------------------------------- */

void buckets_console_declared_buckets(buckets_console_kms *m, buckets_http_response *resp) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_bool(d, o, "managed", m != NULL);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "buckets");
  if (!m) {
    reply(resp, 200, d);
    return;
  }
  yyjson_mut_obj_add_strcpy(d, o, "namespace", m->ns);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, GROUP_PATH "/namespaces/%s/buckets", m->ns);
  yyjson_doc *list = NULL;
  int st = kube_get(m->k, p.data, &list);
  buckets_buf_free(&p);
  if (st != 200) {
    yyjson_doc_free(list);
    yyjson_mut_doc_free(d);
    fail(resp, 502, "KubernetesError", "The Bucket resources could not be read from the Kubernetes API.");
    return;
  }
  size_t i, n;
  yyjson_val *item;
  yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(list), "items"), i, n, item) {
    yyjson_val *spec = yyjson_obj_get(item, "spec"), *meta = yyjson_obj_get(item, "metadata");
    const char *cluster = yyjson_get_str(yyjson_obj_get(spec, "cluster"));
    if (!cluster || strcmp(cluster, m->cluster) != 0) continue;
    const char *res = yyjson_get_str(yyjson_obj_get(meta, "name"));
    const char *bucket = yyjson_get_str(yyjson_obj_get(spec, "name"));
    yyjson_mut_val *b = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, b, "bucket", bucket ? bucket : res ? res : "");
    yyjson_mut_obj_add_strcpy(d, b, "resource", res ? res : "");
    /* declared fields: present, even empty ([] or {}), means the operator keeps them */
    yyjson_mut_obj_add_bool(d, b, "lifecycle", yyjson_obj_get(spec, "lifecycle") != NULL);
    yyjson_mut_obj_add_bool(d, b, "replication", yyjson_obj_get(spec, "replication") != NULL);
    yyjson_mut_obj_add_val(d, b, "spec", yyjson_val_mut_copy(d, spec));
  }
  yyjson_doc_free(list);
  reply(resp, 200, d);
}
