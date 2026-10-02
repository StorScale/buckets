/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "k8s/kube.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/log.h"
#include "net/client.h"

#define SA_DIR "/var/run/secrets/kubernetes.io/serviceaccount"

struct kube {
  buckets_http_client *http;
  buckets_tls_client *tls;
  char *token_file; /* re-read: projected tokens rotate */
  char *token;
  char *manager; /* server-side apply's field manager */
};

static char *read_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  buckets_buf b = BUCKETS_BUF_INIT;
  char tmp[4096];
  size_t n;
  while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) buckets_buf_append(&b, tmp, n);
  fclose(f);
  while (b.len && (b.data[b.len - 1] == '\n' || b.data[b.len - 1] == '\r')) b.data[--b.len] = '\0';
  return b.data ? b.data : buckets_xstrdup("");
}

kube *kube_from_env(char *err, size_t errlen) {
  const char *api = getenv("BUCKETS_KUBE_API");
  char url[512];
  const char *ca = getenv("BUCKETS_KUBE_CA");
  const char *token = getenv("BUCKETS_KUBE_TOKEN");
  const char *token_file = getenv("BUCKETS_KUBE_TOKEN_FILE");
  if (!api) {
    const char *h = getenv("KUBERNETES_SERVICE_HOST"), *p = getenv("KUBERNETES_SERVICE_PORT");
    if (!h) {
      snprintf(err, errlen, "not in a pod and BUCKETS_KUBE_API is not set");
      return NULL;
    }
    snprintf(url, sizeof(url), strchr(h, ':') ? "https://[%s]:%s" : "https://%s:%s", h, p ? p : "443");
    api = url;
    if (!ca) ca = SA_DIR "/ca.crt";
    if (!token && !token_file) token_file = SA_DIR "/token";
  }
  if (strncmp(api, "https://", 8) != 0) {
    snprintf(err, errlen, "BUCKETS_KUBE_API must be an https:// URL");
    return NULL;
  }
  char host[256];
  int port = 443;
  const char *hp = api + 8;
  if (*hp == '[') {
    const char *close = strchr(hp, ']');
    snprintf(host, sizeof(host), "%.*s", close ? (int)(close - hp - 1) : 0, hp + 1);
    if (close && close[1] == ':') port = atoi(close + 2);
  } else {
    const char *colon = strchr(hp, ':'), *slash = strchr(hp, '/');
    size_t hl = colon ? (size_t)(colon - hp) : slash ? (size_t)(slash - hp) : strlen(hp);
    snprintf(host, sizeof(host), "%.*s", (int)hl, hp);
    if (colon) port = atoi(colon + 1);
  }
  kube *k = buckets_xcalloc(1, sizeof(*k));
  if (!(k->tls = buckets_tls_client_new(ca, err, errlen))) {
    free(k);
    return NULL;
  }
  k->http = buckets_http_client_new(host, port, k->tls, 30000);
  k->manager = buckets_xstrdup("buckets-operator");
  if (token_file) k->token_file = buckets_xstrdup(token_file);
  else if (token) k->token = buckets_xstrdup(token);
  return k;
}

void kube_free(kube *k) {
  if (!k) return;
  buckets_http_client_free(k->http);
  buckets_tls_client_free(k->tls);
  free(k->token_file);
  free(k->token);
  free(k->manager);
  free(k);
}

int kube_request(kube *k, const char *method, const char *path, const char *content_type, const char *body,
                 size_t body_len, yyjson_doc **out) {
  if (out) *out = NULL;
  char *token = k->token_file ? read_file(k->token_file) : NULL;
  buckets_buf auth = BUCKETS_BUF_INIT;
  if (token || k->token) buckets_buf_appendf(&auth, "Bearer %s", token ? token : k->token);
  free(token);
  buckets_http_kv h[3];
  size_t nh = 0;
  h[nh++] = (buckets_http_kv){"Accept", "application/json"};
  if (auth.len) h[nh++] = (buckets_http_kv){"Authorization", auth.data};
  if (content_type) h[nh++] = (buckets_http_kv){"Content-Type", content_type};
  buckets_http_result r;
  int status = 0;
  if (buckets_http_client_do(k->http, method, path, h, nh, body, body_len, &r)) {
    status = r.status;
    if (out && r.body.len) *out = yyjson_read(r.body.data, r.body.len, 0);
    buckets_http_result_free(&r);
  }
  buckets_buf_free(&auth);
  return status;
}

int kube_get(kube *k, const char *path, yyjson_doc **out) { return kube_request(k, "GET", path, NULL, NULL, 0, out); }

int kube_get_text(kube *k, const char *path, buckets_buf *out) {
  char *token = k->token_file ? read_file(k->token_file) : NULL;
  buckets_buf auth = BUCKETS_BUF_INIT;
  if (token || k->token) buckets_buf_appendf(&auth, "Bearer %s", token ? token : k->token);
  free(token);
  buckets_http_kv h[1];
  size_t nh = 0;
  if (auth.len) h[nh++] = (buckets_http_kv){"Authorization", auth.data};
  buckets_http_result r;
  int status = 0;
  if (buckets_http_client_do(k->http, "GET", path, h, nh, NULL, 0, &r)) {
    status = r.status;
    buckets_buf_append(out, r.body.data, r.body.len);
    buckets_http_result_free(&r);
  }
  buckets_buf_free(&auth);
  return status;
}

static int send_doc(kube *k, const char *method, const char *path, const char *ctype, yyjson_mut_doc *obj,
                    yyjson_doc **out) {
  size_t n;
  char *json = yyjson_mut_write(obj, 0, &n);
  int st = kube_request(k, method, path, ctype, json, n, out);
  free(json);
  return st;
}

int kube_apply(kube *k, const char *path, yyjson_mut_doc *obj, yyjson_doc **out) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s?fieldManager=%s&force=true", path, k->manager);
  /* JSON is YAML: the apply patch type takes it as is. */
  int st = send_doc(k, "PATCH", p.data, "application/apply-patch+yaml", obj, out);
  buckets_buf_free(&p);
  return st;
}

void kube_set_field_manager(kube *k, const char *name) {
  free(k->manager);
  k->manager = buckets_xstrdup(name);
}

int kube_merge_patch(kube *k, const char *path, yyjson_mut_doc *patch, yyjson_doc **out) {
  return send_doc(k, "PATCH", path, "application/merge-patch+json", patch, out);
}

int kube_update(kube *k, const char *path, yyjson_mut_doc *obj, yyjson_doc **out) {
  return send_doc(k, "PUT", path, "application/json", obj, out);
}

int kube_create(kube *k, const char *collection_path, yyjson_mut_doc *obj, yyjson_doc **out) {
  return send_doc(k, "POST", collection_path, "application/json", obj, out);
}

int kube_delete(kube *k, const char *path) { return kube_request(k, "DELETE", path, NULL, NULL, 0, NULL); }

const char *kube_error_message(yyjson_doc *doc) {
  const char *m = doc ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "message")) : NULL;
  return m ? m : "(no message)";
}
