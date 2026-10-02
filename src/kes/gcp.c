/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Google Secret Manager, as MinIO KES uses it: a secret per key, named after
 * it, replicated automatically, its version 1 holding the stored key. Over
 * Secret Manager's REST API (KES uses gRPC: the same resources). Sign-in: the
 * service account's key (a JWT exchanged for an OAuth token), or, without
 * one, the metadata server (GKE workload identity, the node's account). */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "crypto/base64.h"
#include "kes/store.h"
#include "net/fetch.h"

#define TIMEOUT_MS 15000

typedef struct {
  buckets_kes_store base;
  char base_url[300]; /* https://secretmanager.googleapis.com/v1 */
  char *project, *email, *key_id, *key_pem, *scopes;
  pthread_mutex_t mu;
  char *token;
  int64_t expires;
} gcp;

static const char *env(const char *n) {
  const char *v = getenv(n);
  return v && *v ? v : NULL;
}

static void b64url(buckets_buf *out, const void *p, size_t n) {
  char *s = buckets_xmalloc(n * 4 / 3 + 8);
  buckets_base64_encode(p, n, s);
  for (char *c = s; *c; c++) {
    if (*c == '+') *c = '-';
    else if (*c == '/') *c = '_';
    else if (*c == '=') {
      *c = '\0';
      break;
    }
  }
  buckets_buf_append_c(out, s);
  free(s);
}

/* RS256 over msg with the service account's PEM key */
static bool rs256(const char *pem, const char *msg, buckets_buf *sig) {
  BIO *bio = BIO_new_mem_buf(pem, -1);
  EVP_PKEY *k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!k) return false;
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  size_t n = 0;
  bool ok = EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, k) == 1 &&
            EVP_DigestSign(md, NULL, &n, (const unsigned char *)msg, strlen(msg)) == 1;
  if (ok) {
    unsigned char *s = buckets_xmalloc(n);
    ok = EVP_DigestSign(md, s, &n, (const unsigned char *)msg, strlen(msg)) == 1;
    if (ok) b64url(sig, s, n);
    free(s);
  }
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(k);
  return ok;
}

static bool take_token(gcp *g, const buckets_http_result *r) {
  yyjson_doc *d = yyjson_read(r->body.data, r->body.len, 0);
  yyjson_val *o = yyjson_doc_get_root(d);
  const char *tok = yyjson_get_str(yyjson_obj_get(o, "access_token"));
  int64_t exp = yyjson_get_sint(yyjson_obj_get(o, "expires_in"));
  bool ok = r->status == 200 && tok;
  if (ok) {
    pthread_mutex_lock(&g->mu);
    free(g->token);
    g->token = buckets_xstrdup(tok);
    g->expires = (int64_t)time(NULL) + (exp > 0 ? exp : 3600);
    pthread_mutex_unlock(&g->mu);
  }
  yyjson_doc_free(d);
  return ok;
}

static bool sign_in(gcp *g, char *err, size_t errlen) {
  buckets_http_result r;
  char e2[300];
  if (!g->key_pem) { /* the metadata server */
    char url[400];
    snprintf(url, sizeof(url), "%s/computeMetadata/v1/instance/service-accounts/default/token",
             env("GCE_METADATA_HOST") ? env("GCE_METADATA_HOST") : "http://metadata.google.internal");
    if (strncmp(url, "http", 4) != 0) snprintf(url, sizeof(url), "http://%s/computeMetadata/v1/instance/service-accounts/default/token", env("GCE_METADATA_HOST"));
    buckets_http_kv h[] = {{"Metadata-Flavor", "Google"}};
    if (!buckets_fetch("GET", url, NULL, h, 1, NULL, 0, 5000, &r, e2, sizeof(e2)))
      return snprintf(err, errlen, "gcp: no service account key, and no metadata server: %s", e2), false;
    bool ok = take_token(g, &r);
    if (!ok) snprintf(err, errlen, "gcp: the metadata server gave no token (%d)", r.status);
    buckets_http_result_free(&r);
    return ok;
  }
  const char *aud = env("GOOGLE_OAUTH_TOKEN_URI") ? env("GOOGLE_OAUTH_TOKEN_URI") : "https://oauth2.googleapis.com/token";
  int64_t now = (int64_t)time(NULL);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *h = yyjson_mut_obj(d), *c = yyjson_mut_obj(d);
  yyjson_mut_obj_add_str(d, h, "alg", "RS256");
  yyjson_mut_obj_add_str(d, h, "typ", "JWT");
  if (g->key_id && *g->key_id) yyjson_mut_obj_add_str(d, h, "kid", g->key_id);
  yyjson_mut_obj_add_str(d, c, "iss", g->email);
  yyjson_mut_obj_add_str(d, c, "scope", g->scopes);
  yyjson_mut_obj_add_str(d, c, "aud", aud);
  yyjson_mut_obj_add_int(d, c, "iat", now);
  yyjson_mut_obj_add_int(d, c, "exp", now + 3600);
  char *hj = yyjson_mut_val_write(h, 0, NULL), *cj = yyjson_mut_val_write(c, 0, NULL);
  yyjson_mut_doc_free(d);
  buckets_buf jwt = BUCKETS_BUF_INIT;
  b64url(&jwt, hj, strlen(hj));
  buckets_buf_append_char(&jwt, '.');
  b64url(&jwt, cj, strlen(cj));
  free(hj), free(cj);
  buckets_buf sig = BUCKETS_BUF_INIT;
  if (!rs256(g->key_pem, jwt.data, &sig)) {
    buckets_buf_free(&jwt);
    return snprintf(err, errlen, "gcp: the service account's private key cannot be read"), false;
  }
  buckets_buf_append_char(&jwt, '.');
  buckets_buf_append(&jwt, sig.data, sig.len);
  buckets_buf_free(&sig);
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=");
  buckets_buf_append(&body, jwt.data, jwt.len);
  buckets_buf_free(&jwt);
  buckets_http_kv hd[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  bool ok = false;
  if (buckets_fetch("POST", aud, NULL, hd, 1, body.data, body.len, TIMEOUT_MS, &r, e2, sizeof(e2))) {
    ok = take_token(g, &r);
    if (!ok) {
      yyjson_doc *ed = yyjson_read(r.body.data, r.body.len, 0);
      const char *desc = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ed), "error_description"));
      const char *e = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ed), "error"));
      snprintf(err, errlen, "gcp: signing in as %s failed (%d): %s%s%s", g->email, r.status, e ? e : "", desc ? ": " : "", desc ? desc : "");
      yyjson_doc_free(ed);
    }
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "gcp: signing in: %s", e2);
  }
  buckets_buf_free(&body);
  return ok;
}

/* one Secret Manager call (path after the base URL); 0 on transport failure */
static int call(gcp *g, const char *method, const char *path, const char *body, buckets_buf *out, char *err, size_t errlen) {
  pthread_mutex_lock(&g->mu);
  bool stale = !g->token || g->expires - (int64_t)time(NULL) < 300;
  pthread_mutex_unlock(&g->mu);
  if (stale && !sign_in(g, err, errlen)) return -1;
  pthread_mutex_lock(&g->mu);
  buckets_buf auth = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&auth, "Bearer %s", g->token);
  pthread_mutex_unlock(&g->mu);
  buckets_buf url = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&url, "%s%s", g->base_url, path);
  buckets_http_kv h[] = {{"Authorization", auth.data}, {"Content-Type", "application/json"}};
  buckets_http_result r;
  char e2[300];
  int status = 0;
  if (buckets_fetch(method, url.data, NULL, h, body ? 2 : 1, body, body ? strlen(body) : 0, TIMEOUT_MS, &r, e2, sizeof(e2))) {
    status = r.status;
    if (status / 100 != 2) {
      char m[300];
      buckets_kes_error_text(r.body.data, r.body.len, m, sizeof(m));
      snprintf(err, errlen, "gcp: %s (%d)", m, status);
    }
    if (out) buckets_buf_append(out, r.body.data, r.body.len);
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "gcp: %s", e2);
  }
  memset(auth.data, 0, auth.len);
  buckets_buf_free(&auth);
  buckets_buf_free(&url);
  return status;
}

static buckets_kes_status g_status(buckets_kes_store *s, int64_t *lat, char *err, size_t errlen) {
  gcp *g = (gcp *)s;
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_http_result r;
  char e2[300];
  bool ok = buckets_fetch("GET", g->base_url, NULL, NULL, 0, NULL, 0, TIMEOUT_MS, &r, e2, sizeof(e2));
  clock_gettime(CLOCK_MONOTONIC, &t1);
  *lat = (t1.tv_sec - t0.tv_sec) * 1000000 + (t1.tv_nsec - t0.tv_nsec) / 1000;
  if (!ok) return snprintf(err, errlen, "gcp: %s", e2), BUCKETS_KES_UNREACHABLE;
  buckets_http_result_free(&r);
  return BUCKETS_KES_OK;
}

static buckets_kes_status g_create(buckets_kes_store *s, const char *name, const char *value, size_t n, char *err,
                                   size_t errlen) {
  gcp *g = (gcp *)s;
  char path[400];
  snprintf(path, sizeof(path), "/projects/%s/secrets?secretId=%s", g->project, name);
  int st = call(g, "POST", path, "{\"replication\":{\"automatic\":{}}}", NULL, err, errlen);
  if (st == 409) return BUCKETS_KES_EXISTS;
  if (st != 200) return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
  char *b64 = buckets_xmalloc(n * 4 / 3 + 8);
  buckets_base64_encode((const uint8_t *)value, n, b64);
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&body, "{\"payload\":{\"data\":\"%s\"}}", b64);
  memset(b64, 0, strlen(b64));
  free(b64);
  snprintf(path, sizeof(path), "/projects/%s/secrets/%s:addVersion", g->project, name);
  st = call(g, "POST", path, body.data, NULL, err, errlen);
  memset(body.data, 0, body.len);
  buckets_buf_free(&body);
  if (st == 200) return BUCKETS_KES_OK;
  return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
}

static buckets_kes_status g_get(buckets_kes_store *s, const char *name, buckets_buf *value, char *err, size_t errlen) {
  gcp *g = (gcp *)s;
  char path[400];
  snprintf(path, sizeof(path), "/projects/%s/secrets/%s/versions/1:access", g->project, name);
  buckets_buf out = BUCKETS_BUF_INIT;
  int st = call(g, "GET", path, NULL, &out, err, errlen);
  buckets_kes_status ret = st == 404 ? BUCKETS_KES_NOT_FOUND : st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
  if (st == 200) {
    yyjson_doc *d = yyjson_read(out.data, out.len, 0);
    const char *data = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(d), "payload"), "data"));
    if (data) {
      size_t dl = strlen(data);
      buckets_buf_reserve(value, dl);
      long dn = buckets_base64_decode(data, dl, (uint8_t *)value->data + value->len);
      if (dn >= 0) value->len += (size_t)dn, ret = BUCKETS_KES_OK;
    }
    if (ret != BUCKETS_KES_OK) snprintf(err, errlen, "gcp: failed to read '%s': no payload", name);
    yyjson_doc_free(d);
  }
  if (out.data) memset(out.data, 0, out.len);
  buckets_buf_free(&out);
  return ret;
}

static buckets_kes_status g_del(buckets_kes_store *s, const char *name, char *err, size_t errlen) {
  gcp *g = (gcp *)s;
  char path[400];
  snprintf(path, sizeof(path), "/projects/%s/secrets/%s", g->project, name);
  int st = call(g, "DELETE", path, NULL, NULL, err, errlen);
  if (st == 200) return BUCKETS_KES_OK;
  if (st == 404) return BUCKETS_KES_NOT_FOUND;
  return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
}

static buckets_kes_status g_list(buckets_kes_store *s, char ***names, size_t *n, char *err, size_t errlen) {
  gcp *g = (gcp *)s;
  *names = NULL, *n = 0;
  size_t cap = 0;
  char token[512] = "";
  for (int page = 0; page < 10000; page++) {
    char path[1024];
    snprintf(path, sizeof(path), "/projects/%s/secrets?pageSize=250%s%s", g->project, *token ? "&pageToken=" : "", token);
    buckets_buf out = BUCKETS_BUF_INIT;
    int st = call(g, "GET", path, NULL, &out, err, errlen);
    if (st != 200) {
      buckets_buf_free(&out);
      return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
    }
    yyjson_doc *d = yyjson_read(out.data, out.len, 0);
    yyjson_val *o = yyjson_doc_get_root(d);
    size_t i, max;
    yyjson_val *v;
    yyjson_arr_foreach(yyjson_obj_get(o, "secrets"), i, max, v) {
      const char *full = yyjson_get_str(yyjson_obj_get(v, "name"));
      const char *nm = full && strrchr(full, '/') ? strrchr(full, '/') + 1 : full;
      if (!nm || !buckets_kes_valid_name(nm)) continue;
      if (*n == cap) *names = buckets_xrealloc(*names, (cap = cap ? 2 * cap : 32) * sizeof(char *));
      (*names)[(*n)++] = buckets_xstrdup(nm);
    }
    const char *nt = yyjson_get_str(yyjson_obj_get(o, "nextPageToken"));
    token[0] = '\0';
    if (nt && *nt) {
      buckets_buf enc = BUCKETS_BUF_INIT;
      buckets_url_encode(&enc, nt, false);
      snprintf(token, sizeof(token), "%s", enc.data);
      buckets_buf_free(&enc);
    }
    yyjson_doc_free(d);
    buckets_buf_free(&out);
    if (!*token) break;
  }
  return BUCKETS_KES_OK;
}

static void g_close(buckets_kes_store *s) {
  gcp *g = (gcp *)s;
  if (g->key_pem) memset(g->key_pem, 0, strlen(g->key_pem));
  if (g->token) memset(g->token, 0, strlen(g->token));
  free(g->project), free(g->email), free(g->key_id), free(g->key_pem), free(g->scopes), free(g->token);
  pthread_mutex_destroy(&g->mu);
  free(g);
}

static const buckets_kes_store_ops gcp_ops = {g_status, g_create, g_get, g_del, g_list, g_close};

buckets_kes_store *buckets_kes_gcp_open(yyjson_val *c, char *err, size_t errlen) {
  const char *project = buckets_kes_conf_str(c, "project_id");
  if (!project || !*project) return snprintf(err, errlen, "kesconf: invalid GCP secretmanager keystore: no project ID specified"), NULL;
  gcp *g = buckets_xcalloc(1, sizeof(*g));
  g->base.ops = &gcp_ops;
  pthread_mutex_init(&g->mu, NULL);
  g->project = buckets_xstrdup(project);
  /* endpoint: KES's is gRPC's host:port; REST takes the same host */
  const char *ep = buckets_kes_conf_str(c, "endpoint");
  if (!ep || !*ep) snprintf(g->base_url, sizeof(g->base_url), "https://secretmanager.googleapis.com/v1");
  else if (strstr(ep, "://")) snprintf(g->base_url, sizeof(g->base_url), "%.280s/v1", ep);
  else {
    char host[256];
    snprintf(host, sizeof(host), "%s", ep);
    size_t hl = strlen(host);
    if (hl > 4 && strcmp(host + hl - 4, ":443") == 0) host[hl - 4] = '\0';
    snprintf(g->base_url, sizeof(g->base_url), "https://%s/v1", host);
  }
  snprintf(g->base.desc, sizeof(g->base.desc), "GCP SecretManager: Project: %.200s", project);
  /* scopes: the configuration's, space-separated in the token request */
  buckets_buf sc = BUCKETS_BUF_INIT;
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(yyjson_obj_get(c, "scopes"), i, max, v) {
    if (yyjson_get_str(v) && *yyjson_get_str(v)) buckets_buf_appendf(&sc, "%s%s", sc.len ? " " : "", yyjson_get_str(v));
  }
  g->scopes = sc.data ? sc.data : buckets_xstrdup("https://www.googleapis.com/auth/cloud-platform");
  const char *email = buckets_kes_conf_str(c, "credentials.client_email"), *key = buckets_kes_conf_str(c, "credentials.private_key");
  if (email && *email && key && *key) {
    g->email = buckets_xstrdup(email);
    g->key_pem = buckets_xstrdup(key);
    const char *kid = buckets_kes_conf_str(c, "credentials.private_key_id");
    g->key_id = kid && *kid ? buckets_xstrdup(kid) : NULL;
  }
  int64_t lat;
  if (g_status(&g->base, &lat, err, errlen) != BUCKETS_KES_OK || !sign_in(g, err, errlen)) {
    g_close(&g->base);
    return NULL;
  }
  return &g->base;
}
