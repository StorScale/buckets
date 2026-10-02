/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Azure Key Vault, as MinIO KES uses it: a secret per key, named after it,
 * whose first (oldest) version holds the stored key; creating purges a
 * soft-deleted secret of the same name, deleting deletes and then purges.
 * Sign-in: a service principal's client secret, or a managed identity --
 * AKS workload identity (a federated token) when its environment is there,
 * else the instance metadata service. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
#include "kes/store.h"
#include "net/fetch.h"

#define TIMEOUT_MS 15000
#define API "api-version=7.4"

typedef struct {
  buckets_kes_store base;
  char *endpoint; /* https://name.vault.azure.net, no trailing slash */
  char scope[160];
  char *tenant, *client, *secret; /* client secret sign-in */
  char *mi_client;                /* managed identity's client ID */
  bool managed;
  pthread_mutex_t mu;
  char *token;
  int64_t expires;
} azure;

static const char *env(const char *n) {
  const char *v = getenv(n);
  return v && *v ? v : NULL;
}

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

static void form(buckets_buf *b, const char *k, const char *v) {
  if (b->len) buckets_buf_append_char(b, '&');
  buckets_url_encode(b, k, false);
  buckets_buf_append_char(b, '=');
  buckets_url_encode(b, v, false);
}

/* {"access_token", "expires_in"} (a number, or a string from IMDS) */
static bool take_token(azure *a, const buckets_http_result *r) {
  yyjson_doc *d = yyjson_read(r->body.data, r->body.len, 0);
  yyjson_val *o = yyjson_doc_get_root(d);
  const char *tok = yyjson_get_str(yyjson_obj_get(o, "access_token"));
  yyjson_val *ein = yyjson_obj_get(o, "expires_in");
  int64_t exp = yyjson_is_str(ein) ? atoll(yyjson_get_str(ein)) : yyjson_get_sint(ein);
  bool ok = r->status == 200 && tok;
  if (ok) {
    pthread_mutex_lock(&a->mu);
    free(a->token);
    a->token = buckets_xstrdup(tok);
    a->expires = (int64_t)time(NULL) + (exp > 0 ? exp : 3600);
    pthread_mutex_unlock(&a->mu);
  }
  yyjson_doc_free(d);
  return ok;
}

static bool sign_in(azure *a, char *err, size_t errlen) {
  const char *authority = env("AZURE_AUTHORITY_HOST") ? env("AZURE_AUTHORITY_HOST") : "https://login.microsoftonline.com";
  buckets_buf url = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_http_kv h[2];
  size_t nh = 0;
  const char *method = "POST";
  char *assertion = NULL;
  if (!a->managed) {
    buckets_buf_appendf(&url, "%s%s%s/oauth2/v2.0/token", authority, authority[strlen(authority) - 1] == '/' ? "" : "/", a->tenant);
    form(&body, "grant_type", "client_credentials");
    form(&body, "client_id", a->client);
    form(&body, "client_secret", a->secret);
    form(&body, "scope", a->scope);
    h[nh++] = (buckets_http_kv){"Content-Type", "application/x-www-form-urlencoded"};
  } else if (env("AZURE_FEDERATED_TOKEN_FILE") && env("AZURE_TENANT_ID")) {
    /* AKS workload identity: the projected service account token, exchanged */
    assertion = read_file(env("AZURE_FEDERATED_TOKEN_FILE"));
    if (!assertion) {
      snprintf(err, errlen, "azure: cannot read the federated token %s", env("AZURE_FEDERATED_TOKEN_FILE"));
      return false;
    }
    buckets_buf_appendf(&url, "%s%s%s/oauth2/v2.0/token", authority, authority[strlen(authority) - 1] == '/' ? "" : "/",
                        env("AZURE_TENANT_ID"));
    form(&body, "grant_type", "client_credentials");
    form(&body, "client_id", a->mi_client ? a->mi_client : env("AZURE_CLIENT_ID") ? env("AZURE_CLIENT_ID") : "");
    form(&body, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    form(&body, "client_assertion", assertion);
    form(&body, "scope", a->scope);
    h[nh++] = (buckets_http_kv){"Content-Type", "application/x-www-form-urlencoded"};
  } else {
    /* the instance metadata service */
    method = "GET";
    char resource[160];
    snprintf(resource, sizeof(resource), "%.*s", (int)(strlen(a->scope) - strlen("/.default")), a->scope);
    buckets_buf_appendf(&url, "%s/metadata/identity/oauth2/token?api-version=2018-02-01&resource=",
                        env("AZURE_IMDS_ENDPOINT") ? env("AZURE_IMDS_ENDPOINT") : "http://169.254.169.254");
    buckets_url_encode(&url, resource, false);
    if (a->mi_client) {
      buckets_buf_append_c(&url, "&client_id=");
      buckets_url_encode(&url, a->mi_client, false);
    }
    h[nh++] = (buckets_http_kv){"Metadata", "true"};
  }
  buckets_http_result r;
  char e2[300];
  bool ok = false;
  if (buckets_fetch(method, url.data, NULL, h, nh, body.data, body.len, TIMEOUT_MS, &r, e2, sizeof(e2))) {
    ok = take_token(a, &r);
    if (!ok) {
      char m[300] = "";
      yyjson_doc *d = yyjson_read(r.body.data, r.body.len, 0);
      const char *desc = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "error_description"));
      snprintf(m, sizeof(m), "%s", desc ? desc : "");
      if (!*m) buckets_kes_error_text(r.body.data, r.body.len, m, sizeof(m));
      yyjson_doc_free(d);
      snprintf(err, errlen, "azure: signing in failed (%d): %s", r.status, m);
    }
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "azure: signing in: %s", e2);
  }
  if (body.data) memset(body.data, 0, body.len);
  buckets_buf_free(&body);
  buckets_buf_free(&url);
  if (assertion) memset(assertion, 0, strlen(assertion)), free(assertion);
  return ok;
}

/* One Key Vault call (path after the endpoint, or an absolute nextLink); 0 on
 * a transport failure. code: the error's inner code (or code). */
static int call(azure *a, const char *method, const char *path, const char *body, buckets_buf *out, char *code,
                size_t ccap, char *err, size_t errlen) {
  *code = '\0';
  pthread_mutex_lock(&a->mu);
  bool stale = !a->token || a->expires - (int64_t)time(NULL) < 300;
  pthread_mutex_unlock(&a->mu);
  if (stale && !sign_in(a, err, errlen)) return -1;
  pthread_mutex_lock(&a->mu);
  buckets_buf auth = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&auth, "Bearer %s", a->token);
  pthread_mutex_unlock(&a->mu);
  buckets_buf url = BUCKETS_BUF_INIT;
  if (strncmp(path, "https://", 8) == 0) buckets_buf_append_c(&url, path);
  else buckets_buf_appendf(&url, "%s%s", a->endpoint, path);
  buckets_http_kv h[] = {{"Authorization", auth.data}, {"Content-Type", "application/json"}};
  buckets_http_result r;
  char e2[300];
  int status = 0;
  if (buckets_fetch(method, url.data, NULL, h, body ? 2 : 1, body, body ? strlen(body) : 0, TIMEOUT_MS, &r, e2, sizeof(e2))) {
    status = r.status;
    if (status / 100 != 2) {
      yyjson_doc *d = yyjson_read(r.body.data, r.body.len, 0);
      yyjson_val *e = yyjson_obj_get(yyjson_doc_get_root(d), "error");
      const char *inner = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(e, "innererror"), "code"));
      const char *c = inner ? inner : yyjson_get_str(yyjson_obj_get(e, "code"));
      snprintf(code, ccap, "%s", c ? c : "");
      char m[300];
      buckets_kes_error_text(r.body.data, r.body.len, m, sizeof(m));
      snprintf(err, errlen, "azure: %s (%s, %d)", m, *code ? code : "error", status);
      yyjson_doc_free(d);
    }
    if (out) buckets_buf_append(out, r.body.data, r.body.len);
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "azure: %s", e2);
  }
  memset(auth.data, 0, auth.len);
  buckets_buf_free(&auth);
  buckets_buf_free(&url);
  return status;
}

static buckets_kes_status z_status(buckets_kes_store *s, int64_t *lat, char *err, size_t errlen) {
  azure *a = (azure *)s;
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_http_result r;
  char e2[300];
  bool ok = buckets_fetch("GET", a->endpoint, NULL, NULL, 0, NULL, 0, TIMEOUT_MS, &r, e2, sizeof(e2));
  clock_gettime(CLOCK_MONOTONIC, &t1);
  *lat = (t1.tv_sec - t0.tv_sec) * 1000000 + (t1.tv_nsec - t0.tv_nsec) / 1000;
  if (!ok) return snprintf(err, errlen, "azure: %s", e2), BUCKETS_KES_UNREACHABLE;
  buckets_http_result_free(&r);
  return BUCKETS_KES_OK;
}

/* purges a deleted secret, waiting while it is still being deleted */
static int purge(azure *a, const char *name, int tries, char *code, size_t ccap, char *err, size_t errlen) {
  char path[300];
  snprintf(path, sizeof(path), "/deletedsecrets/%s?" API, name);
  int st = 0;
  for (int i = 0; i < tries; i++) {
    st = call(a, "DELETE", path, NULL, NULL, code, ccap, err, errlen);
    if (st == 200 || st == 204 || st == 404) return 200;
    if (!(st == 409 && strcmp(code, "ObjectIsBeingDeleted") == 0)) return st;
    usleep((useconds_t)(200000 + rand() % 800000));
  }
  return st;
}

static buckets_kes_status z_create(buckets_kes_store *s, const char *name, const char *value, size_t n, char *err,
                                   size_t errlen) {
  azure *a = (azure *)s;
  char path[300], code[128];
  snprintf(path, sizeof(path), "/secrets/%s?" API, name);
  int st = call(a, "GET", path, NULL, NULL, code, sizeof(code), err, errlen);
  if (st == 200) return BUCKETS_KES_EXISTS;
  if (st != 404) return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_strncpy(d, o, "value", value, n);
  char *body = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  st = call(a, "PUT", path, body, NULL, code, sizeof(code), err, errlen);
  /* Azure says ObjectIsDeletedButRecoverable (or ObjectIsBeingDeleted); emulators word it their own way */
  bool deleted = st == 409 && (strcmp(code, "ObjectIsDeletedButRecoverable") == 0 || strcmp(code, "ObjectIsBeingDeleted") == 0 ||
                               strstr(err, "deleted"));
  if (deleted) {
    /* a deleted secret of that name, recoverable: purged, then created */
    if (purge(a, name, 25, code, sizeof(code), err, errlen) == 200) {
      for (int i = 0; i < 7; i++) {
        st = call(a, "PUT", path, body, NULL, code, sizeof(code), err, errlen);
        if (!(st == 409 && (strcmp(code, "ObjectIsBeingDeleted") == 0 || strcmp(code, "ObjectIsDeletedButRecoverable") == 0)))
          break;
        usleep((useconds_t)(200000 + rand() % 800000));
      }
    }
  }
  memset(body, 0, strlen(body));
  free(body);
  if (st == 200) return BUCKETS_KES_OK;
  if (st == 409 && strcmp(code, "ObjectIsDeletedButRecoverable") == 0)
    snprintf(err, errlen, "azure: failed to create '%s': key already exists but is currently marked as deleted. "
                          "Either restore or purge '%s'", name, name);
  return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
}

static buckets_kes_status z_get(buckets_kes_store *s, const char *name, buckets_buf *value, char *err, size_t errlen) {
  azure *a = (azure *)s;
  char path[400], code[128];
  /* the first version: the one KES created (later ones are not KES's) */
  snprintf(path, sizeof(path), "/secrets/%s/versions?" API "&maxresults=25", name);
  buckets_buf out = BUCKETS_BUF_INIT;
  int st = call(a, "GET", path, NULL, &out, code, sizeof(code), err, errlen);
  if (st == 404) return buckets_buf_free(&out), BUCKETS_KES_NOT_FOUND;
  if (st != 200) return buckets_buf_free(&out), st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
  yyjson_doc *d = yyjson_read(out.data, out.len, 0);
  yyjson_val *o = yyjson_doc_get_root(d);
  if (yyjson_get_str(yyjson_obj_get(o, "nextLink"))) {
    yyjson_doc_free(d);
    buckets_buf_free(&out);
    return snprintf(err, errlen, "azure: failed to get '%s': There are too many versions of %s.", name, name), BUCKETS_KES_FAILED;
  }
  char version[128] = "";
  int64_t oldest = 0;
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(yyjson_obj_get(o, "value"), i, max, v) {
    const char *id = yyjson_get_str(yyjson_obj_get(v, "id"));
    int64_t created = yyjson_get_sint(yyjson_obj_get(yyjson_obj_get(v, "attributes"), "created"));
    if (!id || !strrchr(id, '/')) continue;
    if (!*version || created < oldest) {
      snprintf(version, sizeof(version), "%s", strrchr(id, '/') + 1);
      oldest = created;
    }
  }
  yyjson_doc_free(d);
  buckets_buf_free(&out);
  if (!*version) return BUCKETS_KES_NOT_FOUND;
  snprintf(path, sizeof(path), "/secrets/%s/%s?" API, name, version);
  st = call(a, "GET", path, NULL, &out, code, sizeof(code), err, errlen);
  buckets_kes_status ret = st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
  if (st == 200) {
    d = yyjson_read(out.data, out.len, 0);
    o = yyjson_doc_get_root(d);
    yyjson_val *attr = yyjson_obj_get(o, "attributes");
    yyjson_val *en = yyjson_obj_get(attr, "enabled");
    int64_t nbf = yyjson_get_sint(yyjson_obj_get(attr, "nbf")), exp = yyjson_get_sint(yyjson_obj_get(attr, "exp"));
    int64_t now = (int64_t)time(NULL);
    const char *val = yyjson_get_str(yyjson_obj_get(o, "value"));
    if (en && !yyjson_get_bool(en)) snprintf(err, errlen, "azure: The secret \"%s\" is disabled and cannot be used", name);
    else if (nbf && now < nbf) snprintf(err, errlen, "azure: The secret \"%s\" must not be used yet", name);
    else if (exp && now >= exp) snprintf(err, errlen, "azure: The secret \"%s\" is expired and cannot be used", name);
    else if (val) {
      buckets_buf_append_c(value, val);
      ret = BUCKETS_KES_OK;
    }
    yyjson_doc_free(d);
  } else if (st == 404) {
    ret = BUCKETS_KES_NOT_FOUND;
  }
  if (out.data) memset(out.data, 0, out.len);
  buckets_buf_free(&out);
  return ret;
}

static buckets_kes_status z_del(buckets_kes_store *s, const char *name, char *err, size_t errlen) {
  azure *a = (azure *)s;
  char path[300], code[128];
  snprintf(path, sizeof(path), "/secrets/%s?" API, name);
  int st = call(a, "DELETE", path, NULL, NULL, code, sizeof(code), err, errlen);
  if (st == 404) return BUCKETS_KES_NOT_FOUND;
  if (st != 200) return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
  st = purge(a, name, 10, code, sizeof(code), err, errlen);
  if (st == 200 || (st == 409 && strcmp(code, "ObjectIsBeingDeleted") == 0)) return BUCKETS_KES_OK;
  /* deleted but not purged (purge protection, or no purge permission): gone for KES all the same */
  buckets_log_warn("azure: '%s' is deleted but could not be purged: %s", name, err);
  return BUCKETS_KES_OK;
}

static buckets_kes_status z_list(buckets_kes_store *s, char ***names, size_t *n, char *err, size_t errlen) {
  azure *a = (azure *)s;
  *names = NULL, *n = 0;
  size_t cap = 0;
  char *next = buckets_xstrdup("/secrets?" API "&maxresults=25");
  for (int page = 0; next && page < 10000; page++) {
    buckets_buf out = BUCKETS_BUF_INIT;
    char code[128];
    int st = call(a, "GET", next, NULL, &out, code, sizeof(code), err, errlen);
    free(next), next = NULL;
    if (st != 200) {
      buckets_buf_free(&out);
      return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
    }
    yyjson_doc *d = yyjson_read(out.data, out.len, 0);
    yyjson_val *o = yyjson_doc_get_root(d);
    size_t i, max;
    yyjson_val *v;
    yyjson_arr_foreach(yyjson_obj_get(o, "value"), i, max, v) {
      const char *id = yyjson_get_str(yyjson_obj_get(v, "id"));
      const char *nm = id && strrchr(id, '/') ? strrchr(id, '/') + 1 : NULL;
      if (!nm || !buckets_kes_valid_name(nm)) continue;
      if (*n == cap) *names = buckets_xrealloc(*names, (cap = cap ? 2 * cap : 32) * sizeof(char *));
      (*names)[(*n)++] = buckets_xstrdup(nm);
    }
    const char *nl = yyjson_get_str(yyjson_obj_get(o, "nextLink"));
    if (nl && *nl) next = buckets_xstrdup(nl);
    yyjson_doc_free(d);
    buckets_buf_free(&out);
  }
  free(next);
  return BUCKETS_KES_OK;
}

static void z_close(buckets_kes_store *s) {
  azure *a = (azure *)s;
  if (a->secret) memset(a->secret, 0, strlen(a->secret));
  if (a->token) memset(a->token, 0, strlen(a->token));
  free(a->endpoint), free(a->tenant), free(a->client), free(a->secret), free(a->mi_client), free(a->token);
  pthread_mutex_destroy(&a->mu);
  free(a);
}

static const buckets_kes_store_ops azure_ops = {z_status, z_create, z_get, z_del, z_list, z_close};

buckets_kes_store *buckets_kes_azure_open(yyjson_val *c, char *err, size_t errlen) {
  const char *ep = buckets_kes_conf_str(c, "endpoint");
  if (!ep || !*ep) return snprintf(err, errlen, "kesconf: invalid Azure keyvault keystore: no endpoint specified"), NULL;
  yyjson_val *cred = yyjson_obj_get(c, "credentials"), *mi = yyjson_obj_get(c, "managed_identity");
  if (!cred && !mi) return snprintf(err, errlen, "kesconf: invalid Azure keyvault keystore: no authentication method specified"), NULL;
  if (cred && mi) return snprintf(err, errlen, "kesconf: invalid Azure keyvault keystore: more than one authentication method specified"), NULL;
  azure *a = buckets_xcalloc(1, sizeof(*a));
  a->base.ops = &azure_ops;
  pthread_mutex_init(&a->mu, NULL);
  a->endpoint = buckets_xstrdup(ep);
  while (strlen(a->endpoint) && a->endpoint[strlen(a->endpoint) - 1] == '/') a->endpoint[strlen(a->endpoint) - 1] = '\0';
  snprintf(a->base.desc, sizeof(a->base.desc), "Azure KeyVault: %.250s", a->endpoint);
  /* the token's audience: the vault's DNS suffix (vault.azure.net, vault.azure.cn, ...) */
  const char *host = strstr(a->endpoint, "://") ? strstr(a->endpoint, "://") + 3 : a->endpoint;
  const char *dot = strchr(host, '.');
  if (dot && strncmp(dot + 1, "vault.", 6) == 0) snprintf(a->scope, sizeof(a->scope), "https://%s/.default", dot + 1);
  else snprintf(a->scope, sizeof(a->scope), "https://vault.azure.net/.default");
  if (cred) {
    const char *t = buckets_kes_conf_str(cred, "tenant_id"), *ci = buckets_kes_conf_str(cred, "client_id"),
               *cs = buckets_kes_conf_str(cred, "client_secret");
    if (!t || !*t || !ci || !*ci || !cs || !*cs) {
      z_close(&a->base);
      return snprintf(err, errlen, "kesconf: invalid Azure keyvault keystore: tenant_id, client_id and client_secret are required"), NULL;
    }
    a->tenant = buckets_xstrdup(t), a->client = buckets_xstrdup(ci), a->secret = buckets_xstrdup(cs);
  } else {
    a->managed = true;
    const char *ci = buckets_kes_conf_str(mi, "client_id");
    if (!ci || !*ci) {
      z_close(&a->base);
      return snprintf(err, errlen, "kesconf: invalid Azure keyvault keystore: no client ID specified"), NULL;
    }
    a->mi_client = buckets_xstrdup(ci);
  }
  int64_t lat;
  if (z_status(&a->base, &lat, err, errlen) != BUCKETS_KES_OK || !sign_in(a, err, errlen)) {
    z_close(&a->base);
    return NULL;
  }
  return &a->base;
}
