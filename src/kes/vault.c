/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* HashiCorp Vault, as MinIO KES uses it: a KV engine (v1 or v2) holding each
 * key at <engine>[/data]/<prefix>/<name> as {<name>: <value>} (read at
 * version 1, created with cas=0 so nothing is ever overwritten), the value
 * optionally wrapped by a Transit key ("vault:v1:..."); AppRole or
 * Kubernetes sign-in, the token renewed in the background. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
#include "crypto/base64.h"
#include "kes/store.h"
#include "net/fetch.h"

#define TIMEOUT_MS 15000

typedef struct {
  buckets_kes_store base;
  char *endpoint, *engine, *prefix, *ns, *ca;
  bool v2;
  /* sign-in */
  bool approle;
  char *auth_engine, *auth_ns, *role_id, *secret_id, *role, *jwt;
  char *transit_engine, *transit_key;
  /* state */
  pthread_mutex_t mu;
  char *token;
  int64_t ttl; /* seconds; 0: does not expire */
  bool renewable, sealed;
  pthread_t bg;
  volatile bool stop;
} vault;

static char *dupz(const char *s) { return s && *s ? buckets_xstrdup(s) : NULL; }

/* one request; status 0 on a transport failure (err says why) */
static int call(vault *v, const char *method, const char *path, const char *body, bool with_ns, bool with_token,
                buckets_buf *out, char *err, size_t errlen) {
  buckets_buf url = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&url, "%s/v1/%s", v->endpoint, path);
  buckets_http_kv h[4];
  size_t nh = 0;
  char *tok = NULL;
  if (with_token) {
    pthread_mutex_lock(&v->mu);
    tok = v->token ? buckets_xstrdup(v->token) : NULL;
    pthread_mutex_unlock(&v->mu);
    if (tok) h[nh++] = (buckets_http_kv){"X-Vault-Token", tok};
  }
  const char *ns = with_ns ? v->ns : NULL;
  if (ns) h[nh++] = (buckets_http_kv){"X-Vault-Namespace", ns};
  if (body) h[nh++] = (buckets_http_kv){"Content-Type", "application/json"};
  buckets_http_result r;
  char e2[300];
  int status = 0;
  if (buckets_fetch(method, url.data, v->ca, h, nh, body, body ? strlen(body) : 0, TIMEOUT_MS, &r, e2, sizeof(e2))) {
    status = r.status;
    if (out) buckets_buf_append(out, r.body.data, r.body.len);
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "%s %s: %s", method, url.data, e2);
  }
  free(tok);
  buckets_buf_free(&url);
  return status;
}

/* "vault: ...: <what Vault said> (<status>)" */
static void vault_err(char *err, size_t errlen, const char *what, int status, const buckets_buf *body) {
  char m[400];
  buckets_kes_error_text(body->data, body->len, m, sizeof(m));
  snprintf(err, errlen, "vault: %s: %s%s(%d)", what, m, *m ? " " : "", status);
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

/* Signs in; false and why. */
static bool login(vault *v, char *err, size_t errlen) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  char *jwt = NULL;
  if (v->approle) {
    yyjson_mut_obj_add_str(d, o, "role_id", v->role_id);
    yyjson_mut_obj_add_str(d, o, "secret_id", v->secret_id);
  } else {
    /* a path is read at every sign-in: projected service account tokens rotate */
    jwt = strchr(v->jwt, '/') ? read_file(v->jwt) : buckets_xstrdup(v->jwt);
    if (!jwt) {
      yyjson_mut_doc_free(d);
      snprintf(err, errlen, "vault: failed to read the Kubernetes JWT from '%s'", v->jwt);
      return false;
    }
    yyjson_mut_obj_add_str(d, o, "role", v->role);
    yyjson_mut_obj_add_str(d, o, "jwt", jwt);
  }
  char *body = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  char path[300];
  snprintf(path, sizeof(path), "auth/%s/login", v->auth_engine);
  /* the sign-in's namespace: its own, "/" for the root, else the key store's */
  char *saved_ns = v->ns;
  if (v->auth_ns) v->ns = strcmp(v->auth_ns, "/") == 0 ? NULL : v->auth_ns;
  buckets_buf out = BUCKETS_BUF_INIT;
  int st = call(v, "PUT", path, body, true, false, &out, err, errlen);
  v->ns = saved_ns;
  memset(body, 0, strlen(body));
  free(body);
  if (jwt) memset(jwt, 0, strlen(jwt)), free(jwt);
  bool ok = false;
  if (st == 200) {
    yyjson_doc *r = yyjson_read(out.data, out.len, 0);
    yyjson_val *auth = yyjson_obj_get(yyjson_doc_get_root(r), "auth");
    const char *tok = yyjson_get_str(yyjson_obj_get(auth, "client_token"));
    if (tok) {
      pthread_mutex_lock(&v->mu);
      free(v->token);
      v->token = buckets_xstrdup(tok);
      v->ttl = yyjson_get_sint(yyjson_obj_get(auth, "lease_duration"));
      v->renewable = yyjson_get_bool(yyjson_obj_get(auth, "renewable"));
      pthread_mutex_unlock(&v->mu);
      ok = true;
    } else {
      snprintf(err, errlen, "vault: authentication failed: Vault returned no token");
    }
    yyjson_doc_free(r);
  } else if (st) {
    char m[400];
    buckets_kes_error_text(out.data, out.len, m, sizeof(m));
    snprintf(err, errlen, "Error making API request. URL: PUT %s/v1/%s Code: %d. Errors: * %s", v->endpoint, path, st, m);
  }
  buckets_buf_free(&out);
  return ok;
}

static bool renew(vault *v) {
  buckets_buf out = BUCKETS_BUF_INIT;
  char err[300];
  bool ok = false;
  for (int i = 0; i < 3 && !ok; i++) {
    buckets_buf_reset(&out);
    if (call(v, "PUT", "auth/token/renew-self", "{}", true, true, &out, err, sizeof(err)) != 200) continue;
    yyjson_doc *r = yyjson_read(out.data, out.len, 0);
    yyjson_val *auth = yyjson_obj_get(yyjson_doc_get_root(r), "auth");
    const char *tok = yyjson_get_str(yyjson_obj_get(auth, "client_token"));
    if (tok) {
      pthread_mutex_lock(&v->mu);
      free(v->token);
      v->token = buckets_xstrdup(tok);
      v->ttl = yyjson_get_sint(yyjson_obj_get(auth, "lease_duration"));
      v->renewable = yyjson_get_bool(yyjson_obj_get(auth, "renewable"));
      pthread_mutex_unlock(&v->mu);
      ok = true;
    }
    yyjson_doc_free(r);
  }
  buckets_buf_free(&out);
  return ok;
}

/* sys/health (no namespace): 200 active, 429/472/473 standbys, 501 not initialized, 503 sealed */
static buckets_kes_status health(vault *v, char *err, size_t errlen) {
  buckets_buf out = BUCKETS_BUF_INIT;
  int st = call(v, "GET", "sys/health", NULL, false, false, &out, err, errlen);
  buckets_buf_free(&out);
  if (st == 0) return BUCKETS_KES_UNREACHABLE;
  if (st == 503) return snprintf(err, errlen, "vault: key store is sealed"), BUCKETS_KES_UNREACHABLE;
  if (st == 501) return snprintf(err, errlen, "vault: not initialized"), BUCKETS_KES_UNREACHABLE;
  return BUCKETS_KES_OK;
}

static void *background(void *arg) {
  vault *v = arg;
  time_t renew_at = 0, health_at = 0;
  for (;;) {
    for (int i = 0; i < 10 && !v->stop; i++) usleep(100 * 1000);
    if (v->stop) return NULL;
    time_t now = time(NULL);
    if (now >= health_at) {
      char err[300];
      buckets_kes_status hs = health(v, err, sizeof(err));
      pthread_mutex_lock(&v->mu);
      v->sealed = hs == BUCKETS_KES_UNREACHABLE && strstr(err, "sealed");
      pthread_mutex_unlock(&v->mu);
      health_at = now + 10;
    }
    pthread_mutex_lock(&v->mu);
    int64_t ttl = v->ttl;
    bool renewable = v->renewable, sealed = v->sealed;
    pthread_mutex_unlock(&v->mu);
    if (!ttl || sealed) continue;
    if (!renew_at) renew_at = now + (ttl * 80 / 100 > 1 ? ttl * 80 / 100 : 1);
    if (now < renew_at) continue;
    char err[300];
    bool ok = (renewable && renew(v)) || login(v, err, sizeof(err));
    if (!ok) buckets_log_warn("vault: renewing the token failed: %s", err);
    pthread_mutex_lock(&v->mu);
    ttl = v->ttl;
    pthread_mutex_unlock(&v->mu);
    renew_at = ok && ttl ? now + (ttl * 80 / 100 > 1 ? ttl * 80 / 100 : 1) : now + 3;
  }
}

static bool is_sealed(vault *v) {
  pthread_mutex_lock(&v->mu);
  bool s = v->sealed;
  pthread_mutex_unlock(&v->mu);
  return s;
}

static void location(vault *v, const char *kind, const char *name, char *out, size_t cap) {
  /* <engine>/data/<prefix>/<name> (v2), <engine>/<prefix>/<name> (v1); kind "metadata" for v2 deletes and lists */
  snprintf(out, cap, "%s%s%s%s%s%s%s", v->engine, v->v2 ? "/" : "", v->v2 ? kind : "", v->prefix ? "/" : "",
           v->prefix ? v->prefix : "", name ? "/" : "", name ? name : "");
}

/* Transit: wrap and unwrap a stored value */
static bool transit(vault *v, bool encrypt, const char *in, size_t n, buckets_buf *out, char *err, size_t errlen) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  char *b64 = NULL;
  if (encrypt) {
    b64 = buckets_xmalloc(n * 4 / 3 + 8);
    buckets_base64_encode((const uint8_t *)in, n, b64);
    yyjson_mut_obj_add_str(d, o, "plaintext", b64);
  } else {
    yyjson_mut_obj_add_strncpy(d, o, "ciphertext", in, n);
  }
  char *body = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  char path[300];
  snprintf(path, sizeof(path), "%s/%s/%s", v->transit_engine, encrypt ? "encrypt" : "decrypt", v->transit_key);
  buckets_buf r = BUCKETS_BUF_INIT;
  int st = call(v, "PUT", path, body, true, true, &r, err, errlen);
  memset(body, 0, strlen(body));
  free(body);
  free(b64);
  bool ok = false;
  if (st == 200) {
    yyjson_doc *rd = yyjson_read(r.data, r.len, 0);
    yyjson_val *data = yyjson_obj_get(yyjson_doc_get_root(rd), "data");
    const char *v2 = yyjson_get_str(yyjson_obj_get(data, encrypt ? "ciphertext" : "plaintext"));
    if (v2 && encrypt && strncmp(v2, "vault:v1:", 9) == 0) {
      buckets_buf_append_c(out, v2);
      ok = true;
    } else if (v2 && !encrypt) {
      size_t vl = strlen(v2);
      buckets_buf_reserve(out, vl);
      long dn = buckets_base64_decode(v2, vl, (uint8_t *)out->data + out->len);
      if (dn >= 0) out->len += (size_t)dn, ok = true;
    }
    if (!ok) snprintf(err, errlen, "vault: failed to %s key: invalid vault response", encrypt ? "encrypt" : "decrypt");
    yyjson_doc_free(rd);
  } else if (st) {
    vault_err(err, errlen, encrypt ? "failed to encrypt key" : "failed to decrypt key", st, &r);
  }
  buckets_buf_free(&r);
  return ok;
}

static buckets_kes_status v_status(buckets_kes_store *s, int64_t *lat, char *err, size_t errlen) {
  struct timespec a, b;
  clock_gettime(CLOCK_MONOTONIC, &a);
  buckets_kes_status st = health((vault *)s, err, errlen);
  clock_gettime(CLOCK_MONOTONIC, &b);
  *lat = (b.tv_sec - a.tv_sec) * 1000000 + (b.tv_nsec - a.tv_nsec) / 1000;
  return st;
}

/* The value at a location: NOT_FOUND, or the string under name */
static buckets_kes_status read_value(vault *v, const char *name, buckets_buf *value, char *err, size_t errlen) {
  char loc[600], path[700];
  location(v, "data", name, loc, sizeof(loc));
  snprintf(path, sizeof(path), "%s%s", loc, v->v2 ? "?version=1" : "");
  buckets_buf r = BUCKETS_BUF_INIT;
  int st = call(v, "GET", path, NULL, true, true, &r, err, errlen);
  buckets_kes_status out = BUCKETS_KES_FAILED;
  if (st == 404) {
    out = BUCKETS_KES_NOT_FOUND;
  } else if (st == 200) {
    yyjson_doc *d = yyjson_read(r.data, r.len, 0);
    yyjson_val *data = yyjson_obj_get(yyjson_doc_get_root(d), "data");
    if (v->v2) {
      yyjson_val *meta = yyjson_obj_get(data, "metadata");
      data = yyjson_obj_get(data, "data");
      /* a deleted (not destroyed) version reads as data: null */
      if (!yyjson_is_obj(data) && yyjson_get_str(yyjson_obj_get(meta, "deletion_time")) &&
          *yyjson_get_str(yyjson_obj_get(meta, "deletion_time")))
        out = BUCKETS_KES_NOT_FOUND;
    }
    const char *val = yyjson_get_str(yyjson_obj_get(data, name));
    if (val) {
      buckets_buf_append_c(value, val);
      out = BUCKETS_KES_OK;
    } else if (out != BUCKETS_KES_NOT_FOUND) {
      snprintf(err, errlen, "vault: failed to read '%s': entry exists but no secret key is present", loc);
    }
    yyjson_doc_free(d);
  } else if (st) {
    vault_err(err, errlen, "failed to read key", st, &r);
    if (st == 503) out = BUCKETS_KES_UNREACHABLE;
  } else {
    out = BUCKETS_KES_UNREACHABLE;
  }
  buckets_buf_free(&r);
  return out;
}

static buckets_kes_status v_get(buckets_kes_store *s, const char *name, buckets_buf *value, char *err, size_t errlen) {
  vault *v = (vault *)s;
  if (is_sealed(v)) return snprintf(err, errlen, "vault: key store is sealed"), BUCKETS_KES_UNREACHABLE;
  buckets_buf raw = BUCKETS_BUF_INIT;
  buckets_kes_status st = read_value(v, name, &raw, err, errlen);
  if (st == BUCKETS_KES_OK && raw.len > 9 && strncmp(raw.data, "vault:v1:", 9) == 0) {
    if (!v->transit_key) {
      snprintf(err, errlen, "vault: failed to read '%s': key is encrypted with vault transit key", name);
      st = BUCKETS_KES_FAILED;
    } else if (!transit(v, false, raw.data, raw.len, value, err, errlen)) {
      st = BUCKETS_KES_FAILED;
    }
  } else if (st == BUCKETS_KES_OK) {
    buckets_buf_append(value, raw.data, raw.len);
  }
  if (raw.data) memset(raw.data, 0, raw.len);
  buckets_buf_free(&raw);
  return st;
}

static buckets_kes_status v_create(buckets_kes_store *s, const char *name, const char *value, size_t n, char *err,
                                   size_t errlen) {
  vault *v = (vault *)s;
  if (is_sealed(v)) return snprintf(err, errlen, "vault: key store is sealed"), BUCKETS_KES_UNREACHABLE;
  buckets_buf existing = BUCKETS_BUF_INIT;
  buckets_kes_status st = read_value(v, name, &existing, err, errlen);
  buckets_buf_free(&existing);
  if (st == BUCKETS_KES_OK) return BUCKETS_KES_EXISTS;
  if (st != BUCKETS_KES_NOT_FOUND) return st;
  buckets_buf wrapped = BUCKETS_BUF_INIT;
  if (v->transit_key) {
    if (!transit(v, true, value, n, &wrapped, err, errlen)) return BUCKETS_KES_FAILED;
    value = wrapped.data, n = wrapped.len;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d), *data = o;
  yyjson_mut_doc_set_root(d, o);
  if (v->v2) {
    yyjson_mut_obj_add_int(d, yyjson_mut_obj_add_obj(d, o, "options"), "cas", 0); /* atomic: never overwrite */
    data = yyjson_mut_obj_add_obj(d, o, "data");
  }
  yyjson_mut_obj_add(data, yyjson_mut_strcpy(d, name), yyjson_mut_strncpy(d, value, n));
  char *body = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  char loc[600];
  location(v, "data", name, loc, sizeof(loc));
  buckets_buf r = BUCKETS_BUF_INIT;
  int code = call(v, "PUT", loc, body, true, true, &r, err, errlen);
  memset(body, 0, strlen(body));
  free(body);
  buckets_buf_free(&wrapped);
  st = BUCKETS_KES_OK;
  if (code == 400 && r.len && memmem(r.data, r.len, "check-and-set", 13)) st = BUCKETS_KES_EXISTS;
  else if (code != 200 && code != 204) {
    if (code) vault_err(err, errlen, "failed to create key", code, &r);
    st = code ? BUCKETS_KES_FAILED : BUCKETS_KES_UNREACHABLE;
  }
  buckets_buf_free(&r);
  return st;
}

static buckets_kes_status v_del(buckets_kes_store *s, const char *name, char *err, size_t errlen) {
  vault *v = (vault *)s;
  if (is_sealed(v)) return snprintf(err, errlen, "vault: key store is sealed"), BUCKETS_KES_UNREACHABLE;
  buckets_buf existing = BUCKETS_BUF_INIT;
  buckets_kes_status st = read_value(v, name, &existing, err, errlen);
  buckets_buf_free(&existing);
  if (st != BUCKETS_KES_OK) return st;
  char loc[600];
  location(v, "metadata", name, loc, sizeof(loc)); /* v2: every version goes */
  buckets_buf r = BUCKETS_BUF_INIT;
  int code = call(v, "DELETE", loc, NULL, true, true, &r, err, errlen);
  st = BUCKETS_KES_OK;
  if (code != 200 && code != 204) {
    if (code) vault_err(err, errlen, "failed to delete key", code, &r);
    st = code ? BUCKETS_KES_FAILED : BUCKETS_KES_UNREACHABLE;
  }
  buckets_buf_free(&r);
  return st;
}

static buckets_kes_status v_list(buckets_kes_store *s, char ***names, size_t *n, char *err, size_t errlen) {
  vault *v = (vault *)s;
  *names = NULL, *n = 0;
  if (is_sealed(v)) return snprintf(err, errlen, "vault: key store is sealed"), BUCKETS_KES_UNREACHABLE;
  char loc[600], path[700];
  location(v, "metadata", NULL, loc, sizeof(loc));
  snprintf(path, sizeof(path), "%s?list=true", loc);
  buckets_buf r = BUCKETS_BUF_INIT;
  int code = call(v, "GET", path, NULL, true, true, &r, err, errlen);
  buckets_kes_status st = BUCKETS_KES_OK;
  if (code == 200) {
    yyjson_doc *d = yyjson_read(r.data, r.len, 0);
    yyjson_val *keys = yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(d), "data"), "keys");
    size_t i, max;
    yyjson_val *k;
    *names = buckets_xcalloc(yyjson_arr_size(keys) + 1, sizeof(char *));
    yyjson_arr_foreach(keys, i, max, k) {
      const char *name = yyjson_get_str(k);
      if (name && !strchr(name, '/')) (*names)[(*n)++] = buckets_xstrdup(name); /* "x/": a folder, not a key */
    }
    yyjson_doc_free(d);
  } else if (code != 404) { /* 404: nothing there yet */
    if (code) vault_err(err, errlen, "failed to list keys", code, &r);
    st = code ? BUCKETS_KES_FAILED : BUCKETS_KES_UNREACHABLE;
  }
  buckets_buf_free(&r);
  return st;
}

static void free_fields(vault *v) {
  char **secrets[] = {&v->secret_id, &v->token, &v->jwt};
  for (size_t i = 0; i < 3; i++)
    if (*secrets[i]) memset(*secrets[i], 0, strlen(*secrets[i]));
  char *all[] = {v->endpoint,  v->engine, v->prefix, v->ns,    v->ca,          v->auth_engine, v->auth_ns,
                 v->role_id,   v->secret_id, v->role, v->jwt, v->transit_engine, v->transit_key, v->token};
  for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) free(all[i]);
  free(v);
}

static void v_close(buckets_kes_store *s) {
  vault *v = (vault *)s;
  v->stop = true;
  pthread_join(v->bg, NULL);
  pthread_mutex_destroy(&v->mu);
  free_fields(v);
}

static const buckets_kes_store_ops vault_ops = {v_status, v_create, v_get, v_del, v_list, v_close};

buckets_kes_store *buckets_kes_vault_open(yyjson_val *c, char *err, size_t errlen) {
  const char *ep = buckets_kes_conf_str(c, "endpoint");
  if (!ep || !*ep) return snprintf(err, errlen, "kesconf: invalid vault keystore: no endpoint specified"), NULL;
  const char *version = buckets_kes_conf_str(c, "version");
  if (version && *version && strcmp(version, "v1") != 0 && strcmp(version, "v2") != 0)
    return snprintf(err, errlen, "vault: invalid engine API version '%s'", version), NULL;
  yyjson_val *ar = yyjson_obj_get(c, "approle"), *k8s = yyjson_obj_get(c, "kubernetes");
  bool has_ar = ar && (buckets_kes_conf_str(ar, "id") || buckets_kes_conf_str(ar, "secret"));
  bool has_k8s = k8s && (buckets_kes_conf_str(k8s, "role") || buckets_kes_conf_str(k8s, "jwt"));
  if (!has_ar && !has_k8s) return snprintf(err, errlen, "kesconf: invalid vault keystore: no authentication method specified"), NULL;
  if (has_ar && has_k8s)
    return snprintf(err, errlen, "kesconf: invalid vault keystore: more than one authentication method specified"), NULL;
  if (buckets_kes_conf_str(c, "tls.key") || buckets_kes_conf_str(c, "tls.cert"))
    return snprintf(err, errlen, "vault: client certificates (tls.key, tls.cert) are not supported by buckets-kes"), NULL;
  vault *v = buckets_xcalloc(1, sizeof(*v));
  v->base.ops = &vault_ops;
  snprintf(v->base.desc, sizeof(v->base.desc), "Hashicorp Vault: %s", ep);
  v->endpoint = buckets_xstrdup(ep);
  while (strlen(v->endpoint) && v->endpoint[strlen(v->endpoint) - 1] == '/') v->endpoint[strlen(v->endpoint) - 1] = '\0';
  /* KES's defaults: the "kv" engine, API v1 */
  v->engine = buckets_xstrdup(buckets_kes_conf_str(c, "engine") && *buckets_kes_conf_str(c, "engine") ? buckets_kes_conf_str(c, "engine") : "kv");
  v->v2 = version && strcmp(version, "v2") == 0;
  const char *prefix = buckets_kes_conf_str(c, "prefix");
  if (prefix) {
    while (*prefix == '/') prefix++;
    v->prefix = dupz(prefix);
    if (v->prefix)
      while (strlen(v->prefix) && v->prefix[strlen(v->prefix) - 1] == '/') v->prefix[strlen(v->prefix) - 1] = '\0';
    if (v->prefix && !*v->prefix) free(v->prefix), v->prefix = NULL;
  }
  v->ns = dupz(buckets_kes_conf_str(c, "namespace"));
  v->ca = dupz(buckets_kes_conf_str(c, "tls.ca"));
  v->approle = has_ar;
  if (has_ar) {
    v->auth_engine = buckets_xstrdup(buckets_kes_conf_str(ar, "engine") && *buckets_kes_conf_str(ar, "engine") ? buckets_kes_conf_str(ar, "engine") : "approle");
    v->auth_ns = dupz(buckets_kes_conf_str(ar, "namespace"));
    v->role_id = buckets_xstrdup(buckets_kes_conf_str(ar, "id") ? buckets_kes_conf_str(ar, "id") : "");
    v->secret_id = buckets_xstrdup(buckets_kes_conf_str(ar, "secret") ? buckets_kes_conf_str(ar, "secret") : "");
  } else {
    v->auth_engine = buckets_xstrdup(buckets_kes_conf_str(k8s, "engine") && *buckets_kes_conf_str(k8s, "engine") ? buckets_kes_conf_str(k8s, "engine") : "kubernetes");
    v->auth_ns = dupz(buckets_kes_conf_str(k8s, "namespace"));
    v->role = buckets_xstrdup(buckets_kes_conf_str(k8s, "role") ? buckets_kes_conf_str(k8s, "role") : "");
    v->jwt = buckets_xstrdup(buckets_kes_conf_str(k8s, "jwt") ? buckets_kes_conf_str(k8s, "jwt") : "");
  }
  yyjson_val *tr = yyjson_obj_get(c, "transit");
  if (tr) {
    const char *key = buckets_kes_conf_str(tr, "key");
    if (!key || !*key) {
      free_fields(v);
      return snprintf(err, errlen, "vault: transit key name is empty"), NULL;
    }
    v->transit_key = buckets_xstrdup(key);
    v->transit_engine = buckets_xstrdup(buckets_kes_conf_str(tr, "engine") && *buckets_kes_conf_str(tr, "engine") ? buckets_kes_conf_str(tr, "engine") : "transit");
  }
  pthread_mutex_init(&v->mu, NULL);
  if (!login(v, err, errlen)) {
    pthread_mutex_destroy(&v->mu);
    free_fields(v);
    return NULL;
  }
  pthread_create(&v->bg, NULL, background, v);
  return &v->base;
}
