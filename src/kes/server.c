/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "kes/server.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "core/log.h"
#include "core/timefmt.h"
#include "core/yaml.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "kes/key.h"

#ifndef BUCKETS_VERSION
#define BUCKETS_VERSION "dev"
#endif
#ifndef BUCKETS_COMMIT
#define BUCKETS_COMMIT ""
#endif

#define MAX_BODY 1000000 /* KES's mem.MB */

/* ---- configuration ------------------------------------------------------------------ */

/* ${VAR} -> the environment, as KES's env[T] does */
static char *expand_env(const char *s) {
  buckets_buf b = BUCKETS_BUF_INIT;
  for (const char *p = s; *p;) {
    const char *close;
    if (p[0] == '$' && p[1] == '{' && (close = strchr(p + 2, '}'))) {
      char name[256];
      snprintf(name, sizeof(name), "%.*s", (int)(close - p - 2), p + 2);
      const char *v = getenv(name);
      if (v) buckets_buf_append_c(&b, v);
      p = close + 1;
    } else {
      buckets_buf_append_char(&b, *p++);
    }
  }
  return b.data ? b.data : buckets_xstrdup("");
}

static yyjson_mut_val *yaml_to_json(yyjson_mut_doc *d, const buckets_yaml_node *n) {
  if (!n || buckets_yaml_is_null(n)) return yyjson_mut_null(d);
  if (n->kind == BUCKETS_YAML_SCALAR) {
    char *v = expand_env(n->value ? n->value : "");
    yyjson_mut_val *s = yyjson_mut_strcpy(d, v);
    free(v);
    return s;
  }
  if (n->kind == BUCKETS_YAML_SEQ) {
    yyjson_mut_val *a = yyjson_mut_arr(d);
    for (size_t i = 0; i < n->n; i++) yyjson_mut_arr_append(a, yaml_to_json(d, n->items[i]));
    return a;
  }
  yyjson_mut_val *o = yyjson_mut_obj(d);
  for (size_t i = 0; i + 1 < n->n; i += 2)
    yyjson_mut_obj_add(o, yyjson_mut_strcpy(d, n->items[i]->value ? n->items[i]->value : ""), yaml_to_json(d, n->items[i + 1]));
  return o;
}

yyjson_doc *buckets_kes_config_load(const char *path, char *err, size_t errlen) {
  FILE *f = fopen(path, "r");
  if (!f) return snprintf(err, errlen, "failed to read config file '%s'", path), NULL;
  buckets_buf b = BUCKETS_BUF_INIT;
  char tmp[4096];
  size_t n;
  while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) buckets_buf_append(&b, tmp, n);
  fclose(f);
  char e2[300];
  buckets_yaml_node *root = buckets_yaml_parse(b.data ? b.data : "", b.len, e2, sizeof(e2));
  if (b.data) memset(b.data, 0, b.len);
  buckets_buf_free(&b);
  if (!root) return snprintf(err, errlen, "failed to read config file: %s", e2), NULL;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, yaml_to_json(d, root));
  buckets_yaml_free(root);
  yyjson_doc *out = yyjson_mut_doc_imut_copy(d, NULL);
  yyjson_mut_doc_free(d);
  if (!yyjson_is_obj(yyjson_doc_get_root(out))) {
    yyjson_doc_free(out);
    return snprintf(err, errlen, "kesconf: invalid config"), NULL;
  }
  return out;
}

/* "10s", "5m", "1h30m", "250ms" -> milliseconds; -1 if malformed */
static int64_t duration_ms(const char *s) {
  if (!s || !*s) return 0;
  int64_t total = 0;
  while (*s) {
    char *end;
    double v = strtod(s, &end);
    if (end == s) return -1;
    if (strncmp(end, "ms", 2) == 0) total += (int64_t)v, end += 2;
    else if (*end == 's') total += (int64_t)(v * 1000), end++;
    else if (*end == 'm') total += (int64_t)(v * 60000), end++;
    else if (*end == 'h') total += (int64_t)(v * 3600000), end++;
    else return -1;
    s = end;
  }
  return total;
}

static bool truthy(const char *s) { return s && (strcasecmp(s, "true") == 0 || strcasecmp(s, "on") == 0 || strcmp(s, "1") == 0); }

/* ---- the server ----------------------------------------------------------------------- */

typedef struct {
  char *name;
  char **allow, **deny;
  size_t nallow, ndeny;
} policy;

typedef struct {
  char id[65];
  size_t policy;
} ident;

typedef struct {
  char *name;
  buckets_kes_key key;
  int64_t loaded, used; /* ms */
} cached;

struct buckets_kes_server {
  yyjson_doc *conf;
  const char *addr, *tls_cert, *tls_key;
  char admin[65];
  policy *policies;
  size_t npolicies;
  ident *idents;
  size_t nidents;
  char **skip_auth;
  size_t nskip;
  buckets_kes_store *store;
  int64_t started;
  int64_t expiry_any, expiry_unused, expiry_offline; /* ms; 0: never */
  pthread_mutex_t mu;
  cached *cache;
  size_t ncache;
  bool offline;
  pthread_t bg;
  volatile bool stop;
};

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool valid_identity(const char *s) {
  if (strlen(s) != 64) return false;
  for (const char *p = s; *p; p++)
    if (!isxdigit((unsigned char)*p)) return false;
  return true;
}

static char **str_list(yyjson_val *arr, size_t *n) {
  *n = 0;
  char **out = buckets_xcalloc(yyjson_arr_size(arr) + 1, sizeof(char *));
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(arr, i, max, v) {
    if (yyjson_is_str(v) && *yyjson_get_str(v)) out[(*n)++] = buckets_xstrdup(yyjson_get_str(v));
  }
  return out;
}

static void *background(void *arg) {
  buckets_kes_server *s = arg;
  while (!s->stop) {
    for (int i = 0; i < 100 && !s->stop; i++) usleep(100 * 1000); /* 10 s */
    if (s->stop) break;
    int64_t lat;
    char err[300] = "";
    bool offline = s->store->ops->status(s->store, &lat, err, sizeof(err)) != BUCKETS_KES_OK;
    pthread_mutex_lock(&s->mu);
    if (offline != s->offline) buckets_log_warn(offline ? "key store is offline: %s" : "key store is reachable again%s", err);
    s->offline = offline;
    pthread_mutex_unlock(&s->mu);
  }
  return NULL;
}

void buckets_kes_server_free(buckets_kes_server *s) {
  if (!s) return;
  if (s->bg) {
    s->stop = true;
    pthread_join(s->bg, NULL);
  }
  buckets_kes_store_close(s->store);
  for (size_t i = 0; i < s->npolicies; i++) {
    for (size_t j = 0; j < s->policies[i].nallow; j++) free(s->policies[i].allow[j]);
    for (size_t j = 0; j < s->policies[i].ndeny; j++) free(s->policies[i].deny[j]);
    free(s->policies[i].allow);
    free(s->policies[i].deny);
    free(s->policies[i].name);
  }
  free(s->policies);
  free(s->idents);
  for (size_t i = 0; i < s->nskip; i++) free(s->skip_auth[i]);
  free(s->skip_auth);
  for (size_t i = 0; i < s->ncache; i++) {
    buckets_kes_key_wipe(&s->cache[i].key);
    free(s->cache[i].name);
  }
  free(s->cache);
  pthread_mutex_destroy(&s->mu);
  yyjson_doc_free(s->conf);
  free(s);
}

#define FAIL(...) (snprintf(err, errlen, __VA_ARGS__), buckets_kes_server_free(s), (buckets_kes_server *)NULL)

buckets_kes_server *buckets_kes_server_new(yyjson_doc *config, char *err, size_t errlen) {
  buckets_kes_server *s = buckets_xcalloc(1, sizeof(*s));
  pthread_mutex_init(&s->mu, NULL);
  s->conf = config;
  yyjson_val *c = yyjson_doc_get_root(config);
  const char *version = buckets_kes_conf_str(c, "version");
  if (version && *version && strcmp(version, "v1") != 0) return FAIL("kesconf: invalid config version '%s'", version);
  s->addr = buckets_kes_conf_str(c, "address");
  if (!s->addr || !*s->addr) s->addr = "0.0.0.0:7373";
  const char *admin = buckets_kes_conf_str(c, "admin.identity");
  if (!admin || !*admin) return FAIL("kesconf: invalid admin identity: no admin identity");
  if (strcmp(admin, "disabled") != 0 && !valid_identity(admin)) return FAIL("kesconf: invalid admin identity '%s'", admin);
  snprintf(s->admin, sizeof(s->admin), "%s", strcmp(admin, "disabled") == 0 ? "" : admin);
  for (char *p = s->admin; *p; p++) *p = (char)tolower((unsigned char)*p);
  s->tls_key = buckets_kes_conf_str(c, "tls.key");
  s->tls_cert = buckets_kes_conf_str(c, "tls.cert");
  if (!s->tls_key || !*s->tls_key) return FAIL("kesconf: invalid tls config: no private key");
  if (!s->tls_cert || !*s->tls_cert) return FAIL("kesconf: invalid tls config: no certificate");
  if (buckets_kes_conf_str(c, "tls.password") && *buckets_kes_conf_str(c, "tls.password"))
    return FAIL("kesconf: invalid tls config: encrypted private keys are not supported by buckets-kes");

  /* policies, and the identities they apply to */
  yyjson_val *pols = yyjson_obj_get(c, "policy");
  s->policies = buckets_xcalloc(yyjson_obj_size(pols) + 1, sizeof(policy));
  yyjson_obj_iter it = yyjson_obj_iter_with(pols);
  for (yyjson_val *k; (k = yyjson_obj_iter_next(&it));) {
    yyjson_val *p = yyjson_obj_iter_get_val(k);
    policy *pol = &s->policies[s->npolicies++];
    pol->name = buckets_xstrdup(yyjson_get_str(k));
    pol->allow = str_list(yyjson_obj_get(p, "allow"), &pol->nallow);
    pol->deny = str_list(yyjson_obj_get(p, "deny"), &pol->ndeny);
    size_t i, max;
    yyjson_val *id;
    yyjson_arr_foreach(yyjson_obj_get(p, "identities"), i, max, id) {
      const char *v = yyjson_get_str(id);
      if (!v || !*v) continue;
      if (!valid_identity(v)) return FAIL("kesconf: invalid policy '%s': invalid identity '%s'", pol->name, v);
      if (strcasecmp(v, s->admin) == 0)
        return FAIL("kesconf: invalid policy '%s': identity '%s' is already admin", pol->name, v);
      for (size_t j = 0; j < s->nidents; j++)
        if (strcasecmp(s->idents[j].id, v) == 0)
          return FAIL("kesconf: identity '%s' is assigned to more than one policy", v);
      s->idents = buckets_xrealloc(s->idents, (s->nidents + 1) * sizeof(ident));
      snprintf(s->idents[s->nidents].id, 65, "%s", v);
      for (char *q = s->idents[s->nidents].id; *q; q++) *q = (char)tolower((unsigned char)*q);
      s->idents[s->nidents++].policy = s->npolicies - 1;
    }
  }
  /* routes anyone may call */
  yyjson_val *api = yyjson_obj_get(c, "api");
  s->skip_auth = buckets_xcalloc(yyjson_obj_size(api) + 1, sizeof(char *));
  it = yyjson_obj_iter_with(api);
  for (yyjson_val *k; (k = yyjson_obj_iter_next(&it));)
    if (truthy(buckets_kes_conf_str(yyjson_obj_iter_get_val(k), "skip_auth"))) s->skip_auth[s->nskip++] = buckets_xstrdup(yyjson_get_str(k));
  /* the key cache */
  s->expiry_any = duration_ms(buckets_kes_conf_str(c, "cache.expiry.any"));
  s->expiry_unused = duration_ms(buckets_kes_conf_str(c, "cache.expiry.unused"));
  s->expiry_offline = duration_ms(buckets_kes_conf_str(c, "cache.expiry.offline"));
  if (s->expiry_any < 0 || s->expiry_unused < 0 || s->expiry_offline < 0) return FAIL("kesconf: invalid cache expiry");

  s->store = buckets_kes_store_open(yyjson_obj_get(c, "keystore"), err, errlen);
  if (!s->store) {
    buckets_kes_server_free(s);
    return NULL;
  }
  /* "keys": created at startup when missing */
  size_t i, max;
  yyjson_val *kv;
  yyjson_arr_foreach(yyjson_obj_get(c, "keys"), i, max, kv) {
    const char *name = buckets_kes_conf_str(kv, "name");
    if (!name || !buckets_kes_valid_name(name)) return FAIL("kesconf: invalid key name '%s'", name ? name : "");
    buckets_kes_key k;
    buckets_kes_key_new(&k, s->admin);
    buckets_buf enc = BUCKETS_BUF_INIT;
    buckets_kes_key_encode(&k, &enc);
    buckets_kes_key_wipe(&k);
    char e2[400] = "";
    buckets_kes_status st = s->store->ops->create(s->store, name, enc.data, enc.len, e2, sizeof(e2));
    OPENSSL_cleanse(enc.data, enc.len);
    buckets_buf_free(&enc);
    if (st != BUCKETS_KES_OK && st != BUCKETS_KES_EXISTS) return FAIL("failed to create key '%s': %s", name, e2);
  }
  s->started = (int64_t)time(NULL);
  pthread_create(&s->bg, NULL, background, s);
  return s;
}

const char *buckets_kes_server_address(const buckets_kes_server *s) { return s->addr; }
void buckets_kes_server_tls_files(const buckets_kes_server *s, const char **cert, const char **key) {
  *cert = s->tls_cert, *key = s->tls_key;
}
const char *buckets_kes_server_store_desc(const buckets_kes_server *s) { return s->store->desc; }

/* ---- the key cache --------------------------------------------------------------------- */

static void cache_drop(buckets_kes_server *s, const char *name) {
  pthread_mutex_lock(&s->mu);
  for (size_t i = 0; i < s->ncache; i++) {
    if (strcmp(s->cache[i].name, name) != 0) continue;
    buckets_kes_key_wipe(&s->cache[i].key);
    free(s->cache[i].name);
    s->cache[i] = s->cache[--s->ncache];
    break;
  }
  pthread_mutex_unlock(&s->mu);
}

/* A key, from the cache or the store. */
static buckets_kes_status get_key(buckets_kes_server *s, const char *name, buckets_kes_key *out, char *err, size_t errlen) {
  int64_t now = now_ms();
  pthread_mutex_lock(&s->mu);
  for (size_t i = 0; i < s->ncache; i++) {
    cached *c = &s->cache[i];
    if (strcmp(c->name, name) != 0) continue;
    bool fresh = (!s->expiry_any || now - c->loaded < s->expiry_any) && (!s->expiry_unused || now - c->used < s->expiry_unused);
    bool kept = s->offline && s->expiry_offline && now - c->loaded < s->expiry_offline;
    if (fresh || kept) {
      c->used = now;
      *out = c->key;
      pthread_mutex_unlock(&s->mu);
      return BUCKETS_KES_OK;
    }
  }
  pthread_mutex_unlock(&s->mu);
  buckets_buf v = BUCKETS_BUF_INIT;
  buckets_kes_status st = s->store->ops->get(s->store, name, &v, err, errlen);
  if (st == BUCKETS_KES_OK) {
    char e2[200];
    if (!buckets_kes_key_decode(v.data ? v.data : "", v.len, out, e2, sizeof(e2))) {
      snprintf(err, errlen, "failed to parse key '%s': %s", name, e2);
      st = BUCKETS_KES_FAILED;
    }
  }
  if (v.data) OPENSSL_cleanse(v.data, v.len);
  buckets_buf_free(&v);
  if (st != BUCKETS_KES_OK) return st;
  cache_drop(s, name);
  pthread_mutex_lock(&s->mu);
  s->cache = buckets_xrealloc(s->cache, (s->ncache + 1) * sizeof(cached));
  s->cache[s->ncache++] = (cached){buckets_xstrdup(name), *out, now, now};
  pthread_mutex_unlock(&s->mu);
  return BUCKETS_KES_OK;
}

/* ---- replies ------------------------------------------------------------------------------ */

static void reply_json(buckets_http_response *resp, int status, yyjson_mut_doc *d) {
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append(&resp->body, js, n);
  buckets_buf_append_char(&resp->body, '\n');
  OPENSSL_cleanse(js, n);
  free(js);
}

/* KES's api.Fail: {"message": and json.Encoder's output, whose newline
 * lands before the closing brace. */
static void fail(buckets_http_response *resp, int status, const char *msg) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *v = yyjson_mut_strcpy(d, msg);
  yyjson_mut_doc_set_root(d, v);
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append_c(&resp->body, "{\"message\":");
  buckets_buf_append(&resp->body, js, n);
  buckets_buf_append_c(&resp->body, "\n}");
  free(js);
}

static void ok_empty(buckets_http_response *resp) {
  resp->status = 200;
  buckets_buf_reset(&resp->body);
}

static yyjson_mut_doc *obj(yyjson_mut_val **o) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, *o);
  return d;
}

static void add_b64(yyjson_mut_doc *d, yyjson_mut_val *o, const char *k, const void *p, size_t n) {
  char *s = buckets_xmalloc(n * 4 / 3 + 8);
  buckets_base64_encode(p, n, s);
  yyjson_mut_obj_add_strcpy(d, o, k, s);
  OPENSSL_cleanse(s, strlen(s));
  free(s);
}

/* A store failure as KES reports it. */
static void store_fail(buckets_kes_server *s, const buckets_http_request *req, buckets_http_response *resp,
                       buckets_kes_status st, const char *err, const char *what) {
  (void)s;
  if (st == BUCKETS_KES_NOT_FOUND) { fail(resp, 404, "key does not exist"); return; }
  if (st == BUCKETS_KES_EXISTS) { fail(resp, 400, "key already exists"); return; }
  buckets_log_error("%s (%.*s %.*s)", err && *err ? err : what, (int)req->method.n, req->method.p, (int)req->path.n, req->path.p);
  fail(resp, 502, what);
}

/* JSON body field: base64 bytes; false if present but malformed */
static bool body_bytes(yyjson_val *o, const char *k, buckets_buf *out) {
  yyjson_val *v = yyjson_obj_get(o, k);
  if (!v || yyjson_is_null(v)) return true;
  const char *s = yyjson_get_str(v);
  if (!s) return false;
  size_t n = strlen(s);
  buckets_buf_reserve(out, n);
  long dn = buckets_base64_decode(s, n, (uint8_t *)out->data + out->len);
  if (dn < 0) return false;
  out->len += (size_t)dn;
  return true;
}

/* ---- identities ------------------------------------------------------------------------------ */

bool buckets_kes_cert_identity(const buckets_buf *chain, size_t n, char hex[65], char *err, size_t errlen) {
  const unsigned char *p = (const unsigned char *)(chain ? chain->data : NULL);
  const unsigned char *end = p ? p + chain->len : NULL;
  bool found = false;
  for (size_t i = 0; i < n && p && p + 4 <= end; i++) {
    uint32_t l;
    memcpy(&l, p, 4);
    p += 4;
    const unsigned char *q = p;
    X509 *x = d2i_X509(NULL, &q, l);
    p += l;
    if (!x) continue;
    if (X509_get_extension_flags(x) & EXFLAG_CA) { /* as Go's cert.IsCA */
      X509_free(x);
      continue;
    }
    if (found) {
      X509_free(x);
      return snprintf(err, errlen, "tls: received more than one client certificate"), false;
    }
    unsigned char *der = NULL;
    int dn = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &der);
    X509_free(x);
    if (dn <= 0) return snprintf(err, errlen, "tls: invalid client certificate"), false;
    uint8_t h[32];
    buckets_sha256(der, (size_t)dn, h);
    OPENSSL_free(der);
    buckets_hex_encode(h, 32, hex);
    hex[64] = '\0';
    found = true;
  }
  if (!found) snprintf(err, errlen, "tls: client certificate is required");
  return found;
}

static bool match(const char *pattern, const char *path) {
  size_t n = strlen(pattern);
  if (!n) return false;
  if (pattern[n - 1] == '*') return strncmp(path, pattern, n - 1) == 0;
  return strcmp(path, pattern) == 0;
}

/* ---- routes ---------------------------------------------------------------------------- */

typedef enum { AUTH_NONE, AUTH_IDENTIFY, AUTH_IDENTITY } auth_kind; /* IDENTIFY: a certificate, no policy */

typedef struct {
  const char *method, *path; /* path: a prefix when it ends in '/' */
  int max_body, timeout;
  auth_kind auth;
  void (*fn)(buckets_kes_server *s, const buckets_http_request *req, const char *resource, const char *identity,
             yyjson_val *body, buckets_http_response *resp);
} route;

static void h_version(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                      yyjson_val *body, buckets_http_response *resp) {
  (void)s, (void)req, (void)res, (void)id, (void)body;
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_obj_add_str(d, o, "version", BUCKETS_VERSION);
  yyjson_mut_obj_add_str(d, o, "commit", BUCKETS_COMMIT);
  reply_json(resp, 200, d);
}

static void h_ready(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                    yyjson_val *body, buckets_http_response *resp) {
  (void)req, (void)res, (void)id, (void)body;
  int64_t lat;
  char err[300] = "";
  buckets_kes_status st = s->store->ops->status(s->store, &lat, err, sizeof(err));
  if (st == BUCKETS_KES_OK) { ok_empty(resp); return; }
  buckets_log_warn("%s", err);
  fail(resp, st == BUCKETS_KES_UNREACHABLE ? 504 : 502, st == BUCKETS_KES_UNREACHABLE ? "key store is not reachable" : "key store is unavailable");
}

static void h_status(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                     yyjson_val *body, buckets_http_response *resp) {
  (void)req, (void)res, (void)id, (void)body;
  int64_t lat = 0;
  char err[300];
  bool reachable = s->store->ops->status(s->store, &lat, err, sizeof(err)) == BUCKETS_KES_OK;
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_obj_add_str(d, o, "version", BUCKETS_VERSION);
#if defined(__APPLE__)
  yyjson_mut_obj_add_str(d, o, "os", "darwin"); /* runtime.GOOS */
#else
  yyjson_mut_obj_add_str(d, o, "os", "linux");
#endif
#if defined(__aarch64__)
  yyjson_mut_obj_add_str(d, o, "arch", "arm64");
#else
  yyjson_mut_obj_add_str(d, o, "arch", "amd64");
#endif
  yyjson_mut_obj_add_uint(d, o, "uptime", (uint64_t)((int64_t)time(NULL) - s->started));
  yyjson_mut_obj_add_int(d, o, "num_cpu", cpus);
  yyjson_mut_obj_add_int(d, o, "num_cpu_used", cpus);
  yyjson_mut_obj_add_uint(d, o, "mem_heap_used", (uint64_t)ru.ru_maxrss * 1024);
  yyjson_mut_obj_add_uint(d, o, "mem_stack_used", 0);
  if (reachable) yyjson_mut_obj_add_int(d, o, "keystore_latency", lat / 1000 > 0 ? lat / 1000 : 1);
  else yyjson_mut_obj_add_bool(d, o, "keystore_unreachable", true);
  reply_json(resp, 200, d);
}

static void h_metrics(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                      yyjson_val *body, buckets_http_response *resp) {
  (void)req, (void)res, (void)id, (void)body;
  resp->status = 200;
  buckets_http_resp_header_set(resp, "Content-Type", "text/plain; version=0.0.4");
  buckets_buf_reset(&resp->body);
  pthread_mutex_lock(&s->mu);
  size_t cached_keys = s->ncache;
  bool offline = s->offline;
  pthread_mutex_unlock(&s->mu);
  buckets_buf_appendf(&resp->body,
                      "# HELP kes_system_up_time Uptime in seconds.\n# TYPE kes_system_up_time gauge\nkes_system_up_time %lld\n"
                      "# HELP buckets_kes_cached_keys Keys in the cache.\n# TYPE buckets_kes_cached_keys gauge\n"
                      "buckets_kes_cached_keys %zu\n"
                      "# HELP buckets_kes_keystore_offline Whether the key store is unreachable.\n"
                      "# TYPE buckets_kes_keystore_offline gauge\nbuckets_kes_keystore_offline %d\n",
                      (long long)((int64_t)time(NULL) - s->started), cached_keys, offline ? 1 : 0);
}

static void h_api(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                  yyjson_val *body, buckets_http_response *resp);

static bool check_name(const char *res, buckets_http_response *resp) {
  if (buckets_kes_valid_name(res)) return true;
  char m[200];
  snprintf(m, sizeof(m), "key name '%s' is empty, too long or contains invalid characters", res);
  fail(resp, 400, m);
  return false;
}

static void store_new_key(buckets_kes_server *s, const buckets_http_request *req, const char *res, buckets_kes_key *k,
                          buckets_http_response *resp) {
  buckets_buf enc = BUCKETS_BUF_INIT;
  buckets_kes_key_encode(k, &enc);
  buckets_kes_key_wipe(k);
  char err[400] = "";
  buckets_kes_status st = s->store->ops->create(s->store, res, enc.data, enc.len, err, sizeof(err));
  OPENSSL_cleanse(enc.data, enc.len);
  buckets_buf_free(&enc);
  if (st != BUCKETS_KES_OK) { store_fail(s, req, resp, st, err, "failed to create key"); return; }
  buckets_log_info("secret key '%s' created", res);
  ok_empty(resp);
}

static void h_create(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                     yyjson_val *body, buckets_http_response *resp) {
  (void)body;
  if (!check_name(res, resp)) return;
  buckets_kes_key k;
  buckets_kes_key_new(&k, id);
  store_new_key(s, req, res, &k, resp);
}

static void h_import(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                     yyjson_val *body, buckets_http_response *resp) {
  if (!check_name(res, resp)) return;
  buckets_buf raw = BUCKETS_BUF_INIT;
  if (!body_bytes(body, "key", &raw)) {
    buckets_buf_free(&raw);
    fail(resp, 400, "invalid import key request body");
    return;
  }
  const char *cipher = yyjson_get_str(yyjson_obj_get(body, "cipher"));
  buckets_kes_key k;
  char m[200];
  if (raw.len != 32) {
    snprintf(m, sizeof(m), "invalid key size for '%s'", cipher ? cipher : "");
    fail(resp, 406, m);
  } else if (!buckets_kes_key_import(&k, cipher, (const uint8_t *)raw.data, id)) {
    snprintf(m, sizeof(m), "algorithm '%s' is not supported", cipher ? cipher : "");
    fail(resp, 406, m);
  } else {
    store_new_key(s, req, res, &k, resp);
  }
  OPENSSL_cleanse(raw.data, raw.len);
  buckets_buf_free(&raw);
}

static void h_describe(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                       yyjson_val *body, buckets_http_response *resp) {
  (void)id, (void)body;
  if (!check_name(res, resp)) return;
  buckets_kes_key k;
  char err[400] = "";
  buckets_kes_status st = get_key(s, res, &k, err, sizeof(err));
  if (st != BUCKETS_KES_OK) { store_fail(s, req, resp, st, err, "failed to read key"); return; }
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_obj_add_strcpy(d, o, "name", res);
  yyjson_mut_obj_add_str(d, o, "algorithm", buckets_kes_cipher_name(k.cipher));
  char at[64];
  buckets_time_rfc3339_nano(k.created_sec, k.created_nsec, at);
  if (k.created_sec) yyjson_mut_obj_add_strcpy(d, o, "created_at", at);
  if (k.created_by[0]) yyjson_mut_obj_add_strcpy(d, o, "created_by", k.created_by);
  buckets_kes_key_wipe(&k);
  reply_json(resp, 200, d);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void h_list(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                   yyjson_val *body, buckets_http_response *resp) {
  (void)id, (void)body;
  /* the resource is a name prefix, "*" for every key (KES's listKeys and validPattern) */
  size_t rl = strlen(res);
  bool ok = rl <= 80 && strcmp(res, "_") != 0;
  for (size_t i = 0; ok && i < rl; i++) {
    char c = res[i];
    ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
         (c == '-' && i > 0 && i < rl - 1) || (c == '*' && i == rl - 1);
  }
  if (!ok) {
    char m[200];
    snprintf(m, sizeof(m), "listing pattern '%s' is empty, too long or is invalid", res);
    fail(resp, 400, m);
    return;
  }
  const char *prefix = strcmp(res, "*") == 0 ? "" : res;
  char **names;
  size_t n;
  char err[400] = "";
  buckets_kes_status st = s->store->ops->list(s->store, &names, &n, err, sizeof(err));
  if (st != BUCKETS_KES_OK) {
    store_fail(s, req, resp, st, err, "failed to list keys");
    return;
  }
  qsort(names, n, sizeof(char *), cmp_str);
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "names");
  for (size_t i = 0; i < n; i++) {
    if (strncmp(names[i], prefix, strlen(prefix)) == 0) yyjson_mut_arr_add_strcpy(d, arr, names[i]);
    free(names[i]);
  }
  free(names);
  reply_json(resp, 200, d);
}

static void h_delete(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                     yyjson_val *body, buckets_http_response *resp) {
  (void)id, (void)body;
  if (!check_name(res, resp)) return;
  char err[400] = "";
  buckets_kes_status st = s->store->ops->del(s->store, res, err, sizeof(err));
  cache_drop(s, res);
  if (st != BUCKETS_KES_OK) { store_fail(s, req, resp, st, err, "failed to delete key"); return; }
  buckets_log_info("secret key '%s' deleted", res);
  ok_empty(resp);
}

static void h_generate(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                       yyjson_val *body, buckets_http_response *resp) {
  (void)id;
  if (!check_name(res, resp)) return;
  buckets_buf ctx = BUCKETS_BUF_INIT;
  if (!body_bytes(body, "context", &ctx)) {
    buckets_buf_free(&ctx);
    fail(resp, 400, "invalid request body");
    return;
  }
  buckets_kes_key k;
  char err[400] = "";
  buckets_kes_status st = get_key(s, res, &k, err, sizeof(err));
  if (st != BUCKETS_KES_OK) {
    buckets_buf_free(&ctx);
    { store_fail(s, req, resp, st, err, "failed to read key"); return; }
  }
  uint8_t dek[32];
  buckets_random(dek, 32);
  buckets_buf ct = BUCKETS_BUF_INIT;
  buckets_kes_encrypt(&k, dek, 32, ctx.data, ctx.len, &ct);
  buckets_kes_key_wipe(&k);
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  add_b64(d, o, "plaintext", dek, 32);
  add_b64(d, o, "ciphertext", ct.data, ct.len);
  OPENSSL_cleanse(dek, 32);
  buckets_buf_free(&ct);
  buckets_buf_free(&ctx);
  reply_json(resp, 200, d);
}

static void h_encrypt(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                      yyjson_val *body, buckets_http_response *resp) {
  (void)id;
  if (!check_name(res, resp)) return;
  buckets_buf pt = BUCKETS_BUF_INIT, ctx = BUCKETS_BUF_INIT, ct = BUCKETS_BUF_INIT;
  buckets_kes_key k;
  char err[400] = "";
  buckets_kes_status st;
  if (!body_bytes(body, "plaintext", &pt) || !body_bytes(body, "context", &ctx)) fail(resp, 400, "invalid request body");
  else if ((st = get_key(s, res, &k, err, sizeof(err))) != BUCKETS_KES_OK) store_fail(s, req, resp, st, err, "failed to read key");
  else {
    buckets_kes_encrypt(&k, pt.data, pt.len, ctx.data, ctx.len, &ct);
    buckets_kes_key_wipe(&k);
    yyjson_mut_val *o;
    yyjson_mut_doc *d = obj(&o);
    add_b64(d, o, "ciphertext", ct.data, ct.len);
    reply_json(resp, 200, d);
  }
  if (pt.data) OPENSSL_cleanse(pt.data, pt.len);
  buckets_buf_free(&pt);
  buckets_buf_free(&ctx);
  buckets_buf_free(&ct);
}

static void h_decrypt(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                      yyjson_val *body, buckets_http_response *resp) {
  (void)id;
  if (!check_name(res, resp)) return;
  buckets_buf ct = BUCKETS_BUF_INIT, ctx = BUCKETS_BUF_INIT, pt = BUCKETS_BUF_INIT;
  buckets_kes_key k;
  char err[400] = "";
  buckets_kes_status st;
  if (!body_bytes(body, "ciphertext", &ct) || !body_bytes(body, "context", &ctx)) fail(resp, 400, "invalid request body");
  else if ((st = get_key(s, res, &k, err, sizeof(err))) != BUCKETS_KES_OK) store_fail(s, req, resp, st, err, "failed to read key");
  else {
    bool ok = buckets_kes_decrypt(&k, ct.data, ct.len, ctx.data, ctx.len, &pt);
    buckets_kes_key_wipe(&k);
    if (!ok) {
      fail(resp, 400, "decryption failed: ciphertext is not authentic");
    } else {
      yyjson_mut_val *o;
      yyjson_mut_doc *d = obj(&o);
      add_b64(d, o, "plaintext", pt.data, pt.len);
      reply_json(resp, 200, d);
    }
  }
  if (pt.data) OPENSSL_cleanse(pt.data, pt.len);
  buckets_buf_free(&pt);
  buckets_buf_free(&ct);
  buckets_buf_free(&ctx);
}

static void h_hmac(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                   yyjson_val *body, buckets_http_response *resp) {
  (void)id;
  if (!check_name(res, resp)) return;
  buckets_buf msg = BUCKETS_BUF_INIT;
  buckets_kes_key k;
  char err[400] = "";
  buckets_kes_status st;
  if (!body_bytes(body, "message", &msg)) fail(resp, 400, "invalid request body");
  else if ((st = get_key(s, res, &k, err, sizeof(err))) != BUCKETS_KES_OK) store_fail(s, req, resp, st, err, "failed to read key");
  else if (!k.has_hmac) {
    buckets_kes_key_wipe(&k);
    fail(resp, 409, "key does not support HMAC");
  } else {
    uint8_t mac[32];
    buckets_kes_hmac(&k, msg.data, msg.len, mac);
    buckets_kes_key_wipe(&k);
    yyjson_mut_val *o;
    yyjson_mut_doc *d = obj(&o);
    add_b64(d, o, "hmac", mac, 32);
    reply_json(resp, 200, d);
  }
  buckets_buf_free(&msg);
}

static const policy *policy_named(buckets_kes_server *s, const char *name) {
  for (size_t i = 0; i < s->npolicies; i++)
    if (strcmp(s->policies[i].name, name) == 0) return &s->policies[i];
  return NULL;
}

static void h_policy(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                     yyjson_val *body, buckets_http_response *resp) {
  (void)id, (void)body;
  bool read = buckets_str_has_prefix(req->path, "/v1/policy/read/");
  const policy *p = policy_named(s, res);
  if (!p) { fail(resp, 404, "policy does not exist"); return; }
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_obj_add_strcpy(d, o, "name", p->name);
  if (read) {
    yyjson_mut_val *a = yyjson_mut_obj_add_obj(d, o, "allow"), *dn = yyjson_mut_obj_add_obj(d, o, "deny");
    for (size_t i = 0; i < p->nallow; i++) yyjson_mut_obj_add(a, yyjson_mut_strcpy(d, p->allow[i]), yyjson_mut_obj(d));
    for (size_t i = 0; i < p->ndeny; i++) yyjson_mut_obj_add(dn, yyjson_mut_strcpy(d, p->deny[i]), yyjson_mut_obj(d));
  }
  char at[64];
  buckets_time_rfc3339_nano(s->started, 0, at);
  yyjson_mut_obj_add_strcpy(d, o, "created_at", at);
  yyjson_mut_obj_add_strcpy(d, o, "created_by", s->admin);
  reply_json(resp, 200, d);
}

static void h_policy_list(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                          yyjson_val *body, buckets_http_response *resp) {
  (void)req, (void)id, (void)body;
  size_t rl = strlen(res);
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, "names");
  for (size_t i = 0; i < s->npolicies; i++)
    if (strcmp(res, "*") == 0 || (rl && res[rl - 1] == '*' ? strncmp(s->policies[i].name, res, rl - 1) == 0 : strcmp(s->policies[i].name, res) == 0))
      yyjson_mut_arr_add_strcpy(d, a, s->policies[i].name);
  yyjson_mut_obj_add_str(d, o, "continue_at", "");
  reply_json(resp, 200, d);
}

static int cmp_strp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void add_rules(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, char **rules, size_t n) {
  if (!n) return; /* omitempty */
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, o, key);
  for (size_t i = 0; i < n; i++) yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, rules[i]), yyjson_mut_obj(d));
}

/* describe: KES's describeIdentity. self: every identity gets an answer (KES
 * answers only the admin, looking the caller up by an empty resource), in the
 * shape kms-go's DescribeSelf decodes: the policy's name, its rules beside it. */
static void h_identity(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                       yyjson_val *body, buckets_http_response *resp) {
  (void)body;
  bool self = buckets_str_eq_c(req->path, "/v1/identity/self/describe");
  const char *who = self ? id : res;
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  char at[64];
  buckets_time_rfc3339_nano(s->started, 0, at);
  if (self) yyjson_mut_obj_add_strcpy(d, o, "identity", who);
  if (*s->admin && strcasecmp(who, s->admin) == 0) {
    yyjson_mut_obj_add_bool(d, o, "admin", true);
    yyjson_mut_obj_add_strcpy(d, o, "created_at", at);
  } else {
    const ident *found = NULL;
    for (size_t i = 0; i < s->nidents; i++)
      if (strcasecmp(s->idents[i].id, who) == 0) found = &s->idents[i];
    if (!found) {
      yyjson_mut_doc_free(d);
      fail(resp, 404, "identity does not exist");
      return;
    }
    const policy *p = &s->policies[found->policy];
    if (!self) yyjson_mut_obj_add_strcpy(d, o, "policy", p->name);
    yyjson_mut_obj_add_strcpy(d, o, "created_at", at);
    if (*s->admin) yyjson_mut_obj_add_strcpy(d, o, "created_by", s->admin);
    if (self) {
      yyjson_mut_obj_add_strcpy(d, o, "policy", p->name);
      add_rules(d, o, "allow", p->allow, p->nallow);
      add_rules(d, o, "deny", p->deny, p->ndeny);
    }
  }
  reply_json(resp, 200, d);
}

/* KES's listIdentities: the admin and the policies' identities, sorted; "" and
 * "*" list all, anything else is a prefix (a trailing '*' dropped). */
static void h_identity_list(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                            yyjson_val *body, buckets_http_response *resp) {
  (void)req, (void)id, (void)body;
  size_t rl = strlen(res);
  bool all = !rl || strcmp(res, "*") == 0;
  size_t pl = rl && res[rl - 1] == '*' ? rl - 1 : rl;
  const char **ids = buckets_xcalloc(s->nidents + 2, sizeof(char *));
  size_t n = 0;
  if (*s->admin && (all || strncmp(s->admin, res, pl) == 0)) ids[n++] = s->admin;
  for (size_t i = 0; i < s->nidents; i++)
    if (all || strncmp(s->idents[i].id, res, pl) == 0) ids[n++] = s->idents[i].id;
  qsort(ids, n, sizeof(char *), cmp_strp);
  yyjson_mut_val *o;
  yyjson_mut_doc *d = obj(&o);
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, "identities");
  for (size_t i = 0; i < n; i++) yyjson_mut_arr_add_strcpy(d, a, ids[i]);
  yyjson_mut_obj_add_str(d, o, "continue_at", "");
  free(ids);
  reply_json(resp, 200, d);
}

static void h_logs(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                   yyjson_val *body, buckets_http_response *resp) {
  (void)s, (void)req, (void)res, (void)id, (void)body;
  fail(resp, 501, "buckets-kes does not stream its logs: read them from its output");
}

static const route ROUTES[] = {
    {"GET", "/version", 0, 10, AUTH_NONE, h_version},
    {"GET", "/v1/ready", 0, 15, AUTH_IDENTITY, h_ready},
    {"GET", "/v1/status", 0, 15, AUTH_IDENTITY, h_status},
    {"GET", "/v1/metrics", 0, 15, AUTH_IDENTITY, h_metrics},
    {"GET", "/v1/api", 0, 10, AUTH_IDENTITY, h_api},
    {"PUT", "/v1/key/create/", 0, 15, AUTH_IDENTITY, h_create},
    {"PUT", "/v1/key/import/", MAX_BODY, 15, AUTH_IDENTITY, h_import},
    {"GET", "/v1/key/describe/", 0, 15, AUTH_IDENTITY, h_describe},
    {"GET", "/v1/key/list/", 0, 15, AUTH_IDENTITY, h_list},
    {"DELETE", "/v1/key/delete/", 0, 15, AUTH_IDENTITY, h_delete},
    {"PUT", "/v1/key/generate/", MAX_BODY, 15, AUTH_IDENTITY, h_generate},
    {"PUT", "/v1/key/encrypt/", MAX_BODY, 15, AUTH_IDENTITY, h_encrypt},
    {"PUT", "/v1/key/decrypt/", MAX_BODY, 15, AUTH_IDENTITY, h_decrypt},
    {"PUT", "/v1/key/hmac/", MAX_BODY, 15, AUTH_IDENTITY, h_hmac},
    {"GET", "/v1/policy/describe/", 0, 15, AUTH_IDENTITY, h_policy},
    {"GET", "/v1/policy/read/", 0, 15, AUTH_IDENTITY, h_policy},
    {"GET", "/v1/policy/list/", 0, 15, AUTH_IDENTITY, h_policy_list},
    {"GET", "/v1/identity/describe/", 0, 15, AUTH_IDENTITY, h_identity},
    {"GET", "/v1/identity/self/describe", 0, 15, AUTH_IDENTIFY, h_identity},
    {"GET", "/v1/identity/list/", 0, 15, AUTH_IDENTITY, h_identity_list},
    {"GET", "/v1/log/error", 0, 0, AUTH_IDENTITY, h_logs},
    {"GET", "/v1/log/audit", 0, 0, AUTH_IDENTITY, h_logs},
};
static const size_t NROUTES = sizeof(ROUTES) / sizeof(ROUTES[0]);

static void h_api(buckets_kes_server *s, const buckets_http_request *req, const char *res, const char *id,
                  yyjson_val *body, buckets_http_response *resp) {
  (void)s, (void)req, (void)res, (void)id, (void)body;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *a = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, a);
  for (size_t i = 0; i < NROUTES; i++) {
    yyjson_mut_val *r = yyjson_mut_arr_add_obj(d, a);
    yyjson_mut_obj_add_str(d, r, "method", ROUTES[i].method);
    yyjson_mut_obj_add_str(d, r, "path", ROUTES[i].path);
    yyjson_mut_obj_add_int(d, r, "max_body", ROUTES[i].max_body);
    yyjson_mut_obj_add_int(d, r, "timeout", ROUTES[i].timeout);
  }
  reply_json(resp, 200, d);
}


/* Percent-decoding of the resource (names are plain, but clients escape '*'). */
static void unescape(const char *in, size_t n, char *out, size_t cap) {
  size_t w = 0;
  for (size_t i = 0; i < n && w + 1 < cap; i++) {
    if (in[i] == '%' && i + 2 < n && isxdigit((unsigned char)in[i + 1]) && isxdigit((unsigned char)in[i + 2])) {
      char h[3] = {in[i + 1], in[i + 2], 0};
      out[w++] = (char)strtol(h, NULL, 16);
      i += 2;
    } else {
      out[w++] = in[i];
    }
  }
  out[w] = '\0';
}

void buckets_kes_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_kes_server *s = ud;
  char path[512];
  unescape(req->path.p, req->path.n, path, sizeof(path));
  const route *r = NULL;
  for (size_t i = 0; i < NROUTES && !r; i++) {
    size_t pl = strlen(ROUTES[i].path);
    bool prefix = ROUTES[i].path[pl - 1] == '/';
    /* a prefix route also takes its bare path (an empty resource), as Go's mux redirects it */
    if (prefix ? strncmp(path, ROUTES[i].path, pl) == 0 || (strncmp(path, ROUTES[i].path, pl - 1) == 0 && !path[pl - 1])
               : strcmp(path, ROUTES[i].path) == 0)
      r = &ROUTES[i];
  }
  if (!r) { /* http.NotFound */
    resp->status = 404;
    buckets_http_resp_header_set(resp, "Content-Type", "text/plain; charset=utf-8");
    buckets_http_resp_header_set(resp, "X-Content-Type-Options", "nosniff");
    buckets_buf_reset(&resp->body);
    buckets_buf_append_c(&resp->body, "404 page not found\n");
    return;
  }
  /* POST stands in for PUT, as with KES */
  if (!buckets_str_eq_c(req->method, r->method) && !(buckets_str_eq_c(req->method, "POST") && strcmp(r->method, "PUT") == 0)) {
    buckets_http_resp_header_set(resp, "Accept", r->method);
    char m[120];
    snprintf(m, sizeof(m), "received method '%.*s' expected '%s'", (int)req->method.n, req->method.p, r->method);
    { fail(resp, 405, m); return; }
  }
  const char *resource = strlen(path) >= strlen(r->path) ? path + strlen(r->path) : "";
  char id[65] = "";
  bool skip = r->auth == AUTH_NONE;
  for (size_t i = 0; i < s->nskip && !skip; i++) skip = strcmp(s->skip_auth[i], r->path) == 0;
  if (!skip) {
    char err[120];
    if (!req->secure) { fail(resp, 400, "insecure connection: TLS is required"); return; }
    if (!buckets_kes_cert_identity(req->peer_certs, req->npeer_certs, id, err, sizeof(err))) { fail(resp, 400, err); return; }
    if (r->auth == AUTH_IDENTITY && (!*s->admin || strcmp(id, s->admin) != 0)) {
      const policy *p = NULL;
      for (size_t i = 0; i < s->nidents && !p; i++)
        if (strcmp(s->idents[i].id, id) == 0) p = &s->policies[s->idents[i].policy];
      bool allowed = false;
      if (p) {
        allowed = false;
        bool denied = false;
        for (size_t i = 0; i < p->ndeny && !denied; i++) denied = match(p->deny[i], path);
        for (size_t i = 0; i < p->nallow && !denied && !allowed; i++) allowed = match(p->allow[i], path);
      }
      if (!allowed) { fail(resp, 403, "not authorized: insufficient permissions"); return; }
    }
  }
  yyjson_doc *body = NULL;
  bool import = r->fn == h_import;
  const char *bad_body = import ? "invalid import key request body" : "invalid request body";
  if (r->max_body && req->body_len != 0) {
    /* however it came (in memory, spooled, streamed, or chunked as MinIO's
     * kms-go sends it: no length), up to the route's limit */
    buckets_buf raw = BUCKETS_BUF_INIT;
    buckets_http_body_cursor cur = {req, 0};
    char chunk[16384];
    long k;
    bool too_large = false;
    while ((k = buckets_http_body_read(&cur, chunk, sizeof(chunk))) > 0 && !too_large) {
      if (raw.len + (size_t)k > (size_t)r->max_body) too_large = true;
      else buckets_buf_append(&raw, chunk, (size_t)k);
    }
    if (too_large || k < 0) {
      buckets_buf_free(&raw);
      fail(resp, too_large ? 413 : 400, too_large ? "request body too large" : bad_body);
      return;
    }
    body = raw.len ? yyjson_read(raw.data, raw.len, 0) : NULL;
    if (raw.data) OPENSSL_cleanse(raw.data, raw.len);
    buckets_buf_free(&raw);
    if (!body && (import || cur.off > 0)) { fail(resp, 400, bad_body); return; }
  } else if (import) { /* json.Decode of nothing: EOF */
    fail(resp, 400, bad_body);
    return;
  }
  r->fn(s, req, resource, id, yyjson_doc_get_root(body), resp);
  if (body) yyjson_doc_free(body);
}
