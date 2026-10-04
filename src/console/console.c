/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "console/console.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include <pthread.h>

#include "core/log.h"
#include "net/fetch.h"
#include "core/query.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/madmin.h"
#include "crypto/sha256.h"
#include "s3/sign.h"
#include "console/idpconfig.h"
#include "console/kmsconfig.h"
#include "iam/idpsettings.h"

#define COOKIE_NAME "buckets-session"
#define COOKIE_AD "buckets-console-v1"
#define MAX_JSON_BODY (1 << 20)

struct buckets_console {
  buckets_console_config cfg;
  buckets_http_client *http;
  char host_header[300];
  uint8_t key[32];
  pthread_mutex_t signin_mu; /* guards signin and the file's last state */
  struct signin *signin;      /* how people sign in now */
  time_t signin_checked;      /* when identity_file was last looked at */
  struct stat signin_st;      /* identity_file as last read */
  buckets_console_kms *kms;   /* KMS settings through the operator; NULL outside Kubernetes */
  buckets_console_idp *idp;   /* the Identity page through the operator; NULL outside Kubernetes */
};

/* ---- how people sign in -------------------------------------------------------------- */

/* One set of sign-in settings, shared by the requests using it while a newer
 * one may replace it (identity_file changed). */
typedef struct signin {
  _Atomic int refs;
  char *config_url, *client_id, *client_secret, *scopes, *display_name, *redirect_uri; /* OpenID: config_url set */
  bool ldap;
  bool from_file;
  pthread_mutex_t mu;
  char *authorize, *token; /* from discovery, once fetched */
} signin;

static char *dup_or_null(const char *s) { return s && *s ? buckets_xstrdup(s) : NULL; }

static signin *signin_new(void) {
  signin *g = buckets_xcalloc(1, sizeof(*g));
  atomic_init(&g->refs, 1);
  pthread_mutex_init(&g->mu, NULL);
  return g;
}

static void wipe_free(char *s) {
  if (s) OPENSSL_cleanse(s, strlen(s));
  free(s);
}

static void signin_release(signin *g) {
  if (!g || atomic_fetch_sub(&g->refs, 1) != 1) return;
  free(g->config_url);
  free(g->client_id);
  wipe_free(g->client_secret);
  free(g->scopes);
  free(g->display_name);
  free(g->redirect_uri);
  free(g->authorize);
  free(g->token);
  pthread_mutex_destroy(&g->mu);
  free(g);
}

static void signin_defaults(signin *g) {
  if (!g->scopes) g->scopes = buckets_xstrdup("openid profile email");
  if (!g->display_name) g->display_name = buckets_xstrdup("OpenID");
  if (!g->client_id) {
    free(g->config_url);
    g->config_url = NULL;
  }
}

static signin *signin_from_cfg(const buckets_console_config *cfg) {
  signin *g = signin_new();
  g->config_url = dup_or_null(cfg->oidc_config_url);
  g->client_id = dup_or_null(cfg->oidc_client_id);
  g->client_secret = dup_or_null(cfg->oidc_client_secret);
  g->scopes = dup_or_null(cfg->oidc_scopes);
  g->display_name = dup_or_null(cfg->oidc_display_name);
  g->redirect_uri = dup_or_null(cfg->oidc_redirect_uri);
  g->ldap = cfg->ldap;
  signin_defaults(g);
  return g;
}

/* From the console's view of identity settings ({"oidc", "ldap"}). */
static signin *signin_from_view(yyjson_val *v) {
  signin *g = signin_new();
  yyjson_val *o = yyjson_obj_get(v, "oidc");
  if (yyjson_is_obj(o)) {
    g->config_url = dup_or_null(yyjson_get_str(yyjson_obj_get(o, "configUrl")));
    g->client_id = dup_or_null(yyjson_get_str(yyjson_obj_get(o, "clientId")));
    g->client_secret = dup_or_null(yyjson_get_str(yyjson_obj_get(o, "clientSecret")));
    g->scopes = dup_or_null(yyjson_get_str(yyjson_obj_get(o, "scopes")));
    g->display_name = dup_or_null(yyjson_get_str(yyjson_obj_get(o, "displayName")));
    g->redirect_uri = dup_or_null(yyjson_get_str(yyjson_obj_get(o, "redirectUri")));
  }
  g->ldap = yyjson_is_obj(yyjson_obj_get(v, "ldap"));
  signin_defaults(g);
  return g;
}

/* From identity settings (the Identity page's candidate), as the operator
 * would give them to the console. */
static signin *signin_from_settings(yyjson_val *settings) {
  yyjson_mut_doc *m = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(m, buckets_idp_console_view(m, settings));
  yyjson_doc *v = yyjson_mut_doc_imut_copy(m, NULL);
  yyjson_mut_doc_free(m);
  signin *g = signin_from_view(yyjson_doc_get_root(v));
  yyjson_doc_free(v);
  return g;
}

static bool same_file(const struct stat *a, const struct stat *b) {
  return a->st_ino == b->st_ino && a->st_dev == b->st_dev && a->st_size == b->st_size &&
         a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

/* Reads identity_file again when it changed (signin_mu held); its absence
 * brings back the startup settings. */
static void signin_reload(buckets_console *c) {
  time_t now = time(NULL);
  if (now == c->signin_checked) return;
  c->signin_checked = now;
  struct stat st;
  if (stat(c->cfg.identity_file, &st) != 0) {
    if (c->signin->from_file) {
      buckets_log_info("console: %s is gone; signing in with the startup settings", c->cfg.identity_file);
      signin_release(c->signin);
      c->signin = signin_from_cfg(&c->cfg);
      memset(&c->signin_st, 0, sizeof(c->signin_st));
    }
    return;
  }
  if (c->signin->from_file && same_file(&st, &c->signin_st)) return;
  yyjson_read_err e;
  yyjson_doc *d = yyjson_read_file(c->cfg.identity_file, 0, NULL, &e);
  if (!d) {
    buckets_log_warn("console: %s: %s; keeping the current sign-in settings", c->cfg.identity_file, e.msg);
    c->signin_st = st;
    return;
  }
  signin *g = signin_from_view(yyjson_doc_get_root(d));
  yyjson_doc_free(d);
  g->from_file = true;
  buckets_log_info("console: sign-in settings from %s: %s%s%s", c->cfg.identity_file, g->config_url ? g->display_name : "",
                   g->config_url && g->ldap ? " and " : "", g->ldap ? "LDAP" : g->config_url ? "" : "access keys only");
  signin_release(c->signin);
  c->signin = g;
  c->signin_st = st;
}

/* The current sign-in settings; release with signin_release. */
static signin *signin_get(buckets_console *c) {
  pthread_mutex_lock(&c->signin_mu);
  if (c->cfg.identity_file) signin_reload(c);
  signin *g = c->signin;
  atomic_fetch_add(&g->refs, 1);
  pthread_mutex_unlock(&c->signin_mu);
  return g;
}

buckets_console *buckets_console_new(const buckets_console_config *cfg) {
  buckets_console *c = buckets_xcalloc(1, sizeof(*c));
  c->cfg = *cfg;
  if (c->cfg.sts_duration <= 0) c->cfg.sts_duration = 3600;
  if (!c->cfg.region || !*c->cfg.region) c->cfg.region = "us-east-1";
  c->http = buckets_http_client_new(cfg->upstream_host, cfg->upstream_port, cfg->upstream_tls, 5 * 60 * 1000);
  snprintf(c->host_header, sizeof(c->host_header), "%s:%d", cfg->upstream_host, cfg->upstream_port);
  pthread_mutex_init(&c->signin_mu, NULL);
  c->signin = signin_from_cfg(&c->cfg);
  c->kms = buckets_console_kms_new();
  c->idp = buckets_console_idp_new();
  /* MinIO console: the cookie key comes from CONSOLE_PBKDF_PASSPHRASE/SALT;
   * without them every restart (and every replica) gets its own key. */
  if (cfg->passphrase && *cfg->passphrase) {
    const char *salt = cfg->salt && *cfg->salt ? cfg->salt : "buckets-console";
    PKCS5_PBKDF2_HMAC(cfg->passphrase, (int)strlen(cfg->passphrase), (const unsigned char *)salt, (int)strlen(salt),
                      4096, EVP_sha256(), 32, c->key);
  } else {
    buckets_random(c->key, sizeof(c->key));
    buckets_log_warn("console: CONSOLE_PBKDF_PASSPHRASE is not set; sessions end when this process does");
  }
  return c;
}

void buckets_console_free(buckets_console *c) {
  if (!c) return;
  buckets_http_client_free(c->http);
  OPENSSL_cleanse(c->key, sizeof(c->key));
  signin_release(c->signin);
  pthread_mutex_destroy(&c->signin_mu);
  buckets_console_kms_free(c->kms);
  buckets_console_idp_free(c->idp);
  free(c);
}

/* ---- sessions ---------------------------------------------------------------- */

/* AES-256-GCM under the cookie key, base64url(nonce || ciphertext || tag). */
static bool seal_blob(const buckets_console *c, const char *ad, const void *data, size_t n, buckets_buf *out) {
  size_t total = BUCKETS_AEAD_NONCE + n + BUCKETS_AEAD_TAG;
  uint8_t *raw = buckets_xmalloc(total);
  buckets_random(raw, BUCKETS_AEAD_NONCE);
  bool ok = buckets_aead_seal1(BUCKETS_AEAD_AES_256_GCM, c->key, raw, ad, strlen(ad), data, n, raw + BUCKETS_AEAD_NONCE);
  if (ok) {
    char *enc = buckets_xmalloc(total * 4 / 3 + 8);
    buckets_base64url_raw_encode(raw, total, enc);
    buckets_buf_append_c(out, enc);
    free(enc);
  }
  free(raw);
  return ok;
}

static bool open_blob(const buckets_console *c, const char *ad, const char *in, size_t n, buckets_buf *out) {
  if (n > 16384) return false;
  uint8_t *raw = buckets_xmalloc(n + 4);
  long rn = buckets_base64url_raw_decode(in, n, raw);
  bool ok = rn > BUCKETS_AEAD_NONCE + BUCKETS_AEAD_TAG;
  if (ok) {
    size_t pn = (size_t)rn - BUCKETS_AEAD_NONCE - BUCKETS_AEAD_TAG;
    buckets_buf_reserve(out, pn + 1);
    ok = buckets_aead_open1(BUCKETS_AEAD_AES_256_GCM, c->key, raw, ad, strlen(ad), raw + BUCKETS_AEAD_NONCE,
                            (size_t)rn - BUCKETS_AEAD_NONCE, (uint8_t *)out->data + out->len);
    if (ok) out->len += pn, out->data[out->len] = '\0';
  }
  free(raw);
  return ok;
}

bool buckets_console_seal(const buckets_console *c, const buckets_console_session *s, buckets_buf *cookie) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "ak", s->access_key);
  yyjson_mut_obj_add_str(d, o, "sk", s->secret_key);
  yyjson_mut_obj_add_str(d, o, "st", s->session_token);
  yyjson_mut_obj_add_str(d, o, "user", s->user);
  yyjson_mut_obj_add_int(d, o, "exp", s->expires);
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  if (!json) return false;
  size_t total = BUCKETS_AEAD_NONCE + n + BUCKETS_AEAD_TAG;
  uint8_t *raw = buckets_xmalloc(total);
  buckets_random(raw, BUCKETS_AEAD_NONCE);
  bool ok = buckets_aead_seal1(BUCKETS_AEAD_AES_256_GCM, c->key, raw, COOKIE_AD, strlen(COOKIE_AD), json, n,
                               raw + BUCKETS_AEAD_NONCE);
  OPENSSL_cleanse(json, n);
  free(json);
  if (ok) {
    char *enc = buckets_xmalloc(total * 4 / 3 + 8);
    buckets_base64url_raw_encode(raw, total, enc);
    buckets_buf_append_c(cookie, enc);
    free(enc);
  }
  free(raw);
  return ok;
}

static void copy_str(yyjson_val *o, const char *k, char *out, size_t cap) {
  const char *v = yyjson_get_str(yyjson_obj_get(o, k));
  snprintf(out, cap, "%s", v ? v : "");
}

bool buckets_console_open(const buckets_console *c, const char *cookie, size_t n, buckets_console_session *s) {
  memset(s, 0, sizeof(*s));
  if (n > 16384) return false;
  uint8_t *raw = buckets_xmalloc(n + 4);
  long rn = buckets_base64url_raw_decode(cookie, n, raw);
  bool ok = rn > BUCKETS_AEAD_NONCE + BUCKETS_AEAD_TAG;
  char *json = NULL;
  size_t jn = 0;
  if (ok) {
    jn = (size_t)rn - BUCKETS_AEAD_NONCE - BUCKETS_AEAD_TAG;
    json = buckets_xmalloc(jn + 1);
    ok = buckets_aead_open1(BUCKETS_AEAD_AES_256_GCM, c->key, raw, COOKIE_AD, strlen(COOKIE_AD), raw + BUCKETS_AEAD_NONCE,
                            (size_t)rn - BUCKETS_AEAD_NONCE, (uint8_t *)json);
  }
  yyjson_doc *d = ok ? yyjson_read(json, jn, 0) : NULL;
  yyjson_val *o = d ? yyjson_doc_get_root(d) : NULL;
  if (yyjson_is_obj(o)) {
    copy_str(o, "ak", s->access_key, sizeof(s->access_key));
    copy_str(o, "sk", s->secret_key, sizeof(s->secret_key));
    copy_str(o, "st", s->session_token, sizeof(s->session_token));
    copy_str(o, "user", s->user, sizeof(s->user));
    s->expires = yyjson_get_sint(yyjson_obj_get(o, "exp"));
    ok = *s->access_key && *s->secret_key && s->expires > (int64_t)time(NULL);
  } else {
    ok = false;
  }
  yyjson_doc_free(d);
  if (json) OPENSSL_cleanse(json, jn), free(json);
  free(raw);
  if (!ok) memset(s, 0, sizeof(*s));
  return ok;
}

/* A cookie's value (p NULL when absent). */
static buckets_str cookie_value(const buckets_http_request *req, const char *name) {
  for (size_t i = 0; i < req->nheaders; i++) {
    if (!buckets_str_ieq_c(req->headers[i].name, "Cookie")) continue;
    buckets_str rest = req->headers[i].value, part;
    while (rest.n) {
      buckets_str_cut(rest, ';', &part, &rest);
      part = buckets_str_trim(part);
      buckets_str k, v;
      if (buckets_str_cut(part, '=', &k, &v) && buckets_str_eq_c(k, name)) return v;
    }
  }
  return (buckets_str){NULL, 0};
}

/* The session cookie of a request, if valid. */
static bool request_session(const buckets_console *c, const buckets_http_request *req, buckets_console_session *s) {
  buckets_str v = cookie_value(req, COOKIE_NAME);
  return v.p && buckets_console_open(c, v.p, v.n, s);
}

static void set_cookie(const buckets_console *c, buckets_http_response *resp, const char *value, int max_age) {
  buckets_http_resp_headerf(resp, "Set-Cookie", COOKIE_NAME "=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s", value,
                            max_age, c->cfg.secure_cookie ? "; Secure" : "");
}

/* ---- responses ------------------------------------------------------------------ */

static void json_error(buckets_http_response *resp, int status, const char *code, const char *message) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "code", code);
  yyjson_mut_obj_add_str(d, o, "message", message);
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

/* The text of <tag>...</tag> in an XML document. */
static bool xml_text(const char *doc, size_t n, const char *tag, char *out, size_t cap) {
  char open[64], close[64];
  snprintf(open, sizeof(open), "<%s>", tag);
  snprintf(close, sizeof(close), "</%s>", tag);
  const char *a = memmem(doc, n, open, strlen(open));
  if (!a) return false;
  a += strlen(open);
  const char *b = memmem(a, n - (size_t)(a - doc), close, strlen(close));
  if (!b || (size_t)(b - a) >= cap) return false;
  memcpy(out, a, (size_t)(b - a));
  out[b - a] = '\0';
  return true;
}

/* A signed request whose whole reply is buffered (login, admin). */
static bool upstream_call(buckets_console *c, const buckets_sigv4_creds *cr, const char *method, const char *path,
                          const char *query, const buckets_http_kv *hdrs, size_t nhdrs, const void *body, size_t n,
                          buckets_http_result *res) {
  uint8_t sum[32];
  char hash[65];
  buckets_sha256(body ? body : "", n, sum);
  buckets_hex_encode(sum, 32, hash);
  buckets_sigv4_signed sg;
  if (!buckets_sigv4_sign(cr, method, path, query, c->host_header, hdrs, nhdrs, hash, time(NULL), &sg)) return false;
  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&target, path);
  if (query && *query) buckets_buf_appendf(&target, "?%s", query);
  bool ok = buckets_http_client_do(c->http, method, target.data, sg.kv, sg.n, body, n, res);
  buckets_buf_free(&target);
  return ok;
}

/* ---- login ------------------------------------------------------------------------ */

static void form_escape(buckets_buf *b, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
        *p == '.' || *p == '~')
      buckets_buf_append_char(b, (char)*p);
    else buckets_buf_appendf(b, "%%%c%c", hex[*p >> 4], hex[*p & 15]);
  }
}

static void handle_login(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp) {
  if (req->body_len > MAX_JSON_BODY || req->body_fd >= 0 || req->pipe) {
    json_error(resp, 400, "InvalidRequest", "request too large");
    return;
  }
  yyjson_doc *d = yyjson_read(req->body.p ? req->body.p : "", req->body.n, 0);
  yyjson_val *o = d ? yyjson_doc_get_root(d) : NULL;
  const char *ak = yyjson_get_str(yyjson_obj_get(o, "accessKey"));
  const char *sk = yyjson_get_str(yyjson_obj_get(o, "secretKey"));
  if (!ak || !sk || !*ak || !*sk) {
    yyjson_doc_free(d);
    json_error(resp, 400, "InvalidRequest", "accessKey and secretKey are required");
    return;
  }
  const char *method = yyjson_get_str(yyjson_obj_get(o, "method"));
  bool ldap = method && strcmp(method, "ldap") == 0;
  signin *g = signin_get(c);
  bool ldap_on = g->ldap;
  signin_release(g);
  if (ldap && !ldap_on) {
    yyjson_doc_free(d);
    json_error(resp, 400, "InvalidRequest", "LDAP sign-in is not enabled");
    return;
  }
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result res;
  bool ok;
  if (ldap) {
    /* AssumeRoleWithLDAPIdentity: the directory checks the password. */
    buckets_buf body = BUCKETS_BUF_INIT, eu = BUCKETS_BUF_INIT, ep = BUCKETS_BUF_INIT;
    form_escape(&eu, ak);
    form_escape(&ep, sk);
    buckets_buf_appendf(&body, "Action=AssumeRoleWithLDAPIdentity&Version=2011-06-15&DurationSeconds=%d&LDAPUsername=%s&LDAPPassword=%s",
                        c->cfg.sts_duration, eu.data, ep.data);
    ok = buckets_http_client_do(c->http, "POST", "/", h, 1, body.data, body.len, &res);
    OPENSSL_cleanse(body.data, body.len);
    OPENSSL_cleanse(ep.data, ep.len);
    buckets_buf_free(&body);
    buckets_buf_free(&eu);
    buckets_buf_free(&ep);
  } else {
    /* STS AssumeRole with the user's own keys proves them and yields
     * credentials the console can hold instead. */
    char body[128];
    int bn = snprintf(body, sizeof(body), "Action=AssumeRole&Version=2011-06-15&DurationSeconds=%d", c->cfg.sts_duration);
    buckets_sigv4_creds cr = {.access_key = ak, .secret_key = sk, .region = c->cfg.region, .service = "sts"};
    ok = upstream_call(c, &cr, "POST", "/", NULL, h, 1, body, (size_t)bn, &res);
  }
  if (!ok) {
    yyjson_doc_free(d);
    json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
    return;
  }
  const char *xml = res.body.data ? res.body.data : "";
  buckets_console_session s = {0};
  char exp[64] = "";
  if (res.status == 200 && xml_text(xml, res.body.len, "AccessKeyId", s.access_key, sizeof(s.access_key)) &&
      xml_text(xml, res.body.len, "SecretAccessKey", s.secret_key, sizeof(s.secret_key)) &&
      xml_text(xml, res.body.len, "SessionToken", s.session_token, sizeof(s.session_token))) {
    xml_text(xml, res.body.len, "Expiration", exp, sizeof(exp));
    snprintf(s.user, sizeof(s.user), "%s", ak);
    s.expires = (int64_t)time(NULL) + c->cfg.sts_duration;
    buckets_buf cookie = BUCKETS_BUF_INIT;
    if (buckets_console_seal(c, &s, &cookie)) {
      set_cookie(c, resp, cookie.data, c->cfg.sts_duration);
      resp->status = 204;
    } else {
      json_error(resp, 500, "InternalError", "could not create the session");
    }
    buckets_buf_free(&cookie);
  } else {
    char code[128] = "AccessDenied", msg[512] = "Invalid login";
    xml_text(xml, res.body.len, "Code", code, sizeof(code));
    xml_text(xml, res.body.len, "Message", msg, sizeof(msg));
    json_error(resp, res.status >= 500 ? 502 : 401, code, msg);
  }
  OPENSSL_cleanse(&s, sizeof(s));
  buckets_http_result_free(&res);
  yyjson_doc_free(d);
}

static void json_reply(buckets_http_response *resp, yyjson_mut_doc *d) {
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = 200;
  buckets_http_resp_header(resp, "Content-Type", "application/json");
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

static void handle_login_methods(buckets_console *c, buckets_http_response *resp) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  signin *g = signin_get(c);
  yyjson_mut_obj_add_bool(d, o, "ldap", g->ldap);
  yyjson_mut_obj_add_bool(d, o, "share", c->cfg.s3_url != NULL);
  bool oidc = g->config_url != NULL;
  yyjson_mut_obj_add_bool(d, o, "oidc", oidc);
  if (oidc) yyjson_mut_obj_add_strcpy(d, o, "oidcName", g->display_name);
  /* with OpenID sign-in, people come from the identity provider: no local users unless asked for */
  yyjson_mut_obj_add_bool(d, o, "localUsers", c->cfg.local_users_set ? c->cfg.local_users : !oidc);
  signin_release(g);
  json_reply(resp, d);
}

/* ---- OpenID sign-in ------------------------------------------------------------------ */

#define OIDC_COOKIE "buckets-oidc"
#define OIDC_AD "buckets-console-oidc-v1"

/* The provider's endpoints, from its discovery document (fetched once per settings). */
static bool oidc_endpoints(const buckets_console *c, signin *g, char **authorize, char **token, char *err, size_t errlen) {
  pthread_mutex_lock(&g->mu);
  if (!g->authorize) {
    buckets_http_result res;
    if (buckets_fetch("GET", g->config_url, c->cfg.oidc_ca_file, NULL, 0, NULL, 0, 10000, &res, err, errlen)) {
      yyjson_doc *d = res.status == 200 ? yyjson_read(res.body.data ? res.body.data : "", res.body.len, 0) : NULL;
      yyjson_val *o = d ? yyjson_doc_get_root(d) : NULL;
      const char *a = yyjson_get_str(yyjson_obj_get(o, "authorization_endpoint"));
      const char *t = yyjson_get_str(yyjson_obj_get(o, "token_endpoint"));
      if (a && t) {
        g->authorize = buckets_xstrdup(a);
        g->token = buckets_xstrdup(t);
      } else {
        snprintf(err, errlen, "the discovery document (%d) lacks authorization or token endpoints", res.status);
      }
      yyjson_doc_free(d);
      buckets_http_result_free(&res);
    }
  }
  bool ok = g->authorize != NULL;
  if (ok) {
    *authorize = buckets_xstrdup(g->authorize);
    *token = buckets_xstrdup(g->token);
  }
  pthread_mutex_unlock(&g->mu);
  return ok;
}

static void redirect_uri(const signin *g, const buckets_http_request *req, buckets_buf *out) {
  if (g && g->redirect_uri) {
    buckets_buf_append_c(out, g->redirect_uri);
    return;
  }
  buckets_str host = buckets_http_header_get(req, "Host"), proto = buckets_http_header_get(req, "X-Forwarded-Proto");
  bool https = req->secure || (proto.p && buckets_str_eq_c(proto, "https"));
  buckets_buf_appendf(out, "%s://%.*s/oauth_callback", https ? "https" : "http", (int)host.n, host.p ? host.p : "");
}

static void redirect(buckets_http_response *resp, const char *location) {
  resp->status = 302;
  buckets_http_resp_header(resp, "Location", location);
  buckets_http_resp_header(resp, "Cache-Control", "no-store");
}

static void login_error_redirect(buckets_http_response *resp, const char *msg) {
  buckets_buf loc = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&loc, "/login?error=");
  form_escape(&loc, msg);
  redirect(resp, loc.data);
  buckets_buf_free(&loc);
}

static bool may_configure(buckets_console *c, const buckets_console_session *s);

/* What the Identity page's endpoints and tests do as the signed-in admin. */
typedef struct {
  buckets_console *c;
  const buckets_console_session *s;
} admin_ctx;

static int admin_get(void *ud, const char *api, const char *query, bool decrypt, buckets_buf *out) {
  admin_ctx *a = ud;
  buckets_sigv4_creds cr = {.access_key = a->s->access_key, .secret_key = a->s->secret_key,
                            .session_token = a->s->session_token, .region = a->c->cfg.region};
  char path[256];
  snprintf(path, sizeof(path), "/minio/admin/v3/%s", api);
  buckets_http_result res;
  if (!upstream_call(a->c, &cr, "GET", path, query, NULL, 0, NULL, 0, &res)) return 0;
  int st = res.status;
  if (st == 200 && decrypt) {
    if (!buckets_madmin_decrypt(a->s->secret_key, res.body.data ? res.body.data : "", res.body.len, out)) st = 0;
  } else {
    buckets_buf_append(out, res.body.data ? res.body.data : "", res.body.len);
  }
  buckets_http_result_free(&res);
  return st;
}

static void idp_session(buckets_console *c, const buckets_http_request *req, admin_ctx *a, buckets_buf *callback,
                        buckets_console_idp_session *out) {
  signin *g = signin_get(c);
  redirect_uri(g, req, callback);
  signin_release(g);
  *out = (buckets_console_idp_session){admin_get, a, c->cfg.region, c->cfg.oidc_ca_file, callback->data};
}

static void html_escape(buckets_buf *b, const char *s) {
  for (; *s; s++) {
    if (*s == '<') buckets_buf_append_c(b, "&lt;");
    else if (*s == '>') buckets_buf_append_c(b, "&gt;");
    else if (*s == '&') buckets_buf_append_c(b, "&amp;");
    else if (*s == '"') buckets_buf_append_c(b, "&quot;");
    else buckets_buf_append_char(b, *s);
  }
}

/* The test sign-in's popup ends here: it tells the Identity page and closes. */
static void test_page(buckets_http_response *resp, bool passed, const char *message) {
  uint8_t r[16];
  char nonce[32];
  buckets_random(r, sizeof(r));
  buckets_base64url_raw_encode(r, sizeof(r), nonce);
  resp->status = 200;
  buckets_http_resp_header(resp, "Content-Type", "text/html; charset=utf-8");
  buckets_http_resp_header(resp, "Cache-Control", "no-store");
  buckets_http_resp_headerf(resp, "Content-Security-Policy",
                            "default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; frame-ancestors 'none'", nonce);
  buckets_buf_append_c(&resp->body, "<!doctype html><meta charset=\"utf-8\"><title>Sign-in test</title>"
                                    "<body style=\"font:14px system-ui,sans-serif;padding:24px\"><p>");
  html_escape(&resp->body, message);
  buckets_buf_appendf(&resp->body,
                      "</p><p>You can close this window.</p><script nonce=\"%s\">try{window.opener&&window.opener.postMessage("
                      "{type:'buckets-identity-test',passed:%s},location.origin)}catch(e){}setTimeout(function(){window.close()},"
                      "%d)</script>",
                      nonce, passed ? "true" : "false", passed ? 1200 : 6000);
}

/* GET /api/v1/login/oidc: to the provider. With test=1 (the Identity page's
 * popup, as an admin who may change the configuration), to the provider of
 * the candidate settings instead, to try them without signing in. */
static void handle_oidc_start(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp) {
  buckets_query q = {0};
  buckets_query_parse(req->query, &q);
  bool test = buckets_query_get(&q, "test") != NULL;
  buckets_query_free(&q);
  signin *g = NULL;
  char hash[17] = "";
  if (test) {
    buckets_console_session s;
    bool ok = request_session(c, req, &s) && may_configure(c, &s);
    OPENSSL_cleanse(&s, sizeof(s));
    if (!ok) {
      test_page(resp, false, "Testing sign-in needs an administrator's session (admin:ConfigUpdate).");
      return;
    }
    yyjson_doc *cand = c->idp ? buckets_console_idp_candidate(c->idp, hash) : NULL;
    yyjson_val *cs = yyjson_doc_get_root(cand);
    if (!yyjson_is_obj(yyjson_obj_get(cs, "openid"))) {
      yyjson_doc_free(cand);
      test_page(resp, false, "Save OpenID settings before testing them.");
      return;
    }
    g = signin_from_settings(cs);
    yyjson_doc_free(cand);
  } else {
    g = signin_get(c);
  }
  if (!g->config_url) {
    signin_release(g);
    json_error(resp, 404, "NotConfigured", "OpenID sign-in is not configured");
    return;
  }
  char *authorize = NULL, *token = NULL, err[512] = "";
  if (!oidc_endpoints(c, g, &authorize, &token, err, sizeof(err))) {
    buckets_log_warn("console: OpenID discovery: %s", err);
    if (test) {
      char msg[700];
      snprintf(msg, sizeof(msg), "The identity provider cannot be reached: %s", err);
      test_page(resp, false, msg);
    } else {
      login_error_redirect(resp, "The identity provider cannot be reached.");
    }
    signin_release(g);
    return;
  }
  uint8_t r[32];
  char state[48], nonce[48];
  buckets_random(r, sizeof(r));
  buckets_base64url_raw_encode(r, 24, state);
  buckets_random(r, sizeof(r));
  buckets_base64url_raw_encode(r, 24, nonce);
  char json[320];
  int jn = snprintf(json, sizeof(json), "{\"state\":\"%s\",\"nonce\":\"%s\",\"exp\":%lld,\"test\":\"%s\"}", state, nonce,
                    (long long)time(NULL) + 600, hash);
  buckets_buf ck = BUCKETS_BUF_INIT, loc = BUCKETS_BUF_INIT, ru = BUCKETS_BUF_INIT;
  seal_blob(c, OIDC_AD, json, (size_t)jn, &ck);
  /* Lax: the provider's redirect back is a cross-site navigation. */
  buckets_http_resp_headerf(resp, "Set-Cookie", OIDC_COOKIE "=%s; Path=/oauth_callback; Max-Age=600; HttpOnly; SameSite=Lax%s", ck.data,
                            c->cfg.secure_cookie ? "; Secure" : "");
  redirect_uri(g, req, &ru);
  buckets_buf_appendf(&loc, "%s%sresponse_type=code&client_id=", authorize, strchr(authorize, '?') ? "&" : "?");
  form_escape(&loc, g->client_id);
  buckets_buf_append_c(&loc, "&redirect_uri=");
  form_escape(&loc, ru.data);
  buckets_buf_append_c(&loc, "&scope=");
  form_escape(&loc, g->scopes);
  buckets_buf_appendf(&loc, "&state=%s&nonce=%s", state, nonce);
  if (test) buckets_buf_append_c(&loc, "&prompt=login"); /* a real sign-in, not a remembered one */
  redirect(resp, loc.data);
  buckets_buf_free(&ck);
  buckets_buf_free(&loc);
  buckets_buf_free(&ru);
  free(authorize);
  free(token);
  signin_release(g);
}

/* A display name from the ID token's claims (bucketsd verifies the token). */
static void token_user(const char *jwt, char *out, size_t cap) {
  snprintf(out, cap, "openid");
  const char *a = strchr(jwt, '.'), *b = a ? strchr(a + 1, '.') : NULL;
  if (!b) return;
  size_t n = (size_t)(b - a - 1);
  uint8_t *raw = buckets_xmalloc(n + 4);
  long rn = buckets_base64url_raw_decode(a + 1, n, raw);
  yyjson_doc *d = rn > 0 ? yyjson_read((const char *)raw, (size_t)rn, 0) : NULL;
  yyjson_val *o = d ? yyjson_doc_get_root(d) : NULL;
  static const char *const claims[] = {"preferred_username", "email", "name", "sub"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(claims); i++) {
    const char *v = yyjson_get_str(yyjson_obj_get(o, claims[i]));
    if (v && *v) {
      snprintf(out, cap, "%s", v);
      break;
    }
  }
  yyjson_doc_free(d);
  free(raw);
}

/* The test sign-in's ID token, checked against the candidate it tested, and
 * the outcome recorded for the Identity page (and its Apply). */
static void finish_test(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp, yyjson_val *cand,
                        const char *hash, const char *id_token, const char *access_token) {
  buckets_console_session s;
  if (!request_session(c, req, &s) || !may_configure(c, &s)) {
    OPENSSL_cleanse(&s, sizeof(s));
    test_page(resp, false, "Your console session ended during the test: sign in to the console again and retry.");
    return;
  }
  admin_ctx a = {c, &s};
  buckets_buf cb = BUCKETS_BUF_INIT;
  buckets_console_idp_session sess;
  idp_session(c, req, &a, &cb, &sess);
  yyjson_mut_doc *r = buckets_console_idp_check_token(cand, id_token, access_token, &sess);
  buckets_console_idp_record_test(c->idp, hash, "openid", r);
  yyjson_mut_val *root = yyjson_mut_doc_get_root(r);
  bool passed = yyjson_mut_get_bool(yyjson_mut_obj_get(root, "passed"));
  const char *e = yyjson_mut_get_str(yyjson_mut_obj_get(root, "error"));
  char msg[1400];
  if (passed) snprintf(msg, sizeof(msg), "Signed in as %s: the settings work.", yyjson_mut_get_str(yyjson_mut_obj_get(root, "user")));
  else snprintf(msg, sizeof(msg), "%s", e ? e : "The test failed.");
  test_page(resp, passed, msg);
  yyjson_mut_doc_free(r);
  buckets_buf_free(&cb);
  OPENSSL_cleanse(&s, sizeof(s));
}

static void handle_oidc_callback(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp) {
  buckets_http_resp_headerf(resp, "Set-Cookie", OIDC_COOKIE "=; Path=/oauth_callback; Max-Age=0; HttpOnly; SameSite=Lax");
  buckets_query q = {0};
  buckets_query_parse(req->query, &q);
  const char *code = buckets_query_get(&q, "code"), *state = buckets_query_get(&q, "state");
  const char *perr = buckets_query_get(&q, "error_description");
  if (!perr) perr = buckets_query_get(&q, "error");
  buckets_buf st = BUCKETS_BUF_INIT, ru = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_str ck = cookie_value(req, OIDC_COOKIE);
  yyjson_doc *sd = NULL, *td = NULL, *cand = NULL;
  char *authorize = NULL, *token = NULL;
  buckets_http_result tres = {0}, sres = {0};
  bool have_t = false, have_s = false;
  signin *g = NULL;
  /* the state names the test, when the sign-in is one */
  bool opened = ck.p && open_blob(c, OIDC_AD, ck.p, ck.n, &st);
  if (opened) sd = yyjson_read(st.data, st.len, 0);
  const char *test = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(sd), "test"));
  if (test && !*test) test = NULL;
#define FAIL(msg) \
  do { \
    if (test) test_page(resp, false, msg); \
    else login_error_redirect(resp, msg); \
    goto out; \
  } while (0)
  if (perr) FAIL(perr);
  const char *want = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(sd), "state"));
  if (!code || !state || !opened || !want || strcmp(want, state) != 0 ||
      yyjson_get_sint(yyjson_obj_get(yyjson_doc_get_root(sd), "exp")) < time(NULL))
    FAIL("The sign-in expired or did not start here; please try again.");
  if (test) {
    char hash[17] = "";
    cand = c->idp ? buckets_console_idp_candidate(c->idp, hash) : NULL;
    if (!cand || strcmp(hash, test) != 0) FAIL("The settings changed during the test: test them again.");
    g = signin_from_settings(yyjson_doc_get_root(cand));
  } else {
    g = signin_get(c);
  }
  char err[512] = "";
  if (!g->config_url || !oidc_endpoints(c, g, &authorize, &token, err, sizeof(err)))
    FAIL("The identity provider cannot be reached.");
  /* the code for tokens */
  redirect_uri(g, req, &ru);
  buckets_buf_append_c(&body, "grant_type=authorization_code&code=");
  form_escape(&body, code);
  buckets_buf_append_c(&body, "&redirect_uri=");
  form_escape(&body, ru.data);
  buckets_buf_append_c(&body, "&client_id=");
  form_escape(&body, g->client_id);
  if (g->client_secret) {
    buckets_buf_append_c(&body, "&client_secret=");
    form_escape(&body, g->client_secret);
  }
  buckets_http_kv fh[] = {{"Content-Type", "application/x-www-form-urlencoded"}, {"Accept", "application/json"}};
  have_t = buckets_fetch("POST", token, c->cfg.oidc_ca_file, fh, 2, body.data, body.len, 10000, &tres, err, sizeof(err));
  td = have_t && tres.status == 200 ? yyjson_read(tres.body.data ? tres.body.data : "", tres.body.len, 0) : NULL;
  const char *id_token = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(td), "id_token"));
  if (!id_token) {
    buckets_log_warn("console: OpenID token exchange failed (%d): %s", have_t ? tres.status : 0, have_t ? "" : err);
    if (test) {
      /* the provider's own words: a wrong secret or redirect URI shows here */
      yyjson_doc *ed = have_t ? yyjson_read(tres.body.data ? tres.body.data : "", tres.body.len, 0) : NULL;
      const char *why = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ed), "error_description"));
      if (!why) why = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ed), "error"));
      char msg[900];
      snprintf(msg, sizeof(msg), "The provider did not issue a token for this client%s%s", why ? ": " : ".", why ? why : "");
      yyjson_doc_free(ed);
      test_page(resp, false, msg);
      goto out;
    }
    FAIL("The identity provider did not issue a token.");
  }
  if (test) {
    finish_test(c, req, resp, yyjson_doc_get_root(cand), test, id_token,
                yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(td), "access_token")));
    goto out;
  }
  /* the token for credentials */
  buckets_buf_reset(&body);
  buckets_buf_appendf(&body, "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&DurationSeconds=%d&WebIdentityToken=",
                      c->cfg.sts_duration);
  form_escape(&body, id_token);
  buckets_http_kv sh[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  have_s = buckets_http_client_do(c->http, "POST", "/", sh, 1, body.data, body.len, &sres);
  const char *xml = have_s && sres.body.data ? sres.body.data : "";
  buckets_console_session s = {0};
  if (have_s && sres.status == 200 && xml_text(xml, sres.body.len, "AccessKeyId", s.access_key, sizeof(s.access_key)) &&
      xml_text(xml, sres.body.len, "SecretAccessKey", s.secret_key, sizeof(s.secret_key)) &&
      xml_text(xml, sres.body.len, "SessionToken", s.session_token, sizeof(s.session_token))) {
    token_user(id_token, s.user, sizeof(s.user));
    s.expires = (int64_t)time(NULL) + c->cfg.sts_duration;
    buckets_buf cookie = BUCKETS_BUF_INIT;
    if (buckets_console_seal(c, &s, &cookie)) {
      set_cookie(c, resp, cookie.data, c->cfg.sts_duration);
      redirect(resp, "/");
    } else {
      login_error_redirect(resp, "Could not create the session.");
    }
    buckets_buf_free(&cookie);
  } else {
    char msg[512] = "The storage service refused the identity.";
    if (have_s) xml_text(xml, sres.body.len, "Message", msg, sizeof(msg));
    login_error_redirect(resp, msg);
  }
  OPENSSL_cleanse(&s, sizeof(s));
#undef FAIL
out:
  if (have_t) buckets_http_result_free(&tres);
  if (have_s) buckets_http_result_free(&sres);
  yyjson_doc_free(sd);
  yyjson_doc_free(td);
  yyjson_doc_free(cand);
  signin_release(g);
  free(authorize);
  free(token);
  OPENSSL_cleanse(body.data ? body.data : (char *)"", body.len);
  buckets_buf_free(&st);
  buckets_buf_free(&ru);
  buckets_buf_free(&body);
  buckets_query_free(&q);
}

static void path_escape(buckets_buf *b, const char *s, bool keep_slash) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    bool plain = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' ||
                 *p == '_' || *p == '.' || *p == '~' || (keep_slash && *p == '/');
    if (plain) buckets_buf_append_char(b, (char)*p);
    else buckets_buf_appendf(b, "%%%c%c", hex[*p >> 4], hex[*p & 15]);
  }
}

/* A presigned GET at the public S3 URL, valid while the session is (and at
 * most 7 days): the link keeps working without the console. */
static void handle_share(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp,
                         const buckets_console_session *s) {
  if (!c->cfg.s3_url) {
    json_error(resp, 501, "NotConfigured", "share links need BUCKETS_CONSOLE_S3_URL (the S3 endpoint browsers can reach)");
    return;
  }
  buckets_query q = {0};
  buckets_query_parse(req->query, &q);
  const char *bucket = buckets_query_get(&q, "bucket"), *key = buckets_query_get(&q, "key");
  const char *vid = buckets_query_get(&q, "versionId"), *exp_s = buckets_query_get(&q, "expires");
  if (!bucket || !*bucket || !key || !*key) {
    buckets_query_free(&q);
    json_error(resp, 400, "InvalidRequest", "bucket and key are required");
    return;
  }
  int64_t now = (int64_t)time(NULL);
  int64_t left = s->expires - now;
  int64_t expires = exp_s ? strtoll(exp_s, NULL, 10) : 24 * 3600;
  if (expires <= 0 || expires > left) expires = left;
  if (expires > 7 * 24 * 3600) expires = 7 * 24 * 3600;
  /* scheme://authority from the configured URL */
  const char *auth = strstr(c->cfg.s3_url, "://");
  auth = auth ? auth + 3 : c->cfg.s3_url;
  char host[512];
  snprintf(host, sizeof(host), "%.*s", (int)strcspn(auth, "/"), auth);
  buckets_buf path = BUCKETS_BUF_INIT, extra = BUCKETS_BUF_INIT, qs = BUCKETS_BUF_INIT, url = BUCKETS_BUF_INIT;
  buckets_buf_append_char(&path, '/');
  path_escape(&path, bucket, false);
  buckets_buf_append_char(&path, '/');
  path_escape(&path, key, true);
  if (vid && *vid) {
    buckets_buf_append_c(&extra, "versionId=");
    path_escape(&extra, vid, false);
  }
  buckets_sigv4_creds cr = {.access_key = s->access_key, .secret_key = s->secret_key,
                            .session_token = s->session_token, .region = c->cfg.region};
  buckets_sigv4_presign(&cr, "GET", path.data, extra.data, host, (int)expires, (time_t)now, &qs);
  buckets_buf_appendf(&url, "%.*s%s%s?%s", (int)(auth - c->cfg.s3_url), c->cfg.s3_url, host, path.data, qs.data);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_strcpy(d, o, "url", url.data);
  yyjson_mut_obj_add_int(d, o, "expiresAt", now + expires);
  json_reply(resp, d);
  buckets_buf_free(&path);
  buckets_buf_free(&extra);
  buckets_buf_free(&qs);
  buckets_buf_free(&url);
  buckets_query_free(&q);
}

/* Whether the session may change the servers' configuration (admin:ConfigUpdate),
 * as bucketsd decides it for GetConfigKV. */
static bool may_configure(buckets_console *c, const buckets_console_session *s) {
  buckets_sigv4_creds cr = {.access_key = s->access_key, .secret_key = s->secret_key,
                            .session_token = s->session_token, .region = c->cfg.region};
  buckets_http_result res;
  if (!upstream_call(c, &cr, "GET", "/minio/admin/v3/get-config-kv", "key=region", NULL, 0, NULL, 0, &res)) return false;
  bool ok = res.status == 200;
  buckets_http_result_free(&res);
  return ok;
}

static void handle_session(buckets_http_response *resp, const buckets_console_session *s) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "accessKey", s->user);
  yyjson_mut_obj_add_int(d, o, "expiresAt", s->expires);
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = 200;
  buckets_http_resp_header(resp, "Content-Type", "application/json");
  buckets_http_resp_header(resp, "Cache-Control", "no-store");
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

/* ---- the proxy -------------------------------------------------------------------------- */

/* Request headers passed to bucketsd (the rest, including cookies, stay here). */
static bool forward_request_header(buckets_str name) {
  static const char *const allow[] = {"Content-Type", "Content-MD5", "Range", "If-Match", "If-None-Match",
                                      "If-Modified-Since", "If-Unmodified-Since", "Cache-Control", "Content-Disposition",
                                      "Content-Encoding", "Content-Language", "Expires"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(allow); i++)
    if (buckets_str_ieq_c(name, allow[i])) return true;
  if (name.n > 6 && strncasecmp(name.p, "x-amz-", 6) == 0) {
    static const char *const own[] = {"x-amz-date", "x-amz-content-sha256", "x-amz-security-token"};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(own); i++)
      if (buckets_str_ieq_c(name, own[i])) return false;
    return true;
  }
  return name.n > 8 && strncasecmp(name.p, "x-minio-", 8) == 0;
}

/* Response headers passed back to the browser. */
static bool forward_response_header(const char *name, size_t n) {
  static const char *const allow[] = {"Content-Type", "ETag", "Last-Modified", "Content-Range", "Accept-Ranges",
                                      "Content-Disposition", "Content-Encoding", "Content-Language", "Cache-Control",
                                      "Expires"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(allow); i++)
    if (strlen(allow[i]) == n && strncasecmp(name, allow[i], n) == 0) return true;
  return (n > 6 && strncasecmp(name, "x-amz-", 6) == 0) || (n > 8 && strncasecmp(name, "x-minio-", 8) == 0);
}

static void copy_response_headers(const buckets_buf *headers, buckets_http_response *resp) {
  const char *p = headers->data, *end = p ? p + headers->len : NULL;
  while (p && p < end) {
    const char *eol = memchr(p, '\n', (size_t)(end - p));
    if (!eol) eol = end;
    const char *colon = memchr(p, ':', (size_t)(eol - p));
    if (colon && forward_response_header(p, (size_t)(colon - p))) {
      const char *v = colon + 1, *ve = eol;
      while (v < ve && *v == ' ') v++;
      while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ')) ve--;
      char name[128], value[4096];
      snprintf(name, sizeof(name), "%.*s", (int)(colon - p), p);
      snprintf(value, sizeof(value), "%.*s", (int)(ve - v), v);
      buckets_http_resp_header(resp, name, value);
    }
    p = eol + 1;
  }
}

typedef struct {
  buckets_http_body_cursor cur;
} body_src;

static long body_read(void *ud, void *buf, size_t n) { return buckets_http_body_read(&((body_src *)ud)->cur, buf, n); }

static long stream_body(void *ud, char *buf, size_t cap) { return buckets_http_stream_read(ud, buf, cap); }

static void proxy(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp,
                  const buckets_console_session *s, const char *upstream_path) {
  char method[16];
  snprintf(method, sizeof(method), "%.*s", (int)req->method.n, req->method.p);
  char *query = buckets_str_dup(req->query);
  buckets_http_kv hdrs[BUCKETS_SIGN_MAX_HEADERS];
  size_t nh = 0;
  char *owned[BUCKETS_SIGN_MAX_HEADERS * 2];
  size_t no = 0;
  bool encrypt = buckets_str_eq_c(buckets_http_header_get(req, "X-Console-Encrypt"), "1");
  bool decrypt = buckets_str_eq_c(buckets_http_header_get(req, "X-Console-Decrypt"), "1");
  /* An encrypted admin body is octet-stream, as madmin sends it. */
  if (encrypt) hdrs[nh++] = (buckets_http_kv){"Content-Type", "application/octet-stream"};
  for (size_t i = 0; i < req->nheaders; i++) {
    buckets_str nm = req->headers[i].name;
    if (encrypt && buckets_str_ieq_c(nm, "Content-Type")) continue;
    if (!forward_request_header(nm) || nh >= BUCKETS_SIGN_MAX_HEADERS - 5) continue;
    owned[no++] = buckets_str_dup(nm);
    owned[no++] = buckets_str_dup(req->headers[i].value);
    hdrs[nh++] = (buckets_http_kv){owned[no - 2], owned[no - 1]};
  }
  buckets_sigv4_creds cr = {.access_key = s->access_key, .secret_key = s->secret_key,
                            .session_token = s->session_token, .region = c->cfg.region};
  bool in_memory = req->body_fd < 0 && !req->pipe;
  if (encrypt || decrypt || (in_memory && req->body_len <= MAX_JSON_BODY)) {
    /* Small bodies (and every admin call that needs madmin encryption) are
     * signed over their hash and answered from memory. */
    buckets_buf enc = BUCKETS_BUF_INIT;
    const void *body = req->body.p;
    size_t bn = req->body.n;
    if (!in_memory) {
      json_error(resp, 413, "EntityTooLarge", "request body too large");
      goto done;
    }
    if (encrypt) {
      if (!buckets_madmin_encrypt(s->secret_key, body ? body : "", bn, &enc)) {
        json_error(resp, 500, "InternalError", "encryption failed");
        goto done;
      }
      body = enc.data, bn = enc.len;
    }
    if (!encrypt && !decrypt) {
      /* Plain small requests still stream the reply (downloads). */
      uint8_t sum[32];
      char hash[65];
      buckets_sha256(body ? body : "", bn, sum);
      buckets_hex_encode(sum, 32, hash);
      buckets_sigv4_signed sg;
      buckets_buf target = BUCKETS_BUF_INIT, rh = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&target, upstream_path);
      if (*query) buckets_buf_appendf(&target, "?%s", query);
      int status = 0;
      buckets_http_stream *st = NULL;
      if (buckets_sigv4_sign(&cr, method, upstream_path, query, c->host_header, hdrs, nh, hash, time(NULL), &sg)) {
        body_src src = {{.req = req}};
        st = buckets_http_client_open(c->http, method, target.data, sg.kv, sg.n, bn ? body_read : NULL, &src,
                                      (int64_t)bn, &status, &rh);
      }
      if (!st) {
        json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
      } else {
        resp->status = status;
        copy_response_headers(&rh, resp);
        int64_t len = buckets_http_stream_length(st);
        bool head = strcmp(method, "HEAD") == 0;
        if (head) {
          resp->head_only = true;
          const char *cl = buckets_http_headers_get(&rh, "Content-Length", NULL);
          resp->content_length = cl ? strtoll(cl, NULL, 10) : 0;
          resp->stream = stream_body, resp->stream_ud = st, resp->stream_free = buckets_http_stream_free;
        } else if (len >= 0) {
          resp->content_length = len;
          resp->stream = stream_body, resp->stream_ud = st, resp->stream_free = buckets_http_stream_free;
        } else { /* chunked (trace, logs, event listening): relayed as it comes */
          resp->chunked = true;
          resp->stream = stream_body, resp->stream_ud = st, resp->stream_free = buckets_http_stream_free;
        }
      }
      buckets_buf_free(&target);
      buckets_buf_free(&rh);
      buckets_buf_free(&enc);
      goto done;
    }
    buckets_http_result res;
    if (!upstream_call(c, &cr, method, upstream_path, query, hdrs, nh, body, bn, &res)) {
      json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
    } else {
      resp->status = res.status;
      /* Only replies that are madmin-encrypted are decrypted, so the SPA can
       * ask for it on every admin read. */
      if (decrypt && res.status == 200 && buckets_madmin_is_encrypted(res.body.data ? res.body.data : "", res.body.len)) {
        buckets_buf plain = BUCKETS_BUF_INIT;
        if (buckets_madmin_decrypt(s->secret_key, res.body.data ? res.body.data : "", res.body.len, &plain)) {
          buckets_http_resp_header(resp, "Content-Type", "application/json");
          buckets_buf_append(&resp->body, plain.data ? plain.data : "", plain.len);
        } else {
          json_error(resp, 502, "DecryptionFailed", "could not decrypt the storage service's reply");
        }
        buckets_buf_free(&plain);
      } else {
        copy_response_headers(&res.headers, resp);
        buckets_buf_append(&resp->body, res.body.data ? res.body.data : "", res.body.len);
      }
      buckets_http_result_free(&res);
    }
    buckets_buf_free(&enc);
    goto done;
  }
  {
    /* Large uploads stream through unsigned (UNSIGNED-PAYLOAD). */
    buckets_sigv4_signed sg;
    buckets_buf target = BUCKETS_BUF_INIT, rh = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&target, upstream_path);
    if (*query) buckets_buf_appendf(&target, "?%s", query);
    int status = 0;
    buckets_http_stream *st = NULL;
    body_src src = {{.req = req}};
    if (buckets_sigv4_sign(&cr, method, upstream_path, query, c->host_header, hdrs, nh, "UNSIGNED-PAYLOAD", time(NULL),
                           &sg))
      st = buckets_http_client_open(c->http, method, target.data, sg.kv, sg.n, body_read, &src, req->body_len, &status, &rh);
    if (!st) {
      json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
    } else {
      resp->status = status;
      copy_response_headers(&rh, resp);
      char buf[65536];
      long k;
      while ((k = buckets_http_stream_read(st, buf, sizeof(buf))) > 0) buckets_buf_append(&resp->body, buf, (size_t)k);
      buckets_http_stream_free(st);
    }
    buckets_buf_free(&target);
    buckets_buf_free(&rh);
  }
done:
  for (size_t i = 0; i < no; i++) free(owned[i]);
  free(query);
}

/* ---- static files -------------------------------------------------------------------------- */

static const char *content_type(const char *path) {
  static const struct {
    const char *ext, *type;
  } types[] = {{".html", "text/html; charset=utf-8"}, {".js", "text/javascript; charset=utf-8"},
               {".css", "text/css; charset=utf-8"},   {".json", "application/json"},
               {".svg", "image/svg+xml"},             {".png", "image/png"},
               {".ico", "image/x-icon"},              {".woff2", "font/woff2"},
               {".woff", "font/woff"},                {".txt", "text/plain; charset=utf-8"},
               {".map", "application/json"}};
  const char *dot = strrchr(path, '.');
  for (size_t i = 0; dot && i < BUCKETS_ARRAY_LEN(types); i++)
    if (strcasecmp(dot, types[i].ext) == 0) return types[i].type;
  return "application/octet-stream";
}

static bool read_file(const char *path, buckets_buf *out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return false;
  }
  char buf[65536];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) buckets_buf_append(out, buf, (size_t)n);
  close(fd);
  return n == 0;
}

static void serve_static(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp) {
  if (!c->cfg.web_dir) {
    json_error(resp, 404, "NotFound", "no web console is installed");
    return;
  }
  char rel[1024];
  snprintf(rel, sizeof(rel), "%.*s", (int)req->path.n, req->path.p);
  bool bad = strstr(rel, "..") != NULL || strchr(rel, '\\') != NULL;
  char path[2048];
  snprintf(path, sizeof(path), "%s%s", c->cfg.web_dir, bad || strcmp(rel, "/") == 0 ? "/index.html" : rel);
  buckets_buf body = BUCKETS_BUF_INIT;
  bool asset = strncmp(rel, "/assets/", 8) == 0;
  if (bad || !read_file(path, &body)) {
    buckets_buf_reset(&body);
    /* Client-side routes fall back to the SPA; missing assets are 404. */
    snprintf(path, sizeof(path), "%s/index.html", c->cfg.web_dir);
    if (asset || !read_file(path, &body)) {
      buckets_buf_free(&body);
      json_error(resp, 404, "NotFound", "not found");
      return;
    }
  }
  resp->status = 200;
  buckets_http_resp_header(resp, "Content-Type", content_type(path));
  buckets_http_resp_header(resp, "Cache-Control", asset ? "public, max-age=31536000, immutable" : "no-cache");
  buckets_http_resp_header(resp, "X-Content-Type-Options", "nosniff");
  buckets_http_resp_header(resp, "X-Frame-Options", "DENY");
  buckets_http_resp_header(resp, "Referrer-Policy", "same-origin");
  if (strcmp(content_type(path), "text/html; charset=utf-8") == 0)
    buckets_http_resp_header(resp, "Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; frame-ancestors 'none'");
  resp->head_only = buckets_str_eq_c(req->method, "HEAD");
  buckets_buf_append(&resp->body, body.data ? body.data : "", body.len);
  buckets_buf_free(&body);
}

/* ---- routing -------------------------------------------------------------------------------------- */

void buckets_console_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_console *c = ud;
  buckets_str path = req->path;
  if (buckets_str_eq_c(path, "/healthz")) {
    resp->status = 200;
    buckets_buf_append_c(&resp->body, "ok");
    return;
  }
  if (buckets_str_eq_c(path, "/oauth_callback")) {
    handle_oidc_callback(c, req, resp);
    return;
  }
  if (!buckets_str_has_prefix(path, "/api/")) {
    if (!buckets_str_eq_c(req->method, "GET") && !buckets_str_eq_c(req->method, "HEAD")) {
      json_error(resp, 405, "MethodNotAllowed", "method not allowed");
      return;
    }
    serve_static(c, req, resp);
    return;
  }
  buckets_http_resp_header(resp, "Cache-Control", "no-store");
  bool safe = buckets_str_eq_c(req->method, "GET") || buckets_str_eq_c(req->method, "HEAD");
  if (!safe && !buckets_str_eq_c(buckets_http_header_get(req, "X-Console-Request"), "1")) {
    json_error(resp, 403, "Forbidden", "missing X-Console-Request header");
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/login")) {
    if (!buckets_str_eq_c(req->method, "POST")) json_error(resp, 405, "MethodNotAllowed", "use POST");
    else handle_login(c, req, resp);
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/login/oidc")) {
    handle_oidc_start(c, req, resp);
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/login-methods")) {
    handle_login_methods(c, resp);
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/logout")) {
    set_cookie(c, resp, "", 0);
    resp->status = 204;
    return;
  }
  buckets_console_session s;
  if (!request_session(c, req, &s)) {
    json_error(resp, 401, "Unauthorized", "not logged in");
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/session")) {
    handle_session(resp, &s);
  } else if (buckets_str_eq_c(path, "/api/v1/share")) {
    handle_share(c, req, resp, &s);
  } else if (buckets_str_has_prefix(path, "/api/v1/s3/") || buckets_str_eq_c(path, "/api/v1/s3")) {
    char up[4096];
    snprintf(up, sizeof(up), "/%.*s", (int)(path.n > 11 ? path.n - 11 : 0), path.p + 11);
    proxy(c, req, resp, &s, up);
  } else if (buckets_str_has_prefix(path, "/api/v1/admin/")) {
    char up[4096];
    snprintf(up, sizeof(up), "/minio/admin/v3/%.*s", (int)(path.n - 14), path.p + 14);
    proxy(c, req, resp, &s, up);
  } else if (buckets_str_eq_c(path, "/api/v1/kms-config") || buckets_str_has_prefix(path, "/api/v1/kms-config/")) {
    if (!may_configure(c, &s)) {
      json_error(resp, 403, "AccessDenied", "Setting up the KMS needs the admin:ConfigUpdate permission.");
    } else {
      char sub[64];
      snprintf(sub, sizeof(sub), "%.*s", (int)(path.n - 18), path.p + 18);
      buckets_console_kms_handle(c->kms, req, sub, resp);
    }
  } else if (buckets_str_eq_c(path, "/api/v1/identity-config") || buckets_str_has_prefix(path, "/api/v1/identity-config/")) {
    if (!may_configure(c, &s)) {
      json_error(resp, 403, "AccessDenied", "Setting up sign-in needs the admin:ConfigUpdate permission.");
    } else {
      char sub[64];
      snprintf(sub, sizeof(sub), "%.*s", (int)(path.n - 23), path.p + 23);
      admin_ctx a = {c, &s};
      buckets_buf cb = BUCKETS_BUF_INIT;
      buckets_console_idp_session sess;
      idp_session(c, req, &a, &cb, &sess);
      buckets_console_idp_handle(c->idp, req, sub, &sess, resp);
      buckets_buf_free(&cb);
    }
  } else if (buckets_str_has_prefix(path, "/api/v1/kms/")) { /* the KMS API: keys, status */
    char up[4096];
    snprintf(up, sizeof(up), "/minio/kms/v1/%.*s", (int)(path.n - 12), path.p + 12);
    proxy(c, req, resp, &s, up);
  } else {
    json_error(resp, 404, "NotFound", "unknown API");
  }
  OPENSSL_cleanse(&s, sizeof(s));
}
