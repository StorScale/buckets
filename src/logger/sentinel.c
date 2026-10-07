/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "logger/sentinel.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/buf.h"
#include "core/common.h"
#include "net/client.h"
#include "net/fetch.h"

void buckets_sentinel_url(const char *endpoint, const char *dcr, const char *stream, char *out, size_t cap) {
  size_t el = strlen(endpoint);
  while (el && endpoint[el - 1] == '/') el--;
  snprintf(out, cap, "%.*s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01", (int)el, endpoint, dcr,
           stream);
}

typedef struct {
  char *login, *tenant, *client_id, *client_secret, *scope, *ca_file;
  pthread_mutex_t mu;
  char token[8000];
  time_t expires;
} sentinel_auth;

static void form_escape(buckets_buf *b, const char *s) {
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
        strchr("-_.~", *p))
      buckets_buf_append_char(b, (char)*p);
    else
      buckets_buf_appendf(b, "%%%02X", *p);
  }
}

/* A token for the Logs Ingestion API: the cached one, or a new one from Entra ID (client credentials). */
static bool bearer(void *ud, char *token, size_t cap, char *err, size_t errlen) {
  sentinel_auth *a = ud;
  pthread_mutex_lock(&a->mu);
  if (*a->token && time(NULL) < a->expires - 60) {
    snprintf(token, cap, "%s", a->token);
    pthread_mutex_unlock(&a->mu);
    return true;
  }
  char url[1024];
  snprintf(url, sizeof(url), "%s/%s/oauth2/v2.0/token", a->login, a->tenant);
  buckets_buf form = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&form, "grant_type=client_credentials&client_id=");
  form_escape(&form, a->client_id);
  buckets_buf_append_c(&form, "&client_secret=");
  form_escape(&form, a->client_secret);
  buckets_buf_append_c(&form, "&scope=");
  form_escape(&form, a->scope);
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result r;
  bool ok = buckets_fetch("POST", url, a->ca_file, h, 1, form.data, form.len, 15000, &r, err, errlen);
  memset(form.data, 0, form.len); /* the secret */
  buckets_buf_free(&form);
  if (ok) {
    yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    yyjson_val *root = yyjson_doc_get_root(d);
    const char *tok = yyjson_get_str(yyjson_obj_get(root, "access_token"));
    yyjson_val *exp = yyjson_obj_get(root, "expires_in");
    long long secs = yyjson_is_str(exp) ? atoll(yyjson_get_str(exp)) : yyjson_get_sint(exp);
    if (r.status == 200 && tok && strlen(tok) < sizeof(a->token)) {
      snprintf(a->token, sizeof(a->token), "%s", tok);
      a->expires = time(NULL) + (secs > 0 ? secs : 300);
      snprintf(token, cap, "%s", a->token);
    } else {
      const char *why = yyjson_get_str(yyjson_obj_get(root, "error_description"));
      snprintf(err, errlen, "signing in to Entra ID for Sentinel: %d %s", r.status,
               why                                             ? why
               : yyjson_get_str(yyjson_obj_get(root, "error")) ? yyjson_get_str(yyjson_obj_get(root, "error"))
                                                               : "");
      ok = false;
    }
    yyjson_doc_free(d);
    buckets_http_result_free(&r);
  }
  pthread_mutex_unlock(&a->mu);
  return ok;
}

static const char *env(const char *k) {
  const char *v = getenv(k);
  return v && *v ? v : NULL;
}

/* A secret from <name>_FILE (a mounted Secret), else from <name>; malloc'd. */
static char *secret(const char *name) {
  char fk[128];
  snprintf(fk, sizeof(fk), "%s_FILE", name);
  const char *path = env(fk);
  if (!path) return env(name) ? buckets_xstrdup(env(name)) : NULL;
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
  buf[n] = '\0';
  char *s = buckets_xstrdup(buf);
  memset(buf, 0, sizeof(buf));
  return s;
}

buckets_http_target *buckets_sentinel_target_from_env(const char *deployment_id, const char *ca_file,
                                                      char *err, size_t errlen) {
  *err = '\0';
  const char *endpoint = env("BUCKETS_AUDIT_SENTINEL_ENDPOINT");
  if (!endpoint) return NULL;
  const char *dcr = env("BUCKETS_AUDIT_SENTINEL_DCR_ID"), *stream = env("BUCKETS_AUDIT_SENTINEL_STREAM");
  const char *tenant = env("BUCKETS_AUDIT_SENTINEL_TENANT_ID"),
             *client = env("BUCKETS_AUDIT_SENTINEL_CLIENT_ID");
  char *sec = secret("BUCKETS_AUDIT_SENTINEL_CLIENT_SECRET");
  const char *missing = !dcr      ? "DCR_ID"
                        : !stream ? "STREAM"
                        : !tenant ? "TENANT_ID"
                        : !client ? "CLIENT_ID"
                        : !sec    ? "CLIENT_SECRET"
                                  : NULL;
  if (missing) {
    snprintf(err, errlen, "BUCKETS_AUDIT_SENTINEL_%s is not set", missing);
    free(sec);
    return NULL;
  }
  static sentinel_auth
      *g_auth; /* the process's one Sentinel sign-in: reachable for as long as the target lives */
  if (g_auth) {
    free(sec);
    snprintf(err, errlen, "the Sentinel target is set up once per process");
    return NULL;
  }
  sentinel_auth *a = g_auth = buckets_xcalloc(1, sizeof(*a));
  const char *login = env("BUCKETS_AUDIT_SENTINEL_LOGIN_URL");
  a->login = buckets_xstrdup(login ? login : "https://login.microsoftonline.com");
  size_t ll = strlen(a->login);
  while (ll && a->login[ll - 1] == '/') a->login[--ll] = '\0';
  a->tenant = buckets_xstrdup(tenant);
  a->client_id = buckets_xstrdup(client);
  a->client_secret = sec;
  const char *scope = env("BUCKETS_AUDIT_SENTINEL_SCOPE");
  a->scope = buckets_xstrdup(scope ? scope : "https://monitor.azure.com/.default");
  a->ca_file = ca_file ? buckets_xstrdup(ca_file) : NULL;
  pthread_mutex_init(&a->mu, NULL);
  char url[2048];
  buckets_sentinel_url(endpoint, dcr, stream, url, sizeof(url));
  const char *bs = env("BUCKETS_AUDIT_SENTINEL_BATCH_SIZE"), *qs = env("BUCKETS_AUDIT_SENTINEL_QUEUE_SIZE");
  buckets_http_target_cfg cfg = {
      .name = "audit-sentinel",
      .endpoint = url,
      .ca_file = ca_file,
      .user_agent = "Buckets (audit to Sentinel)",
      .deployment_id = deployment_id,
      .batch_size = bs ? atoi(bs) : 100,
      .queue_size = qs ? atoi(qs) : 100000,
      .queue_dir = env("BUCKETS_AUDIT_SENTINEL_QUEUE_DIR"),
      .max_retry = 0,
      .retry_interval_ms = 3000,
      .http_timeout_ms = 15000,
      .json_array = true,
      .bearer = bearer,
      .bearer_ud = a,
  };
  return buckets_http_target_new(&cfg, err, errlen);
}
