/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Azure Blob Storage warm backend (MinIO's warm-backend-azure.go): block
 * blobs over the REST API, authorized with the account's shared key or a
 * service principal's OAuth token. */
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/sha256.h"
#include "net/fetch.h"
#include "tier/internal.h"

#define AZ_VERSION "2021-08-06"
#define AZ_SINGLE_PUT_MAX (256LL * 1024 * 1024)
#define AZ_BLOCK_SIZE (64LL * 1024 * 1024)

typedef struct {
  buckets_warm base;
  buckets_http_client *c;
  char host[512]; /* the Host header */
  char *base_path; /* "" or the endpoint's path ("/devstoreaccount1" for Azurite) */
  char *account;
  uint8_t *key;
  size_t key_len;
  bool sp; /* service principal */
  char *tenant, *client_id, *client_secret;
  pthread_mutex_t mu;
  char *token;
  time_t token_exp;
  char *container, *prefix, *access_tier;
} warm_azure;

/* URI-encodes a blob name, keeping '/' (url.PathEscape per segment). */
static void path_escape(buckets_buf *out, const char *s) { buckets_url_encode(out, s, true); }

static void blob_path(warm_azure *w, const char *object, buckets_buf *out) {
  buckets_buf_append_c(out, w->base_path);
  buckets_buf_append_c(out, "/");
  path_escape(out, w->container);
  if (object) {
    buckets_buf_append_c(out, "/");
    buckets_buf dest = BUCKETS_BUF_INIT;
    buckets_warm_dest(w->prefix, object, &dest);
    path_escape(out, dest.data);
    buckets_buf_free(&dest);
  }
}

static int kv_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_http_kv *)a)->name, ((const buckets_http_kv *)b)->name);
}

/* The SharedKey signature over the request (the storage services' scheme). */
static void shared_key(warm_azure *w, const char *method, const char *path, const char *query, buckets_http_kv *h,
                       size_t nh, int64_t length, char *auth, size_t cap) {
  const char *std[] = {"Content-Encoding", "Content-Language", NULL, "Content-MD5", "Content-Type", "Date",
                       "If-Modified-Since", "If-Match", "If-None-Match", "If-Unmodified-Since", "Range"};
  buckets_buf s = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&s, method);
  buckets_buf_append_c(&s, "\n");
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(std); k++) {
    if (!std[k]) { /* Content-Length: empty when zero */
      if (length > 0) buckets_buf_appendf(&s, "%lld", (long long)length);
    } else {
      for (size_t i = 0; i < nh; i++)
        if (strcasecmp(h[i].name, std[k]) == 0) buckets_buf_append_c(&s, h[i].value);
    }
    buckets_buf_append_c(&s, "\n");
  }
  /* x-ms-* headers, lower-cased and sorted */
  buckets_http_kv ms[16];
  char names[16][64];
  size_t nm = 0;
  for (size_t i = 0; i < nh && nm < 16; i++) {
    if (strncasecmp(h[i].name, "x-ms-", 5) != 0) continue;
    size_t j = 0;
    for (; h[i].name[j] && j < 63; j++) names[nm][j] = (char)tolower((unsigned char)h[i].name[j]);
    names[nm][j] = '\0';
    ms[nm] = (buckets_http_kv){names[nm], h[i].value};
    nm++;
  }
  qsort(ms, nm, sizeof(ms[0]), kv_cmp);
  for (size_t i = 0; i < nm; i++) buckets_buf_appendf(&s, "%s:%s\n", ms[i].name, ms[i].value);
  /* canonicalized resource: /account + escaped path, then the sorted query */
  buckets_buf_appendf(&s, "/%s%s", w->account, path);
  if (query && *query) {
    char *q = buckets_xstrdup(query);
    char *parts[16];
    size_t np = 0;
    for (char *tok = strtok(q, "&"); tok && np < 16; tok = strtok(NULL, "&")) parts[np++] = tok;
    for (size_t i = 1; i < np; i++)
      for (size_t j = i; j > 0 && strcmp(parts[j - 1], parts[j]) > 0; j--) {
        char *t = parts[j];
        parts[j] = parts[j - 1];
        parts[j - 1] = t;
      }
    for (size_t i = 0; i < np; i++) {
      char *eq = strchr(parts[i], '=');
      if (eq) *eq = '\0';
      buckets_buf dec = BUCKETS_BUF_INIT;
      const char *v = eq ? eq + 1 : "";
      /* values are sent escaped; the string to sign has them decoded */
      for (const char *p = v; *p; p++) {
        if (*p == '%' && p[1] && p[2]) {
          char hx[3] = {p[1], p[2], 0};
          buckets_buf_append_char(&dec, (char)strtol(hx, NULL, 16));
          p += 2;
        } else {
          buckets_buf_append_char(&dec, *p);
        }
      }
      for (char *k = parts[i]; *k; k++) *k = (char)tolower((unsigned char)*k);
      buckets_buf_appendf(&s, "\n%s:%s", parts[i], dec.data ? dec.data : "");
      buckets_buf_free(&dec);
    }
    free(q);
  }
  uint8_t mac[32];
  buckets_hmac_sha256(w->key, w->key_len, s.data, s.len, mac);
  char b64[64];
  buckets_base64_encode(mac, 32, b64);
  snprintf(auth, cap, "SharedKey %s:%s", w->account, b64);
  buckets_buf_free(&s);
}

/* The service principal's token (client credentials), cached until near its expiry. */
static bool sp_token(warm_azure *w, char *out, size_t cap, char *err, size_t errlen) {
  pthread_mutex_lock(&w->mu);
  if (w->token && time(NULL) + 60 < w->token_exp) {
    snprintf(out, cap, "%s", w->token);
    pthread_mutex_unlock(&w->mu);
    return true;
  }
  pthread_mutex_unlock(&w->mu);
  char url[512];
  snprintf(url, sizeof(url), "https://login.microsoftonline.com/%s/oauth2/v2.0/token", w->tenant);
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&body, "grant_type=client_credentials&scope=https%3A%2F%2Fstorage.azure.com%2F.default&client_id=");
  buckets_url_encode(&body, w->client_id, false);
  buckets_buf_append_c(&body, "&client_secret=");
  buckets_url_encode(&body, w->client_secret, false);
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result r;
  bool ok = buckets_fetch("POST", url, NULL, h, 1, body.data, body.len, 30000, &r, err, errlen);
  buckets_buf_free(&body);
  if (!ok) return false;
  yyjson_doc *d = r.status == 200 ? yyjson_read(r.body.data, r.body.len, 0) : NULL;
  const char *tok = d ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "access_token")) : NULL;
  int64_t exp = d ? yyjson_get_int(yyjson_obj_get(yyjson_doc_get_root(d), "expires_in")) : 0;
  if (tok) {
    pthread_mutex_lock(&w->mu);
    free(w->token);
    w->token = buckets_xstrdup(tok);
    w->token_exp = time(NULL) + (exp > 0 ? exp : 3600);
    pthread_mutex_unlock(&w->mu);
    snprintf(out, cap, "%s", tok);
  } else {
    snprintf(err, errlen, "unable to get a token for the service principal (HTTP %d)", r.status);
  }
  yyjson_doc_free(d);
  buckets_http_result_free(&r);
  return tok != NULL;
}

/* The common headers and the authorization of one request; h has room for 4 more. */
static bool authorize(warm_azure *w, const char *method, const char *path, const char *query, buckets_http_kv *h,
                      size_t *nh, int64_t length, char date[40], char *auth, size_t cap, char *err, size_t errlen) {
  buckets_time_http(time(NULL), date);
  h[(*nh)++] = (buckets_http_kv){"x-ms-date", date};
  h[(*nh)++] = (buckets_http_kv){"x-ms-version", AZ_VERSION};
  if (w->sp) {
    char tok[4096];
    if (!sp_token(w, tok, sizeof(tok), err, errlen)) return false;
    snprintf(auth, cap, "Bearer %s", tok);
  } else {
    shared_key(w, method, path, query, h, *nh, length, auth, cap);
  }
  h[(*nh)++] = (buckets_http_kv){"Authorization", auth};
  return true;
}

/* azureToObjectError */
static buckets_warm_err az_error(int status, const buckets_buf *headers, const buckets_buf *body, bool object, char *err,
                                 size_t errlen) {
  char code[128] = "", msg[512] = "";
  size_t n;
  const char *h = buckets_http_headers_get(headers, "x-ms-error-code", &n);
  if (h) snprintf(code, sizeof(code), "%.*s", (int)n, h);
  if (body && body->data) {
    const char *m = strstr(body->data, "<Message>"), *e = m ? strstr(m, "</Message>") : NULL;
    if (m && e) snprintf(msg, sizeof(msg), "%.*s", (int)(e - m - 9), m + 9);
    const char *cs = strstr(body->data, "<Code>"), *ce = cs ? strstr(cs, "</Code>") : NULL;
    if (!*code && cs && ce) snprintf(code, sizeof(code), "%.*s", (int)(ce - cs - 6), cs + 6);
  }
  char *nl = strchr(msg, '\n');
  if (nl) *nl = '\0';
  snprintf(err, errlen, "%s", *msg ? msg : *code ? code : "unexpected response");
  if (status == 0) return BUCKETS_WARM_ERR_DOWN;
  if (strcmp(code, "ContainerNotFound") == 0 || strcmp(code, "ContainerBeingDeleted") == 0) {
    snprintf(err, errlen, "Bucket not found");
    return BUCKETS_WARM_ERR_BUCKET;
  }
  if (strcmp(code, "AuthenticationFailed") == 0 || strcmp(code, "AuthorizationFailure") == 0)
    return BUCKETS_WARM_ERR_CREDENTIALS;
  if (status == 404) return object ? BUCKETS_WARM_ERR_NOT_FOUND : BUCKETS_WARM_ERR_BUCKET;
  return BUCKETS_WARM_ERR_OTHER;
}

static buckets_warm_err az_do(warm_azure *w, const char *method, const char *path, const char *query,
                              const buckets_http_kv *extra, size_t nextra, buckets_http_read_fn rd, void *rd_ud,
                              int64_t length, bool object, buckets_http_stream **stream, buckets_buf *body, char *err,
                              size_t errlen) {
  buckets_http_kv h[16];
  size_t nh = 0;
  for (size_t i = 0; i < nextra && nh < 10; i++) h[nh++] = extra[i];
  char date[40], auth[4200];
  if (!authorize(w, method, path, query, h, &nh, length, date, auth, sizeof(auth), err, errlen))
    return BUCKETS_WARM_ERR_CREDENTIALS;
  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&target, path);
  if (query && *query) {
    buckets_buf_append_c(&target, "?");
    buckets_buf_append_c(&target, query);
  }
  int status = 0;
  buckets_buf headers = BUCKETS_BUF_INIT;
  buckets_http_stream *st =
      buckets_http_client_open(w->c, method, target.data, h, nh, rd, rd_ud, length, &status, &headers);
  buckets_buf_free(&target);
  if (!st) {
    snprintf(err, errlen, "%s", *buckets_http_client_dial_error(w->c) ? buckets_http_client_dial_error(w->c)
                                                                     : "connection failed");
    buckets_buf_free(&headers);
    return BUCKETS_WARM_ERR_DOWN;
  }
  buckets_warm_err e = BUCKETS_WARM_OK;
  if (status / 100 != 2) {
    buckets_buf b = BUCKETS_BUF_INIT;
    char tmp[8192];
    long k;
    while ((k = buckets_http_stream_read(st, tmp, sizeof(tmp))) > 0) buckets_buf_append(&b, tmp, (size_t)k);
    buckets_http_stream_free(st);
    e = az_error(status, &headers, &b, object, err, errlen);
    buckets_buf_free(&b);
  } else if (stream) {
    *stream = st;
  } else {
    char tmp[8192];
    long k;
    while ((k = buckets_http_stream_read(st, tmp, sizeof(tmp))) > 0)
      if (body) buckets_buf_append(body, tmp, (size_t)k);
    buckets_http_stream_free(st);
  }
  buckets_buf_free(&headers);
  return e;
}

/* A window of the source stream (one block). */
typedef struct {
  buckets_http_read_fn rd;
  void *ud;
  int64_t left;
} window;

static long window_read(void *ud, void *buf, size_t n) {
  window *win = ud;
  if (win->left <= 0) return 0;
  long k = win->rd(win->ud, buf, (size_t)BUCKETS_MIN((int64_t)n, win->left));
  if (k > 0) win->left -= k;
  return k;
}

typedef struct {
  const char *p;
  size_t n, off;
} mem_src;

static long mem_read(void *ud, void *buf, size_t n) {
  mem_src *m = ud;
  size_t k = BUCKETS_MIN(n, m->n - m->off);
  memcpy(buf, m->p + m->off, k);
  m->off += k;
  return (long)k;
}

static buckets_warm_err az_put(buckets_warm *bw, const char *object, buckets_http_read_fn rd, void *rd_ud, int64_t length,
                               const char *orig_name, char *rv, size_t rvcap, char *err, size_t errlen) {
  warm_azure *w = (warm_azure *)bw;
  buckets_buf path = BUCKETS_BUF_INIT;
  blob_path(w, object, &path);
  buckets_http_kv h[4];
  size_t nh = 0;
  if (orig_name) h[nh++] = (buckets_http_kv){"x-ms-meta-name", orig_name};
  if (*w->access_tier) h[nh++] = (buckets_http_kv){"x-ms-access-tier", w->access_tier};
  buckets_warm_err e;
  if (length <= AZ_SINGLE_PUT_MAX) {
    h[nh++] = (buckets_http_kv){"x-ms-blob-type", "BlockBlob"};
    e = az_do(w, "PUT", path.data, NULL, h, nh, rd, rd_ud, length, true, NULL, NULL, err, errlen);
  } else { /* staged blocks, then the list */
    buckets_buf list = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&list, "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
    e = BUCKETS_WARM_OK;
    for (int64_t off = 0, i = 0; off < length && !e; off += AZ_BLOCK_SIZE, i++) {
      char raw[16], id[32];
      snprintf(raw, sizeof(raw), "%08lld", (long long)i);
      buckets_base64_encode((const uint8_t *)raw, strlen(raw), id);
      buckets_buf q = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&q, "blockid=");
      buckets_url_encode(&q, id, false);
      buckets_buf_append_c(&q, "&comp=block");
      window win = {rd, rd_ud, BUCKETS_MIN(AZ_BLOCK_SIZE, length - off)};
      e = az_do(w, "PUT", path.data, q.data, NULL, 0, window_read, &win, win.left, true, NULL, NULL, err, errlen);
      buckets_buf_free(&q);
      buckets_buf_appendf(&list, "<Latest>%s</Latest>", id);
    }
    buckets_buf_append_c(&list, "</BlockList>");
    if (!e) { /* the metadata and access tier go with the list */
      mem_src m = {list.data, list.len, 0};
      e = az_do(w, "PUT", path.data, "comp=blocklist", h, nh, mem_read, &m, (int64_t)list.len, true, NULL, NULL, err,
                errlen);
    }
    buckets_buf_free(&list);
  }
  buckets_buf_free(&path);
  (void)rv, (void)rvcap; /* VersionID only with blob versioning, not kept */
  return e;
}

static buckets_warm_err az_get(buckets_warm *bw, const char *object, const char *rv, int64_t off, int64_t len,
                               buckets_warm_stream **out, char *err, size_t errlen) {
  (void)rv;
  warm_azure *w = (warm_azure *)bw;
  buckets_buf path = BUCKETS_BUF_INIT;
  blob_path(w, object, &path);
  char range[80];
  buckets_http_kv h[1];
  size_t nh = 0;
  if (off > 0 || len >= 0) {
    if (len >= 0) snprintf(range, sizeof(range), "bytes=%lld-%lld", (long long)off, (long long)(off + len - 1));
    else snprintf(range, sizeof(range), "bytes=%lld-", (long long)off);
    h[nh++] = (buckets_http_kv){"x-ms-range", range};
  }
  buckets_http_stream *st = NULL;
  buckets_warm_err e = az_do(w, "GET", path.data, NULL, h, nh, NULL, NULL, 0, true, &st, NULL, err, errlen);
  buckets_buf_free(&path);
  if (!e) {
    buckets_warm_stream *s = buckets_xcalloc(1, sizeof(*s));
    s->body = st;
    s->remaining = len >= 0 ? len : -1;
    *out = s;
  }
  return e;
}

static buckets_warm_err az_remove(buckets_warm *bw, const char *object, const char *rv, char *err, size_t errlen) {
  (void)rv;
  warm_azure *w = (warm_azure *)bw;
  buckets_buf path = BUCKETS_BUF_INIT;
  blob_path(w, object, &path);
  buckets_warm_err e = az_do(w, "DELETE", path.data, NULL, NULL, 0, NULL, NULL, 0, true, NULL, NULL, err, errlen);
  buckets_buf_free(&path);
  return e;
}

static buckets_warm_err az_in_use(buckets_warm *bw, bool *in_use, char *err, size_t errlen) {
  warm_azure *w = (warm_azure *)bw;
  buckets_buf path = BUCKETS_BUF_INIT, q = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  blob_path(w, NULL, &path);
  buckets_buf_append_c(&q, "comp=list&maxresults=1&prefix=");
  buckets_url_encode(&q, w->prefix, false);
  buckets_buf_append_c(&q, "&restype=container");
  buckets_warm_err e = az_do(w, "GET", path.data, q.data, NULL, 0, NULL, NULL, 0, false, NULL, &body, err, errlen);
  if (!e) *in_use = body.data && strstr(body.data, "<Blob>");
  buckets_buf_free(&path);
  buckets_buf_free(&q);
  buckets_buf_free(&body);
  return e;
}

static void az_destroy(buckets_warm *bw) {
  warm_azure *w = (warm_azure *)bw;
  buckets_http_client_free(w->c);
  free(w->base_path);
  free(w->account);
  free(w->key);
  free(w->tenant);
  free(w->client_id);
  free(w->client_secret);
  free(w->token);
  free(w->container);
  free(w->prefix);
  free(w->access_tier);
  pthread_mutex_destroy(&w->mu);
  free(w);
}

static const buckets_warm_ops k_azure_ops = {az_put, az_get, az_remove, az_in_use, az_destroy};

/* blob.PossibleAccessTierValues, matched case-insensitively (else none) */
static const char *access_tier(const char *sc) {
  static const char *const tiers[] = {"Archive", "Cold", "Cool", "Hot", "P10", "P15", "P20", "P30", "P4", "P40",
                                      "P50", "P6", "P60", "P70", "P80", "Premium"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(tiers); i++)
    if (strcasecmp(sc, tiers[i]) == 0) return tiers[i];
  return "";
}

buckets_warm *buckets_warm_azure_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen) {
  bool sp = *t->azure.sp_tenant_id && *t->azure.sp_client_id && *t->azure.sp_client_secret;
  bool any_sp = *t->azure.sp_tenant_id || *t->azure.sp_client_id || *t->azure.sp_client_secret;
  if (!*t->azure.account_name) {
    snprintf(err, errlen, "the account name is required");
    return NULL;
  }
  if (*t->azure.account_key && any_sp) {
    snprintf(err, errlen, "multiple authentication mechanisms are provided");
    return NULL;
  }
  if (!*t->azure.account_key && !sp) {
    snprintf(err, errlen, "no authentication mechanism was provided");
    return NULL;
  }
  if (!*t->azure.bucket) {
    snprintf(err, errlen, "no bucket name was provided");
    return NULL;
  }
  char ep[1024];
  if (*t->azure.endpoint) snprintf(ep, sizeof(ep), "%s", t->azure.endpoint);
  else snprintf(ep, sizeof(ep), "https://%s.blob.core.windows.net", t->azure.account_name);
  bool secure = strncmp(ep, "https://", 8) == 0;
  if (!secure && strncmp(ep, "http://", 7) != 0) {
    snprintf(err, errlen, "parse \"%s\": invalid URI for request", ep);
    return NULL;
  }
  const char *hp = ep + (secure ? 8 : 7);
  size_t hl = strcspn(hp, "/");
  warm_azure *w = buckets_xcalloc(1, sizeof(*w));
  w->base.ops = &k_azure_ops;
  pthread_mutex_init(&w->mu, NULL);
  snprintf(w->host, sizeof(w->host), "%.*s", (int)hl, hp);
  const char *bp = hp + hl;
  size_t bl = strlen(bp);
  while (bl && bp[bl - 1] == '/') bl--;
  w->base_path = buckets_xstrndup(bp, bl);
  char host[512];
  int port = secure ? 443 : 80;
  const char *colon = strrchr(w->host, ':');
  if (colon && !strchr(colon, ']')) {
    snprintf(host, sizeof(host), "%.*s", (int)(colon - w->host), w->host);
    port = atoi(colon + 1);
  } else {
    snprintf(host, sizeof(host), "%s", w->host);
  }
  w->c = buckets_http_client_new(host, port, secure ? tls : NULL, 15 * 60 * 1000);
  w->account = buckets_xstrdup(t->azure.account_name);
  w->sp = sp;
  if (!sp) {
    size_t kl = strlen(t->azure.account_key);
    w->key = buckets_xmalloc(kl * 3 / 4 + 4);
    long k = buckets_base64_decode(t->azure.account_key, kl, w->key);
    if (k < 0) {
      snprintf(err, errlen, "decode account key: illegal base64 data");
      az_destroy(&w->base);
      return NULL;
    }
    w->key_len = (size_t)k;
  }
  w->tenant = buckets_xstrdup(t->azure.sp_tenant_id);
  w->client_id = buckets_xstrdup(t->azure.sp_client_id);
  w->client_secret = buckets_xstrdup(t->azure.sp_client_secret);
  w->container = buckets_xstrdup(t->azure.bucket);
  size_t pl = strlen(t->azure.prefix);
  if (pl && t->azure.prefix[pl - 1] == '/') pl--;
  w->prefix = buckets_xstrndup(t->azure.prefix, pl);
  w->access_tier = buckets_xstrdup(access_tier(t->azure.storage_class));
  return &w->base;
}
