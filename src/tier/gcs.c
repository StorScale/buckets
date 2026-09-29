/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Google Cloud Storage warm backend (MinIO's warm-backend-gcs.go):
 * objects over the JSON API, authorized with OAuth tokens from the tier's
 * credentials.json (a service account's signed JWT, or an authorized
 * user's refresh token). STORAGE_EMULATOR_HOST points it at an emulator
 * without authorization, as Google's Go client does. */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "crypto/base64.h"
#include "net/fetch.h"
#include "tier/internal.h"

#define GCS_DEFAULT "https://storage.googleapis.com"
#define GCS_SCOPE "https://www.googleapis.com/auth/devstorage.read_write"

typedef struct {
  buckets_warm base;
  buckets_http_client *c;
  char *base_path; /* the endpoint's path prefix, usually "" */
  bool anonymous;  /* an emulator */
  /* credentials */
  char *type, *client_email, *private_key, *token_uri, *client_id, *client_secret, *refresh_token;
  pthread_mutex_t mu;
  char *token;
  time_t token_exp;
  char *bucket, *prefix, *storage_class;
} warm_gcs;

/* ---- OAuth -------------------------------------------------------------------------------- */

static void b64url(const void *p, size_t n, buckets_buf *out) {
  char *s = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
  buckets_base64url_raw_encode(p, n, s);
  buckets_buf_append_c(out, s);
  free(s);
}

/* A JWT signed with the service account's key (RS256). */
static bool service_jwt(warm_gcs *w, buckets_buf *out, char *err, size_t errlen) {
  long long now = (long long)time(NULL);
  buckets_buf claims = BUCKETS_BUF_INIT;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *r = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, r);
  yyjson_mut_obj_add_strcpy(d, r, "iss", w->client_email);
  yyjson_mut_obj_add_str(d, r, "scope", GCS_SCOPE);
  yyjson_mut_obj_add_strcpy(d, r, "aud", w->token_uri);
  yyjson_mut_obj_add_int(d, r, "exp", now + 3600);
  yyjson_mut_obj_add_int(d, r, "iat", now);
  size_t cl;
  char *cj = yyjson_mut_write(d, 0, &cl);
  yyjson_mut_doc_free(d);
  b64url("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", 27, out);
  buckets_buf_append_c(out, ".");
  b64url(cj, cl, out);
  free(cj);
  buckets_buf_free(&claims);
  BIO *bio = BIO_new_mem_buf(w->private_key, -1);
  EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
  BIO_free(bio);
  if (!key) {
    snprintf(err, errlen, "unable to parse the service account's private key");
    return false;
  }
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  size_t sl = 0;
  bool ok = EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) == 1 &&
            EVP_DigestSign(md, NULL, &sl, (const uint8_t *)out->data, out->len) == 1;
  uint8_t *sig = ok ? buckets_xmalloc(sl) : NULL;
  ok = ok && EVP_DigestSign(md, sig, &sl, (const uint8_t *)out->data, out->len) == 1;
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(key);
  if (ok) {
    buckets_buf_append_c(out, ".");
    b64url(sig, sl, out);
  } else {
    snprintf(err, errlen, "unable to sign the token request");
  }
  free(sig);
  return ok;
}

static bool access_token(warm_gcs *w, char *out, size_t cap, char *err, size_t errlen) {
  pthread_mutex_lock(&w->mu);
  if (w->token && time(NULL) + 60 < w->token_exp) {
    snprintf(out, cap, "%s", w->token);
    pthread_mutex_unlock(&w->mu);
    return true;
  }
  pthread_mutex_unlock(&w->mu);
  buckets_buf body = BUCKETS_BUF_INIT;
  if (strcmp(w->type, "authorized_user") == 0) {
    buckets_buf_append_c(&body, "grant_type=refresh_token&client_id=");
    buckets_url_encode(&body, w->client_id, false);
    buckets_buf_append_c(&body, "&client_secret=");
    buckets_url_encode(&body, w->client_secret, false);
    buckets_buf_append_c(&body, "&refresh_token=");
    buckets_url_encode(&body, w->refresh_token, false);
  } else {
    buckets_buf jwt = BUCKETS_BUF_INIT;
    if (!service_jwt(w, &jwt, err, errlen)) {
      buckets_buf_free(&jwt);
      buckets_buf_free(&body);
      return false;
    }
    buckets_buf_append_c(&body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=");
    buckets_buf_append(&body, jwt.data, jwt.len);
    buckets_buf_free(&jwt);
  }
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result r;
  bool ok = buckets_fetch("POST", w->token_uri, NULL, h, 1, body.data, body.len, 30000, &r, err, errlen);
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
    snprintf(err, errlen, "oauth2: cannot fetch token: HTTP %d", r.status);
  }
  yyjson_doc_free(d);
  buckets_http_result_free(&r);
  return tok != NULL;
}

/* ---- requests ----------------------------------------------------------------------------- */

/* gcsToObjectError, from the JSON error document */
static buckets_warm_err gcs_error(int status, const buckets_buf *body, bool object, char *err, size_t errlen) {
  yyjson_doc *d = body && body->len ? yyjson_read(body->data, body->len, 0) : NULL;
  yyjson_val *e = yyjson_obj_get(yyjson_doc_get_root(d), "error");
  const char *msg = yyjson_get_str(yyjson_obj_get(e, "message"));
  yyjson_val *first = yyjson_arr_get_first(yyjson_obj_get(e, "errors"));
  const char *reason = yyjson_get_str(yyjson_obj_get(first, "reason"));
  snprintf(err, errlen, "googleapi: Error %d: %s", status, msg ? msg : "unexpected response");
  buckets_warm_err we = BUCKETS_WARM_ERR_OTHER;
  if (status == 404 || (reason && strcmp(reason, "notFound") == 0)) {
    bool bucket_msg = msg && strstr(msg, "bucket") && !strstr(msg, "object");
    we = object && !bucket_msg ? BUCKETS_WARM_ERR_NOT_FOUND : BUCKETS_WARM_ERR_BUCKET;
    if (we == BUCKETS_WARM_ERR_BUCKET) snprintf(err, errlen, "Bucket not found");
  } else if (status == 401 || (reason && (strcmp(reason, "keyInvalid") == 0 || strcmp(reason, "required") == 0))) {
    we = BUCKETS_WARM_ERR_CREDENTIALS;
  }
  yyjson_doc_free(d);
  return we;
}

static buckets_warm_err gcs_do(warm_gcs *w, const char *method, const char *target, const buckets_http_kv *extra,
                               size_t nextra, buckets_http_read_fn rd, void *rd_ud, int64_t length, bool object,
                               buckets_http_stream **stream, buckets_buf *body, char *err, size_t errlen) {
  buckets_http_kv h[8];
  size_t nh = 0;
  for (size_t i = 0; i < nextra && nh < 6; i++) h[nh++] = extra[i];
  char auth[4200];
  if (!w->anonymous) {
    char tok[4096];
    if (!access_token(w, tok, sizeof(tok), err, errlen)) return BUCKETS_WARM_ERR_CREDENTIALS;
    snprintf(auth, sizeof(auth), "Bearer %s", tok);
    h[nh++] = (buckets_http_kv){"Authorization", auth};
  }
  int status = 0;
  buckets_buf headers = BUCKETS_BUF_INIT;
  buckets_http_stream *st = buckets_http_client_open(w->c, method, target, h, nh, rd, rd_ud, length, &status, &headers);
  buckets_buf_free(&headers);
  if (!st) {
    snprintf(err, errlen, "%s", *buckets_http_client_dial_error(w->c) ? buckets_http_client_dial_error(w->c)
                                                                     : "connection failed");
    return BUCKETS_WARM_ERR_DOWN;
  }
  if (status / 100 == 2 && stream) {
    *stream = st;
    return BUCKETS_WARM_OK;
  }
  buckets_buf b = BUCKETS_BUF_INIT;
  char tmp[8192];
  long k;
  while ((k = buckets_http_stream_read(st, tmp, sizeof(tmp))) > 0) buckets_buf_append(&b, tmp, (size_t)k);
  buckets_http_stream_free(st);
  buckets_warm_err e = BUCKETS_WARM_OK;
  if (status / 100 != 2) e = gcs_error(status, &b, object, err, errlen);
  else if (body) buckets_buf_append(body, b.data, b.len);
  buckets_buf_free(&b);
  return e;
}

static void object_target(warm_gcs *w, const char *object, const char *query, buckets_buf *out) {
  buckets_buf_appendf(out, "%s/storage/v1/b/", w->base_path);
  buckets_url_encode(out, w->bucket, false);
  buckets_buf_append_c(out, "/o/");
  buckets_buf dest = BUCKETS_BUF_INIT;
  buckets_warm_dest(w->prefix, object, &dest);
  buckets_url_encode(out, dest.data, false); /* '/' too */
  buckets_buf_free(&dest);
  if (query) {
    buckets_buf_append_c(out, "?");
    buckets_buf_append_c(out, query);
  }
}

/* The multipart/related upload body: the metadata part, then the bytes. */
typedef struct {
  const char *head;
  size_t head_n, head_off;
  buckets_http_read_fn rd;
  void *ud;
  int64_t left;
  const char *tail;
  size_t tail_n, tail_off;
} upload_body;

static long upload_read(void *ud, void *buf, size_t n) {
  upload_body *u = ud;
  if (u->head_off < u->head_n) {
    size_t k = BUCKETS_MIN(n, u->head_n - u->head_off);
    memcpy(buf, u->head + u->head_off, k);
    u->head_off += k;
    return (long)k;
  }
  if (u->left > 0) {
    long k = u->rd(u->ud, buf, (size_t)BUCKETS_MIN((int64_t)n, u->left));
    if (k > 0) u->left -= k;
    return k > 0 ? k : -1; /* the source may not end early */
  }
  size_t k = BUCKETS_MIN(n, u->tail_n - u->tail_off);
  memcpy(buf, u->tail + u->tail_off, k);
  u->tail_off += k;
  return (long)k;
}

static buckets_warm_err gcs_put(buckets_warm *bw, const char *object, buckets_http_read_fn rd, void *rd_ud,
                                int64_t length, const char *orig_name, char *rv, size_t rvcap, char *err, size_t errlen) {
  warm_gcs *w = (warm_gcs *)bw;
  (void)rv, (void)rvcap; /* MinIO keeps no remote version for GCS */
  buckets_buf dest = BUCKETS_BUF_INIT;
  buckets_warm_dest(w->prefix, object, &dest);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *r = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, r);
  yyjson_mut_obj_add_strcpy(d, r, "name", dest.data);
  if (*w->storage_class) yyjson_mut_obj_add_strcpy(d, r, "storageClass", w->storage_class);
  if (orig_name) {
    yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, r, "metadata");
    yyjson_mut_obj_add_strcpy(d, m, "name", orig_name);
  }
  char *meta = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  static const char boundary[] = "buckets-tier-boundary-7c1f4e";
  buckets_buf head = BUCKETS_BUF_INIT, tail = BUCKETS_BUF_INIT, target = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&head, "--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n--%s\r\nContent-Type: "
                             "application/octet-stream\r\n\r\n",
                      boundary, meta, boundary);
  buckets_buf_appendf(&tail, "\r\n--%s--\r\n", boundary);
  free(meta);
  buckets_buf_appendf(&target, "%s/upload/storage/v1/b/", w->base_path);
  buckets_url_encode(&target, w->bucket, false);
  buckets_buf_append_c(&target, "/o?uploadType=multipart");
  char ctype[128];
  snprintf(ctype, sizeof(ctype), "multipart/related; boundary=%s", boundary);
  buckets_http_kv h[] = {{"Content-Type", ctype}};
  upload_body u = {head.data, head.len, 0, rd, rd_ud, length, tail.data, tail.len, 0};
  buckets_warm_err e = gcs_do(w, "POST", target.data, h, 1, upload_read, &u, (int64_t)(head.len + tail.len) + length,
                              false, NULL, NULL, err, errlen);
  buckets_buf_free(&head);
  buckets_buf_free(&tail);
  buckets_buf_free(&target);
  buckets_buf_free(&dest);
  return e;
}

static buckets_warm_err gcs_get(buckets_warm *bw, const char *object, const char *rv, int64_t off, int64_t len,
                                buckets_warm_stream **out, char *err, size_t errlen) {
  (void)rv;
  warm_gcs *w = (warm_gcs *)bw;
  buckets_buf target = BUCKETS_BUF_INIT;
  object_target(w, object, "alt=media", &target);
  char range[80];
  buckets_http_kv h[2];
  size_t nh = 0;
  h[nh++] = (buckets_http_kv){"Accept-Encoding", "gzip"}; /* ReadCompressed: the bytes as stored */
  if (off > 0 || len >= 0) {
    if (len >= 0) snprintf(range, sizeof(range), "bytes=%lld-%lld", (long long)off, (long long)(off + len - 1));
    else snprintf(range, sizeof(range), "bytes=%lld-", (long long)off);
    h[nh++] = (buckets_http_kv){"Range", range};
  }
  buckets_http_stream *st = NULL;
  buckets_warm_err e = gcs_do(w, "GET", target.data, h, nh, NULL, NULL, 0, true, &st, NULL, err, errlen);
  buckets_buf_free(&target);
  if (!e) {
    buckets_warm_stream *s = buckets_xcalloc(1, sizeof(*s));
    s->body = st;
    s->remaining = len >= 0 ? len : -1;
    *out = s;
  }
  return e;
}

static buckets_warm_err gcs_remove(buckets_warm *bw, const char *object, const char *rv, char *err, size_t errlen) {
  (void)rv;
  warm_gcs *w = (warm_gcs *)bw;
  buckets_buf target = BUCKETS_BUF_INIT;
  object_target(w, object, NULL, &target);
  buckets_warm_err e = gcs_do(w, "DELETE", target.data, NULL, 0, NULL, NULL, 0, true, NULL, NULL, err, errlen);
  buckets_buf_free(&target);
  return e;
}

static buckets_warm_err gcs_in_use(buckets_warm *bw, bool *in_use, char *err, size_t errlen) {
  warm_gcs *w = (warm_gcs *)bw;
  buckets_buf target = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&target, "%s/storage/v1/b/", w->base_path);
  buckets_url_encode(&target, w->bucket, false);
  buckets_buf_append_c(&target, "/o?delimiter=%2F&maxResults=1&prefix=");
  buckets_url_encode(&target, w->prefix, false);
  buckets_warm_err e = gcs_do(w, "GET", target.data, NULL, 0, NULL, NULL, 0, false, NULL, &body, err, errlen);
  if (!e) {
    yyjson_doc *d = yyjson_read(body.data ? body.data : "{}", body.len ? body.len : 2, 0);
    yyjson_val *r = yyjson_doc_get_root(d);
    *in_use = yyjson_arr_size(yyjson_obj_get(r, "items")) > 0 || yyjson_arr_size(yyjson_obj_get(r, "prefixes")) > 0;
    yyjson_doc_free(d);
  }
  buckets_buf_free(&target);
  buckets_buf_free(&body);
  return e;
}

static void gcs_destroy(buckets_warm *bw) {
  warm_gcs *w = (warm_gcs *)bw;
  buckets_http_client_free(w->c);
  free(w->base_path);
  free(w->type);
  free(w->client_email);
  free(w->private_key);
  free(w->token_uri);
  free(w->client_id);
  free(w->client_secret);
  free(w->refresh_token);
  free(w->token);
  free(w->bucket);
  free(w->prefix);
  free(w->storage_class);
  pthread_mutex_destroy(&w->mu);
  free(w);
}

static const buckets_warm_ops k_gcs_ops = {gcs_put, gcs_get, gcs_remove, gcs_in_use, gcs_destroy};

static char *jdup(yyjson_val *o, const char *k) {
  const char *s = yyjson_get_str(yyjson_obj_get(o, k));
  return buckets_xstrdup(s ? s : "");
}

buckets_warm *buckets_warm_gcs_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen) {
  if (!*t->gcs.creds) {
    snprintf(err, errlen, "empty credentials unsupported");
    return NULL;
  }
  if (!*t->gcs.bucket) {
    snprintf(err, errlen, "no bucket name was provided");
    return NULL;
  }
  /* GetCredentialJSON: base64.URLEncoding */
  size_t cn = strlen(t->gcs.creds);
  uint8_t *cj = buckets_xmalloc(cn * 3 / 4 + 4);
  long k = buckets_base64url_decode(t->gcs.creds, cn, cj);
  yyjson_doc *doc = k >= 0 ? yyjson_read((const char *)cj, (size_t)k, 0) : NULL;
  free(cj);
  yyjson_val *r = yyjson_doc_get_root(doc);
  if (!yyjson_is_obj(r)) {
    yyjson_doc_free(doc);
    snprintf(err, errlen, "invalid credentials JSON");
    return NULL;
  }
  warm_gcs *w = buckets_xcalloc(1, sizeof(*w));
  w->base.ops = &k_gcs_ops;
  pthread_mutex_init(&w->mu, NULL);
  w->type = jdup(r, "type");
  w->client_email = jdup(r, "client_email");
  w->private_key = jdup(r, "private_key");
  w->token_uri = jdup(r, "token_uri");
  if (!*w->token_uri) {
    free(w->token_uri);
    w->token_uri = buckets_xstrdup("https://oauth2.googleapis.com/token");
  }
  w->client_id = jdup(r, "client_id");
  w->client_secret = jdup(r, "client_secret");
  w->refresh_token = jdup(r, "refresh_token");
  yyjson_doc_free(doc);
  /* the endpoint: STORAGE_EMULATOR_HOST (anonymous), else Google's */
  const char *emu = getenv("STORAGE_EMULATOR_HOST");
  char ep[1024];
  if (emu && *emu) {
    snprintf(ep, sizeof(ep), "%s%s", strstr(emu, "://") ? "" : "http://", emu);
    w->anonymous = true;
  } else {
    snprintf(ep, sizeof(ep), "%s", GCS_DEFAULT);
    if (strcmp(w->type, "service_account") != 0 && strcmp(w->type, "authorized_user") != 0) {
      snprintf(err, errlen, "unsupported credentials type \"%s\"", w->type);
      gcs_destroy(&w->base);
      return NULL;
    }
  }
  bool secure = strncmp(ep, "https://", 8) == 0;
  const char *hp = ep + (secure ? 8 : 7);
  size_t hl = strcspn(hp, "/");
  char host[512];
  snprintf(host, sizeof(host), "%.*s", (int)hl, hp);
  int port = secure ? 443 : 80;
  char *colon = strrchr(host, ':');
  if (colon && !strchr(colon, ']')) {
    port = atoi(colon + 1);
    *colon = '\0';
  }
  const char *bp = hp + hl;
  size_t bl = strlen(bp);
  while (bl && bp[bl - 1] == '/') bl--;
  w->base_path = buckets_xstrndup(bp, bl);
  w->c = buckets_http_client_new(host, port, secure ? tls : NULL, 15 * 60 * 1000);
  w->bucket = buckets_xstrdup(t->gcs.bucket);
  w->prefix = buckets_xstrdup(t->gcs.prefix); /* MinIO does not trim it for GCS */
  w->storage_class = buckets_xstrdup(t->gcs.storage_class);
  return &w->base;
}
