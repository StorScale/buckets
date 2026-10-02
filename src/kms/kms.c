/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "kms/kms.h"

#include <openssl/crypto.h>
#include <stdatomic.h>
#include <time.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "config/config.h"
#include "core/common.h"
#include "erasure/layout.h"
#include "net/client.h"
#include "net/tls.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/sha256.h"
#include "notify/event.h"

typedef enum { KMS_BUILTIN, KMS_KES } kms_kind;

struct buckets_kms {
  kms_kind kind;
  char *key_id; /* the (default) key */
  uint8_t key[32];
  /* KES */
  char **eps;
  size_t neps;
  buckets_http_client **cli;
  buckets_tls_client *tls;
  _Atomic unsigned rr;
  _Atomic uint64_t ok, err, fail;
  _Atomic uint64_t latency[BUCKETS_KMS_LATENCY_BUCKETS];
};

const int64_t buckets_kms_latency_ms[BUCKETS_KMS_LATENCY_BUCKETS] = {10, 50, 100, 250, 500, 1000, 1500, 3000, 5000, 10000};

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* updateMetrics: the first bucket at least as large as the latency and all
 * after it; not-supported (5xx) failures count as failures, other KMS errors
 * as errors. */
static buckets_kms_err metered(buckets_kms *k, int64_t start, buckets_kms_err e) {
  int64_t ms = (mono_ns() - start) / 1000000LL;
  int b = 0;
  while (b < BUCKETS_KMS_LATENCY_BUCKETS - 1 && ms >= buckets_kms_latency_ms[b]) b++;
  for (int i = b; i < BUCKETS_KMS_LATENCY_BUCKETS; i++) atomic_fetch_add(&k->latency[i], 1);
  if (e == BUCKETS_KMS_OK) atomic_fetch_add(&k->ok, 1);
  else if (e == BUCKETS_KMS_ERR_NOT_SUPPORTED || e == BUCKETS_KMS_ERR_UNAVAILABLE) atomic_fetch_add(&k->fail, 1);
  else atomic_fetch_add(&k->err, 1);
  return e;
}

void buckets_kms_metrics_get(buckets_kms *k, buckets_kms_metrics *out) {
  out->ok = atomic_load(&k->ok), out->err = atomic_load(&k->err), out->fail = atomic_load(&k->fail);
  for (int i = 0; i < BUCKETS_KMS_LATENCY_BUCKETS; i++) out->latency[i] = atomic_load(&k->latency[i]);
}

void buckets_kms_free(buckets_kms *k) {
  if (!k) return;
  for (size_t i = 0; i < k->neps; i++) {
    free(k->eps[i]);
    buckets_http_client_free(k->cli[i]);
  }
  free(k->eps);
  free(k->cli);
  buckets_tls_client_free(k->tls);
  free(k->key_id);
  OPENSSL_cleanse(k->key, sizeof(k->key));
  free(k);
}

/* ParseSecretKey */
buckets_kms *buckets_kms_builtin(const char *spec, char *err, size_t errlen) {
  const char *colon = strchr(spec, ':');
  if (!colon) {
    snprintf(err, errlen, "kms: invalid secret key format");
    return NULL;
  }
  const char *b64 = colon + 1;
  size_t bl = strlen(b64);
  uint8_t *key = buckets_xmalloc(bl + 3);
  long n = buckets_base64_decode(b64, bl, key);
  if (n < 0) {
    free(key);
    snprintf(err, errlen, "illegal base64 data");
    return NULL;
  }
  if (n != 32) {
    free(key);
    snprintf(err, errlen, "kms: invalid key length %ld", n);
    return NULL;
  }
  buckets_kms *k = buckets_xcalloc(1, sizeof(*k));
  k->key_id = buckets_xstrndup(spec, (size_t)(colon - spec));
  memcpy(k->key, key, 32);
  OPENSSL_cleanse(key, 32);
  free(key);
  return k;
}

static buckets_kms *kes_from_env(char *err, size_t errlen);

static bool env_set(const char *name) { return buckets_config_getenv(name) != NULL; }

static bool any_set(const char *const *names) {
  for (size_t i = 0; names[i]; i++)
    if (env_set(names[i])) return true;
  return false;
}

buckets_kms *buckets_kms_from_env(char *err, size_t errlen) {
  *err = '\0';
  /* IsPresent */
  static const char *const kms_vars[] = {"MINIO_KMS_SERVER", "MINIO_KMS_ENCLAVE", "MINIO_KMS_API_KEY",
                                         "MINIO_KMS_SSE_KEY", NULL};
  static const char *const kes_vars[] = {"MINIO_KMS_KES_ENDPOINT", "MINIO_KMS_KES_KEY_NAME", "MINIO_KMS_KES_API_KEY",
                                         "MINIO_KMS_KES_KEY_FILE", "MINIO_KMS_KES_CERT_FILE",
                                         "MINIO_KMS_KES_KEY_PASSWORD", "MINIO_KMS_KES_CAPATH", NULL};
  const char *sk = buckets_config_getenv("MINIO_KMS_SECRET_KEY"), *skf = buckets_config_getenv("MINIO_KMS_SECRET_KEY_FILE");
  bool kms_p = any_set(kms_vars), kes_p = any_set(kes_vars), static_p = (sk && *sk) || (skf && *skf);
  if (kms_p && kes_p) return snprintf(err, errlen, "kms: configuration for MinIO KMS and MinIO KES is present"), NULL;
  if (kms_p && static_p)
    return snprintf(err, errlen, "kms: configuration for MinIO KMS and static KMS key is present"), NULL;
  if (kes_p && static_p)
    return snprintf(err, errlen, "kms: configuration for MinIO KES and static KMS key is present"), NULL;
  if (kms_p) return snprintf(err, errlen, "kms: MinIO KMS (MINIO_KMS_SERVER) is not supported"), NULL;
  if (kes_p) return kes_from_env(err, errlen);
  const char *spec = buckets_config_getenv("MINIO_KMS_SECRET_KEY");
  const char *file = buckets_config_getenv("MINIO_KMS_SECRET_KEY_FILE");
  if (spec && *spec && file && *file) {
    snprintf(err, errlen, "kms: only one of MINIO_KMS_SECRET_KEY or MINIO_KMS_SECRET_KEY_FILE may be set");
    return NULL;
  }
  if (file && *file) {
    FILE *f = fopen(file, "r");
    if (!f) {
      snprintf(err, errlen, "kms: unable to read %s", file);
      return NULL;
    }
    char line[512] = "";
    if (!fgets(line, sizeof(line), f)) line[0] = '\0';
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';
    buckets_kms *k = buckets_kms_builtin(line, err, errlen);
    OPENSSL_cleanse(line, sizeof(line));
    return k;
  }
  if (spec && *spec) return buckets_kms_builtin(spec, err, errlen);
  return NULL;
}

const char *buckets_kms_default_key(const buckets_kms *k) { return k->key_id; }
const char *buckets_kms_type(const buckets_kms *k) {
  return k->kind == KMS_KES ? "MinIO KES" : "MinIO builtin"; /* kms.Type.String() */
}
bool buckets_kms_is_builtin(const buckets_kms *k) { return k->kind == KMS_BUILTIN; }

/* HMAC-SHA256(key, iv): the per-ciphertext AES-GCM key. */
static void sealing_key(const buckets_kms *k, const uint8_t iv[16], uint8_t out[32]) {
  buckets_hmac_sha256(k->key, 32, iv, 16, out);
}

static buckets_kms_err builtin_generate(buckets_kms *k, const char *name, const char *context, uint8_t plaintext[32],
                                buckets_buf *ciphertext, char *key_id, size_t key_id_cap) {
  if (!name || !*name) name = k->key_id;
  if (strcmp(name, k->key_id) != 0) return BUCKETS_KMS_ERR_KEY_NOT_FOUND;
  uint8_t random[28]; /* iv (16) || nonce (12) */
  buckets_random(random, sizeof(random));
  uint8_t key[32];
  sealing_key(k, random, key);
  buckets_random(plaintext, 32);
  uint8_t sealed[32 + BUCKETS_AEAD_TAG];
  bool ok = buckets_aead_seal1(BUCKETS_AEAD_AES_256_GCM, key, random + 16, context, strlen(context), plaintext, 32, sealed);
  OPENSSL_cleanse(key, sizeof(key));
  if (!ok) return BUCKETS_KMS_ERR_UNAVAILABLE;
  buckets_buf_append(ciphertext, sealed, sizeof(sealed));
  buckets_buf_append(ciphertext, random, sizeof(random));
  snprintf(key_id, key_id_cap, "%s", name);
  return BUCKETS_KMS_OK;
}

/* parseCiphertext: raw bytes, or the JSON form {"aead","id","iv","nonce","bytes"}. */
static bool parse_json_ciphertext(const uint8_t *ct, size_t n, buckets_buf *out, int *alg) {
  yyjson_doc *d = yyjson_read((const char *)ct, n, 0);
  yyjson_val *r = d ? yyjson_doc_get_root(d) : NULL;
  bool ok = false;
  const char *a = yyjson_get_str(yyjson_obj_get(r, "aead"));
  const char *iv = yyjson_get_str(yyjson_obj_get(r, "iv"));
  const char *nonce = yyjson_get_str(yyjson_obj_get(r, "nonce"));
  const char *bytes = yyjson_get_str(yyjson_obj_get(r, "bytes"));
  if (a && iv && nonce && bytes &&
      (strcmp(a, "AES-256-GCM-HMAC-SHA-256") == 0 || strcmp(a, "ChaCha20Poly1305") == 0)) {
    uint8_t ivb[24], nb[20];
    size_t bl = strlen(bytes);
    uint8_t *bb = buckets_xmalloc(bl + 3);
    long bn = buckets_base64_decode(bytes, bl, bb);
    if (buckets_base64_decode(iv, strlen(iv), ivb) == 16 && buckets_base64_decode(nonce, strlen(nonce), nb) == 12 && bn >= 0) {
      buckets_buf_append(out, bb, (size_t)bn);
      buckets_buf_append(out, ivb, 16);
      buckets_buf_append(out, nb, 12);
      *alg = a[0] == 'A' ? BUCKETS_AEAD_AES_256_GCM : BUCKETS_AEAD_CHACHA20_POLY1305;
      ok = true;
    }
    free(bb);
  }
  yyjson_doc_free(d);
  return ok;
}

/* HChaCha20(key, iv[0:16]): the ChaCha20Poly1305 sealing key of JSON ciphertexts. */
static bool hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]) {
  uint32_t s[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  for (int i = 0; i < 8; i++) s[4 + i] = (uint32_t)key[4 * i] | (uint32_t)key[4 * i + 1] << 8 | (uint32_t)key[4 * i + 2] << 16 | (uint32_t)key[4 * i + 3] << 24;
  for (int i = 0; i < 4; i++) s[12 + i] = (uint32_t)nonce[4 * i] | (uint32_t)nonce[4 * i + 1] << 8 | (uint32_t)nonce[4 * i + 2] << 16 | (uint32_t)nonce[4 * i + 3] << 24;
#define ROTL(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define QR(a, b, c, d) (a += b, d ^= a, d = ROTL(d, 16), c += d, b ^= c, b = ROTL(b, 12), a += b, d ^= a, d = ROTL(d, 8), c += d, b ^= c, b = ROTL(b, 7))
  for (int i = 0; i < 10; i++) {
    QR(s[0], s[4], s[8], s[12]), QR(s[1], s[5], s[9], s[13]), QR(s[2], s[6], s[10], s[14]), QR(s[3], s[7], s[11], s[15]);
    QR(s[0], s[5], s[10], s[15]), QR(s[1], s[6], s[11], s[12]), QR(s[2], s[7], s[8], s[13]), QR(s[3], s[4], s[9], s[14]);
  }
  const int idx[8] = {0, 1, 2, 3, 12, 13, 14, 15};
  for (int i = 0; i < 8; i++) {
    uint32_t v = s[idx[i]];
    out[4 * i] = (uint8_t)v, out[4 * i + 1] = (uint8_t)(v >> 8), out[4 * i + 2] = (uint8_t)(v >> 16), out[4 * i + 3] = (uint8_t)(v >> 24);
  }
  return true;
}

static buckets_kms_err builtin_decrypt(buckets_kms *k, const char *name, const uint8_t *ciphertext, size_t n, const char *context,
                               uint8_t plaintext[32]) {
  if (!name || strcmp(name, k->key_id) != 0) return BUCKETS_KMS_ERR_KEY_NOT_FOUND;
  buckets_buf raw = BUCKETS_BUF_INIT;
  int alg = BUCKETS_AEAD_AES_256_GCM;
  if (!(n && ciphertext[0] == '{' && ciphertext[n - 1] == '}' && parse_json_ciphertext(ciphertext, n, &raw, &alg))) {
    buckets_buf_reset(&raw);
    buckets_buf_append(&raw, ciphertext, n);
  }
  buckets_kms_err e = BUCKETS_KMS_ERR_DECRYPT;
  if (raw.len == 32 + BUCKETS_AEAD_TAG + 28) {
    const uint8_t *iv = (const uint8_t *)raw.data + raw.len - 28, *nonce = iv + 16;
    uint8_t key[32];
    if (alg == BUCKETS_AEAD_AES_256_GCM) sealing_key(k, iv, key);
    else hchacha20(k->key, iv, key);
    if (buckets_aead_open1((buckets_aead_alg)alg, key, nonce, context, strlen(context), raw.data, 32 + BUCKETS_AEAD_TAG,
                           plaintext))
      e = BUCKETS_KMS_OK;
    OPENSSL_cleanse(key, sizeof(key));
  }
  buckets_buf_free(&raw);
  return e;
}


/* ---- KES (kms-go/kes: JSON over mutual TLS) ------------------------------------------------ */

static void kes_url_escape(buckets_buf *b, const char *s) {
  /* url.PathEscape */
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr("-_.~$&+,;=:@", *p))
      buckets_buf_append_char(b, (char)*p);
    else buckets_buf_appendf(b, "%%%02X", *p);
  }
}

typedef struct {
  int status;       /* 0: no endpoint answered */
  buckets_buf body;
  char message[512]; /* the error's message */
} kes_resp;

/* lb.Send: the endpoints in turn from a rotating start; a transport failure
 * moves on to the next */
static void kes_call(buckets_kms *k, const char *method, const char *api, const char *arg, const char *body,
                     kes_resp *r) {
  memset(r, 0, sizeof(*r));
  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&target, api);
  if (arg) buckets_buf_append_char(&target, '/'), kes_url_escape(&target, arg);
  unsigned start = atomic_fetch_add(&k->rr, 1);
  for (size_t i = 0; i < k->neps && !r->status; i++) {
    size_t e = (start + i) % k->neps;
    buckets_http_kv h[] = {{"Content-Type", "application/json"}, {"Accept", "application/json"}};
    buckets_http_result res;
    if (!buckets_http_client_do(k->cli[e], method, target.data, h, body ? 2 : 1, body, body ? strlen(body) : 0, &res)) {
      snprintf(r->message, sizeof(r->message), "%s", buckets_http_client_dial_error(k->cli[e]));
      continue;
    }
    r->status = res.status;
    buckets_buf_append(&r->body, res.body.data ? res.body.data : "", res.body.len);
    if (res.status >= 400) {
      /* parseErrorResponse: {"message"} or {"error"}, else the body's text */
      yyjson_doc *d = yyjson_read(res.body.data ? res.body.data : "", res.body.len, 0);
      yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
      const char *m = yyjson_get_str(yyjson_obj_get(root, "error"));
      if (!m || !*m) m = yyjson_get_str(yyjson_obj_get(root, "message"));
      if (m) snprintf(r->message, sizeof(r->message), "%s", m);
      else snprintf(r->message, sizeof(r->message), "%.*s", (int)res.body.len, res.body.data ? res.body.data : "");
      yyjson_doc_free(d);
    }
    buckets_http_result_free(&res);
  }
  buckets_buf_free(&target);
}

/* the kes errors MinIO tells apart, else the operation's failure */
static buckets_kms_err kes_err(const kes_resp *r) {
  if (r->status == 404 && !strcmp(r->message, "key does not exist")) return BUCKETS_KMS_ERR_KEY_NOT_FOUND;
  if (r->status == 400 && (!strcmp(r->message, "key already exists") || !strcmp(r->message, "key does already exist")))
    return BUCKETS_KMS_ERR_KEY_EXISTS;
  if (r->status == 403 &&
      (!strcmp(r->message, "not authorized: insufficient permissions") || !strcmp(r->message, "prohibited by policy")))
    return BUCKETS_KMS_ERR_PERMISSION;
  if (r->status == 400 && !strcmp(r->message, "decryption failed: ciphertext is not authentic"))
    return BUCKETS_KMS_ERR_DECRYPT;
  return BUCKETS_KMS_ERR_FAILED;
}

static char *b64(const void *p, size_t n) {
  char *o = buckets_xmalloc(4 * (n / 3 + 2) + 1);
  buckets_base64_encode(p, n, o);
  return o;
}

/* a base64 JSON field of the response, decoded */
static bool kes_field(const kes_resp *r, const char *name, buckets_buf *out) {
  yyjson_doc *d = yyjson_read(r->body.data ? r->body.data : "", r->body.len, 0);
  const char *v = yyjson_get_str(yyjson_obj_get(d ? yyjson_doc_get_root(d) : NULL, name));
  bool ok = false;
  if (v) {
    size_t n = strlen(v);
    uint8_t *buf = buckets_xmalloc(n + 3);
    long k = buckets_base64_decode(v, n, buf);
    if (k >= 0) buckets_buf_append(out, buf, (size_t)k), ok = true;
    OPENSSL_cleanse(buf, n + 3);
    free(buf);
  }
  yyjson_doc_free(d);
  return ok;
}

static buckets_kms_err kes_generate(buckets_kms *k, const char *name, const char *context, uint8_t plaintext[32],
                                    buckets_buf *ciphertext, char *key_id, size_t key_id_cap) {
  if (!name || !*name) name = k->key_id;
  char *ctx = b64(context, strlen(context));
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&body, "{\"context\":\"%s\"}", ctx);
  free(ctx);
  kes_resp r;
  kes_call(k, "POST", "/v1/key/generate", name, body.data, &r);
  buckets_buf_free(&body);
  buckets_kms_err e = BUCKETS_KMS_OK;
  buckets_buf pt = BUCKETS_BUF_INIT;
  if (r.status != 200) e = kes_err(&r);
  else if (!kes_field(&r, "plaintext", &pt) || pt.len != 32 || !kes_field(&r, "ciphertext", ciphertext))
    e = BUCKETS_KMS_ERR_FAILED;
  else memcpy(plaintext, pt.data, 32), snprintf(key_id, key_id_cap, "%s", name);
  if (pt.data) OPENSSL_cleanse(pt.data, pt.len);
  buckets_buf_free(&pt);
  buckets_buf_free(&r.body);
  return e;
}

static buckets_kms_err kes_decrypt(buckets_kms *k, const char *name, const uint8_t *ciphertext, size_t n,
                                   const char *context, uint8_t plaintext[32]) {
  char *ct = b64(ciphertext, n), *ctx = b64(context, strlen(context));
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&body, "{\"ciphertext\":\"%s\",\"context\":\"%s\"}", ct, ctx);
  free(ct);
  free(ctx);
  kes_resp r;
  kes_call(k, "POST", "/v1/key/decrypt", name ? name : "", body.data, &r);
  buckets_buf_free(&body);
  buckets_kms_err e = BUCKETS_KMS_OK;
  buckets_buf pt = BUCKETS_BUF_INIT;
  if (r.status != 200) e = kes_err(&r);
  else if (!kes_field(&r, "plaintext", &pt) || pt.len != 32) e = BUCKETS_KMS_ERR_FAILED;
  else memcpy(plaintext, pt.data, 32);
  if (pt.data) OPENSSL_cleanse(pt.data, pt.len);
  buckets_buf_free(&pt);
  buckets_buf_free(&r.body);
  return e;
}

static buckets_kms_err kes_create(buckets_kms *k, const char *name) {
  kes_resp r;
  kes_call(k, "POST", "/v1/key/create", name, NULL, &r);
  buckets_kms_err e = r.status == 200 ? BUCKETS_KMS_OK : kes_err(&r);
  buckets_buf_free(&r.body);
  return e;
}

static buckets_kms_err kes_delete(buckets_kms *k, const char *name) {
  kes_resp r;
  kes_call(k, "DELETE", "/v1/key/delete", name, NULL, &r);
  buckets_kms_err e = r.status == 200 ? BUCKETS_KMS_OK : kes_err(&r);
  buckets_buf_free(&r.body);
  return e;
}

static size_t kes_list(buckets_kms *k, const char *prefix, char ***names) {
  kes_resp r;
  /* KES lists the keys whose names start with the resource, "*" for all
   * (an empty one reaches Go's KES only through a redirect) */
  kes_call(k, "GET", "/v1/key/list", *prefix ? prefix : "*", NULL, &r);
  size_t n = 0, cap = 0;
  if (r.status == 200) {
    /* {"names":[...]} or, from older servers, NDJSON {"name":...} lines */
    yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    yyjson_val *arr = d ? yyjson_obj_get(yyjson_doc_get_root(d), "names") : NULL;
    if (yyjson_is_arr(arr)) {
      size_t i, max;
      yyjson_val *v;
      yyjson_arr_foreach(arr, i, max, v) {
        if (n == cap) *names = buckets_xrealloc(*names, (cap = cap ? cap * 2 : 16) * sizeof(char *));
        (*names)[n++] = buckets_xstrdup(yyjson_get_str(v) ? yyjson_get_str(v) : "");
      }
    } else if (!d) {
      for (char *line = r.body.data; line && *line;) {
        char *nl = strchr(line, '\n');
        yyjson_doc *ld = yyjson_read(line, nl ? (size_t)(nl - line) : strlen(line), 0);
        const char *nm = yyjson_get_str(yyjson_obj_get(ld ? yyjson_doc_get_root(ld) : NULL, "name"));
        if (nm) {
          if (n == cap) *names = buckets_xrealloc(*names, (cap = cap ? cap * 2 : 16) * sizeof(char *));
          (*names)[n++] = buckets_xstrdup(nm);
        }
        yyjson_doc_free(ld);
        line = nl ? nl + 1 : NULL;
      }
    }
    yyjson_doc_free(d);
  }
  buckets_buf_free(&r.body);
  return n;
}

void buckets_kms_status_endpoints(buckets_kms *k, const char *self_host, buckets_buf *out) {
  buckets_buf_append_char(out, '{');
  if (k->kind == KMS_BUILTIN) {
    buckets_buf_appendf(out, "\"%s\":\"online\"", self_host);
  } else {
    /* each endpoint's /v1/status; sorted, as Go writes a map */
    size_t *order = buckets_xcalloc(k->neps ? k->neps : 1, sizeof(size_t));
    for (size_t i = 0; i < k->neps; i++) order[i] = i;
    for (size_t i = 1; i < k->neps; i++)
      for (size_t j = i; j > 0 && strcmp(k->eps[order[j - 1]], k->eps[order[j]]) > 0; j--) {
        size_t t = order[j];
        order[j] = order[j - 1], order[j - 1] = t;
      }
    for (size_t i = 0; i < k->neps; i++) {
      size_t e = order[i];
      buckets_http_result res;
      bool up = buckets_http_client_do(k->cli[e], "GET", "/v1/status", NULL, 0, NULL, 0, &res);
      if (up) up = res.status == 200, buckets_http_result_free(&res);
      buckets_buf_appendf(out, "%s\"%s\":\"%s\"", i ? "," : "", k->eps[e], up ? "online" : "offline");
    }
    free(order);
  }
  buckets_buf_append_char(out, '}');
}

buckets_kms_err buckets_kms_version(buckets_kms *k, char *out, size_t cap) {
  if (k->kind == KMS_BUILTIN) {
    snprintf(out, cap, "v1");
    return BUCKETS_KMS_OK;
  }
  kes_resp r;
  kes_call(k, "GET", "/version", NULL, NULL, &r);
  buckets_kms_err e = r.status == 200 ? BUCKETS_KMS_OK : kes_err(&r);
  if (!e) {
    yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    const char *v = yyjson_get_str(yyjson_obj_get(d ? yyjson_doc_get_root(d) : NULL, "version"));
    snprintf(out, cap, "%s", v ? v : "");
    yyjson_doc_free(d);
  }
  buckets_buf_free(&r.body);
  return e;
}

buckets_kms_err buckets_kms_apis_json(buckets_kms *k, buckets_buf *out) {
  if (k->kind == KMS_BUILTIN) return BUCKETS_KMS_ERR_NOT_SUPPORTED;
  kes_resp r;
  kes_call(k, "GET", "/v1/api", NULL, NULL, &r);
  buckets_kms_err e = r.status == 200 ? BUCKETS_KMS_OK : kes_err(&r);
  if (!e) {
    yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    yyjson_val *arr = d ? yyjson_doc_get_root(d) : NULL, *v;
    size_t i, max, shown = 0;
    buckets_buf_append_char(out, '[');
    yyjson_arr_foreach(arr, i, max, v) {
      const char *m = yyjson_get_str(yyjson_obj_get(v, "method")), *p = yyjson_get_str(yyjson_obj_get(v, "path"));
      buckets_buf_appendf(out, "%s{\"Method\":", shown++ ? "," : "");
      buckets_json_go_string(out, m ? m : "", m ? strlen(m) : 0);
      buckets_buf_append_c(out, ",\"Path\":");
      buckets_json_go_string(out, p ? p : "", p ? strlen(p) : 0);
      buckets_buf_appendf(out, ",\"MaxBody\":%lld,\"Timeout\":%lld}", (long long)yyjson_get_sint(yyjson_obj_get(v, "max_body")),
                          (long long)yyjson_get_sint(yyjson_obj_get(v, "timeout")));
    }
    buckets_buf_append_char(out, ']');
    yyjson_doc_free(d);
  } else if (r.status == 403) {
    e = BUCKETS_KMS_ERR_PERMISSION;
  }
  buckets_buf_free(&r.body);
  return e;
}

/* Connect's KES branch */
static buckets_kms *kes_new(const char *ep, const char *key, const char *api, const char *kf, const char *cf,
                            const char *pw, const char *ca, char *err, size_t errlen) {
  if (!ep) return snprintf(err, errlen, "kms: incomplete configuration for MinIO KES: missing 'MINIO_KMS_KES_ENDPOINT'"), NULL;
  if (!key) return snprintf(err, errlen, "kms: incomplete configuration for MinIO KES: missing 'MINIO_KMS_KES_KEY_NAME'"), NULL;
  if (kf || cf || pw) {
    if (api)
      return snprintf(err, errlen, "kms: invalid configuration for MinIO KES: 'MINIO_KMS_KES_API_KEY' and client "
                                   "certificate is present"), NULL;
    if (!cf) return snprintf(err, errlen, "kms: incomplete configuration for MinIO KES: missing 'MINIO_KMS_KES_CERT_FILE'"), NULL;
    if (!kf) return snprintf(err, errlen, "kms: incomplete configuration for MinIO KES: missing 'MINIO_KMS_KES_KEY_FILE'"), NULL;
  } else if (!api) {
    return snprintf(err, errlen, "kms: incomplete configuration for MinIO KES: missing authentication method"), NULL;
  }
  if (!*ep) return snprintf(err, errlen, "kms: no KES server endpoint provided"), NULL;
  buckets_kms *k = buckets_xcalloc(1, sizeof(*k));
  k->kind = KMS_KES;
  k->key_id = buckets_xstrdup(key);
  /* expandEndpoints */
  char *copy = buckets_xstrdup(ep);
  for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
    while (*tok == ' ') tok++;
    size_t tl = strlen(tok);
    while (tl && tok[tl - 1] == ' ') tok[--tl] = '\0';
    if (!*tok) continue;
    char **exp = NULL;
    size_t nexp = 0;
    buckets_ell_arg a;
    if (buckets_ell_has(tok) && buckets_ell_parse(tok, &a)) {
      exp = buckets_ell_expand(&a, &nexp);
      buckets_ell_arg_free(&a);
    } else if (buckets_ell_has(tok)) {
      snprintf(err, errlen, "kms: invalid endpoint '%s'", tok);
      free(copy);
      buckets_kms_free(k);
      return NULL;
    } else {
      exp = buckets_xmalloc(sizeof(char *));
      exp[0] = buckets_xstrdup(tok);
      nexp = 1;
    }
    for (size_t i = 0; i < nexp; i++) {
      k->eps = buckets_xrealloc(k->eps, (k->neps + 1) * sizeof(char *));
      k->eps[k->neps++] = exp[i];
    }
    free(exp);
  }
  free(copy);
  char e2[512];
  /* the KES server's CA: MINIO_KMS_KES_CAPATH, else the certs directory's CAs */
  k->tls = buckets_tls_client_new(ca && *ca ? ca : NULL, e2, sizeof(e2));
  if (!k->tls) {
    snprintf(err, errlen, "%s", e2);
    buckets_kms_free(k);
    return NULL;
  }
  if (api) {
    const char *b = strncmp(api, "kes:v1:", 7) == 0 ? api + 7 : api;
    uint8_t raw[64];
    long n = strlen(b) < 60 ? buckets_base64_decode(b, strlen(b), raw) : -1;
    if (n != 33) {
      snprintf(err, errlen, n < 0 ? "illegal base64 data" : "kes: invalid API key: invalid length");
      buckets_kms_free(k);
      return NULL;
    }
    if (raw[0] != 0) {
      snprintf(err, errlen, "kes: invalid API key: unsupported type");
      buckets_kms_free(k);
      return NULL;
    }
    if (!buckets_tls_client_use_ed25519(k->tls, raw + 1, "kes-client", e2, sizeof(e2))) {
      snprintf(err, errlen, "%s", e2);
      OPENSSL_cleanse(raw, sizeof(raw));
      buckets_kms_free(k);
      return NULL;
    }
    OPENSSL_cleanse(raw, sizeof(raw));
  } else if (!buckets_tls_client_use_cert_password(k->tls, cf, kf, pw, e2, sizeof(e2))) {
    snprintf(err, errlen, "Unable to load KES client certificate as specified by the shell environment: %s", e2);
    buckets_kms_free(k);
    return NULL;
  }
  k->cli = buckets_xcalloc(k->neps ? k->neps : 1, sizeof(*k->cli));
  for (size_t i = 0; i < k->neps; i++) {
    const char *u = k->eps[i];
    if (!strncmp(u, "https://", 8)) u += 8;
    char host[256] = "";
    int port = 443;
    const char *colon = strrchr(u, ':'), *slash = strchr(u, '/');
    if (u[0] == '[') {
      const char *end = strchr(u, ']');
      snprintf(host, sizeof(host), "%.*s", end ? (int)(end - u - 1) : 0, u + 1);
      if (end && end[1] == ':') port = atoi(end + 2);
    } else if (colon && (!slash || colon < slash)) {
      snprintf(host, sizeof(host), "%.*s", (int)(colon - u), u);
      port = atoi(colon + 1);
    } else {
      snprintf(host, sizeof(host), "%.*s", slash ? (int)(slash - u) : (int)strlen(u), u);
    }
    k->cli[i] = buckets_http_client_new(host, port, k->tls, 15000);
  }
  return k;
}

static buckets_kms *kes_from_env(char *err, size_t errlen) {
  return kes_new(buckets_config_getenv("MINIO_KMS_KES_ENDPOINT"), buckets_config_getenv("MINIO_KMS_KES_KEY_NAME"),
                 buckets_config_getenv("MINIO_KMS_KES_API_KEY"), buckets_config_getenv("MINIO_KMS_KES_KEY_FILE"),
                 buckets_config_getenv("MINIO_KMS_KES_CERT_FILE"), buckets_config_getenv("MINIO_KMS_KES_KEY_PASSWORD"),
                 buckets_config_getenv("MINIO_KMS_KES_CAPATH"), err, errlen);
}

buckets_kms *buckets_kms_kes_new(const char *endpoints, const char *key_name, const char *api_key, const char *ca_path,
                                 char *err, size_t errlen) {
  return kes_new(endpoints, key_name, api_key, NULL, NULL, NULL, ca_path, err, errlen);
}

buckets_kms_err buckets_kms_generate(buckets_kms *k, const char *name, const char *context, uint8_t plaintext[32],
                                     buckets_buf *ciphertext, char *key_id, size_t key_id_cap) {
  int64_t t = mono_ns();
  if (k->kind == KMS_KES) return metered(k, t, kes_generate(k, name, context, plaintext, ciphertext, key_id, key_id_cap));
  return metered(k, t, builtin_generate(k, name, context, plaintext, ciphertext, key_id, key_id_cap));
}

buckets_kms_err buckets_kms_decrypt(buckets_kms *k, const char *name, const uint8_t *ciphertext, size_t n,
                                    const char *context, uint8_t plaintext[32]) {
  int64_t t = mono_ns();
  if (k->kind == KMS_KES) return metered(k, t, kes_decrypt(k, name, ciphertext, n, context, plaintext));
  return metered(k, t, builtin_decrypt(k, name, ciphertext, n, context, plaintext));
}

buckets_kms_err buckets_kms_create_key(buckets_kms *k, const char *name) {
  int64_t t = mono_ns();
  if (k->kind == KMS_KES) return metered(k, t, kes_create(k, name));
  return metered(k, t, strcmp(name, k->key_id) == 0 ? BUCKETS_KMS_ERR_KEY_EXISTS : BUCKETS_KMS_ERR_NOT_SUPPORTED);
}

buckets_kms_err buckets_kms_delete_key(buckets_kms *k, const char *name) {
  int64_t t = mono_ns();
  if (k->kind == KMS_KES) return metered(k, t, kes_delete(k, name));
  return metered(k, t, BUCKETS_KMS_ERR_NOT_SUPPORTED); /* the static key is the only key */
}

size_t buckets_kms_list_keys(buckets_kms *k, const char *prefix, char ***names) {
  *names = NULL;
  if (k->kind == KMS_KES) return kes_list(k, prefix ? prefix : "", names);
  if (strncmp(k->key_id, prefix ? prefix : "", strlen(prefix ? prefix : "")) != 0) return 0;
  *names = buckets_xmalloc(sizeof(char *));
  (*names)[0] = buckets_xstrdup(k->key_id);
  return 1;
}

/* ---- kms.Context ------------------------------------------------------------------------- */

static void escape_json(buckets_buf *out, const char *s) {
  static const char hex[] = "0123456789abcdef";
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {
    unsigned char c = *p;
    if (c < 0x80) {
      bool safe = c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&';
      if (safe) {
        buckets_buf_append_char(out, (char)c);
      } else if (c == '"' || c == '\\') {
        buckets_buf_append_char(out, '\\');
        buckets_buf_append_char(out, (char)c);
      } else if (c == '\n') {
        buckets_buf_append_c(out, "\\n");
      } else if (c == '\r') {
        buckets_buf_append_c(out, "\\r");
      } else if (c == '\t') {
        buckets_buf_append_c(out, "\\t");
      } else {
        char e[7] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15], 0};
        buckets_buf_append_c(out, e);
      }
      p++;
      continue;
    }
    /* UTF-8: copy valid sequences; invalid bytes become �; U+2028/9 are escaped */
    size_t len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 0;
    bool valid = len != 0;
    for (size_t i = 1; valid && i < len; i++) valid = (p[i] & 0xC0) == 0x80;
    if (!valid) {
      buckets_buf_append_c(out, "\\ufffd");
      p++;
      continue;
    }
    if (len == 3 && c == 0xE2 && p[1] == 0x80 && (p[2] == 0xA8 || p[2] == 0xA9)) {
      buckets_buf_append_c(out, p[2] == 0xA8 ? "\\u2028" : "\\u2029");
    } else {
      buckets_buf_append(out, p, len);
    }
    p += len;
  }
}

static int cmp_idx(const void *a, const void *b, void *ud) {
  const char *const *keys = ud;
  return strcmp(keys[*(const size_t *)a], keys[*(const size_t *)b]);
}

void buckets_kms_context_text(const char *const *keys, const char *const *values, size_t n, buckets_buf *out) {
  if (!n) {
    buckets_buf_append_c(out, "{}");
    return;
  }
  size_t *ix = buckets_xmalloc(n * sizeof(size_t));
  for (size_t i = 0; i < n; i++) {
    size_t j = i;
    for (; j > 0 && cmp_idx(&ix[j - 1], &i, (void *)keys) > 0; j--) ix[j] = ix[j - 1];
    ix[j] = i;
  }
  buckets_buf_append_char(out, '{');
  for (size_t i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(out, ',');
    buckets_buf_append_char(out, '"');
    escape_json(out, keys[ix[i]]);
    buckets_buf_append_c(out, "\":\"");
    escape_json(out, values[ix[i]]);
    buckets_buf_append_char(out, '"');
  }
  buckets_buf_append_char(out, '}');
  free(ix);
}
