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
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/sha256.h"

struct buckets_kms {
  char *key_id;
  uint8_t key[32];
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

buckets_kms *buckets_kms_from_env(char *err, size_t errlen) {
  *err = '\0';
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
  (void)k;
  return "MinIO builtin"; /* kms.Type.String() */
}

/* HMAC-SHA256(key, iv): the per-ciphertext AES-GCM key. */
static void sealing_key(const buckets_kms *k, const uint8_t iv[16], uint8_t out[32]) {
  buckets_hmac_sha256(k->key, 32, iv, 16, out);
}

static buckets_kms_err generate(buckets_kms *k, const char *name, const char *context, uint8_t plaintext[32],
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

static buckets_kms_err decrypt(buckets_kms *k, const char *name, const uint8_t *ciphertext, size_t n, const char *context,
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

buckets_kms_err buckets_kms_generate(buckets_kms *k, const char *name, const char *context, uint8_t plaintext[32],
                                     buckets_buf *ciphertext, char *key_id, size_t key_id_cap) {
  int64_t t = mono_ns();
  return metered(k, t, generate(k, name, context, plaintext, ciphertext, key_id, key_id_cap));
}

buckets_kms_err buckets_kms_decrypt(buckets_kms *k, const char *name, const uint8_t *ciphertext, size_t n,
                                    const char *context, uint8_t plaintext[32]) {
  int64_t t = mono_ns();
  return metered(k, t, decrypt(k, name, ciphertext, n, context, plaintext));
}

buckets_kms_err buckets_kms_create_key(buckets_kms *k, const char *name) {
  int64_t t = mono_ns();
  return metered(k, t, strcmp(name, k->key_id) == 0 ? BUCKETS_KMS_ERR_KEY_EXISTS : BUCKETS_KMS_ERR_NOT_SUPPORTED);
}

size_t buckets_kms_list_keys(buckets_kms *k, const char *prefix, char ***names) {
  *names = NULL;
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
