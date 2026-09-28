/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/objkey.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

#include "crypto/aead.h"
#include "crypto/dare.h"

typedef struct {
  EVP_MAC_CTX *ctx;
} hmac;

static void hmac_init(hmac *h, const uint8_t *key, size_t n) {
  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  h->ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end()};
  EVP_MAC_init(h->ctx, key, n, params);
}
static void hmac_write(hmac *h, const void *p, size_t n) { EVP_MAC_update(h->ctx, p, n); }
static void hmac_sum(hmac *h, uint8_t out[32]) {
  size_t n;
  EVP_MAC_final(h->ctx, out, &n, 32);
  EVP_MAC_CTX_free(h->ctx);
}

void buckets_objkey_generate(const uint8_t ext[32], const uint8_t *nonce32, uint8_t key[32]) {
  uint8_t nonce[32];
  if (nonce32) memcpy(nonce, nonce32, 32);
  else buckets_random(nonce, 32);
  hmac h;
  hmac_init(&h, ext, 32);
  hmac_write(&h, "object-encryption-key generation", 32);
  hmac_write(&h, nonce, 32);
  hmac_sum(&h, key);
}

/* Go's path.Clean on s[0:n], appended to out. */
static void path_clean(const char *s, buckets_buf *out) {
  size_t n = strlen(s);
  if (!n) {
    buckets_buf_append_char(out, '.');
    return;
  }
  bool rooted = s[0] == '/';
  size_t base = out->len;
  if (rooted) buckets_buf_append_char(out, '/');
  size_t dotdot = out->len; /* where a leading ".." can no longer back up */
  size_t r = rooted;
  while (r < n) {
    if (s[r] == '/') {
      r++;
    } else if (s[r] == '.' && (r + 1 == n || s[r + 1] == '/')) {
      r++;
    } else if (s[r] == '.' && s[r + 1] == '.' && (r + 2 == n || s[r + 2] == '/')) {
      r += 2;
      if (out->len > dotdot) {
        size_t w = out->len - 1;
        while (w > dotdot && out->data[w] != '/') w--;
        out->len = w;
        out->data[w] = '\0';
      } else if (!rooted) {
        if (out->len > base) buckets_buf_append_char(out, '/');
        buckets_buf_append(out, "..", 2);
        dotdot = out->len;
      }
    } else {
      if ((rooted && out->len != base + 1) || (!rooted && out->len != base)) buckets_buf_append_char(out, '/');
      for (; r < n && s[r] != '/'; r++) buckets_buf_append_char(out, s[r]);
    }
  }
  if (out->len == base) buckets_buf_append_char(out, '.');
}

void buckets_path_join(const char *a, const char *b, buckets_buf *out) {
  if (!*a && !*b) return; /* path.Join of empty elements is "" */
  buckets_buf joined = BUCKETS_BUF_INIT;
  if (*a) buckets_buf_append_c(&joined, a);
  if (*a && *b) buckets_buf_append_char(&joined, '/');
  if (*b) buckets_buf_append_c(&joined, b);
  path_clean(joined.data, out);
  buckets_buf_free(&joined);
}

static void sealing_key(const uint8_t ext[32], const uint8_t iv[32], const char *domain, const char *bucket,
                        const char *object, uint8_t out[32]) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_path_join(bucket, object, &p);
  hmac h;
  hmac_init(&h, ext, 32);
  hmac_write(&h, iv, 32);
  hmac_write(&h, domain, strlen(domain));
  hmac_write(&h, BUCKETS_SEAL_ALGORITHM, strlen(BUCKETS_SEAL_ALGORITHM));
  hmac_write(&h, p.data ? p.data : "", p.len);
  hmac_sum(&h, out);
  buckets_buf_free(&p);
}

void buckets_objkey_seal(const uint8_t key[32], const uint8_t ext[32], const uint8_t *iv32, const char *domain,
                         const char *bucket, const char *object, uint8_t iv_out[32], uint8_t sealed[BUCKETS_SEALED_KEY_LEN]) {
  if (iv32) memcpy(iv_out, iv32, 32);
  else buckets_random(iv_out, 32);
  uint8_t sk[32];
  sealing_key(ext, iv_out, domain, bucket, object, sk);
  buckets_dare_encrypt_buffer(sk, key, 32, sealed);
  OPENSSL_cleanse(sk, sizeof(sk));
}

bool buckets_objkey_unseal(const uint8_t ext[32], const uint8_t sealed[BUCKETS_SEALED_KEY_LEN], const uint8_t iv[32],
                           const char *algorithm, const char *domain, const char *bucket, const char *object,
                           uint8_t key[32]) {
  if (strcmp(algorithm, BUCKETS_SEAL_ALGORITHM) != 0) return false; /* DARE 1.0 sealing is not supported */
  uint8_t sk[32], out[BUCKETS_SEALED_KEY_LEN];
  sealing_key(ext, iv, domain, bucket, object, sk);
  long n = buckets_dare_decrypt_buffer(sk, sealed, BUCKETS_SEALED_KEY_LEN, out);
  OPENSSL_cleanse(sk, sizeof(sk));
  if (n != 32) return false;
  memcpy(key, out, 32);
  OPENSSL_cleanse(out, sizeof(out));
  return true;
}

void buckets_objkey_part_key(const uint8_t key[32], uint32_t part, uint8_t out[32]) {
  uint8_t le[4] = {(uint8_t)part, (uint8_t)(part >> 8), (uint8_t)(part >> 16), (uint8_t)(part >> 24)};
  hmac h;
  hmac_init(&h, key, 32);
  hmac_write(&h, le, 4);
  hmac_sum(&h, out);
}

static void etag_key(const uint8_t key[32], uint8_t out[32]) {
  hmac h;
  hmac_init(&h, key, 32);
  hmac_write(&h, "SSE-etag", 8);
  hmac_sum(&h, out);
}

void buckets_objkey_seal_etag(const uint8_t key[32], const uint8_t *etag, size_t n, buckets_buf *out) {
  if (!n) return;
  uint8_t k[32];
  etag_key(key, k);
  size_t sz = buckets_dare_encrypted_size(n);
  buckets_buf_reserve(out, sz);
  buckets_dare_encrypt_buffer(k, etag, n, (uint8_t *)out->data + out->len);
  out->len += sz;
  out->data[out->len] = '\0';
  OPENSSL_cleanse(k, sizeof(k));
}

bool buckets_objkey_unseal_etag(const uint8_t key[32], const uint8_t *etag, size_t n, buckets_buf *out) {
  if (n <= 16) { /* IsETagSealed */
    buckets_buf_append(out, etag, n);
    return true;
  }
  uint8_t k[32];
  etag_key(key, k);
  buckets_buf_reserve(out, n);
  long r = buckets_dare_decrypt_buffer(k, etag, n, (uint8_t *)out->data + out->len);
  OPENSSL_cleanse(k, sizeof(k));
  if (r < 0) return false;
  out->len += (size_t)r;
  out->data[out->len] = '\0';
  return true;
}
