/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/madmin.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

#define SALT_LEN 32
#define NONCE_LEN 8
#define TAG_LEN 16
#define FRAG 16384

enum { ARGON2ID_AES_GCM = 0x00, ARGON2ID_CHACHA20 = 0x01, PBKDF2_AES_GCM = 0x02 };

static bool derive(uint8_t id, const char *password, const uint8_t *salt, uint8_t key[32]) {
  if (id == PBKDF2_AES_GCM) {
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_LEN, 8192, EVP_sha256(), 32, key) == 1;
  }
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
  if (!kdf) return false;
  EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!ctx) return false;
  uint32_t iter = 1, mem = 64 * 1024, lanes = 4, threads = 1; /* threads never change the output */
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)password, strlen(password)),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, SALT_LEN),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
      OSSL_PARAM_construct_end(),
  };
  bool ok = EVP_KDF_derive(ctx, key, 32, params) == 1;
  EVP_KDF_CTX_free(ctx);
  return ok;
}

static const EVP_CIPHER *cipher_for(uint8_t id) {
  return id == ARGON2ID_CHACHA20 ? EVP_chacha20_poly1305() : EVP_aes_256_gcm();
}

/* One AEAD seal/open of a fragment (12-byte nonce, 16-byte tag). */
static bool aead(bool seal, uint8_t id, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ad, size_t adn,
                 const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16]) {
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  int len;
  bool ok = c && EVP_CipherInit_ex(c, cipher_for(id), NULL, NULL, NULL, seal) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
            EVP_CipherInit_ex(c, NULL, NULL, key, nonce, seal) == 1 &&
            (adn == 0 || EVP_CipherUpdate(c, NULL, &len, ad, (int)adn) == 1) &&
            (n == 0 || EVP_CipherUpdate(c, out, &len, in, (int)n) == 1);
  if (ok && !seal) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag) == 1;
  if (ok) ok = EVP_CipherFinal_ex(c, out + n, &len) == 1;
  if (ok && seal) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) == 1;
  EVP_CIPHER_CTX_free(c);
  return ok;
}

static void set_seq(uint8_t nonce[12], uint32_t seq) {
  nonce[8] = (uint8_t)seq;
  nonce[9] = (uint8_t)(seq >> 8);
  nonce[10] = (uint8_t)(seq >> 16);
  nonce[11] = (uint8_t)(seq >> 24);
}

/* sio's associated data: flag byte | tag of an empty message under seq 0. */
static bool stream_ad(uint8_t id, const uint8_t key[32], const uint8_t base[8], uint8_t ad[1 + TAG_LEN]) {
  uint8_t nonce[12];
  memcpy(nonce, base, 8);
  set_seq(nonce, 0);
  uint8_t none[1];
  ad[0] = 0x00;
  return aead(true, id, key, nonce, NULL, 0, none, 0, none, ad + 1);
}

bool buckets_madmin_is_encrypted(const void *data, size_t n) {
  const uint8_t *p = data;
  return n > SALT_LEN && (p[SALT_LEN] == ARGON2ID_AES_GCM || p[SALT_LEN] == ARGON2ID_CHACHA20 || p[SALT_LEN] == PBKDF2_AES_GCM);
}

bool buckets_madmin_encrypt(const char *password, const void *data, size_t n, buckets_buf *out) {
  uint8_t salt[SALT_LEN], base[NONCE_LEN], key[32], ad[1 + TAG_LEN];
  if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(base, NONCE_LEN) != 1) return false;
  uint8_t id = ARGON2ID_AES_GCM;
  if (!derive(id, password, salt, key) || !stream_ad(id, key, base, ad)) return false;
  buckets_buf_append(out, salt, SALT_LEN);
  buckets_buf_append_char(out, (char)id);
  buckets_buf_append(out, base, NONCE_LEN);
  const uint8_t *p = data;
  uint32_t seq = 1;
  uint8_t nonce[12];
  memcpy(nonce, base, 8);
  /* Full fragments while more than one fragment remains; the rest is final. */
  for (;;) {
    bool final = n <= FRAG;
    size_t take = final ? n : FRAG;
    ad[0] = final ? 0x80 : 0x00;
    set_seq(nonce, seq++);
    buckets_buf_reserve(out, take + TAG_LEN);
    uint8_t *dst = (uint8_t *)out->data + out->len;
    uint8_t tag[TAG_LEN];
    if (!aead(true, id, key, nonce, ad, sizeof(ad), p, take, dst, tag)) return false;
    out->len += take;
    buckets_buf_append(out, tag, TAG_LEN);
    p += take;
    n -= take;
    if (final) break;
  }
  return true;
}

bool buckets_madmin_decrypt(const char *password, const void *data, size_t n, buckets_buf *out) {
  const uint8_t *p = data;
  if (n < SALT_LEN + 1 + NONCE_LEN + TAG_LEN) return false;
  uint8_t id = p[SALT_LEN];
  if (id != ARGON2ID_AES_GCM && id != ARGON2ID_CHACHA20 && id != PBKDF2_AES_GCM) return false;
  uint8_t key[32], ad[1 + TAG_LEN], base[NONCE_LEN];
  memcpy(base, p + SALT_LEN + 1, NONCE_LEN);
  if (!derive(id, password, p, key) || !stream_ad(id, key, base, ad)) return false;
  p += SALT_LEN + 1 + NONCE_LEN;
  n -= SALT_LEN + 1 + NONCE_LEN;
  uint32_t seq = 1;
  uint8_t nonce[12];
  memcpy(nonce, base, 8);
  while (n > 0) {
    bool final = n <= FRAG + TAG_LEN;
    size_t frag = final ? n : FRAG + TAG_LEN;
    if (frag < TAG_LEN) return false;
    size_t plen = frag - TAG_LEN;
    ad[0] = final ? 0x80 : 0x00;
    set_seq(nonce, seq++);
    buckets_buf_reserve(out, plen + 1);
    uint8_t tag[TAG_LEN];
    memcpy(tag, p + plen, TAG_LEN);
    if (!aead(false, id, key, nonce, ad, sizeof(ad), p, plen, (uint8_t *)out->data + out->len, tag)) return false;
    out->len += plen;
    p += frag;
    n -= frag;
  }
  if (out->data) out->data[out->len] = '\0';
  return true;
}
