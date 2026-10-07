/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/aead.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "crypto/fips.h"

struct buckets_aead {
  EVP_CIPHER_CTX *enc, *dec;
};

/* NULL when refused: ChaCha20-Poly1305 in FIPS mode */
static const EVP_CIPHER *cipher_of(buckets_aead_alg alg) {
  return alg == BUCKETS_AEAD_CHACHA20_POLY1305 ? buckets_cipher_chacha20poly1305() : buckets_cipher_aes256gcm();
}

static EVP_CIPHER_CTX *keyed(const EVP_CIPHER *cipher, const uint8_t key[32], int enc) {
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  if (!c) return NULL;
  if (EVP_CipherInit_ex(c, cipher, NULL, NULL, NULL, enc) != 1 ||
      EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, BUCKETS_AEAD_NONCE, NULL) != 1 ||
      EVP_CipherInit_ex(c, NULL, NULL, key, NULL, enc) != 1) {
    EVP_CIPHER_CTX_free(c);
    return NULL;
  }
  return c;
}

buckets_aead *buckets_aead_new(buckets_aead_alg alg, const uint8_t key[32]) {
  return buckets_aead_new_cipher(cipher_of(alg), key);
}

buckets_aead *buckets_aead_new_cipher(const EVP_CIPHER *cipher, const uint8_t key[32]) {
  if (!cipher) return NULL;
  buckets_aead *a = buckets_xcalloc(1, sizeof(*a));
  a->enc = keyed(cipher, key, 1);
  a->dec = keyed(cipher, key, 0);
  if (!a->enc || !a->dec) buckets_fatal("aead: cipher setup failed");
  return a;
}

void buckets_aead_free(buckets_aead *a) {
  if (!a) return;
  EVP_CIPHER_CTX_free(a->enc);
  EVP_CIPHER_CTX_free(a->dec);
  free(a);
}

bool buckets_aead_seal(buckets_aead *a, const uint8_t nonce[12], const void *ad, size_t adn, const void *in, size_t n,
                       uint8_t *out) {
  EVP_CIPHER_CTX *c = a->enc;
  int len;
  return EVP_CipherInit_ex(c, NULL, NULL, NULL, nonce, 1) == 1 &&
         (adn == 0 || EVP_CipherUpdate(c, NULL, &len, ad, (int)adn) == 1) &&
         (n == 0 || EVP_CipherUpdate(c, out, &len, in, (int)n) == 1) && EVP_CipherFinal_ex(c, out + n, &len) == 1 &&
         EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, BUCKETS_AEAD_TAG, out + n) == 1;
}

bool buckets_aead_open(buckets_aead *a, const uint8_t nonce[12], const void *ad, size_t adn, const void *in, size_t n,
                       uint8_t *out) {
  if (n < BUCKETS_AEAD_TAG) return false;
  size_t cn = n - BUCKETS_AEAD_TAG;
  uint8_t tag[BUCKETS_AEAD_TAG];
  memcpy(tag, (const uint8_t *)in + cn, BUCKETS_AEAD_TAG); /* out may overlap in */
  EVP_CIPHER_CTX *c = a->dec;
  int len;
  return EVP_CipherInit_ex(c, NULL, NULL, NULL, nonce, 0) == 1 &&
         (adn == 0 || EVP_CipherUpdate(c, NULL, &len, ad, (int)adn) == 1) &&
         (cn == 0 || EVP_CipherUpdate(c, out, &len, in, (int)cn) == 1) &&
         EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, BUCKETS_AEAD_TAG, tag) == 1 &&
         EVP_CipherFinal_ex(c, out + cn, &len) == 1;
}

bool buckets_aead_seal1(buckets_aead_alg alg, const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t adn,
                        const void *in, size_t n, uint8_t *out) {
  buckets_aead *a = buckets_aead_new(alg, key);
  if (!a) return false;
  bool ok = buckets_aead_seal(a, nonce, ad, adn, in, n, out);
  buckets_aead_free(a);
  return ok;
}

bool buckets_aead_open1(buckets_aead_alg alg, const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t adn,
                        const void *in, size_t n, uint8_t *out) {
  buckets_aead *a = buckets_aead_new(alg, key);
  if (!a) return false;
  bool ok = buckets_aead_open(a, nonce, ad, adn, in, n, out);
  buckets_aead_free(a);
  return ok;
}

void buckets_random(void *out, size_t n) {
  if (RAND_bytes(out, (int)n) != 1) buckets_fatal("out of entropy");
}
