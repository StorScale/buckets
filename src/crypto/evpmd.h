/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_EVPMD_H
#define BUCKETS_CRYPTO_EVPMD_H

/* The digest contexts' common part (sha1.c, sha256.c, md5.c): an EVP_MD_CTX of an algorithm fetched once
 * (crypto/fips.h). */

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static inline void *buckets_evpmd_init(const EVP_MD *md) {
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  if (!c || EVP_DigestInit_ex2(c, md, NULL) != 1) {
    fprintf(stderr, "crypto: digest setup failed\n");
    abort();
  }
  return c;
}

static inline void buckets_evpmd_update(void *c, const void *data, size_t n) {
  if (n) EVP_DigestUpdate(c, data, n);
}

static inline void buckets_evpmd_final(void **c, uint8_t *out) {
  EVP_DigestFinal_ex(*c, out, NULL);
  EVP_MD_CTX_free(*c);
  *c = NULL;
}

static inline void buckets_evpmd_cleanup(void **c) {
  EVP_MD_CTX_free(*c);
  *c = NULL;
}

static inline void buckets_evpmd_oneshot(const EVP_MD *md, const void *data, size_t n, uint8_t *out) {
  if (EVP_Digest(data, n, out, NULL, md, NULL) != 1) {
    fprintf(stderr, "crypto: digest failed\n");
    abort();
  }
}

/* HMAC with the module's HMAC (EVP_MAC), keyed per call. */
static inline void buckets_evp_hmac(const char *digest, const void *key, size_t key_len, const void *msg,
                                    size_t msg_len, uint8_t *out, size_t out_len) {
  static const uint8_t none[1];
  size_t got = 0;
  if (!EVP_Q_mac(NULL, "HMAC", NULL, digest, NULL, key_len ? key : none, key_len, msg, msg_len, out, out_len,
                 &got) ||
      got != out_len) {
    fprintf(stderr, "crypto: HMAC-%s failed\n", digest);
    abort();
  }
}

#endif
