/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_AEAD_H
#define BUCKETS_CRYPTO_AEAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* AES-256-GCM and ChaCha20-Poly1305 with 12-byte nonces and 16-byte tags
 * (Go's cipher.AEAD: Seal appends the tag, Open expects it at the end). */

typedef enum { BUCKETS_AEAD_AES_256_GCM = 0, BUCKETS_AEAD_CHACHA20_POLY1305 = 1 } buckets_aead_alg;

#define BUCKETS_AEAD_TAG 16
#define BUCKETS_AEAD_NONCE 12

typedef struct buckets_aead buckets_aead;

/* A keyed cipher, reusable for any number of seal/open calls. NULL when the algorithm is refused: ChaCha20-Poly1305
 * in FIPS mode (crypto/fips.h). */
buckets_aead *buckets_aead_new(buckets_aead_alg alg, const uint8_t key[32]);
/* The same over an EVP cipher (an AEAD with 12-byte nonces and 16-byte tags); NULL for a NULL cipher. */
struct evp_cipher_st;
buckets_aead *buckets_aead_new_cipher(const struct evp_cipher_st *cipher, const uint8_t key[32]);
void buckets_aead_free(buckets_aead *a);
/* out gets n + 16 bytes (ciphertext || tag); out may equal in. */
bool buckets_aead_seal(buckets_aead *a, const uint8_t nonce[12], const void *ad, size_t adn, const void *in, size_t n,
                       uint8_t *out);
/* in holds n bytes of ciphertext || tag (n >= 16); out gets n - 16 bytes.
 * False when authentication fails. */
bool buckets_aead_open(buckets_aead *a, const uint8_t nonce[12], const void *ad, size_t adn, const void *in, size_t n,
                       uint8_t *out);

/* One-shot forms; false when the algorithm is refused, too. */
bool buckets_aead_seal1(buckets_aead_alg alg, const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t adn,
                        const void *in, size_t n, uint8_t *out);
bool buckets_aead_open1(buckets_aead_alg alg, const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t adn,
                        const void *in, size_t n, uint8_t *out);

/* Cryptographically secure random bytes. */
void buckets_random(void *out, size_t n);

#endif
