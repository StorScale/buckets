/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_KES_KEY_H
#define BUCKETS_KES_KEY_H

/* KES's keys, as MinIO KES stores and uses them, so either server reads
 * what the other wrote:
 *
 * - stored: base64 of a protobuf KeyVersion {SecretKey{key, type},
 *   HMACKey{key, hash}, CreatedAt (Timestamp), CreatedBy}; the older JSON
 *   form {"bytes", "algorithm", "created_at", "created_by"} is read too;
 * - ciphertexts: AEAD(ciphertext || tag) || iv(16) || nonce(12), where the
 *   AEAD key is HMAC-SHA256(key, iv) for AES-256-GCM and HChaCha20(key, iv)
 *   for ChaCha20-Poly1305; the older msgpack and JSON ciphertexts decrypt. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

typedef enum { BUCKETS_KES_AES256 = 1, BUCKETS_KES_CHACHA20 = 2 } buckets_kes_cipher;

typedef struct {
  buckets_kes_cipher cipher;
  uint8_t key[32];
  bool has_hmac; /* keys from before KES 2024 have no HMAC key */
  uint8_t hmac[32];
  int64_t created_sec; /* unix */
  int32_t created_nsec;
  char created_by[80]; /* the creator's identity, or "" */
} buckets_kes_key;

/* A new AES-256 key with an HMAC key, created now by identity. */
void buckets_kes_key_new(buckets_kes_key *k, const char *created_by);
/* An imported key: bytes as given, a new HMAC key. False for an unknown
 * cipher name ("AES256", "AES256-GCM_SHA256", "ChaCha20", "XCHACHA20-POLY1305"). */
bool buckets_kes_key_import(buckets_kes_key *k, const char *cipher, const uint8_t bytes[32], const char *created_by);
void buckets_kes_key_wipe(buckets_kes_key *k);

/* The stored form (base64 of the protobuf). */
void buckets_kes_key_encode(const buckets_kes_key *k, buckets_buf *out);
/* Either stored form; false (why in err) if neither. */
bool buckets_kes_key_decode(const char *s, size_t n, buckets_kes_key *k, char *err, size_t errlen);

const char *buckets_kes_cipher_name(buckets_kes_cipher c); /* "AES256", "ChaCha20" */

/* Encrypts with associated data ctx (may be empty). */
void buckets_kes_encrypt(const buckets_kes_key *k, const void *pt, size_t n, const void *ctx, size_t nctx,
                         buckets_buf *out);
/* False when the ciphertext is not authentic (or not one of the forms). */
bool buckets_kes_decrypt(const buckets_kes_key *k, const void *ct, size_t n, const void *ctx, size_t nctx,
                         buckets_buf *out);
/* HMAC-SHA256 with the key's HMAC key (has_hmac must be set). */
void buckets_kes_hmac(const buckets_kes_key *k, const void *msg, size_t n, uint8_t out[32]);

#endif
