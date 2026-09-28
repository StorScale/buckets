/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_DARE_H
#define BUCKETS_CRYPTO_DARE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto/aead.h"

/* DARE 2.0 (github.com/minio/sio): a stream split into packages of a
 * 16-byte header, up to 64 KiB of AEAD-encrypted payload and a 16-byte tag.
 * Header: 0x20, cipher, payload length - 1 (LE uint16), 12 random bytes
 * whose top bit marks the final package. The AEAD nonce is those 12 bytes
 * with the sequence number XORed into the last four (LE); the associated
 * data is the first 4 header bytes. Every package but the last carries
 * exactly 64 KiB; an empty stream has no packages. */

#define BUCKETS_DARE_HEADER 16
#define BUCKETS_DARE_TAG 16
#define BUCKETS_DARE_OVERHEAD (BUCKETS_DARE_HEADER + BUCKETS_DARE_TAG)
#define BUCKETS_DARE_PAYLOAD 65536
#define BUCKETS_DARE_PACKAGE (BUCKETS_DARE_PAYLOAD + BUCKETS_DARE_OVERHEAD)
#define BUCKETS_DARE_VERSION20 0x20

typedef struct {
  buckets_aead *aead;
  uint8_t cipher;
  uint8_t rand[12];
  uint32_t seq;
  bool finalized;
} buckets_dare_enc;

/* A random nonce (nonce NULL) or a given one; AES-256-GCM, as MinIO picks on
 * CPUs with AES instructions. */
void buckets_dare_enc_init(buckets_dare_enc *e, const uint8_t key[32], const uint8_t *nonce, uint32_t seq);
void buckets_dare_enc_free(buckets_dare_enc *e);
/* Seals n (1..64 KiB) bytes into out (n + 32 bytes); returns n + 32. */
size_t buckets_dare_seal(buckets_dare_enc *e, const void *in, size_t n, bool final, uint8_t *out);

typedef enum {
  BUCKETS_DARE_OK = 0,
  BUCKETS_DARE_ERR_VERSION = -1,
  BUCKETS_DARE_ERR_CIPHER = -2,
  BUCKETS_DARE_ERR_SIZE = -3,
  BUCKETS_DARE_ERR_NONCE = -4,
  BUCKETS_DARE_ERR_TAG = -5,
  BUCKETS_DARE_ERR_UNEXPECTED_DATA = -6, /* a package after the final one */
} buckets_dare_err;

typedef struct {
  uint8_t key[32];
  buckets_aead *aead[2];
  uint32_t seq;
  bool have_ref, finalized;
  uint8_t ref[BUCKETS_DARE_HEADER];
} buckets_dare_dec;

/* seq: the first package's sequence number (reads that start mid-stream). */
void buckets_dare_dec_init(buckets_dare_dec *d, const uint8_t key[32], uint32_t seq);
void buckets_dare_dec_free(buckets_dare_dec *d);
/* The whole package's size from its header. */
size_t buckets_dare_package_size(const uint8_t header[BUCKETS_DARE_HEADER]);
/* Opens one package (exactly its bytes) into out; returns the payload
 * length, or a buckets_dare_err. */
long buckets_dare_open(buckets_dare_dec *d, const uint8_t *pkg, size_t n, uint8_t *out);
bool buckets_dare_finalized(const buckets_dare_dec *d);

/* sio.EncryptedSize / DecryptedSize */
uint64_t buckets_dare_encrypted_size(uint64_t n);
bool buckets_dare_decrypted_size(uint64_t n, uint64_t *out);

/* A whole (small) stream: sio.Encrypt into out, buckets_dare_encrypted_size(n)
 * bytes; and sio.DecryptBuffer, returning the plaintext length or -1. */
size_t buckets_dare_encrypt_buffer(const uint8_t key[32], const void *in, size_t n, uint8_t *out);
long buckets_dare_decrypt_buffer(const uint8_t key[32], const void *in, size_t n, uint8_t *out);

#endif
