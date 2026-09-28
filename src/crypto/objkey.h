/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_OBJKEY_H
#define BUCKETS_CRYPTO_OBJKEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* Object encryption keys (MinIO internal/crypto/key.go): each object gets a
 * random 256-bit key, sealed with the external key (KMS data key or SSE-C
 * customer key) and stored in the object's metadata. */

#define BUCKETS_SEAL_ALGORITHM "DAREv2-HMAC-SHA256"
#define BUCKETS_INSECURE_SEAL_ALGORITHM "DARE-SHA256"
#define BUCKETS_SEALED_KEY_LEN 64

/* GenerateKey: HMAC-SHA256(ext, "object-encryption-key generation" || nonce),
 * nonce random unless given (tests). */
void buckets_objkey_generate(const uint8_t ext[32], const uint8_t *nonce32, uint8_t key[32]);
/* ObjectKey.Seal: into sealed (64 bytes); iv random unless given. domain is
 * "SSE-S3", "SSE-KMS" or "SSE-C". */
void buckets_objkey_seal(const uint8_t key[32], const uint8_t ext[32], const uint8_t *iv32, const char *domain,
                         const char *bucket, const char *object, uint8_t iv_out[32], uint8_t sealed[BUCKETS_SEALED_KEY_LEN]);
/* ObjectKey.Unseal: false when the external key is wrong or the sealed key
 * was tampered with (ErrSecretKeyMismatch), or the algorithm is unsupported. */
bool buckets_objkey_unseal(const uint8_t ext[32], const uint8_t sealed[BUCKETS_SEALED_KEY_LEN], const uint8_t iv[32],
                           const char *algorithm, const char *domain, const char *bucket, const char *object,
                           uint8_t key[32]);
/* DerivePartKey: HMAC-SHA256(key, LE32(part number)). */
void buckets_objkey_part_key(const uint8_t key[32], uint32_t part, uint8_t out[32]);
/* SealETag / UnsealETag (an ETag of 16 bytes or less is not sealed). */
void buckets_objkey_seal_etag(const uint8_t key[32], const uint8_t *etag, size_t n, buckets_buf *out);
bool buckets_objkey_unseal_etag(const uint8_t key[32], const uint8_t *etag, size_t n, buckets_buf *out);

/* Go's path.Join(bucket, object): the canonical "bucket/object" keys are bound to. */
void buckets_path_join(const char *a, const char *b, buckets_buf *out);

#endif
