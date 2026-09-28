/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_MADMIN_H
#define BUCKETS_CRYPTO_MADMIN_H

#include "core/buf.h"

/* madmin's EncryptData/DecryptData, which the admin API uses for anything
 * carrying credentials: 32-byte salt | algorithm id | 8-byte nonce | a
 * secure-io/sio stream (16 KiB fragments) under a key derived from the
 * caller's secret key with Argon2id (t=1, m=64 MiB, p=4) -- or PBKDF2 for
 * FIPS-mode clients. */
bool buckets_madmin_encrypt(const char *password, const void *data, size_t n, buckets_buf *out);
bool buckets_madmin_decrypt(const char *password, const void *data, size_t n, buckets_buf *out);
bool buckets_madmin_is_encrypted(const void *data, size_t n);

#endif
