/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_FIPS_H
#define BUCKETS_CRYPTO_FIPS_H

/* FIPS 140-3 mode (docs/design/fips-mode.md, docs/fips.md). With BUCKETS_FIPS=on, every security function runs in
 * OpenSSL's FIPS provider: buckets_crypto_init installs the module for this machine (openssl fipsinstall, as its
 * security policy requires), loads it with the base and default providers, and makes "fips=yes" the default
 * property, so nothing else is fetched unless asked for by name. Without it, OpenSSL's default provider serves
 * everything, through the same calls.
 *
 *   BUCKETS_FIPS              on: FIPS mode (the -fips images set it); off or unset: not
 *   BUCKETS_FIPS_MODULE       the provider (default /usr/lib/buckets/fips/fips.so, as in the -fips images)
 *   BUCKETS_FIPS_OPENSSL      the openssl program that installs it (default /usr/lib/buckets/fips/openssl)
 *   BUCKETS_FIPS_DIR          where the per-machine configuration goes (default: a new directory under $TMPDIR)
 *   BUCKETS_FIPS_STRICT       on: refuse admin payloads sealed outside the module (Argon2id) as well */

#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>

/* Sets up OpenSSL, once, before anything uses it. False (and why) in FIPS mode when the module can't be installed,
 * loaded or self-tested; the caller must not go on. */
bool buckets_crypto_init(char *err, size_t errlen);

bool buckets_fips_mode(void);
bool buckets_fips_strict(void);
/* The FIPS provider's name and version ("OpenSSL FIPS Provider 3.1.2"), or "" outside FIPS mode. */
const char *buckets_fips_module(void);

/* The digests, fetched once: from the FIPS provider in FIPS mode. MD5 always comes from the default provider: its
 * uses (S3 ETags, Content-MD5) protect nothing. */
const EVP_MD *buckets_md_sha1(void);
const EVP_MD *buckets_md_sha256(void);
const EVP_MD *buckets_md_sha512(void);
const EVP_MD *buckets_md_md5(void);
/* AES-256-GCM, and ChaCha20-Poly1305 (NULL in FIPS mode: not approved). */
const EVP_CIPHER *buckets_cipher_aes256gcm(void);
const EVP_CIPHER *buckets_cipher_chacha20poly1305(void);
/* ChaCha20-Poly1305 for madmin payloads only, outside the module in FIPS mode unless strict (NULL then). */
const EVP_CIPHER *buckets_cipher_chacha20poly1305_madmin(void);
/* The property query for algorithms allowed outside the module ("-fips" in FIPS mode, else ""). */
const char *buckets_crypto_nonfips_props(void);

#endif
