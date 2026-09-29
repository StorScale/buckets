/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NOTIFY_NKEYS_H
#define BUCKETS_NOTIFY_NKEYS_H

#include <stdbool.h>
#include <stddef.h>

/* NATS NKeys (github.com/nats-io/nkeys): ed25519 keys written as base32
 * with a type prefix and a CRC16. From a seed ("SU..."), the public key
 * ("U...") and a signature of a server nonce, base64url without padding, as
 * nats.go sends in CONNECT. */
bool buckets_nkey_from_seed(const char *seed, char *public_key, size_t pkcap, char *err, size_t errlen);
bool buckets_nkey_sign(const char *seed, const void *msg, size_t n, char *sig_b64url, size_t sigcap, char *err,
                       size_t errlen);

/* A .creds file (nats.UserCredentials): the user JWT and seed between the
 * "-----BEGIN ...-----" markers, in that order. Malloc'd. */
bool buckets_nats_creds_read(const char *path, char **jwt, char **seed, char *err, size_t errlen);

/* nats.NkeyOptionFromSeed's file (nkeys.ParseDecoratedNKey): the second
 * decorated block, else the first line starting with SO, SA or SU; it must
 * be a user seed. Malloc'd. */
bool buckets_nkey_seed_file(const char *path, char **seed, char *err, size_t errlen);

#endif
