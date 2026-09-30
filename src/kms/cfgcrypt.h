/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_KMS_CFGCRYPT_H
#define BUCKETS_KMS_CFGCRYPT_H

/* Configuration sealed with the KMS (MinIO internal/config/crypto.go):
 * config.json, its history and the IAM files, when a KMS is configured.
 * A version byte, the metadata's length (uint32 LE) and its JSON
 * {"keyid","kmskey","algorithm","nonce"} -- a data key from the KMS bound to
 * the context {".minio.sys": ".minio.sys/<path>"} -- then the plaintext as a
 * sio-go STREAM under that key. */

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"
#include "kms/kms.h"

/* EncryptBytes for a .minio.sys path ("config/config.json"). */
bool buckets_cfgcrypt_seal(buckets_kms *k, const char *path, const void *data, size_t n, buckets_buf *out);
/* DecryptBytes: the context of path under .minio.sys, then (as MinIO's
 * decryptData also tries for IAM) path itself. */
bool buckets_cfgcrypt_open(buckets_kms *k, const char *path, const void *data, size_t n, buckets_buf *out);

#endif
