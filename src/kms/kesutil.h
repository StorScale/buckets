/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_KMS_KESUTIL_H
#define BUCKETS_KMS_KESUTIL_H

/* What running a KES server takes, for the operator (which runs one per
 * cluster) and the console (which configures it): API keys and their
 * identities, a server certificate, and the key store settings people fill
 * in, turned into KES's own configuration. */

#include <stdbool.h>
#include <stddef.h>
#include <yyjson.h>

#include "core/buf.h"

/* A new KES API key, "kes:v1:" and the base64 of a type byte (0, Ed25519)
 * and a 32-byte seed. */
void buckets_kes_api_key_new(char out[64]);
/* The identity KES knows an API key's holder by: the hex SHA-256 of its
 * Ed25519 public key's SubjectPublicKeyInfo. False if the key is malformed. */
bool buckets_kes_identity(const char *api_key, char hex[65]);

/* A self-signed ECDSA P-256 server certificate for the given DNS names, valid
 * for days, usable as its own trust anchor. PEM into cert and key. */
bool buckets_kes_server_cert(const char *const *dns, size_t ndns, int days, buckets_buf *cert, buckets_buf *key,
                             char *err, size_t errlen);

/* ---- key store settings ----------------------------------------------------------
 *
 * The settings a person fills in, as JSON:
 *   {"backend": "vault" | "aws" | "azure" | "gcp",
 *    "vault": {"endpoint", "engine", "version", "namespace", "prefix",
 *              "auth": "approle" | "kubernetes",
 *              "approle": {"engine", "id", "secret"},
 *              "kubernetes": {"engine", "role"},
 *              "transit": {"engine", "key"}, "caCert"},
 *    "aws": {"region", "endpoint", "kmsKey", "accessKey", "secretKey", "sessionToken"},
 *    "azure": {"endpoint", "auth": "secret" | "managedIdentity", "tenantId", "clientId",
 *              "clientSecret", "managedIdentityClientId"},
 *    "gcp": {"projectId", "endpoint", "credentials"}}  (credentials: a service account's JSON key)
 * Only the chosen backend's object matters. */

/* The settings' secret fields, as "backend.path.to.field": shown to nobody
 * once saved. NULL-terminated. */
extern const char *const buckets_kes_secret_fields[];

/* Checks settings and writes KES's "keystore" object for them into d.
 * ca_path: where a Vault CA certificate (vault.caCert) is mounted. On error,
 * NULL and why, in words for the person who filled them in. */
yyjson_mut_val *buckets_kes_keystore(yyjson_mut_doc *d, yyjson_val *settings, const char *ca_path, char *err,
                                     size_t errlen);

/* A copy of settings with each secret field set replaced by "" and listed
 * in "secretsSet" (an array of the field names above). */
yyjson_mut_val *buckets_kes_settings_redacted(yyjson_mut_doc *d, yyjson_val *settings);
/* In settings (mutable), each secret field left empty takes its value from
 * saved, when saved has one for the same backend: editing keeps secrets
 * nobody retyped. */
void buckets_kes_settings_keep_secrets(yyjson_mut_doc *d, yyjson_mut_val *settings, yyjson_val *saved);

/* A one-line summary of where keys are kept ("HashiCorp Vault at https://...",
 * "AWS Secrets Manager in us-east-1", ...). */
void buckets_kes_settings_describe(yyjson_val *settings, char *out, size_t cap);

#endif
