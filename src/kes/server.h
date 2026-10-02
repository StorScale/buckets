/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_KES_SERVER_H
#define BUCKETS_KES_SERVER_H

/* buckets-kes: a key server speaking MinIO KES's API (the /v1/key APIs, /v1/status,
 * /v1/ready, ...), so bucketsd, MinIO and the KES clients use it as they use
 * KES, and reading KES's configuration file. Clients are known by their TLS
 * certificate: the identity is the hex SHA-256 of its public key, which is
 * the admin's or has a policy (allow and deny path patterns, '*' ending one
 * as a prefix match, deny first). Keys are cached after they are read. */

#include <stdbool.h>
#include <stdint.h>
#include <yyjson.h>

#include "kes/store.h"
#include "net/http.h"

typedef struct buckets_kes_server buckets_kes_server;

/* The configuration file (YAML or JSON, KES's schema; ${VAR} in values reads
 * the environment) as a JSON document; NULL and why. */
yyjson_doc *buckets_kes_config_load(const char *path, char *err, size_t errlen);

/* A server for a configuration: opens the key store (signing in) and creates
 * the configuration's "keys" when missing. NULL and why. The address and TLS
 * files are the caller's to serve (buckets_kes_server_address, _tls_files). */
buckets_kes_server *buckets_kes_server_new(yyjson_doc *config, char *err, size_t errlen);
void buckets_kes_server_free(buckets_kes_server *s);
const char *buckets_kes_server_address(const buckets_kes_server *s); /* "0.0.0.0:7373" */
void buckets_kes_server_tls_files(const buckets_kes_server *s, const char **cert, const char **key);
const char *buckets_kes_server_store_desc(const buckets_kes_server *s);

void buckets_kes_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

/* The identity of a DER certificate chain's leaf (the one certificate that
 * is not a CA): hex SHA-256 of its SubjectPublicKeyInfo. */
bool buckets_kes_cert_identity(const buckets_buf *certs, size_t n, char hex[65], char *err, size_t errlen);

#endif
