/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_KES_STORE_H
#define BUCKETS_KES_STORE_H

/* Where buckets-kes keeps its keys: the KES "keystore" of its configuration
 * (fs, vault, aws, azure, gcp), each laid out as MinIO KES lays it out, so
 * either server reads the keys the other created. Values are stored as given
 * (kes/key.h's encoded form). Every operation is safe to call from several
 * threads. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <yyjson.h>

#include "core/buf.h"

typedef enum {
  BUCKETS_KES_OK = 0,
  BUCKETS_KES_NOT_FOUND,   /* no such key */
  BUCKETS_KES_EXISTS,      /* create: the key exists */
  BUCKETS_KES_UNREACHABLE, /* the key store cannot be reached (or is sealed) */
  BUCKETS_KES_FAILED,      /* it refused or failed: err says how */
} buckets_kes_status;

typedef struct buckets_kes_store buckets_kes_store;

typedef struct {
  /* How long a trivial request took (microseconds). */
  buckets_kes_status (*status)(buckets_kes_store *s, int64_t *latency_us, char *err, size_t errlen);
  buckets_kes_status (*create)(buckets_kes_store *s, const char *name, const char *value, size_t n, char *err,
                               size_t errlen);
  buckets_kes_status (*get)(buckets_kes_store *s, const char *name, buckets_buf *value, char *err, size_t errlen);
  buckets_kes_status (*del)(buckets_kes_store *s, const char *name, char *err, size_t errlen);
  /* Every key's name (any order); the caller frees each and the array. */
  buckets_kes_status (*list)(buckets_kes_store *s, char ***names, size_t *n, char *err, size_t errlen);
  void (*close)(buckets_kes_store *s);
} buckets_kes_store_ops;

struct buckets_kes_store {
  const buckets_kes_store_ops *ops;
  char desc[300]; /* "Hashicorp Vault: https://...", as KES says it */
};

/* A key store from the configuration's "keystore" object (KES's schema).
 * Connects (signing in where the store needs it); NULL and why on failure,
 * which ends the server: a KES that cannot reach its key store does not
 * start. */
buckets_kes_store *buckets_kes_store_open(yyjson_val *keystore, char *err, size_t errlen);
void buckets_kes_store_close(buckets_kes_store *s);

/* The backends. */
buckets_kes_store *buckets_kes_fs_open(yyjson_val *conf, char *err, size_t errlen);
buckets_kes_store *buckets_kes_vault_open(yyjson_val *conf, char *err, size_t errlen);
buckets_kes_store *buckets_kes_aws_open(yyjson_val *conf, char *err, size_t errlen);
buckets_kes_store *buckets_kes_azure_open(yyjson_val *conf, char *err, size_t errlen);
buckets_kes_store *buckets_kes_gcp_open(yyjson_val *conf, char *err, size_t errlen);

/* Helpers for the backends. */
const char *buckets_kes_conf_str(yyjson_val *o, const char *path); /* "a.b.c"; NULL when absent */
bool buckets_kes_valid_name(const char *s);                         /* KES's validName */
/* A JSON body's error message (Vault's "errors", the clouds' "error"/"message"). */
void buckets_kes_error_text(const char *body, size_t n, char *out, size_t cap);

#endif
