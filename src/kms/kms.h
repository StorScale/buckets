/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_KMS_KMS_H
#define BUCKETS_KMS_KMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* The key management service behind SSE-S3 and SSE-KMS (MinIO internal/kms).
 * Backends: the static key of MINIO_KMS_SECRET_KEY / _FILE ("name:base64 of
 * 32 bytes", MinIO's builtin KMS). KES and MinIO KMS come later. */

typedef enum {
  BUCKETS_KMS_OK = 0,
  BUCKETS_KMS_ERR_KEY_NOT_FOUND,
  BUCKETS_KMS_ERR_KEY_EXISTS,
  BUCKETS_KMS_ERR_NOT_SUPPORTED,
  BUCKETS_KMS_ERR_DECRYPT,
  BUCKETS_KMS_ERR_UNAVAILABLE,
} buckets_kms_err;

typedef struct buckets_kms buckets_kms;

/* From the environment; NULL with *err empty when no KMS is configured, NULL
 * with err set when the configuration is invalid. */
buckets_kms *buckets_kms_from_env(char *err, size_t errlen);
/* A builtin KMS from "name:base64key" (tests, config). */
buckets_kms *buckets_kms_builtin(const char *spec, char *err, size_t errlen);
void buckets_kms_free(buckets_kms *k);

const char *buckets_kms_default_key(const buckets_kms *k);
/* madmin's KMS type name ("Builtin"). */
const char *buckets_kms_type(const buckets_kms *k);

/* GenerateKey: a fresh data key under key name (NULL/"": the default key),
 * bound to the context (kms.Context.MarshalText); ciphertext gets the sealed
 * key as stored in object metadata, key_id the key name used. */
buckets_kms_err buckets_kms_generate(buckets_kms *k, const char *name, const char *context, uint8_t plaintext[32],
                                     buckets_buf *ciphertext, char *key_id, size_t key_id_cap);
buckets_kms_err buckets_kms_decrypt(buckets_kms *k, const char *name, const uint8_t *ciphertext, size_t n,
                                    const char *context, uint8_t plaintext[32]);
/* CreateKey: the builtin KMS only "has" its one key. */
buckets_kms_err buckets_kms_create_key(buckets_kms *k, const char *name);
/* The key names starting with prefix (ListKeys). Caller frees each and the array. */
size_t buckets_kms_list_keys(buckets_kms *k, const char *prefix, char ***names);

/* KMS.Metrics: request counters and a cumulative latency histogram over
 * MinIO's buckets (10ms ... 10s). */
#define BUCKETS_KMS_LATENCY_BUCKETS 10
typedef struct {
  uint64_t ok, err, fail;
  uint64_t latency[BUCKETS_KMS_LATENCY_BUCKETS];
} buckets_kms_metrics;
extern const int64_t buckets_kms_latency_ms[BUCKETS_KMS_LATENCY_BUCKETS];
void buckets_kms_metrics_get(buckets_kms *k, buckets_kms_metrics *out);

/* kms.Context.MarshalText: a JSON object with sorted keys and Go's
 * HTML-safe escaping ("{}" when empty). */
void buckets_kms_context_text(const char *const *keys, const char *const *values, size_t n, buckets_buf *out);

#endif
