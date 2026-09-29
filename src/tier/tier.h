/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_TIER_TIER_H
#define BUCKETS_TIER_TIER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"
#include "net/client.h"
#include "net/tls.h"

/* Remote tiers (MinIO's TierConfigMgr, cmd/tier.go, and the warm backends,
 * cmd/warm-backend*.go): where lifecycle transitions move object data.
 * The configuration is .minio.sys/config/tier-config.bin: a 4-byte header
 * (format 1, version 2) and msgp of {"Tiers": {name: madmin.TierConfig}},
 * SSE-S3-encrypted when a KMS is configured. */

typedef enum {
  BUCKETS_TIER_UNSUPPORTED = 0,
  BUCKETS_TIER_S3,
  BUCKETS_TIER_AZURE,
  BUCKETS_TIER_GCS,
  BUCKETS_TIER_MINIO,
} buckets_tier_type;

/* madmin.TierConfig (every string owned, "" when unset) */
typedef struct {
  char *version, *name;
  buckets_tier_type type;
  bool has_s3, has_azure, has_gcs, has_minio; /* which sub-configurations are present (not nil) */
  struct {
    char *endpoint, *access_key, *secret_key, *bucket, *prefix, *region, *storage_class;
    bool aws_role;
    char *aws_role_web_identity_token_file, *aws_role_arn, *aws_role_session_name;
    int64_t aws_role_duration_seconds;
  } s3;
  struct {
    char *endpoint, *account_name, *account_key, *bucket, *prefix, *region, *storage_class;
    char *sp_tenant_id, *sp_client_id, *sp_client_secret;
  } azure;
  struct {
    char *endpoint, *creds, *bucket, *prefix, *region, *storage_class;
  } gcs;
  struct {
    char *endpoint, *access_key, *secret_key, *bucket, *prefix, *region;
  } minio;
} buckets_tier_config;

void buckets_tier_config_init(buckets_tier_config *t);
void buckets_tier_config_free(buckets_tier_config *t);
void buckets_tier_config_copy(buckets_tier_config *dst, const buckets_tier_config *src);
const char *buckets_tier_type_name(buckets_tier_type t); /* "s3", "azure", "gcs", "minio", "unsupported" */
/* The fields of the configured type. */
const char *buckets_tier_endpoint(const buckets_tier_config *t);
const char *buckets_tier_bucket(const buckets_tier_config *t);
const char *buckets_tier_prefix(const buckets_tier_config *t);
const char *buckets_tier_region(const buckets_tier_config *t);

/* ---- warm backends ---- */

typedef struct buckets_warm buckets_warm;

/* Errors of backend operations. */
typedef enum {
  BUCKETS_WARM_OK = 0,
  BUCKETS_WARM_ERR_DOWN,          /* network failure (BackendDown) */
  BUCKETS_WARM_ERR_NOT_FOUND,     /* the object (or version) is not there */
  BUCKETS_WARM_ERR_BUCKET,        /* the bucket does not exist */
  BUCKETS_WARM_ERR_CREDENTIALS,   /* signature/credential rejected */
  BUCKETS_WARM_ERR_OTHER,
} buckets_warm_err;

/* newWarmBackend: NULL with err on an invalid configuration. tls may be NULL. */
buckets_warm *buckets_warm_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen);
buckets_warm *buckets_warm_ref(buckets_warm *w);
void buckets_warm_release(buckets_warm *w);
const char *buckets_warm_tier(const buckets_warm *w);

/* PutWithMeta: length bytes from rd; *rv gets the remote version ID ("" if unversioned). */
buckets_warm_err buckets_warm_put(buckets_warm *w, const char *object, buckets_http_read_fn rd, void *rd_ud,
                                  int64_t length, const char *orig_name, char *rv, size_t rvcap, char *err,
                                  size_t errlen);
/* Get: [off, off+len) (len < 0: to the end); a stream for
 * buckets_warm_stream_read / buckets_warm_stream_free. */
typedef struct buckets_warm_stream buckets_warm_stream;
buckets_warm_err buckets_warm_get(buckets_warm *w, const char *object, const char *rv, int64_t off, int64_t len,
                                  buckets_warm_stream **out, char *err, size_t errlen);
long buckets_warm_stream_read(buckets_warm_stream *s, void *buf, size_t n);
void buckets_warm_stream_free(buckets_warm_stream *s);
buckets_warm_err buckets_warm_remove(buckets_warm *w, const char *object, const char *rv, char *err, size_t errlen);
/* InUse: anything under the tier's bucket/prefix. */
buckets_warm_err buckets_warm_in_use(buckets_warm *w, bool *in_use, char *err, size_t errlen);

/* ---- the tier configuration manager ---- */

struct buckets_s3_server;
typedef struct buckets_tiers buckets_tiers;

buckets_tiers *buckets_tiers_new(struct buckets_s3_server *s);
void buckets_tiers_free(buckets_tiers *t);
/* Reload: re-reads tier-config.bin (absent: no tiers). */
bool buckets_tiers_reload(buckets_tiers *t);
bool buckets_tiers_empty(buckets_tiers *t);
/* IsTierValid */
bool buckets_tiers_valid(buckets_tiers *t, const char *name);
/* TierType: "internal" when unknown. */
const char *buckets_tiers_type(buckets_tiers *t, const char *name);
/* getDriver: a reference to release, or NULL (err says why). */
buckets_warm *buckets_tiers_driver(buckets_tiers *t, const char *name, char *err, size_t errlen);

/* Admin operations: an admin API error (code, HTTP status and message) on failure. */
typedef struct {
  int status;
  char code[64];
  char message[1024];
} buckets_tier_err;

bool buckets_tiers_add(buckets_tiers *t, const char *json, size_t n, bool force, buckets_tier_err *e);
bool buckets_tiers_edit(buckets_tiers *t, const char *name, const char *json, size_t n, buckets_tier_err *e);
bool buckets_tiers_remove(buckets_tiers *t, const char *name, bool force, buckets_tier_err *e);
bool buckets_tiers_verify(buckets_tiers *t, const char *name, buckets_tier_err *e);
/* ListTiers: the JSON array madmin decodes (secrets REDACTED). */
void buckets_tiers_list_json(buckets_tiers *t, buckets_buf *out);
/* The names of the tiers (strings and array to free). */
size_t buckets_tiers_names(buckets_tiers *t, char ***names);
int64_t buckets_tiers_refreshed_at(buckets_tiers *t); /* unix nanoseconds of the last reload */

/* The msgp codec of tier-config.bin (with its header). */
void buckets_tiers_encode(const buckets_tier_config *tiers, size_t n, buckets_buf *out);
bool buckets_tiers_decode(const void *data, size_t n, buckets_tier_config **tiers, size_t *count);
/* madmin.TierConfig.UnmarshalJSON; err as its errors ("invalid tier config", ...). */
bool buckets_tier_config_parse_json(const char *json, size_t n, buckets_tier_config *out, char *err, size_t errlen);

#endif
