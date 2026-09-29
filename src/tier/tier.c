/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The tier configuration (MinIO's cmd/tier.go and cmd/tier-handlers.go,
 * with madmin.TierConfig's JSON and msgp forms). */
#include "tier/tier.h"

#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/log.h"
#include "core/msgpack.h"
#include "crypto/base64.h"
#include "dist/peer.h"
#include "s3/replicate.h"
#include "s3/server.h"

#define TIER_CONFIG_PATH "config/tier-config.bin"
#define TIER_FORMAT 1
#define TIER_VERSION 2
#define TIER_VERSION_V1 1

/* ---- configurations ------------------------------------------------------------------ */

#define TIER_STRINGS(X, t)                                                                                        \
  X(t->version) X(t->name) X(t->s3.endpoint) X(t->s3.access_key) X(t->s3.secret_key) X(t->s3.bucket)              \
      X(t->s3.prefix) X(t->s3.region) X(t->s3.storage_class) X(t->s3.aws_role_web_identity_token_file)            \
          X(t->s3.aws_role_arn) X(t->s3.aws_role_session_name) X(t->azure.endpoint) X(t->azure.account_name)      \
              X(t->azure.account_key) X(t->azure.bucket) X(t->azure.prefix) X(t->azure.region)                    \
                  X(t->azure.storage_class) X(t->azure.sp_tenant_id) X(t->azure.sp_client_id)                     \
                      X(t->azure.sp_client_secret) X(t->gcs.endpoint) X(t->gcs.creds) X(t->gcs.bucket)            \
                          X(t->gcs.prefix) X(t->gcs.region) X(t->gcs.storage_class) X(t->minio.endpoint)          \
                              X(t->minio.access_key) X(t->minio.secret_key) X(t->minio.bucket) X(t->minio.prefix) \
                                  X(t->minio.region)

void buckets_tier_config_init(buckets_tier_config *t) {
  memset(t, 0, sizeof(*t));
#define INIT(f) f = buckets_xstrdup("");
  TIER_STRINGS(INIT, t)
#undef INIT
}

void buckets_tier_config_free(buckets_tier_config *t) {
#define FREE(f) free(f);
  TIER_STRINGS(FREE, t)
#undef FREE
  memset(t, 0, sizeof(*t));
}

void buckets_tier_config_copy(buckets_tier_config *dst, const buckets_tier_config *src) {
  *dst = *src;
#define DUP(f) f = buckets_xstrdup(f);
  buckets_tier_config *t = dst;
  TIER_STRINGS(DUP, t)
#undef DUP
}

static void set(char **f, const char *v) {
  free(*f);
  *f = buckets_xstrdup(v ? v : "");
}

const char *buckets_tier_type_name(buckets_tier_type t) {
  switch (t) {
    case BUCKETS_TIER_S3: return "s3";
    case BUCKETS_TIER_AZURE: return "azure";
    case BUCKETS_TIER_GCS: return "gcs";
    case BUCKETS_TIER_MINIO: return "minio";
    default: return "unsupported";
  }
}

static buckets_tier_type type_of(const char *s) {
  if (strcmp(s, "s3") == 0) return BUCKETS_TIER_S3;
  if (strcmp(s, "azure") == 0) return BUCKETS_TIER_AZURE;
  if (strcmp(s, "gcs") == 0) return BUCKETS_TIER_GCS;
  if (strcmp(s, "minio") == 0) return BUCKETS_TIER_MINIO;
  return BUCKETS_TIER_UNSUPPORTED;
}

#define FIELD(t, f)                                  \
  (t->type == BUCKETS_TIER_S3      ? t->s3.f         \
   : t->type == BUCKETS_TIER_AZURE ? t->azure.f      \
   : t->type == BUCKETS_TIER_GCS   ? t->gcs.f        \
   : t->type == BUCKETS_TIER_MINIO ? t->minio.f      \
                                   : "")
const char *buckets_tier_endpoint(const buckets_tier_config *t) { return FIELD(t, endpoint); }
const char *buckets_tier_bucket(const buckets_tier_config *t) { return FIELD(t, bucket); }
const char *buckets_tier_prefix(const buckets_tier_config *t) { return FIELD(t, prefix); }
const char *buckets_tier_region(const buckets_tier_config *t) { return FIELD(t, region); }

/* ---- JSON (madmin.TierConfig) ------------------------------------------------------------ */

/* encoding/json matches field names case-insensitively */
static yyjson_val *jget(yyjson_val *o, const char *key) {
  size_t idx, max;
  yyjson_val *k, *v;
  if (!yyjson_is_obj(o)) return NULL;
  yyjson_obj_foreach(o, idx, max, k, v) {
    if (strcasecmp(yyjson_get_str(k), key) == 0) return v;
  }
  return NULL;
}

static bool jstr(yyjson_val *o, const char *key, char **dst, char *err, size_t errlen) {
  yyjson_val *v = jget(o, key);
  if (!v || yyjson_is_null(v)) return true;
  if (!yyjson_is_str(v)) {
    snprintf(err, errlen, "json: cannot unmarshal into Go struct field of type string");
    return false;
  }
  set(dst, yyjson_get_str(v));
  return true;
}

bool buckets_tier_config_parse_json(const char *json, size_t n, buckets_tier_config *out, char *err, size_t errlen) {
  buckets_tier_config_init(out);
  yyjson_doc *doc = yyjson_read(json, n, 0);
  yyjson_val *r = yyjson_doc_get_root(doc);
  bool ok = false;
  if (!yyjson_is_obj(r)) {
    snprintf(err, errlen, "invalid character in tier configuration");
    goto out;
  }
  if (!jstr(r, "Version", &out->version, err, errlen) || !jstr(r, "Name", &out->name, err, errlen)) goto out;
  yyjson_val *tv = jget(r, "Type");
  if (tv && !yyjson_is_null(tv)) {
    const char *ts = yyjson_get_str(tv);
    out->type = ts ? type_of(ts) : BUCKETS_TIER_UNSUPPORTED;
    if (!ts || out->type == BUCKETS_TIER_UNSUPPORTED) {
      snprintf(err, errlen, "unsupported tier type");
      goto out;
    }
  }
  yyjson_val *s3 = jget(r, "S3"), *az = jget(r, "Azure"), *gcs = jget(r, "GCS"), *mn = jget(r, "MinIO");
  out->has_s3 = yyjson_is_obj(s3);
  out->has_azure = yyjson_is_obj(az);
  out->has_gcs = yyjson_is_obj(gcs);
  out->has_minio = yyjson_is_obj(mn);
  bool fields = true;
  if (out->has_s3) {
    fields &= jstr(s3, "Endpoint", &out->s3.endpoint, err, errlen) && jstr(s3, "AccessKey", &out->s3.access_key, err, errlen) &&
              jstr(s3, "SecretKey", &out->s3.secret_key, err, errlen) && jstr(s3, "Bucket", &out->s3.bucket, err, errlen) &&
              jstr(s3, "Prefix", &out->s3.prefix, err, errlen) && jstr(s3, "Region", &out->s3.region, err, errlen) &&
              jstr(s3, "StorageClass", &out->s3.storage_class, err, errlen) &&
              jstr(s3, "AWSRoleWebIdentityTokenFile", &out->s3.aws_role_web_identity_token_file, err, errlen) &&
              jstr(s3, "AWSRoleARN", &out->s3.aws_role_arn, err, errlen) &&
              jstr(s3, "AWSRoleSessionName", &out->s3.aws_role_session_name, err, errlen);
    out->s3.aws_role = yyjson_get_bool(jget(s3, "AWSRole"));
    out->s3.aws_role_duration_seconds = yyjson_get_int(jget(s3, "AWSRoleDurationSeconds"));
  }
  if (out->has_azure) {
    fields &= jstr(az, "Endpoint", &out->azure.endpoint, err, errlen) &&
              jstr(az, "AccountName", &out->azure.account_name, err, errlen) &&
              jstr(az, "AccountKey", &out->azure.account_key, err, errlen) && jstr(az, "Bucket", &out->azure.bucket, err, errlen) &&
              jstr(az, "Prefix", &out->azure.prefix, err, errlen) && jstr(az, "Region", &out->azure.region, err, errlen) &&
              jstr(az, "StorageClass", &out->azure.storage_class, err, errlen);
    yyjson_val *sp = jget(az, "SPAuth");
    fields &= jstr(sp, "TenantID", &out->azure.sp_tenant_id, err, errlen) &&
              jstr(sp, "ClientID", &out->azure.sp_client_id, err, errlen) &&
              jstr(sp, "ClientSecret", &out->azure.sp_client_secret, err, errlen);
  }
  if (out->has_gcs) {
    fields &= jstr(gcs, "Endpoint", &out->gcs.endpoint, err, errlen) && jstr(gcs, "Creds", &out->gcs.creds, err, errlen) &&
              jstr(gcs, "Bucket", &out->gcs.bucket, err, errlen) && jstr(gcs, "Prefix", &out->gcs.prefix, err, errlen) &&
              jstr(gcs, "Region", &out->gcs.region, err, errlen) && jstr(gcs, "StorageClass", &out->gcs.storage_class, err, errlen);
  }
  if (out->has_minio) {
    fields &= jstr(mn, "Endpoint", &out->minio.endpoint, err, errlen) && jstr(mn, "AccessKey", &out->minio.access_key, err, errlen) &&
              jstr(mn, "SecretKey", &out->minio.secret_key, err, errlen) && jstr(mn, "Bucket", &out->minio.bucket, err, errlen) &&
              jstr(mn, "Prefix", &out->minio.prefix, err, errlen) && jstr(mn, "Region", &out->minio.region, err, errlen);
  }
  if (!fields) goto out;
  if (strcmp(out->version, "v1") != 0) {
    snprintf(err, errlen, "invalid tier config version");
    goto out;
  }
  bool present = out->type == BUCKETS_TIER_S3      ? out->has_s3
                 : out->type == BUCKETS_TIER_AZURE ? out->has_azure
                 : out->type == BUCKETS_TIER_GCS   ? out->has_gcs
                 : out->type == BUCKETS_TIER_MINIO ? out->has_minio
                                                   : true;
  if (!present) {
    snprintf(err, errlen, "invalid tier config");
    goto out;
  }
  if (!*out->name) {
    snprintf(err, errlen, "remote tier name empty");
    goto out;
  }
  ok = true;
out:
  yyjson_doc_free(doc);
  if (!ok) buckets_tier_config_free(out);
  return ok;
}

static void jadd(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, const char *v) {
  if (v && *v) yyjson_mut_obj_add_strcpy(d, o, key, v); /* omitempty */
}

/* TierConfig.Clone as json.Marshal writes it: every sub-configuration, the
 * configured one's secret REDACTED. */
static yyjson_mut_val *config_json(yyjson_mut_doc *d, const buckets_tier_config *t) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "Version", t->version);
  if (t->type != BUCKETS_TIER_UNSUPPORTED) yyjson_mut_obj_add_str(d, o, "Type", buckets_tier_type_name(t->type));
  jadd(d, o, "Name", t->name);
  bool s3 = t->type == BUCKETS_TIER_S3, az = t->type == BUCKETS_TIER_AZURE, gcs = t->type == BUCKETS_TIER_GCS,
       mn = t->type == BUCKETS_TIER_MINIO;
  yyjson_mut_val *v = yyjson_mut_obj_add_obj(d, o, "S3");
  if (s3) {
    jadd(d, v, "Endpoint", t->s3.endpoint);
    jadd(d, v, "AccessKey", t->s3.access_key);
    yyjson_mut_obj_add_str(d, v, "SecretKey", "REDACTED");
    jadd(d, v, "Bucket", t->s3.bucket);
    jadd(d, v, "Prefix", t->s3.prefix);
    jadd(d, v, "Region", t->s3.region);
    jadd(d, v, "StorageClass", t->s3.storage_class);
    if (t->s3.aws_role) yyjson_mut_obj_add_bool(d, v, "AWSRole", true);
    jadd(d, v, "AWSRoleWebIdentityTokenFile", t->s3.aws_role_web_identity_token_file);
    jadd(d, v, "AWSRoleARN", t->s3.aws_role_arn);
    jadd(d, v, "AWSRoleSessionName", t->s3.aws_role_session_name);
    if (t->s3.aws_role_duration_seconds) yyjson_mut_obj_add_int(d, v, "AWSRoleDurationSeconds", t->s3.aws_role_duration_seconds);
  }
  v = yyjson_mut_obj_add_obj(d, o, "Azure");
  if (az) {
    jadd(d, v, "Endpoint", t->azure.endpoint);
    jadd(d, v, "AccountName", t->azure.account_name);
    yyjson_mut_obj_add_str(d, v, "AccountKey", "REDACTED");
    jadd(d, v, "Bucket", t->azure.bucket);
    jadd(d, v, "Prefix", t->azure.prefix);
    jadd(d, v, "Region", t->azure.region);
    jadd(d, v, "StorageClass", t->azure.storage_class);
  }
  yyjson_mut_val *sp = yyjson_mut_obj_add_obj(d, v, "SPAuth");
  if (az) {
    jadd(d, sp, "TenantID", t->azure.sp_tenant_id);
    jadd(d, sp, "ClientID", t->azure.sp_client_id);
    jadd(d, sp, "ClientSecret", t->azure.sp_client_secret);
  }
  v = yyjson_mut_obj_add_obj(d, o, "GCS");
  if (gcs) {
    jadd(d, v, "Endpoint", t->gcs.endpoint);
    yyjson_mut_obj_add_str(d, v, "Creds", "REDACTED");
    jadd(d, v, "Bucket", t->gcs.bucket);
    jadd(d, v, "Prefix", t->gcs.prefix);
    jadd(d, v, "Region", t->gcs.region);
    jadd(d, v, "StorageClass", t->gcs.storage_class);
  }
  v = yyjson_mut_obj_add_obj(d, o, "MinIO");
  if (mn) {
    jadd(d, v, "Endpoint", t->minio.endpoint);
    jadd(d, v, "AccessKey", t->minio.access_key);
    yyjson_mut_obj_add_str(d, v, "SecretKey", "REDACTED");
    jadd(d, v, "Bucket", t->minio.bucket);
    jadd(d, v, "Prefix", t->minio.prefix);
    jadd(d, v, "Region", t->minio.region);
  }
  return o;
}

/* ---- msgp (tier-config.bin) --------------------------------------------------------------- */

static void mp_kv(buckets_buf *b, const char *k, const char *v) {
  buckets_mp_cstr(b, k);
  buckets_mp_cstr(b, v ? v : "");
}

static void encode_one(buckets_buf *b, const buckets_tier_config *t) {
  buckets_mp_map(b, 7);
  mp_kv(b, "Version", t->version);
  buckets_mp_cstr(b, "Type");
  buckets_mp_int(b, t->type);
  mp_kv(b, "Name", t->name);
  buckets_mp_cstr(b, "S3");
  if (!t->has_s3) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_map(b, 12);
    mp_kv(b, "Endpoint", t->s3.endpoint);
    mp_kv(b, "AccessKey", t->s3.access_key);
    mp_kv(b, "SecretKey", t->s3.secret_key);
    mp_kv(b, "Bucket", t->s3.bucket);
    mp_kv(b, "Prefix", t->s3.prefix);
    mp_kv(b, "Region", t->s3.region);
    mp_kv(b, "StorageClass", t->s3.storage_class);
    buckets_mp_cstr(b, "AWSRole");
    buckets_mp_bool(b, t->s3.aws_role);
    mp_kv(b, "AWSRoleWebIdentityTokenFile", t->s3.aws_role_web_identity_token_file);
    mp_kv(b, "AWSRoleARN", t->s3.aws_role_arn);
    mp_kv(b, "AWSRoleSessionName", t->s3.aws_role_session_name);
    buckets_mp_cstr(b, "AWSRoleDurationSeconds");
    buckets_mp_int(b, t->s3.aws_role_duration_seconds);
  }
  buckets_mp_cstr(b, "Azure");
  if (!t->has_azure) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_map(b, 8);
    mp_kv(b, "Endpoint", t->azure.endpoint);
    mp_kv(b, "AccountName", t->azure.account_name);
    mp_kv(b, "AccountKey", t->azure.account_key);
    mp_kv(b, "Bucket", t->azure.bucket);
    mp_kv(b, "Prefix", t->azure.prefix);
    mp_kv(b, "Region", t->azure.region);
    mp_kv(b, "StorageClass", t->azure.storage_class);
    buckets_mp_cstr(b, "SPAuth");
    buckets_mp_map(b, 3);
    mp_kv(b, "TenantID", t->azure.sp_tenant_id);
    mp_kv(b, "ClientID", t->azure.sp_client_id);
    mp_kv(b, "ClientSecret", t->azure.sp_client_secret);
  }
  buckets_mp_cstr(b, "GCS");
  if (!t->has_gcs) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_map(b, 6);
    mp_kv(b, "Endpoint", t->gcs.endpoint);
    mp_kv(b, "Creds", t->gcs.creds);
    mp_kv(b, "Bucket", t->gcs.bucket);
    mp_kv(b, "Prefix", t->gcs.prefix);
    mp_kv(b, "Region", t->gcs.region);
    mp_kv(b, "StorageClass", t->gcs.storage_class);
  }
  buckets_mp_cstr(b, "MinIO");
  if (!t->has_minio) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_map(b, 6);
    mp_kv(b, "Endpoint", t->minio.endpoint);
    mp_kv(b, "AccessKey", t->minio.access_key);
    mp_kv(b, "SecretKey", t->minio.secret_key);
    mp_kv(b, "Bucket", t->minio.bucket);
    mp_kv(b, "Prefix", t->minio.prefix);
    mp_kv(b, "Region", t->minio.region);
  }
}

void buckets_tiers_encode(const buckets_tier_config *tiers, size_t n, buckets_buf *out) {
  uint8_t hdr[4] = {TIER_FORMAT, 0, TIER_VERSION, 0};
  buckets_buf_append(out, hdr, 4);
  buckets_mp_map(out, 1);
  buckets_mp_cstr(out, "Tiers");
  buckets_mp_map(out, (uint32_t)n);
  for (size_t i = 0; i < n; i++) {
    buckets_mp_cstr(out, tiers[i].name);
    encode_one(out, &tiers[i]);
  }
}

/* A msgp map of string fields: each key found in names is stored in its slot. */
typedef struct {
  const char *name;
  char **dst;
} sfield;

static bool read_str_into(buckets_mp_reader *r, char **dst) {
  if (buckets_mp_read_nil(r)) return true;
  buckets_str v;
  if (!buckets_mp_read_str(r, &v)) return false;
  free(*dst);
  *dst = buckets_str_dup(v);
  return true;
}

static bool read_fields(buckets_mp_reader *r, const sfield *f, size_t nf, bool (*other)(void *ud, buckets_str key, buckets_mp_reader *r),
                        void *ud, bool *present) {
  *present = false;
  if (buckets_mp_read_nil(r)) return true;
  uint32_t n;
  if (!buckets_mp_read_map(r, &n)) return false;
  *present = true;
  for (uint32_t i = 0; i < n; i++) {
    buckets_str k;
    if (!buckets_mp_read_str(r, &k)) return false;
    bool done = false;
    for (size_t j = 0; j < nf && !done; j++) {
      if (strlen(f[j].name) == k.n && memcmp(f[j].name, k.p, k.n) == 0) {
        if (!read_str_into(r, f[j].dst)) return false;
        done = true;
      }
    }
    if (!done && other && other(ud, k, r)) done = true;
    if (!done && !buckets_mp_skip(r)) return false;
  }
  return true;
}

static bool s3_other(void *ud, buckets_str k, buckets_mp_reader *r) {
  buckets_tier_config *t = ud;
  if (buckets_str_eq_c(k, "AWSRole")) return buckets_mp_read_bool(r, &t->s3.aws_role);
  if (buckets_str_eq_c(k, "AWSRoleDurationSeconds")) return buckets_mp_read_int(r, &t->s3.aws_role_duration_seconds);
  return false;
}

static bool azure_other(void *ud, buckets_str k, buckets_mp_reader *r) {
  buckets_tier_config *t = ud;
  if (!buckets_str_eq_c(k, "SPAuth")) return false;
  sfield f[] = {{"TenantID", &t->azure.sp_tenant_id}, {"ClientID", &t->azure.sp_client_id},
                {"ClientSecret", &t->azure.sp_client_secret}};
  bool present;
  return read_fields(r, f, 3, NULL, NULL, &present);
}

static bool decode_one(buckets_mp_reader *r, buckets_tier_config *t) {
  uint32_t n;
  if (!buckets_mp_read_map(r, &n)) return false;
  for (uint32_t i = 0; i < n; i++) {
    buckets_str k;
    if (!buckets_mp_read_str(r, &k)) return false;
    bool ok;
    if (buckets_str_eq_c(k, "Version")) {
      ok = read_str_into(r, &t->version);
    } else if (buckets_str_eq_c(k, "Name")) {
      ok = read_str_into(r, &t->name);
    } else if (buckets_str_eq_c(k, "Type")) {
      int64_t v;
      ok = buckets_mp_read_int(r, &v);
      t->type = (buckets_tier_type)v;
    } else if (buckets_str_eq_c(k, "S3")) {
      sfield f[] = {{"Endpoint", &t->s3.endpoint},
                    {"AccessKey", &t->s3.access_key},
                    {"SecretKey", &t->s3.secret_key},
                    {"Bucket", &t->s3.bucket},
                    {"Prefix", &t->s3.prefix},
                    {"Region", &t->s3.region},
                    {"StorageClass", &t->s3.storage_class},
                    {"AWSRoleWebIdentityTokenFile", &t->s3.aws_role_web_identity_token_file},
                    {"AWSRoleARN", &t->s3.aws_role_arn},
                    {"AWSRoleSessionName", &t->s3.aws_role_session_name}};
      ok = read_fields(r, f, BUCKETS_ARRAY_LEN(f), s3_other, t, &t->has_s3);
    } else if (buckets_str_eq_c(k, "Azure")) {
      sfield f[] = {{"Endpoint", &t->azure.endpoint}, {"AccountName", &t->azure.account_name},
                    {"AccountKey", &t->azure.account_key}, {"Bucket", &t->azure.bucket},
                    {"Prefix", &t->azure.prefix}, {"Region", &t->azure.region},
                    {"StorageClass", &t->azure.storage_class}};
      ok = read_fields(r, f, BUCKETS_ARRAY_LEN(f), azure_other, t, &t->has_azure);
    } else if (buckets_str_eq_c(k, "GCS")) {
      sfield f[] = {{"Endpoint", &t->gcs.endpoint}, {"Creds", &t->gcs.creds}, {"Bucket", &t->gcs.bucket},
                    {"Prefix", &t->gcs.prefix}, {"Region", &t->gcs.region}, {"StorageClass", &t->gcs.storage_class}};
      ok = read_fields(r, f, BUCKETS_ARRAY_LEN(f), NULL, NULL, &t->has_gcs);
    } else if (buckets_str_eq_c(k, "MinIO")) {
      sfield f[] = {{"Endpoint", &t->minio.endpoint}, {"AccessKey", &t->minio.access_key},
                    {"SecretKey", &t->minio.secret_key}, {"Bucket", &t->minio.bucket},
                    {"Prefix", &t->minio.prefix}, {"Region", &t->minio.region}};
      ok = read_fields(r, f, BUCKETS_ARRAY_LEN(f), NULL, NULL, &t->has_minio);
    } else {
      ok = buckets_mp_skip(r);
    }
    if (!ok) return false;
  }
  return true;
}

bool buckets_tiers_decode(const void *data, size_t n, buckets_tier_config **tiers, size_t *count) {
  *tiers = NULL;
  *count = 0;
  const uint8_t *p = data;
  if (n <= 4) return false;
  unsigned format = (unsigned)(p[0] | p[1] << 8), version = (unsigned)(p[2] | p[3] << 8);
  if (format != TIER_FORMAT || (version != TIER_VERSION && version != TIER_VERSION_V1)) return false;
  buckets_mp_reader r = buckets_mp_reader_init(p + 4, n - 4);
  uint32_t fields;
  if (!buckets_mp_read_map(&r, &fields)) return false;
  for (uint32_t i = 0; i < fields; i++) {
    buckets_str k;
    if (!buckets_mp_read_str(&r, &k)) goto bad;
    if (!buckets_str_eq_c(k, "Tiers")) {
      if (!buckets_mp_skip(&r)) goto bad;
      continue;
    }
    if (buckets_mp_read_nil(&r)) continue;
    uint32_t nt;
    if (!buckets_mp_read_map(&r, &nt) || nt > buckets_mp_remaining(&r)) goto bad;
    *tiers = buckets_xcalloc(nt + 1, sizeof(**tiers));
    for (uint32_t j = 0; j < nt; j++) {
      buckets_str name;
      if (!buckets_mp_read_str(&r, &name)) goto bad;
      buckets_tier_config *t = &(*tiers)[(*count)++];
      buckets_tier_config_init(t);
      if (!decode_one(&r, t)) goto bad;
      if (!*t->name) { /* the map key is the name */
        free(t->name);
        t->name = buckets_str_dup(name);
      }
    }
  }
  return true;
bad:
  for (size_t i = 0; i < *count; i++) buckets_tier_config_free(&(*tiers)[i]);
  free(*tiers);
  *tiers = NULL;
  *count = 0;
  return false;
}

/* ---- the manager ------------------------------------------------------------------------------- */

typedef struct {
  buckets_tier_config cfg;
  buckets_warm *driver; /* cached, or NULL */
} tier;

struct buckets_tiers {
  buckets_s3_server *s;
  pthread_mutex_t mu;
  tier *t;
  size_t n;
  int64_t refreshed_ns;
};

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

buckets_tiers *buckets_tiers_new(buckets_s3_server *s) {
  buckets_tiers *t = buckets_xcalloc(1, sizeof(*t));
  t->s = s;
  pthread_mutex_init(&t->mu, NULL);
  return t;
}

static void clear(buckets_tiers *t) {
  for (size_t i = 0; i < t->n; i++) {
    buckets_tier_config_free(&t->t[i].cfg);
    if (t->t[i].driver) buckets_warm_release(t->t[i].driver);
  }
  free(t->t);
  t->t = NULL;
  t->n = 0;
}

void buckets_tiers_free(buckets_tiers *t) {
  if (!t) return;
  clear(t);
  pthread_mutex_destroy(&t->mu);
  free(t);
}

static long find(buckets_tiers *t, const char *name) {
  for (size_t i = 0; i < t->n; i++)
    if (strcmp(t->t[i].cfg.name, name) == 0) return (long)i;
  return -1;
}

bool buckets_tiers_reload(buckets_tiers *t) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_obj_err e = buckets_s3_config_read(t->s, TIER_CONFIG_PATH, &b);
  if (e == BUCKETS_OBJ_ERR_NO_SUCH_KEY) {
    buckets_buf_free(&b);
    pthread_mutex_lock(&t->mu);
    t->refreshed_ns = now_ns();
    pthread_mutex_unlock(&t->mu);
    return true;
  }
  buckets_tier_config *cfg = NULL;
  size_t n = 0;
  bool ok = !e && buckets_tiers_decode(b.data, b.len, &cfg, &n);
  buckets_buf_free(&b);
  if (!ok) {
    buckets_log_warn("tier: unable to read %s", TIER_CONFIG_PATH);
    return false;
  }
  pthread_mutex_lock(&t->mu);
  clear(t);
  t->t = buckets_xcalloc(n + 1, sizeof(tier));
  for (size_t i = 0; i < n; i++) t->t[i].cfg = cfg[i];
  t->n = n;
  t->refreshed_ns = now_ns();
  pthread_mutex_unlock(&t->mu);
  free(cfg);
  return true;
}

int64_t buckets_tiers_refreshed_at(buckets_tiers *t) {
  pthread_mutex_lock(&t->mu);
  int64_t r = t->refreshed_ns;
  pthread_mutex_unlock(&t->mu);
  return r;
}

bool buckets_tiers_empty(buckets_tiers *t) {
  if (!t) return true;
  pthread_mutex_lock(&t->mu);
  bool e = t->n == 0;
  pthread_mutex_unlock(&t->mu);
  return e;
}

bool buckets_tiers_valid(buckets_tiers *t, const char *name) {
  if (!t || !name) return false;
  pthread_mutex_lock(&t->mu);
  bool v = find(t, name) >= 0;
  pthread_mutex_unlock(&t->mu);
  return v;
}

const char *buckets_tiers_type(buckets_tiers *t, const char *name) {
  if (!t) return "internal";
  pthread_mutex_lock(&t->mu);
  long i = find(t, name);
  const char *r = i >= 0 ? buckets_tier_type_name(t->t[i].cfg.type) : "internal";
  pthread_mutex_unlock(&t->mu);
  return r;
}

size_t buckets_tiers_names(buckets_tiers *t, char ***names) {
  pthread_mutex_lock(&t->mu);
  *names = buckets_xcalloc(t->n + 1, sizeof(char *));
  for (size_t i = 0; i < t->n; i++) (*names)[i] = buckets_xstrdup(t->t[i].cfg.name);
  size_t n = t->n;
  pthread_mutex_unlock(&t->mu);
  return n;
}

static buckets_tls_client *tls_of(buckets_tiers *t) { return t->s->repl ? buckets_repl_tls(t->s->repl) : NULL; }

buckets_warm *buckets_tiers_driver(buckets_tiers *t, const char *name, char *err, size_t errlen) {
  if (!t) {
    snprintf(err, errlen, "Specified remote tier was not found");
    return NULL;
  }
  pthread_mutex_lock(&t->mu);
  long i = find(t, name);
  buckets_warm *w = NULL;
  if (i < 0) {
    snprintf(err, errlen, "Specified remote tier was not found");
  } else {
    if (!t->t[i].driver) t->t[i].driver = buckets_warm_new(&t->t[i].cfg, tls_of(t), err, errlen);
    if (t->t[i].driver) w = buckets_warm_ref(t->t[i].driver);
  }
  pthread_mutex_unlock(&t->mu);
  return w;
}

static bool save(buckets_tiers *t) {
  buckets_buf b = BUCKETS_BUF_INIT;
  pthread_mutex_lock(&t->mu);
  buckets_tier_config *cfg = buckets_xcalloc(t->n + 1, sizeof(*cfg));
  for (size_t i = 0; i < t->n; i++) cfg[i] = t->t[i].cfg; /* shallow */
  buckets_tiers_encode(cfg, t->n, &b);
  pthread_mutex_unlock(&t->mu);
  free(cfg);
  bool ok = buckets_s3_config_write(t->s, TIER_CONFIG_PATH, b.data, b.len);
  buckets_buf_free(&b);
  if (ok && t->s->peers) buckets_peer_notify_iam(t->s->peers, "tier", ""); /* LoadTransitionTierConfig */
  return ok;
}

static void terr(buckets_tier_err *e, int status, const char *code, const char *msg) {
  e->status = status;
  snprintf(e->code, sizeof(e->code), "%s", code);
  snprintf(e->message, sizeof(e->message), "%s", msg);
}

static const char probe_object[] = "probeobject";

static long probe_read(void *ud, void *buf, size_t n) {
  size_t *off = ud;
  static const char data[] = "MinIO";
  size_t k = BUCKETS_MIN(n, 5 - *off);
  memcpy(buf, data + *off, k);
  *off += k;
  return (long)k;
}

/* checkWarmBackend: a probe object put, read back and removed. */
static bool check_backend(buckets_warm *w, buckets_tier_err *e) {
  char rv[256] = "", err[512] = "", msg[800];
  size_t off = 0;
  buckets_warm_err we = buckets_warm_put(w, probe_object, probe_read, &off, 5, NULL, rv, sizeof(rv), err, sizeof(err));
  if (we) {
    if (we == BUCKETS_WARM_ERR_DOWN) {
      terr(e, 400, "XMinioBackendDown", err);
    } else {
      snprintf(msg, sizeof(msg), "failed to perform PUT: %s", err);
      terr(e, 400, "XMinioAdminTierInsufficientPermissions", msg);
    }
    return false;
  }
  buckets_warm_stream *st = NULL;
  we = buckets_warm_get(w, probe_object, "", 0, -1, &st, err, sizeof(err));
  if (st) {
    char buf[64];
    while (buckets_warm_stream_read(st, buf, sizeof(buf)) > 0) {
    }
    buckets_warm_stream_free(st);
  }
  if (we) {
    if (we == BUCKETS_WARM_ERR_DOWN) terr(e, 400, "XMinioBackendDown", err);
    else if (we == BUCKETS_WARM_ERR_BUCKET) terr(e, 400, "XMinioAdminTierBucketNotFound", "Remote tier bucket not found");
    else if (we == BUCKETS_WARM_ERR_CREDENTIALS)
      terr(e, 400, "XMinioAdminTierInvalidCredentials", "Invalid remote tier credentials");
    else {
      snprintf(msg, sizeof(msg), "failed to perform GET: %s", err);
      terr(e, 400, "XMinioAdminTierInsufficientPermissions", msg);
    }
    return false;
  }
  we = buckets_warm_remove(w, probe_object, rv, err, sizeof(err));
  if (we) {
    if (we == BUCKETS_WARM_ERR_DOWN) {
      terr(e, 400, "XMinioBackendDown", err);
    } else {
      snprintf(msg, sizeof(msg), "failed to perform DELETE: %s", err);
      terr(e, 400, "XMinioAdminTierInsufficientPermissions", msg);
    }
    return false;
  }
  return true;
}

/* newWarmBackend(probe) */
static buckets_warm *new_backend(buckets_tiers *t, const buckets_tier_config *cfg, bool probe, buckets_tier_err *e) {
  if (cfg->type == BUCKETS_TIER_UNSUPPORTED || cfg->type > BUCKETS_TIER_MINIO) {
    terr(e, 400, "XMinioAdminTierTypeUnsupported", "Specified tier type is unsupported");
    return NULL;
  }
  char err[512];
  buckets_warm *w = buckets_warm_new(cfg, tls_of(t), err, sizeof(err));
  if (!w) {
    buckets_log_warn("tier %s: %s", cfg->name, err);
    terr(e, 400, "XMinioAdminTierInvalidConfig", "Unable to setup remote tier, check tier configuration");
    return NULL;
  }
  if (probe && !check_backend(w, e)) {
    buckets_warm_release(w);
    return NULL;
  }
  return w;
}

static bool json_error(buckets_tier_err *e, const char *err) {
  if (strcmp(err, "remote tier name empty") == 0) terr(e, 400, "XMinioAdminTierNameEmpty", err);
  else if (strcmp(err, "invalid tier config") == 0) terr(e, 400, "XMinioAdminTierInvalidConfig", err);
  else if (strcmp(err, "invalid tier config version") == 0) terr(e, 400, "XMinioAdminTierInvalidConfigVersion", err);
  else if (strcmp(err, "unsupported tier type") == 0) terr(e, 400, "XMinioAdminTierTypeUnsupported", err);
  else terr(e, 500, "InternalError", err);
  return false;
}

bool buckets_tiers_add(buckets_tiers *t, const char *json, size_t n, bool force, buckets_tier_err *e) {
  buckets_tier_config cfg;
  char err[256];
  if (!buckets_tier_config_parse_json(json, n, &cfg, err, sizeof(err))) return json_error(e, err);
  if (strcmp(cfg.name, "STANDARD") == 0 || strcmp(cfg.name, "REDUCED_REDUNDANCY") == 0) {
    buckets_tier_config_free(&cfg);
    terr(e, 400, "XMinioAdminTierReserved", "Cannot use reserved tier name");
    return false;
  }
  if (!buckets_tiers_reload(t)) {
    buckets_tier_config_free(&cfg);
    terr(e, 500, "InternalError", "unable to read the tier configuration");
    return false;
  }
  bool upper = true;
  for (const char *p = cfg.name; *p; p++) upper &= !islower((unsigned char)*p);
  if (!upper) {
    buckets_tier_config_free(&cfg);
    terr(e, 400, "XMinioAdminTierNameNotUpperCase", "Tier name must be in uppercase");
    return false;
  }
  if (buckets_tiers_valid(t, cfg.name)) {
    buckets_tier_config_free(&cfg);
    terr(e, 409, "XMinioAdminTierAlreadyExists", "Specified remote tier already exists");
    return false;
  }
  buckets_warm *w = new_backend(t, &cfg, true, e);
  if (!w) {
    buckets_tier_config_free(&cfg);
    return false;
  }
  if (!force) {
    bool in_use = false;
    buckets_warm_err we = buckets_warm_in_use(w, &in_use, err, sizeof(err));
    if (we || in_use) {
      buckets_warm_release(w);
      buckets_tier_config_free(&cfg);
      if (we == BUCKETS_WARM_ERR_DOWN) terr(e, 400, "XMinioBackendDown", err);
      else if (we) terr(e, 500, "InternalError", err);
      else terr(e, 409, "XMinioAdminTierBackendInUse", "Specified remote tier is already in use");
      return false;
    }
  }
  pthread_mutex_lock(&t->mu);
  t->t = buckets_xrealloc(t->t, (t->n + 1) * sizeof(tier));
  t->t[t->n++] = (tier){cfg, w};
  pthread_mutex_unlock(&t->mu);
  if (!save(t)) {
    buckets_tiers_reload(t);
    terr(e, 500, "InternalError", "unable to save the tier configuration");
    return false;
  }
  return true;
}

static bool b64_std_decode(const char *s, buckets_buf *out) {
  size_t n = strlen(s);
  uint8_t *d = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64_decode(s, n, d);
  if (k >= 0) buckets_buf_append(out, d, (size_t)k);
  free(d);
  return k >= 0;
}

bool buckets_tiers_edit(buckets_tiers *t, const char *name, const char *json, size_t n, buckets_tier_err *e) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  yyjson_val *r = yyjson_doc_get_root(doc);
  if (!yyjson_is_obj(r)) {
    yyjson_doc_free(doc);
    terr(e, 500, "InternalError", "invalid tier credentials");
    return false;
  }
  if (!buckets_tiers_reload(t)) {
    yyjson_doc_free(doc);
    terr(e, 500, "InternalError", "unable to read the tier configuration");
    return false;
  }
  pthread_mutex_lock(&t->mu);
  long i = find(t, name);
  buckets_tier_config cfg;
  if (i >= 0) buckets_tier_config_copy(&cfg, &t->t[i].cfg);
  pthread_mutex_unlock(&t->mu);
  if (i < 0) {
    yyjson_doc_free(doc);
    terr(e, 404, "XMinioAdminTierNotFound", "Specified remote tier was not found");
    return false;
  }
  const char *ak = yyjson_get_str(jget(r, "access")), *sk = yyjson_get_str(jget(r, "secret"));
  ak = ak ? ak : "";
  sk = sk ? sk : "";
  bool ok = true;
  switch (cfg.type) {
    case BUCKETS_TIER_S3: {
      if (yyjson_get_bool(jget(r, "awsrole"))) cfg.s3.aws_role = true;
      const char *wf = yyjson_get_str(jget(r, "awsroleWebIdentity")), *arn = yyjson_get_str(jget(r, "awsroleARN"));
      if (wf && *wf && arn && *arn) {
        set(&cfg.s3.aws_role_arn, arn);
        set(&cfg.s3.aws_role_web_identity_token_file, wf);
      }
      if (*ak && *sk) {
        set(&cfg.s3.access_key, ak);
        set(&cfg.s3.secret_key, sk);
      }
      break;
    }
    case BUCKETS_TIER_AZURE: {
      if (*sk) set(&cfg.azure.account_key, sk);
      yyjson_val *sp = jget(r, "azSP");
      const char *tid = yyjson_get_str(jget(sp, "TenantID")), *cid = yyjson_get_str(jget(sp, "ClientID")),
                 *cs = yyjson_get_str(jget(sp, "ClientSecret"));
      if (tid && *tid) set(&cfg.azure.sp_tenant_id, tid);
      if (cid && *cid) set(&cfg.azure.sp_client_id, cid);
      if (cs && *cs) set(&cfg.azure.sp_client_secret, cs);
      break;
    }
    case BUCKETS_TIER_GCS: {
      const char *cj = yyjson_get_str(jget(r, "creds")); /* []byte: base64 in JSON */
      buckets_buf raw = BUCKETS_BUF_INIT;
      if (!cj || !b64_std_decode(cj, &raw)) {
        terr(e, 403, "XMinioAdminTierMissingCredentials", "Specified remote credentials are empty");
        ok = false;
      } else {
        char *enc = buckets_xmalloc(4 * ((raw.len + 2) / 3) + 1);
        buckets_base64url_encode((const uint8_t *)raw.data, raw.len, enc);
        set(&cfg.gcs.creds, enc);
        free(enc);
      }
      buckets_buf_free(&raw);
      break;
    }
    case BUCKETS_TIER_MINIO:
      if (!*ak || !*sk) {
        terr(e, 403, "XMinioAdminTierMissingCredentials", "Specified remote credentials are empty");
        ok = false;
      } else {
        set(&cfg.minio.access_key, ak);
        set(&cfg.minio.secret_key, sk);
      }
      break;
    default: break;
  }
  yyjson_doc_free(doc);
  buckets_warm *w = ok ? new_backend(t, &cfg, true, e) : NULL;
  if (!w) {
    buckets_tier_config_free(&cfg);
    return false;
  }
  pthread_mutex_lock(&t->mu);
  i = find(t, name);
  if (i >= 0) {
    buckets_tier_config_free(&t->t[i].cfg);
    if (t->t[i].driver) buckets_warm_release(t->t[i].driver);
    t->t[i] = (tier){cfg, w};
  } else {
    buckets_tier_config_free(&cfg);
    buckets_warm_release(w);
  }
  pthread_mutex_unlock(&t->mu);
  if (!save(t)) {
    terr(e, 500, "InternalError", "unable to save the tier configuration");
    return false;
  }
  return true;
}

bool buckets_tiers_remove(buckets_tiers *t, const char *name, bool force, buckets_tier_err *e) {
  if (!buckets_tiers_reload(t)) {
    terr(e, 500, "InternalError", "unable to read the tier configuration");
    return false;
  }
  char err[512];
  buckets_warm *w = buckets_tiers_driver(t, name, err, sizeof(err));
  if (!w) {
    if (!buckets_tiers_valid(t, name)) return save(t) || true; /* removing a missing tier succeeds */
    terr(e, 400, "XMinioAdminTierInvalidConfig", "Unable to setup remote tier, check tier configuration");
    return false;
  }
  if (!force) {
    bool in_use = false;
    buckets_warm_err we = buckets_warm_in_use(w, &in_use, err, sizeof(err));
    if (we || in_use) {
      buckets_warm_release(w);
      if (we == BUCKETS_WARM_ERR_DOWN) terr(e, 400, "XMinioBackendDown", err);
      else if (we) terr(e, 500, "InternalError", err);
      else terr(e, 400, "XMinioAdminTierBackendNotEmpty", "Specified remote backend is not empty");
      return false;
    }
  }
  buckets_warm_release(w);
  pthread_mutex_lock(&t->mu);
  long i = find(t, name);
  if (i >= 0) {
    buckets_tier_config_free(&t->t[i].cfg);
    if (t->t[i].driver) buckets_warm_release(t->t[i].driver);
    t->t[i] = t->t[--t->n];
  }
  pthread_mutex_unlock(&t->mu);
  if (!save(t)) {
    terr(e, 500, "InternalError", "unable to save the tier configuration");
    return false;
  }
  return true;
}

bool buckets_tiers_verify(buckets_tiers *t, const char *name, buckets_tier_err *e) {
  char err[512];
  buckets_warm *w = buckets_tiers_driver(t, name, err, sizeof(err));
  if (!w) {
    if (!buckets_tiers_valid(t, name)) terr(e, 404, "XMinioAdminTierNotFound", "Specified remote tier was not found");
    else terr(e, 400, "XMinioAdminTierInvalidConfig", "Unable to setup remote tier, check tier configuration");
    return false;
  }
  bool ok = check_backend(w, e);
  buckets_warm_release(w);
  return ok;
}

void buckets_tiers_list_json(buckets_tiers *t, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  pthread_mutex_lock(&t->mu);
  if (!t->n) {
    yyjson_mut_doc_set_root(d, yyjson_mut_null(d)); /* a nil slice */
  } else {
    yyjson_mut_val *a = yyjson_mut_arr(d);
    yyjson_mut_doc_set_root(d, a);
    for (size_t i = 0; i < t->n; i++) yyjson_mut_arr_append(a, config_json(d, &t->t[i].cfg));
  }
  pthread_mutex_unlock(&t->mu);
  size_t n;
  char *j = yyjson_mut_write(d, 0, &n);
  buckets_buf_append(out, j, n);
  free(j);
  yyjson_mut_doc_free(d);
}
