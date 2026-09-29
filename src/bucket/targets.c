/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket remote targets: madmin.BucketTarget JSON and the stored (possibly
 * encrypted) bucket-targets configuration (MinIO cmd/bucket-targets.go,
 * encryptBucketMetadata / decryptBucketMetadata). */
#include "bucket/targets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/dare.h"
#include "crypto/objkey.h"
#include "kms/kms.h"
#include "notify/event.h"

static char *dup0(const char *s) { return buckets_xstrdup(s ? s : ""); }

void buckets_bucket_target_init(buckets_bucket_target *t) {
  memset(t, 0, sizeof(*t));
  char **s[] = {&t->source_bucket, &t->endpoint, &t->target_bucket, &t->access_key, &t->secret_key,
                &t->session_token, &t->path, &t->api, &t->arn, &t->type, &t->region, &t->storage_class,
                &t->reset_id, &t->deployment_id};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(s); i++) *s[i] = dup0("");
  t->creds_exp_sec = t->reset_before_sec = t->last_online_sec = BUCKETS_GO_ZERO_SEC;
}

void buckets_bucket_target_free(buckets_bucket_target *t) {
  char *s[] = {t->source_bucket, t->endpoint, t->target_bucket, t->access_key, t->secret_key, t->session_token,
               t->path, t->api, t->arn, t->type, t->region, t->storage_class, t->reset_id, t->deployment_id};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(s); i++) free(s[i]);
  memset(t, 0, sizeof(*t));
}

void buckets_bucket_target_copy(buckets_bucket_target *dst, const buckets_bucket_target *src) {
  *dst = *src;
  char **d[] = {&dst->source_bucket, &dst->endpoint, &dst->target_bucket, &dst->access_key, &dst->secret_key,
                &dst->session_token, &dst->path, &dst->api, &dst->arn, &dst->type, &dst->region,
                &dst->storage_class, &dst->reset_id, &dst->deployment_id};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(d); i++) *d[i] = dup0(*d[i]);
}

void buckets_bucket_targets_free(buckets_bucket_targets *ts) {
  for (size_t i = 0; i < ts->n; i++) buckets_bucket_target_free(&ts->t[i]);
  free(ts->t);
  ts->t = NULL;
  ts->n = 0;
}

/* ---- JSON in ---- */

static const char *kind_of(yyjson_val *v) {
  return yyjson_is_str(v) ? "string" : yyjson_is_bool(v) ? "bool" : yyjson_is_arr(v) ? "array"
         : yyjson_is_obj(v) ? "object" : "number";
}

typedef struct {
  char *err;
  size_t errlen;
  bool ok;
} jctx;

static void type_err(jctx *j, yyjson_val *v, const char *field, const char *type) {
  if (!j->ok) return;
  snprintf(j->err, j->errlen, "json: cannot unmarshal %s into Go struct field %s of type %s", kind_of(v), field, type);
  j->ok = false;
}

static void get_str(jctx *j, yyjson_val *v, char **dst, const char *field) {
  if (yyjson_is_null(v)) return;
  if (!yyjson_is_str(v)) {
    type_err(j, v, field, "string");
    return;
  }
  free(*dst);
  *dst = dup0(yyjson_get_str(v));
}

static void get_bool(jctx *j, yyjson_val *v, bool *dst, const char *field) {
  if (yyjson_is_null(v)) return;
  if (!yyjson_is_bool(v)) {
    type_err(j, v, field, "bool");
    return;
  }
  *dst = yyjson_get_bool(v);
}

static void get_i64(jctx *j, yyjson_val *v, int64_t *dst, const char *field, const char *type) {
  if (yyjson_is_null(v)) return;
  if (yyjson_is_int(v)) *dst = yyjson_get_sint(v);
  else if (yyjson_is_uint(v)) *dst = (int64_t)yyjson_get_uint(v);
  else type_err(j, v, field, type);
}

static void get_time(jctx *j, yyjson_val *v, int64_t *sec, int32_t *nsec, const char *field) {
  if (yyjson_is_null(v)) return;
  if (!yyjson_is_str(v)) {
    type_err(j, v, field, "time.Time");
    return;
  }
  long long s;
  long ns;
  if (!buckets_time_parse_rfc3339(yyjson_get_str(v), &s, &ns)) {
    if (j->ok) {
      snprintf(j->err, j->errlen, "parsing time \"\\\"%s\\\"\" as \"\\\"2006-01-02T15:04:05Z07:00\\\"\": cannot parse",
               yyjson_get_str(v));
      j->ok = false;
    }
    return;
  }
  *sec = s;
  *nsec = (int32_t)ns;
}

static void parse_target_obj(jctx *j, yyjson_val *o, buckets_bucket_target *t) {
  yyjson_obj_iter it = yyjson_obj_iter_with(o);
  yyjson_val *k;
  while (j->ok && (k = yyjson_obj_iter_next(&it))) {
    const char *n = yyjson_get_str(k);
    yyjson_val *v = yyjson_obj_iter_get_val(k);
#define F(name) (strcasecmp(n, name) == 0)
    if (F("sourcebucket")) get_str(j, v, &t->source_bucket, "BucketTarget.sourcebucket");
    else if (F("endpoint")) get_str(j, v, &t->endpoint, "BucketTarget.endpoint");
    else if (F("targetbucket")) get_str(j, v, &t->target_bucket, "BucketTarget.targetbucket");
    else if (F("secure")) get_bool(j, v, &t->secure, "BucketTarget.secure");
    else if (F("path")) get_str(j, v, &t->path, "BucketTarget.path");
    else if (F("api")) get_str(j, v, &t->api, "BucketTarget.api");
    else if (F("arn")) get_str(j, v, &t->arn, "BucketTarget.arn");
    else if (F("type")) get_str(j, v, &t->type, "BucketTarget.type");
    else if (F("region")) get_str(j, v, &t->region, "BucketTarget.region");
    else if (F("bandwidthlimit")) get_i64(j, v, &t->bandwidth_limit, "BucketTarget.bandwidthlimit", "int64");
    else if (F("replicationSync")) get_bool(j, v, &t->replication_sync, "BucketTarget.replicationSync");
    else if (F("storageclass")) get_str(j, v, &t->storage_class, "BucketTarget.storageclass");
    else if (F("healthCheckDuration")) get_i64(j, v, &t->health_check_ns, "BucketTarget.healthCheckDuration", "time.Duration");
    else if (F("disableProxy")) get_bool(j, v, &t->disable_proxy, "BucketTarget.disableProxy");
    else if (F("resetBeforeDate")) get_time(j, v, &t->reset_before_sec, &t->reset_before_nsec, "BucketTarget.resetBeforeDate");
    else if (F("resetID")) get_str(j, v, &t->reset_id, "BucketTarget.resetID");
    else if (F("totalDowntime")) get_i64(j, v, &t->total_downtime_ns, "BucketTarget.totalDowntime", "time.Duration");
    else if (F("lastOnline")) get_time(j, v, &t->last_online_sec, &t->last_online_nsec, "BucketTarget.lastOnline");
    else if (F("isOnline")) get_bool(j, v, &t->online, "BucketTarget.isOnline");
    else if (F("deploymentID")) get_str(j, v, &t->deployment_id, "BucketTarget.deploymentID");
    else if (F("edge")) get_bool(j, v, &t->edge, "BucketTarget.edge");
    else if (F("edgeSyncBeforeExpiry")) get_bool(j, v, &t->edge_sync_before_expiry, "BucketTarget.edgeSyncBeforeExpiry");
    else if (F("offlineCount")) get_i64(j, v, &t->offline_count, "BucketTarget.offlineCount", "int64");
    else if (F("latency")) {
      if (yyjson_is_null(v)) continue;
      if (!yyjson_is_obj(v)) {
        type_err(j, v, "BucketTarget.latency", "madmin.LatencyStat");
        continue;
      }
      yyjson_obj_iter li = yyjson_obj_iter_with(v);
      yyjson_val *lk;
      while (j->ok && (lk = yyjson_obj_iter_next(&li))) {
        const char *ln = yyjson_get_str(lk);
        yyjson_val *lv = yyjson_obj_iter_get_val(lk);
        if (strcasecmp(ln, "curr") == 0) get_i64(j, lv, &t->lat_curr, "BucketTarget.latency.curr", "time.Duration");
        else if (strcasecmp(ln, "avg") == 0) get_i64(j, lv, &t->lat_avg, "BucketTarget.latency.avg", "time.Duration");
        else if (strcasecmp(ln, "max") == 0) get_i64(j, lv, &t->lat_max, "BucketTarget.latency.max", "time.Duration");
      }
    } else if (F("credentials")) {
      if (yyjson_is_null(v)) {
        t->has_creds = false;
        continue;
      }
      if (!yyjson_is_obj(v)) {
        type_err(j, v, "BucketTarget.credentials", "madmin.Credentials");
        continue;
      }
      t->has_creds = true;
      yyjson_obj_iter ci = yyjson_obj_iter_with(v);
      yyjson_val *ck;
      while (j->ok && (ck = yyjson_obj_iter_next(&ci))) {
        const char *cn = yyjson_get_str(ck);
        yyjson_val *cv = yyjson_obj_iter_get_val(ck);
        if (strcasecmp(cn, "accessKey") == 0) get_str(j, cv, &t->access_key, "BucketTarget.credentials.accessKey");
        else if (strcasecmp(cn, "secretKey") == 0) get_str(j, cv, &t->secret_key, "BucketTarget.credentials.secretKey");
        else if (strcasecmp(cn, "sessionToken") == 0) get_str(j, cv, &t->session_token, "BucketTarget.credentials.sessionToken");
        else if (strcasecmp(cn, "expiration") == 0) get_time(j, cv, &t->creds_exp_sec, &t->creds_exp_nsec, "BucketTarget.credentials.expiration");
      }
    }
#undef F
  }
}

static yyjson_doc *read_doc(const char *json, size_t len, char *err, size_t errlen) {
  yyjson_read_err re;
  yyjson_doc *d = yyjson_read_opts((char *)json, len, 0, NULL, &re);
  if (!d) {
    if (!len || re.code == YYJSON_READ_ERROR_UNEXPECTED_END || re.code == YYJSON_READ_ERROR_EMPTY_CONTENT)
      snprintf(err, errlen, "unexpected end of JSON input");
    else if (re.pos < len) snprintf(err, errlen, "invalid character '%c' looking for beginning of value", json[re.pos]);
    else snprintf(err, errlen, "%s", re.msg);
  }
  return d;
}

bool buckets_bucket_target_parse(const char *json, size_t len, buckets_bucket_target *out, char *err, size_t errlen) {
  buckets_bucket_target_init(out);
  yyjson_doc *d = read_doc(json, len, err, errlen);
  if (!d) return false;
  yyjson_val *root = yyjson_doc_get_root(d);
  jctx j = {err, errlen, true};
  if (yyjson_is_obj(root)) parse_target_obj(&j, root, out);
  else if (!yyjson_is_null(root)) {
    snprintf(err, errlen, "json: cannot unmarshal %s into Go value of type madmin.BucketTarget", kind_of(root));
    j.ok = false;
  }
  yyjson_doc_free(d);
  return j.ok;
}

bool buckets_bucket_targets_parse(const char *json, size_t len, buckets_bucket_targets *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  yyjson_doc *d = read_doc(json, len, err, errlen);
  if (!d) return false;
  yyjson_val *root = yyjson_doc_get_root(d);
  jctx j = {err, errlen, true};
  if (yyjson_is_obj(root)) {
    yyjson_obj_iter it = yyjson_obj_iter_with(root);
    yyjson_val *k;
    while (j.ok && (k = yyjson_obj_iter_next(&it))) {
      if (strcasecmp(yyjson_get_str(k), "targets") != 0) continue;
      yyjson_val *arr = yyjson_obj_iter_get_val(k);
      if (yyjson_is_null(arr)) continue;
      if (!yyjson_is_arr(arr)) {
        type_err(&j, arr, "BucketTargets.targets", "[]madmin.BucketTarget");
        continue;
      }
      buckets_bucket_targets_free(out);
      size_t i, max;
      yyjson_val *e;
      out->t = buckets_xcalloc(yyjson_arr_size(arr) + 1, sizeof(*out->t));
      yyjson_arr_foreach(arr, i, max, e) {
        buckets_bucket_target_init(&out->t[out->n]);
        out->n++;
        if (yyjson_is_obj(e)) parse_target_obj(&j, e, &out->t[out->n - 1]);
      }
    }
  }
  yyjson_doc_free(d);
  if (!j.ok) buckets_bucket_targets_free(out);
  return j.ok;
}

/* ---- JSON out ---- */

static void jstr(buckets_buf *b, const char *key, const char *v) {
  buckets_buf_appendf(b, "\"%s\":", key);
  buckets_json_go_string(b, v ? v : "", v ? strlen(v) : 0);
}

static void jtime(buckets_buf *b, const char *key, int64_t sec, int32_t nsec) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(sec, nsec, ts);
  buckets_buf_appendf(b, "\"%s\":\"%s\"", key, ts);
}

void buckets_bucket_target_json(const buckets_bucket_target *t, bool clone, buckets_buf *b) {
  buckets_buf_append_char(b, '{');
  jstr(b, "sourcebucket", t->source_bucket);
  buckets_buf_append_char(b, ',');
  jstr(b, "endpoint", t->endpoint);
  buckets_buf_append_c(b, ",\"credentials\":");
  if (!t->has_creds && !clone) {
    buckets_buf_append_c(b, "null");
  } else {
    buckets_buf_append_char(b, '{');
    bool any = false;
    if (*t->access_key) {
      jstr(b, "accessKey", t->access_key);
      any = true;
    }
    if (!clone && *t->secret_key) {
      if (any) buckets_buf_append_char(b, ',');
      jstr(b, "secretKey", t->secret_key);
      any = true;
    }
    if (!clone && *t->session_token) {
      if (any) buckets_buf_append_char(b, ',');
      jstr(b, "sessionToken", t->session_token);
      any = true;
    }
    if (any) buckets_buf_append_char(b, ',');
    if (clone) jtime(b, "expiration", BUCKETS_GO_ZERO_SEC, 0);
    else jtime(b, "expiration", t->creds_exp_sec, t->creds_exp_nsec);
    buckets_buf_append_char(b, '}');
  }
  buckets_buf_append_char(b, ',');
  jstr(b, "targetbucket", t->target_bucket);
  buckets_buf_appendf(b, ",\"secure\":%s", t->secure ? "true" : "false");
  if (*t->path) buckets_buf_append_char(b, ','), jstr(b, "path", t->path);
  if (*t->api) buckets_buf_append_char(b, ','), jstr(b, "api", t->api);
  if (*t->arn) buckets_buf_append_char(b, ','), jstr(b, "arn", t->arn);
  buckets_buf_append_char(b, ',');
  jstr(b, "type", t->type);
  if (*t->region) buckets_buf_append_char(b, ','), jstr(b, "region", t->region);
  if (t->bandwidth_limit) buckets_buf_appendf(b, ",\"bandwidthlimit\":%lld", (long long)t->bandwidth_limit);
  buckets_buf_appendf(b, ",\"replicationSync\":%s", t->replication_sync ? "true" : "false");
  if (*t->storage_class) buckets_buf_append_char(b, ','), jstr(b, "storageclass", t->storage_class);
  if (t->health_check_ns) buckets_buf_appendf(b, ",\"healthCheckDuration\":%lld", (long long)t->health_check_ns);
  buckets_buf_appendf(b, ",\"disableProxy\":%s,", t->disable_proxy ? "true" : "false");
  jtime(b, "resetBeforeDate", t->reset_before_sec, t->reset_before_nsec);
  if (*t->reset_id) buckets_buf_append_char(b, ','), jstr(b, "resetID", t->reset_id);
  buckets_buf_appendf(b, ",\"totalDowntime\":%lld,", (long long)t->total_downtime_ns);
  jtime(b, "lastOnline", t->last_online_sec, t->last_online_nsec);
  buckets_buf_appendf(b, ",\"isOnline\":%s,\"latency\":{\"curr\":%lld,\"avg\":%lld,\"max\":%lld}",
                      t->online ? "true" : "false", (long long)t->lat_curr, (long long)t->lat_avg,
                      (long long)t->lat_max);
  if (*t->deployment_id) buckets_buf_append_char(b, ','), jstr(b, "deploymentID", t->deployment_id);
  buckets_buf_appendf(b, ",\"edge\":%s,\"edgeSyncBeforeExpiry\":%s,\"offlineCount\":%lld}", t->edge ? "true" : "false",
                      t->edge_sync_before_expiry ? "true" : "false", (long long)t->offline_count);
}

void buckets_bucket_targets_json(const buckets_bucket_targets *ts, buckets_buf *b) {
  buckets_buf_append_c(b, "{\"targets\":");
  if (!ts->n) {
    buckets_buf_append_c(b, ts->t ? "[]}" : "null}");
    return;
  }
  buckets_buf_append_char(b, '[');
  for (size_t i = 0; i < ts->n; i++) {
    if (i) buckets_buf_append_char(b, ',');
    buckets_bucket_target_json(&ts->t[i], false, b);
  }
  buckets_buf_append_c(b, "]}");
}

/* ---- storage ---- */

static void kms_context(const char *bucket, buckets_buf *out) {
  const char *keys[] = {bucket, "bucket-targets.json"};
  const char *vals[] = {bucket, "bucket-targets.json"};
  /* kms.Context{bucket: bucket, bucketTargetsFile: bucketTargetsFile} (sorted on output) */
  buckets_kms_context_text(keys, vals, strcmp(bucket, "bucket-targets.json") == 0 ? 1 : 2, out);
}

static void b64(const uint8_t *p, size_t n, char *out) { buckets_base64_encode(p, n, out); }

bool buckets_bucket_targets_seal(struct buckets_kms *kms, const char *bucket, const void *json, size_t len,
                                 buckets_buf *data, buckets_buf *meta_json) {
  buckets_buf_reset(data);
  buckets_buf_reset(meta_json);
  if (!kms) {
    buckets_buf_append(data, json, len);
    return true;
  }
  buckets_buf ctx = BUCKETS_BUF_INIT, dek = BUCKETS_BUF_INIT;
  kms_context(bucket, &ctx);
  uint8_t ext[32], key[32], iv[32], sealed[BUCKETS_SEALED_KEY_LEN];
  char key_id[256];
  buckets_kms_err ke = buckets_kms_generate(kms, NULL, ctx.data, ext, &dek, key_id, sizeof(key_id));
  buckets_buf_free(&ctx);
  if (ke) {
    buckets_buf_free(&dek);
    return false;
  }
  buckets_objkey_generate(ext, NULL, key);
  buckets_objkey_seal(key, ext, NULL, "SSE-S3", bucket, "", iv, sealed);
  buckets_buf_reserve(data, (size_t)buckets_dare_encrypted_size(len) + 1);
  data->len = buckets_dare_encrypt_buffer(key, json, len, (uint8_t *)data->data);
  /* json.Marshal(map[string]string): sorted keys */
  char ivb[64], sb[128], db[512];
  b64(iv, 32, ivb);
  b64(sealed, sizeof(sealed), sb);
  if (dek.len * 4 / 3 + 8 > sizeof(db)) {
    buckets_buf_free(&dek);
    return false;
  }
  b64((const uint8_t *)dek.data, dek.len, db);
  buckets_buf_free(&dek);
  buckets_buf_append_c(meta_json, "{");
  jstr(meta_json, "X-Minio-Internal-Server-Side-Encryption-Iv", ivb);
  buckets_buf_append_char(meta_json, ',');
  jstr(meta_json, "X-Minio-Internal-Server-Side-Encryption-S3-Kms-Key-Id", key_id);
  buckets_buf_append_char(meta_json, ',');
  jstr(meta_json, "X-Minio-Internal-Server-Side-Encryption-S3-Kms-Sealed-Key", db);
  buckets_buf_append_char(meta_json, ',');
  jstr(meta_json, "X-Minio-Internal-Server-Side-Encryption-S3-Sealed-Key", sb);
  buckets_buf_append_char(meta_json, ',');
  jstr(meta_json, "X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm", BUCKETS_SEAL_ALGORITHM);
  buckets_buf_append_c(meta_json, "}");
  return true;
}

static const char *meta_get(yyjson_val *o, const char *k) {
  yyjson_val *v = yyjson_obj_get(o, k);
  return v && yyjson_is_str(v) ? yyjson_get_str(v) : NULL;
}

bool buckets_bucket_targets_open(struct buckets_kms *kms, const char *bucket, const void *data, size_t len,
                                 const void *meta_json, size_t meta_len, buckets_bucket_targets *out) {
  memset(out, 0, sizeof(*out));
  if (!len) return true;
  char err[256];
  if (!meta_len) return buckets_bucket_targets_parse(data, len, out, err, sizeof(err));
  yyjson_doc *md = yyjson_read(meta_json, meta_len, 0);
  if (!md) return false;
  yyjson_val *m = yyjson_doc_get_root(md);
  const char *sealed_s = yyjson_is_obj(m) ? meta_get(m, "X-Minio-Internal-Server-Side-Encryption-S3-Sealed-Key") : NULL;
  if (!sealed_s) { /* not SSE-S3: the JSON as stored */
    yyjson_doc_free(md);
    return buckets_bucket_targets_parse(data, len, out, err, sizeof(err));
  }
  bool ok = false;
  const char *iv_s = meta_get(m, "X-Minio-Internal-Server-Side-Encryption-Iv");
  const char *alg = meta_get(m, "X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm");
  const char *kid = meta_get(m, "X-Minio-Internal-Server-Side-Encryption-S3-Kms-Key-Id");
  const char *dk_s = meta_get(m, "X-Minio-Internal-Server-Side-Encryption-S3-Kms-Sealed-Key");
  uint8_t iv[48], sealed[96], dk[512], ext[32], key[32];
  if (kms && iv_s && dk_s && kid && buckets_base64_decode(iv_s, strlen(iv_s), iv) == 32 &&
      buckets_base64_decode(sealed_s, strlen(sealed_s), sealed) == BUCKETS_SEALED_KEY_LEN && strlen(dk_s) < 680) {
    long dkn = buckets_base64_decode(dk_s, strlen(dk_s), dk);
    buckets_buf ctx = BUCKETS_BUF_INIT;
    kms_context(bucket, &ctx);
    if (dkn > 0 && buckets_kms_decrypt(kms, kid, dk, (size_t)dkn, ctx.data, ext) == BUCKETS_KMS_OK &&
        buckets_objkey_unseal(ext, sealed, iv, alg ? alg : BUCKETS_SEAL_ALGORITHM, "SSE-S3", bucket, "", key)) {
      uint8_t *plain = buckets_xmalloc(len + 1);
      long pn = buckets_dare_decrypt_buffer(key, data, len, plain);
      if (pn >= 0) ok = buckets_bucket_targets_parse((const char *)plain, (size_t)pn, out, err, sizeof(err));
      free(plain);
    }
    buckets_buf_free(&ctx);
  }
  yyjson_doc_free(md);
  return ok;
}

/* ---- ARNs ---- */

bool buckets_arn_parse(const char *s, buckets_arn *out) {
  memset(out, 0, sizeof(*out));
  if (strncmp(s, "arn:minio:", 10) != 0) return false;
  const char *tok[6];
  size_t len[6], n = 0;
  const char *p = s;
  for (;;) {
    const char *c = strchr(p, ':');
    if (n == 6) return false;
    tok[n] = p;
    len[n] = c ? (size_t)(c - p) : strlen(p);
    n++;
    if (!c) break;
    p = c + 1;
  }
  if (n != 6 || len[4] == 0 || len[5] == 0) return false;
  if (len[2] >= sizeof(out->type) || len[3] >= sizeof(out->region) || len[4] >= sizeof(out->id) ||
      len[5] >= sizeof(out->bucket))
    return false;
  memcpy(out->type, tok[2], len[2]);
  memcpy(out->region, tok[3], len[3]);
  memcpy(out->id, tok[4], len[4]);
  memcpy(out->bucket, tok[5], len[5]);
  return true;
}

void buckets_arn_generate(const char *type, const char *region, const char *id, const char *bucket, char *out,
                          size_t cap) {
  char u[BUCKETS_UUID_STR_LEN + 1];
  if (!id || !*id) {
    buckets_uuid_v4(u);
    id = u;
  }
  snprintf(out, cap, "arn:minio:%s:%s:%s:%s", type, region ? region : "", id, bucket);
}
