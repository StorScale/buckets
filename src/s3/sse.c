/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/sse.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yyjson.h>

#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/objkey.h"
#include "bucket/metasys.h"
#include "config/config.h"
#include "kms/kms.h"

#define H_SSE "X-Amz-Server-Side-Encryption"
#define H_KMS_ID "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"
#define H_KMS_CTX "X-Amz-Server-Side-Encryption-Context"
#define H_C_ALG "X-Amz-Server-Side-Encryption-Customer-Algorithm"
#define H_C_KEY "X-Amz-Server-Side-Encryption-Customer-Key"
#define H_C_MD5 "X-Amz-Server-Side-Encryption-Customer-Key-Md5"
#define H_CC_ALG "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm"
#define H_CC_KEY "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"
#define H_CC_MD5 "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5"
#define ARN_PREFIX "arn:aws:kms:"

void buckets_sse_req_free(buckets_sse_req *r) {
  buckets_buf_free(&r->context);
  OPENSSL_cleanse(r->ssec_key, sizeof(r->ssec_key));
}

static bool has(s3_ctx *c, const char *h) { return buckets_http_header_get(c->req, h).p != NULL; }
static char *hget(s3_ctx *c, const char *h) {
  buckets_str v = buckets_http_header_get(c->req, h);
  return v.p ? buckets_str_dup(v) : buckets_xstrdup("");
}

static bool s3_requested(s3_ctx *c) {
  buckets_str v = buckets_http_header_get(c->req, H_SSE);
  return v.p && !buckets_str_ieq_c(v, "aws:kms");
}
static bool kms_requested(s3_ctx *c) {
  if (has(c, H_KMS_ID) || has(c, H_KMS_CTX)) return true;
  buckets_str v = buckets_http_header_get(c->req, H_SSE);
  return v.p && !buckets_str_ieq_c(v, "AES256");
}
static bool ssec_requested(s3_ctx *c) { return has(c, H_C_ALG) || has(c, H_C_KEY) || has(c, H_C_MD5); }
static bool ssec_copy_requested(s3_ctx *c) { return has(c, H_CC_ALG) || has(c, H_CC_KEY) || has(c, H_CC_MD5); }

buckets_s3_error buckets_s3_ssec_key(s3_ctx *c, bool copy, uint8_t key[32]) {
  char *alg = hget(c, copy ? H_CC_ALG : H_C_ALG), *k = hget(c, copy ? H_CC_KEY : H_C_KEY),
       *md5 = hget(c, copy ? H_CC_MD5 : H_C_MD5);
  buckets_s3_error e = BUCKETS_ERR_NONE;
  uint8_t raw[64], want[32];
  long kn, mn;
  if (strcmp(alg, "AES256") != 0) e = BUCKETS_ERR_INVALID_SSE_CUSTOMER_ALGORITHM;
  else if (!*k) e = BUCKETS_ERR_MISSING_SSE_CUSTOMER_KEY;
  else if (!*md5) e = BUCKETS_ERR_MISSING_SSE_CUSTOMER_KEY_MD5;
  else if (strlen(k) > 60 || (kn = buckets_base64_decode(k, strlen(k), raw)) != 32) e = BUCKETS_ERR_ACCESS_DENIED; /* ErrInvalidCustomerKey */
  else {
    uint8_t sum[16];
    buckets_md5(raw, 32, sum);
    mn = strlen(md5) <= 40 ? buckets_base64_decode(md5, strlen(md5), want) : -1;
    if (mn != 16 || memcmp(sum, want, 16) != 0) e = BUCKETS_ERR_SSE_CUSTOMER_KEY_MD5_MISMATCH;
    else memcpy(key, raw, 32);
  }
  OPENSSL_cleanse(raw, sizeof(raw));
  free(alg), free(k), free(md5);
  return e;
}

/* crypto.S3KMS.ParseHTTP */
static buckets_s3_error kms_parse(s3_ctx *c, buckets_sse_req *r) {
  buckets_str alg = buckets_http_header_get(c->req, H_SSE);
  if (!alg.p || !buckets_str_eq_c(alg, "aws:kms")) return BUCKETS_ERR_INVALID_ENCRYPTION_METHOD;
  buckets_str ctx = buckets_http_header_get(c->req, H_KMS_CTX);
  if (ctx.p) {
    uint8_t *json = buckets_xmalloc(ctx.n + 3);
    long n = buckets_base64_decode(ctx.p, ctx.n, json);
    yyjson_doc *d = n >= 0 ? yyjson_read((const char *)json, (size_t)n, 0) : NULL;
    yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
    bool ok = yyjson_is_obj(root) || yyjson_is_null(root);
    size_t cnt = 0, cap = yyjson_is_obj(root) ? yyjson_obj_size(root) : 0;
    const char **keys = buckets_xcalloc(cap + 1, sizeof(char *)), **vals = buckets_xcalloc(cap + 1, sizeof(char *));
    yyjson_obj_iter it = yyjson_obj_iter_with(root);
    yyjson_val *k;
    while (ok && yyjson_is_obj(root) && (k = yyjson_obj_iter_next(&it))) {
      yyjson_val *v = yyjson_obj_iter_get_val(k);
      if (!yyjson_is_str(v)) {
        ok = false;
        break;
      }
      keys[cnt] = yyjson_get_str(k), vals[cnt] = yyjson_get_str(v), cnt++;
    }
    if (ok) {
      buckets_kms_context_text(keys, vals, cnt, &r->context);
      r->has_context = cnt > 0;
    }
    free(keys), free(vals);
    yyjson_doc_free(d);
    free(json);
    if (!ok) return BUCKETS_ERR_INVALID_ARGUMENT;
  }
  char *id = hget(c, H_KMS_ID);
  size_t il = strlen(id);
  if (il && (id[0] == ' ' || id[il - 1] == ' ')) {
    free(id);
    return BUCKETS_ERR_INVALID_ENCRYPTION_KEY_ID;
  }
  const char *p = strncmp(id, ARN_PREFIX, strlen(ARN_PREFIX)) == 0 ? id + strlen(ARN_PREFIX) : id;
  snprintf(r->key_id, sizeof(r->key_id), "%s", p);
  free(id);
  return BUCKETS_ERR_NONE;
}

static const char *crypto_message(buckets_s3_error e) {
  switch (e) {
  case BUCKETS_ERR_INVALID_ENCRYPTION_METHOD: return "The encryption method is not supported";
  case BUCKETS_ERR_INVALID_ENCRYPTION_KEY_ID: return "KMS KeyID contains unsupported characters";
  case BUCKETS_ERR_INVALID_SSE_CUSTOMER_ALGORITHM: return "The SSE-C algorithm is not supported";
  case BUCKETS_ERR_MISSING_SSE_CUSTOMER_KEY: return "The SSE-C request is missing the customer key";
  case BUCKETS_ERR_MISSING_SSE_CUSTOMER_KEY_MD5: return "The SSE-C request is missing the customer key MD5";
  case BUCKETS_ERR_ACCESS_DENIED: return "The SSE-C client key is invalid";
  case BUCKETS_ERR_SSE_CUSTOMER_KEY_MD5_MISMATCH:
    return "The provided SSE-C key MD5 does not match the computed MD5 of the SSE-C key";
  default: return "invalid encryption context";
  }
}

bool buckets_s3_sse_put_opts(s3_ctx *c, char *why, size_t cap) {
  buckets_s3_error e = BUCKETS_ERR_NONE;
  if (kms_requested(c)) {
    buckets_sse_req r = {0};
    e = kms_parse(c, &r);
    buckets_sse_req_free(&r);
  } else if (ssec_requested(c)) {
    uint8_t k[32];
    e = buckets_s3_ssec_key(c, false, k);
    OPENSSL_cleanse(k, sizeof(k));
  }
  if (e) snprintf(why, cap, "%s", crypto_message(e));
  return !e;
}

bool buckets_s3_sse_requested(s3_ctx *c) { return s3_requested(c) || kms_requested(c) || ssec_requested(c); }

bool buckets_s3_sse_s3_or_kms_requested(s3_ctx *c) { return s3_requested(c) || kms_requested(c); }

buckets_s3_error buckets_s3_sse_get_opts(s3_ctx *c) {
  if (!ssec_requested(c)) return BUCKETS_ERR_NONE;
  uint8_t k[32];
  buckets_s3_error e = buckets_s3_ssec_key(c, false, k);
  OPENSSL_cleanse(k, sizeof(k));
  return e;
}

/* BucketSSEConfig.Apply: a write asking for no encryption gets the bucket's
 * default (or, with MINIO_KMS_AUTO_ENCRYPTION, SSE-KMS with the default key). */
static void apply_default(s3_ctx *c, buckets_sse_req *r) {
  if (!c->s->meta || !c->bucket) return;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (st->has_sse) {
    if (strcmp(st->sse.algorithm, "AES256") == 0) {
      r->kind = BUCKETS_SSE_S3;
    } else if (strcmp(st->sse.algorithm, "aws:kms") == 0) {
      r->kind = BUCKETS_SSE_KMS;
      snprintf(r->key_id, sizeof(r->key_id), "%s", buckets_sse_config_key(&st->sse));
    }
  } else {
    const char *auto_enc = buckets_config_getenv("MINIO_KMS_AUTO_ENCRYPTION");
    if (auto_enc && buckets_config_parse_bool(auto_enc) == 1) r->kind = BUCKETS_SSE_KMS;
  }
  buckets_bucket_state_release(st);
}

static buckets_s3_error parse(s3_ctx *c, buckets_sse_req *r, bool copy) {
  memset(r, 0, sizeof(*r));
  bool s3 = s3_requested(c), kms = kms_requested(c), ssec = ssec_requested(c);
  if (!s3 && !kms && !ssec) {
    apply_default(c, r);
    return BUCKETS_ERR_NONE;
  }
  if (!copy && ssec_copy_requested(c)) return BUCKETS_ERR_INVALID_ENCRYPTION_PARAMETERS;
  if (ssec && (s3 || kms)) return BUCKETS_ERR_INCOMPATIBLE_ENCRYPTION_METHOD;
  if (s3) {
    r->kind = BUCKETS_SSE_S3;
  } else if (kms) {
    r->kind = BUCKETS_SSE_KMS;
    return kms_parse(c, r);
  } else {
    r->kind = BUCKETS_SSE_C;
    return buckets_s3_ssec_key(c, false, r->ssec_key);
  }
  return BUCKETS_ERR_NONE;
}

buckets_s3_error buckets_s3_sse_parse(s3_ctx *c, buckets_sse_req *r) { return parse(c, r, false); }
buckets_s3_error buckets_s3_sse_parse_copy_dest(s3_ctx *c, buckets_sse_req *r) { return parse(c, r, true); }

static buckets_s3_error kms_error(buckets_kms_err e) {
  switch (e) {
  case BUCKETS_KMS_ERR_KEY_NOT_FOUND: return BUCKETS_SSE_ERR_KMS_KEY_NOT_FOUND;
  case BUCKETS_KMS_ERR_DECRYPT: return BUCKETS_SSE_ERR_KMS_DECRYPT;
  default: return BUCKETS_ERR_INTERNAL_ERROR;
  }
}

void buckets_s3_sse_write_error(s3_ctx *c, buckets_s3_error e) {
  if (e == BUCKETS_SSE_ERR_KMS_KEY_NOT_FOUND)
    buckets_s3_write_custom_error(c, 404, "kms:KeyNotFound", "key with given key ID does not exist");
  else if (e == BUCKETS_SSE_ERR_KMS_DECRYPT)
    buckets_s3_write_custom_error(c, 400, "kms:InvalidCiphertextException", "failed to decrypt ciphertext");
  else buckets_s3_write_error(c, e);
}

/* kms.Context{bucket: path.Join(bucket, object)} plus a user context. */
static void object_context(const char *bucket, const char *object, const char *user_ctx_json, buckets_buf *out) {
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_path_join(bucket, object, &path);
  yyjson_doc *d = user_ctx_json ? yyjson_read(user_ctx_json, strlen(user_ctx_json), 0) : NULL;
  yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
  size_t cap = (yyjson_is_obj(root) ? yyjson_obj_size(root) : 0) + 1, n = 0;
  const char **keys = buckets_xcalloc(cap, sizeof(char *)), **vals = buckets_xcalloc(cap, sizeof(char *));
  bool have_bucket = false;
  yyjson_obj_iter it = yyjson_obj_iter_with(root);
  yyjson_val *k;
  while (yyjson_is_obj(root) && (k = yyjson_obj_iter_next(&it))) {
    keys[n] = yyjson_get_str(k), vals[n] = yyjson_get_str(yyjson_obj_iter_get_val(k));
    if (!vals[n]) vals[n] = "";
    have_bucket |= strcmp(keys[n], bucket) == 0;
    n++;
  }
  if (!have_bucket) keys[n] = bucket, vals[n] = path.data ? path.data : "", n++;
  buckets_kms_context_text(keys, vals, n, out);
  free(keys), free(vals);
  yyjson_doc_free(d);
  buckets_buf_free(&path);
}

static void sys_set_b64(buckets_xl_kv **sys, size_t *n, const char *k, const uint8_t *data, size_t len) {
  char *enc = buckets_xmalloc(len * 4 / 3 + 8);
  buckets_base64_encode(data, len, enc);
  buckets_xl_kv_set(sys, n, k, enc, strlen(enc));
  free(enc);
}

static void sys_set(buckets_xl_kv **sys, size_t *n, const char *k, const char *v) { buckets_xl_kv_set(sys, n, k, v, strlen(v)); }

buckets_s3_error buckets_s3_sse_new_key(s3_ctx *c, const buckets_sse_req *r, const char *bucket, const char *object,
                                        uint8_t key[32], buckets_xl_kv **sys, size_t *nsys) {
  uint8_t ext[32], iv[32], sealed[BUCKETS_SEALED_KEY_LEN];
  const char *domain;
  buckets_buf dek = BUCKETS_BUF_INIT;
  char key_id[256] = "";
  if (r->kind == BUCKETS_SSE_C) {
    memcpy(ext, r->ssec_key, 32);
    domain = "SSE-C";
  } else {
    if (!c->s->kms) return BUCKETS_ERR_KMS_NOT_CONFIGURED;
    buckets_buf ctx = BUCKETS_BUF_INIT;
    object_context(bucket, object, r->kind == BUCKETS_SSE_KMS && r->has_context ? r->context.data : NULL, &ctx);
    buckets_kms_err ke = buckets_kms_generate(c->s->kms, r->kind == BUCKETS_SSE_KMS ? r->key_id : NULL, ctx.data, ext, &dek,
                                             key_id, sizeof(key_id));
    buckets_buf_free(&ctx);
    if (ke) {
      buckets_buf_free(&dek);
      return kms_error(ke);
    }
    domain = r->kind == BUCKETS_SSE_S3 ? "SSE-S3" : "SSE-KMS";
  }
  buckets_objkey_generate(ext, NULL, key);
  buckets_objkey_seal(key, ext, NULL, domain, bucket, object, iv, sealed);
  OPENSSL_cleanse(ext, sizeof(ext));
  sys_set(sys, nsys, BUCKETS_SSE_META_ALGORITHM, BUCKETS_SEAL_ALGORITHM);
  sys_set_b64(sys, nsys, BUCKETS_SSE_META_IV, iv, 32);
  const char *sealed_key = r->kind == BUCKETS_SSE_C    ? BUCKETS_SSE_META_SEALED_SSEC
                           : r->kind == BUCKETS_SSE_S3 ? BUCKETS_SSE_META_SEALED_S3
                                                       : BUCKETS_SSE_META_SEALED_KMS;
  sys_set_b64(sys, nsys, sealed_key, sealed, sizeof(sealed));
  if (r->kind == BUCKETS_SSE_KMS && r->has_context) sys_set_b64(sys, nsys, BUCKETS_SSE_META_CONTEXT, (uint8_t *)r->context.data, r->context.len);
  if (r->kind != BUCKETS_SSE_C) {
    sys_set(sys, nsys, BUCKETS_SSE_META_KEY_ID, key_id);
    sys_set_b64(sys, nsys, BUCKETS_SSE_META_DATA_KEY, (uint8_t *)dek.data, dek.len);
  }
  buckets_buf_free(&dek);
  return BUCKETS_ERR_NONE;
}

/* ---- stored objects ---------------------------------------------------------------------- */

static const char *sys_str(const buckets_object_info *oi, const char *k) {
  const buckets_xl_kv *kv = buckets_object_sys(oi, k);
  return kv ? (const char *)kv->value : NULL;
}

buckets_sse_kind buckets_s3_sse_kind_of(const buckets_object_info *oi) {
  if (sys_str(oi, BUCKETS_SSE_META_SEALED_KMS)) return BUCKETS_SSE_KMS;
  if (sys_str(oi, BUCKETS_SSE_META_SEALED_S3)) return BUCKETS_SSE_S3;
  if (sys_str(oi, BUCKETS_SSE_META_SEALED_SSEC)) return BUCKETS_SSE_C;
  return BUCKETS_SSE_NONE;
}

bool buckets_s3_sse_encrypted(const buckets_object_info *oi) {
  static const char *const any[] = {BUCKETS_SSE_META_SEALED_KMS, BUCKETS_SSE_META_SEALED_S3, BUCKETS_SSE_META_SEALED_SSEC,
                                    BUCKETS_SSE_META_MULTIPART, BUCKETS_SSE_META_IV,          BUCKETS_SSE_META_ALGORITHM,
                                    BUCKETS_SSE_META_KEY_ID,    BUCKETS_SSE_META_DATA_KEY,    BUCKETS_SSE_META_CONTEXT};
  for (size_t i = 0; i < sizeof(any) / sizeof(any[0]); i++)
    if (sys_str(oi, any[i])) return true;
  return false;
}

bool buckets_s3_sse_is_multipart(const buckets_object_info *oi) {
  if (buckets_s3_sse_encrypted(oi)) {
    if (!sys_str(oi, BUCKETS_SSE_META_MULTIPART)) return false;
    uint64_t d;
    for (size_t i = 0; i < oi->nparts; i++)
      if (!buckets_dare_decrypted_size((uint64_t)oi->parts[i].size, &d)) return false;
  }
  return strlen(oi->etag) != 32;
}

int64_t buckets_s3_sse_actual_size(const buckets_object_info *oi) {
  uint64_t d, total = 0;
  if (!buckets_s3_sse_is_multipart(oi)) return buckets_dare_decrypted_size((uint64_t)oi->size, &d) ? (int64_t)d : -1;
  for (size_t i = 0; i < oi->nparts; i++) {
    if (!buckets_dare_decrypted_size((uint64_t)oi->parts[i].size, &d)) return -1;
    total += d;
  }
  return (int64_t)total;
}

static bool b64_field(const buckets_object_info *oi, const char *k, uint8_t *out, size_t want) {
  const char *v = sys_str(oi, k);
  if (!v || strlen(v) > want * 2 + 8) return false;
  return buckets_base64_decode(v, strlen(v), out) == (long)want;
}

buckets_s3_error buckets_s3_sse_object_key(s3_ctx *c, const buckets_object_info *oi, const char *bucket, const char *object,
                                           bool copy, uint8_t key[32]) {
  buckets_sse_kind kind = buckets_s3_sse_kind_of(oi);
  if (kind == BUCKETS_SSE_NONE) return BUCKETS_ERR_OBJECT_TAMPERED;
  uint8_t iv[32], sealed[BUCKETS_SEALED_KEY_LEN], ext[32];
  const char *alg = sys_str(oi, BUCKETS_SSE_META_ALGORITHM);
  const char *sk = kind == BUCKETS_SSE_C ? BUCKETS_SSE_META_SEALED_SSEC : kind == BUCKETS_SSE_S3 ? BUCKETS_SSE_META_SEALED_S3
                                                                                                 : BUCKETS_SSE_META_SEALED_KMS;
  if (!alg || !b64_field(oi, BUCKETS_SSE_META_IV, iv, 32) || !b64_field(oi, sk, sealed, sizeof(sealed)))
    return BUCKETS_ERR_OBJECT_TAMPERED;
  const char *domain = kind == BUCKETS_SSE_C ? "SSE-C" : kind == BUCKETS_SSE_S3 ? "SSE-S3" : "SSE-KMS";
  if (kind == BUCKETS_SSE_C) {
    buckets_s3_error e = buckets_s3_ssec_key(c, copy && ssec_copy_requested(c), ext);
    if (e) return e;
  } else {
    if (!c->s->kms) return BUCKETS_ERR_KMS_NOT_CONFIGURED;
    const char *key_id = sys_str(oi, BUCKETS_SSE_META_KEY_ID);
    const char *dek64 = sys_str(oi, BUCKETS_SSE_META_DATA_KEY);
    if (!key_id || !dek64) return BUCKETS_ERR_OBJECT_TAMPERED;
    uint8_t *dek = buckets_xmalloc(strlen(dek64) + 3);
    long dn = buckets_base64_decode(dek64, strlen(dek64), dek);
    char *user_ctx = NULL;
    const char *ctx64 = kind == BUCKETS_SSE_KMS ? sys_str(oi, BUCKETS_SSE_META_CONTEXT) : NULL;
    if (ctx64) {
      user_ctx = buckets_xmalloc(strlen(ctx64) + 3);
      long cn = buckets_base64_decode(ctx64, strlen(ctx64), (uint8_t *)user_ctx);
      if (cn < 0) cn = 0;
      user_ctx[cn] = '\0';
    }
    buckets_buf ctx = BUCKETS_BUF_INIT;
    object_context(bucket, object, user_ctx, &ctx);
    buckets_kms_err ke = dn < 0 ? BUCKETS_KMS_ERR_DECRYPT : buckets_kms_decrypt(c->s->kms, key_id, dek, (size_t)dn, ctx.data, ext);
    buckets_buf_free(&ctx);
    free(user_ctx);
    free(dek);
    if (ke) return kms_error(ke);
  }
  bool ok = buckets_objkey_unseal(ext, sealed, iv, alg, domain, bucket, object, key);
  OPENSSL_cleanse(ext, sizeof(ext));
  return ok ? BUCKETS_ERR_NONE : BUCKETS_ERR_ACCESS_DENIED; /* ErrSecretKeyMismatch */
}

buckets_s3_error buckets_s3_sse_check_read(s3_ctx *c, const buckets_object_info *oi, bool copy) {
  if (!copy && (s3_requested(c) || kms_requested(c))) return BUCKETS_ERR_INVALID_ENCRYPTION_PARAMETERS;
  bool enc = buckets_s3_sse_encrypted(oi);
  if (!enc && !copy && ssec_requested(c)) return BUCKETS_ERR_INVALID_ENCRYPTION_PARAMETERS;
  if (!enc) return BUCKETS_ERR_NONE;
  buckets_sse_kind kind = buckets_s3_sse_kind_of(oi);
  if (kind == BUCKETS_SSE_C && !ssec_requested(c) && !ssec_copy_requested(c)) return BUCKETS_ERR_SSE_ENCRYPTED_OBJECT;
  if ((kind == BUCKETS_SSE_S3 || kind == BUCKETS_SSE_KMS) && !copy && (ssec_requested(c) || ssec_copy_requested(c)))
    return BUCKETS_ERR_SSE_ENCRYPTED_OBJECT;
  if (buckets_s3_sse_actual_size(oi) < 0) return BUCKETS_ERR_OBJECT_TAMPERED;
  return BUCKETS_ERR_NONE;
}

void buckets_s3_sse_client_etag(s3_ctx *c, const buckets_object_info *oi, const uint8_t *key, char out[80]) {
  size_t n = strlen(oi->etag);
  snprintf(out, 80, "%s", oi->etag);
  if (n == 32 || !buckets_s3_sse_encrypted(oi) || strchr(oi->etag, '-')) return;
  buckets_sse_kind kind = buckets_s3_sse_kind_of(oi);
  if (kind != BUCKETS_SSE_S3 || sys_str(oi, BUCKETS_SSE_META_MULTIPART)) {
    if (n >= 32) snprintf(out, 80, "%s", oi->etag + n - 32); /* etag.Format: the last 16 bytes */
    return;
  }
  uint8_t k[32];
  if (key) {
    memcpy(k, key, 32);
  } else {
    if (buckets_s3_sse_object_key(c, oi, c->bucket, oi->name, false, k)) return;
  }
  uint8_t raw[64];
  if (n % 2 || n / 2 > sizeof(raw) || !buckets_hex_decode(oi->etag, n, raw)) return;
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (buckets_objkey_unseal_etag(k, raw, n / 2, &plain) && plain.len <= 32) buckets_hex_encode((uint8_t *)plain.data, plain.len, out);
  buckets_buf_free(&plain);
  OPENSSL_cleanse(k, sizeof(k));
}

void buckets_s3_sse_kms_key_arn(const buckets_object_info *oi, char *out, size_t cap) {
  const char *id = sys_str(oi, BUCKETS_SSE_META_KEY_ID);
  if (!id) *out = '\0';
  else if (strncmp(id, ARN_PREFIX, strlen(ARN_PREFIX)) == 0) snprintf(out, cap, "%s", id);
  else snprintf(out, cap, ARN_PREFIX "%s", id);
}

void buckets_s3_sse_headers(s3_ctx *c, const buckets_object_info *oi) {
  switch (buckets_s3_sse_kind_of(oi)) {
  case BUCKETS_SSE_S3: buckets_http_resp_header(c->resp, "X-Amz-Server-Side-Encryption", "AES256"); break;
  case BUCKETS_SSE_KMS: {
    char arn[300];
    buckets_s3_sse_kms_key_arn(oi, arn, sizeof(arn));
    buckets_http_resp_header(c->resp, "X-Amz-Server-Side-Encryption", "aws:kms");
    buckets_http_resp_header(c->resp, "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", arn);
    const char *ctx = sys_str(oi, BUCKETS_SSE_META_CONTEXT);
    if (ctx) buckets_http_resp_header(c->resp, "X-Amz-Server-Side-Encryption-Context", ctx);
    break;
  }
  case BUCKETS_SSE_C: {
    char *alg = hget(c, H_C_ALG), *md5 = hget(c, H_C_MD5);
    buckets_http_resp_header(c->resp, "X-Amz-Server-Side-Encryption-Customer-Algorithm", alg);
    buckets_http_resp_header(c->resp, "X-Amz-Server-Side-Encryption-Customer-Key-Md5", md5);
    free(alg), free(md5);
    break;
  }
  default: break;
  }
}

/* ---- writer ------------------------------------------------------------------------------ */

void buckets_sse_writer_init(buckets_sse_writer *w, const uint8_t key[32], buckets_read_fn rd, void *rd_ud, int64_t size,
                             uint32_t cks_type) {
  buckets_sse_writer_init_nonce(w, key, NULL, rd, rd_ud, size, cks_type);
}

void buckets_sse_writer_init_nonce(buckets_sse_writer *w, const uint8_t key[32], const uint8_t *nonce, buckets_read_fn rd,
                                   void *rd_ud, int64_t size, uint32_t cks_type) {
  memset(w, 0, sizeof(*w));
  w->rd = rd;
  w->rd_ud = rd_ud;
  w->remaining = size < 0 ? INT64_MAX : size;
  w->unknown = size < 0;
  buckets_dare_enc_init(&w->enc, key, nonce, 0);
  buckets_md5_init(&w->md5);
  buckets_sha256_init(&w->sha);
  w->cks_type = cks_type;
  if (cks_type) buckets_cksum_hasher_init(&w->cks, cks_type);
  w->in = buckets_xmalloc(BUCKETS_DARE_PAYLOAD);
  w->out = buckets_xmalloc(BUCKETS_DARE_PACKAGE);
}

void buckets_sse_writer_free(buckets_sse_writer *w) {
  buckets_dare_enc_free(&w->enc);
  free(w->in);
  free(w->out);
  w->in = w->out = NULL;
}

long buckets_sse_writer_read(void *ud, void *buf, size_t n) {
  buckets_sse_writer *w = ud;
  if (w->out_pos == w->out_len) {
    if (!w->unknown && w->remaining <= 0 && !w->eof) {
      /* The source must end here (and chunked sources read their trailers). */
      uint8_t one;
      w->eof = true;
      if (w->rd(w->rd_ud, &one, 1) != 0) return -1;
    }
    if (w->remaining <= 0 || w->eof) return 0;
    size_t want = w->remaining < BUCKETS_DARE_PAYLOAD ? (size_t)w->remaining : BUCKETS_DARE_PAYLOAD, got = 0;
    if (w->have_peek) {
      w->in[got++] = w->peek;
      w->have_peek = false;
    }
    while (got < want) {
      long r = w->rd(w->rd_ud, w->in + got, want - got);
      if (r < 0 || (r == 0 && !w->unknown)) return -1; /* short body */
      if (r == 0) {
        w->eof = true;
        break;
      }
      got += (size_t)r;
    }
    bool final;
    if (!w->unknown) {
      final = w->remaining - (int64_t)got == 0;
    } else if (w->eof) {
      final = true;
    } else { /* a full package: final only when nothing follows */
      long r = w->rd(w->rd_ud, &w->peek, 1);
      if (r < 0) return -1;
      w->have_peek = r == 1;
      w->eof = final = r == 0;
    }
    if (!got) return 0; /* an empty stream has no packages */
    if (!w->no_hash) {
      buckets_md5_update(&w->md5, w->in, got);
      buckets_sha256_update(&w->sha, w->in, got);
      if (w->cks_type) buckets_cksum_hasher_update(&w->cks, w->in, got);
    }
    w->remaining -= (int64_t)got;
    w->plain_size += (int64_t)got;
    w->out_len = buckets_dare_seal(&w->enc, w->in, got, final, w->out);
    w->out_pos = 0;
  }
  size_t k = w->out_len - w->out_pos < n ? w->out_len - w->out_pos : n;
  memcpy(buf, w->out + w->out_pos, k);
  w->out_pos += k;
  return (long)k;
}

/* ---- ranges and the reader --------------------------------------------------------------- */

static int64_t part_plain(const buckets_object_info *oi, size_t i) {
  uint64_t d = 0;
  buckets_dare_decrypted_size((uint64_t)oi->parts[i].size, &d);
  return (int64_t)d;
}

bool buckets_s3_sse_range(const buckets_object_info *oi, int64_t off, int64_t len, buckets_sse_range *out) {
  memset(out, 0, sizeof(*out));
  bool mp = buckets_s3_sse_is_multipart(oi);
  size_t nparts = mp ? oi->nparts : 1;
  int64_t sum = 0, enc_sum = 0;
  size_t start = 0, end = 0;
  for (size_t i = 0; i < nparts; i++) {
    int64_t size = mp ? part_plain(oi, i) : buckets_s3_sse_actual_size(oi);
    if (off < sum + size) {
      start = i;
      break;
    }
    sum += size;
    enc_sum += (int64_t)buckets_dare_encrypted_size((uint64_t)size);
    start = i + 1;
  }
  int64_t pkg = (off - sum) / BUCKETS_DARE_PAYLOAD;
  out->skip = (off - sum) % BUCKETS_DARE_PAYLOAD;
  out->enc_off = enc_sum + pkg * BUCKETS_DARE_PACKAGE;
  out->seq = (uint32_t)pkg;
  out->part = start;
  int64_t last = off + len - 1;
  for (size_t i = start; i < nparts; i++) {
    int64_t size = mp ? part_plain(oi, i) : buckets_s3_sse_actual_size(oi);
    if (last < sum + size) {
      end = i;
      break;
    }
    sum += size;
    enc_sum += (int64_t)buckets_dare_encrypted_size((uint64_t)size);
    end = i;
  }
  int64_t end_pkg = (last - sum) / BUCKETS_DARE_PAYLOAD;
  int64_t end_enc = enc_sum + (end_pkg + 1) * BUCKETS_DARE_PACKAGE;
  int64_t last_size = mp ? part_plain(oi, end) : buckets_s3_sse_actual_size(oi);
  int64_t last_enc = (int64_t)buckets_dare_encrypted_size((uint64_t)last_size);
  if (end_enc > enc_sum + last_enc) end_enc = enc_sum + last_enc;
  out->enc_len = len > 0 ? end_enc - out->enc_off : 0;
  return true;
}

struct buckets_sse_reader {
  buckets_read_fn rd;
  void *rd_ud;
  void (*free_rd)(void *);
  uint8_t key[32];
  bool multipart;
  const buckets_xl_part *parts; /* copied */
  buckets_xl_part *parts_own;
  size_t nparts, part;
  int64_t part_left; /* stored bytes left in the current part */
  buckets_dare_dec dec;
  uint8_t *pkg, *plain;
  size_t plain_pos, plain_len;
  int64_t skip, left;
  bool failed;
};

static void start_part(buckets_sse_reader *r, uint32_t seq, int64_t enc_rel) {
  uint8_t k[32];
  if (r->multipart) buckets_objkey_part_key(r->key, (uint32_t)r->parts[r->part].number, k);
  else memcpy(k, r->key, 32);
  buckets_dare_dec_free(&r->dec);
  buckets_dare_dec_init(&r->dec, k, seq);
  OPENSSL_cleanse(k, sizeof(k));
  r->part_left = (r->multipart ? r->parts[r->part].size : INT64_MAX) - enc_rel;
}

buckets_sse_reader *buckets_sse_reader_new(const buckets_object_info *oi, const uint8_t key[32], const buckets_sse_range *rg,
                                           int64_t len, buckets_read_fn rd, void *rd_ud, void (*free_rd)(void *)) {
  buckets_sse_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->rd = rd, r->rd_ud = rd_ud, r->free_rd = free_rd;
  memcpy(r->key, key, 32);
  r->multipart = buckets_s3_sse_is_multipart(oi);
  if (r->multipart && oi->nparts) {
    r->parts_own = buckets_xcalloc(oi->nparts, sizeof(buckets_xl_part));
    memcpy(r->parts_own, oi->parts, oi->nparts * sizeof(buckets_xl_part));
    for (size_t i = 0; i < oi->nparts; i++) r->parts_own[i].etag = NULL, r->parts_own[i].index = NULL;
    r->parts = r->parts_own;
    r->nparts = oi->nparts;
  }
  r->part = rg->part;
  r->pkg = buckets_xmalloc(BUCKETS_DARE_PACKAGE);
  r->plain = buckets_xmalloc(BUCKETS_DARE_PAYLOAD);
  r->skip = rg->skip;
  r->left = len;
  buckets_dare_dec_init(&r->dec, key, 0);
  start_part(r, rg->seq, (int64_t)rg->seq * BUCKETS_DARE_PACKAGE);
  return r;
}

static bool read_full(buckets_sse_reader *r, uint8_t *p, size_t n) {
  size_t got = 0;
  while (got < n) {
    long k = r->rd(r->rd_ud, p + got, n - got);
    if (k <= 0) return false;
    got += (size_t)k;
  }
  return true;
}

/* Decrypts the next package into plain; false at a failure. */
static bool next_package(buckets_sse_reader *r) {
  if (r->multipart && r->part_left <= 0) {
    if (++r->part >= r->nparts) return false;
    start_part(r, 0, 0);
  }
  if (!read_full(r, r->pkg, BUCKETS_DARE_HEADER)) return false;
  size_t size = buckets_dare_package_size(r->pkg);
  if (size > BUCKETS_DARE_PACKAGE || !read_full(r, r->pkg + BUCKETS_DARE_HEADER, size - BUCKETS_DARE_HEADER)) return false;
  long n = buckets_dare_open(&r->dec, r->pkg, size, r->plain);
  if (n < 0) return false;
  r->part_left -= (int64_t)size;
  r->plain_pos = 0;
  r->plain_len = (size_t)n;
  return true;
}

long buckets_sse_reader_read(void *ud, void *buf, size_t n) {
  buckets_sse_reader *r = ud;
  size_t w = 0;
  while (w < n && r->left > 0) {
    if (r->plain_pos == r->plain_len) {
      if (r->failed || !next_package(r)) {
        r->failed = true;
        return w ? (long)w : -1;
      }
      if (r->skip) {
        size_t s = (size_t)r->skip < r->plain_len ? (size_t)r->skip : r->plain_len;
        r->plain_pos = s;
        r->skip -= (int64_t)s;
        continue;
      }
    }
    size_t k = r->plain_len - r->plain_pos;
    if (k > n - w) k = n - w;
    if ((int64_t)k > r->left) k = (size_t)r->left;
    memcpy((uint8_t *)buf + w, r->plain + r->plain_pos, k);
    r->plain_pos += k;
    r->left -= (int64_t)k;
    w += k;
  }
  return (long)w;
}

void buckets_sse_reader_free(void *ud) {
  buckets_sse_reader *r = ud;
  if (!r) return;
  if (r->free_rd) r->free_rd(r->rd_ud);
  buckets_dare_dec_free(&r->dec);
  OPENSSL_cleanse(r->key, sizeof(r->key));
  free(r->parts_own);
  free(r->pkg);
  free(r->plain);
  free(r);
}

void buckets_s3_meta_seal(const uint8_t key[32], const char *base, const void *data, size_t n, buckets_buf *out) {
  if (!n) return;
  uint8_t k[32];
  buckets_hmac_sha256(key, 32, base, strlen(base), k);
  size_t len = buckets_dare_encrypted_size(n);
  uint8_t *enc = buckets_xmalloc(len);
  buckets_dare_encrypt_buffer(k, data, n, enc);
  OPENSSL_cleanse(k, sizeof(k));
  buckets_buf_append(out, enc, len);
  free(enc);
}

bool buckets_s3_meta_open(const uint8_t key[32], const char *base, const void *data, size_t n, buckets_buf *out) {
  if (!n) return true;
  uint8_t k[32];
  buckets_hmac_sha256(key, 32, base, strlen(base), k);
  uint8_t *plain = buckets_xmalloc(n);
  long got = buckets_dare_decrypt_buffer(k, data, n, plain);
  OPENSSL_cleanse(k, sizeof(k));
  if (got >= 0) buckets_buf_append(out, plain, (size_t)got);
  free(plain);
  return got >= 0;
}

bool buckets_s3_sse_unseal_checksum(const uint8_t key[32], buckets_object_info *oi) {
  if (!oi->checksum || !oi->checksum_len) return true;
  uint8_t k[32];
  buckets_hmac_sha256(key, 32, "object-checksum", 15, k);
  uint8_t *plain = buckets_xmalloc(oi->checksum_len);
  long n = buckets_dare_decrypt_buffer(k, oi->checksum, oi->checksum_len, plain);
  OPENSSL_cleanse(k, sizeof(k));
  if (n < 0) {
    free(plain);
    free(oi->checksum);
    oi->checksum = NULL;
    oi->checksum_len = 0;
    return false;
  }
  free(oi->checksum);
  oi->checksum = plain;
  oi->checksum_len = (size_t)n;
  return true;
}
