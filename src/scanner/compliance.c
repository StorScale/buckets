/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "scanner/compliance.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yyjson.h>

#include "bucket/objectlock.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/dare.h"
#include "s3/sse.h"

/* user metadata as MinIO writes it (canonical case) or as some clients send it (lower case) */
static const char *meta2(const buckets_object_info *v, const char *lower, const char *canon) {
  const char *m = buckets_object_meta(v, lower);
  return m ? m : buckets_object_meta(v, canon);
}

static void count(buckets_compliance_count *c, int64_t size) {
  c->versions++;
  c->bytes += size > 0 ? (uint64_t)size : 0;
}

/* Whether the version's object key is sealed with ChaCha20-Poly1305: the cipher byte of the sealed key's DARE
 * header. MinIO seals the key and encrypts the data in one request with the same choice of cipher. */
static bool sealed_with_chacha20(const buckets_object_info *v) {
  static const char *const keys[] = {BUCKETS_SSE_META_SEALED_S3, BUCKETS_SSE_META_SEALED_KMS,
                                     BUCKETS_SSE_META_SEALED_SSEC};
  for (size_t i = 0; i < v->nmeta_sys; i++) {
    const buckets_xl_kv *kv = &v->meta_sys[i];
    bool sealed = false;
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]) && !sealed; k++) sealed = strcmp(kv->key, keys[k]) == 0;
    if (!sealed || kv->value_len < 4) continue;
    uint8_t head[3]; /* the first four base64 characters */
    return buckets_base64_decode((const char *)kv->value, 4, head) == 3 && head[0] == BUCKETS_DARE_VERSION20 &&
           head[1] == 1;
  }
  return false;
}

void buckets_compliance_add(buckets_compliance_counts *c, const buckets_object_info *v, int64_t size,
                            int64_t now) {
  if (v->delete_marker) return;
  switch (buckets_s3_sse_kind_of(v)) {
    case BUCKETS_SSE_S3: count(&c->sse_s3, size); break;
    case BUCKETS_SSE_KMS: count(&c->sse_kms, size); break;
    case BUCKETS_SSE_C: count(&c->sse_c, size); break;
    default: count(&c->plain, size); break;
  }
  if (sealed_with_chacha20(v)) count(&c->chacha20, size);
  const char *mode = meta2(v, BUCKETS_LOCK_MODE_META, "X-Amz-Object-Lock-Mode");
  const char *until = meta2(v, BUCKETS_LOCK_UNTIL_META, "X-Amz-Object-Lock-Retain-Until-Date");
  long long sec;
  long nsec;
  if (mode && until && buckets_time_parse_rfc3339(until, &sec, &nsec) && sec > now) {
    if (strcasecmp(mode, "COMPLIANCE") == 0)
      count(&c->compliance, size);
    else if (strcasecmp(mode, "GOVERNANCE") == 0)
      count(&c->governance, size);
    else
      sec = 0;
    if (sec > c->latest_until) c->latest_until = sec;
  }
  const char *hold = meta2(v, BUCKETS_LOCK_HOLD_META, "X-Amz-Object-Lock-Legal-Hold");
  if (hold && strcasecmp(hold, "ON") == 0) count(&c->legal_hold, size);
}

static void put_count(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key,
                      const buckets_compliance_count *c) {
  yyjson_mut_val *x = yyjson_mut_obj_add_obj(d, o, key);
  yyjson_mut_obj_add_uint(d, x, "versions", c->versions);
  yyjson_mut_obj_add_uint(d, x, "bytes", c->bytes);
}

static const struct {
  const char *key;
  size_t off;
} k_fields[] = {
    {"sseS3", offsetof(buckets_compliance_counts, sse_s3)},
    {"sseKms", offsetof(buckets_compliance_counts, sse_kms)},
    {"sseC", offsetof(buckets_compliance_counts, sse_c)},
    {"unencrypted", offsetof(buckets_compliance_counts, plain)},
    {"governance", offsetof(buckets_compliance_counts, governance)},
    {"compliance", offsetof(buckets_compliance_counts, compliance)},
    {"legalHold", offsetof(buckets_compliance_counts, legal_hold)},
    {"chacha20", offsetof(buckets_compliance_counts, chacha20)},
};

void buckets_compliance_json(const buckets_compliance_bucket *b, size_t n, int64_t scanned_at,
                             buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *bs;
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_sint(d, root, "scannedAt", scanned_at);
  bs = yyjson_mut_obj_add_obj(d, root, "buckets");
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *o = yyjson_mut_obj(d);
    yyjson_mut_obj_add(bs, yyjson_mut_strcpy(d, b[i].name), o);
    for (size_t f = 0; f < sizeof(k_fields) / sizeof(k_fields[0]); f++)
      put_count(d, o, k_fields[f].key,
                (const buckets_compliance_count *)((const char *)&b[i].c + k_fields[f].off));
    yyjson_mut_obj_add_sint(d, o, "latestRetainUntil", b[i].c.latest_until);
  }
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  if (j) buckets_buf_append(out, j, len);
  free(j);
  yyjson_mut_doc_free(d);
}

bool buckets_compliance_lookup(const char *json, size_t len, const char *bucket,
                               buckets_compliance_counts *out, int64_t *scanned_at) {
  memset(out, 0, sizeof(*out));
  *scanned_at = 0;
  yyjson_doc *d = json && len ? yyjson_read(json, len, 0) : NULL;
  yyjson_val *root = yyjson_doc_get_root(d);
  *scanned_at = yyjson_get_sint(yyjson_obj_get(root, "scannedAt"));
  yyjson_val *o = yyjson_obj_get(yyjson_obj_get(root, "buckets"), bucket);
  if (o) {
    for (size_t f = 0; f < sizeof(k_fields) / sizeof(k_fields[0]); f++) {
      yyjson_val *x = yyjson_obj_get(o, k_fields[f].key);
      buckets_compliance_count *c = (buckets_compliance_count *)((char *)out + k_fields[f].off);
      c->versions = yyjson_get_uint(yyjson_obj_get(x, "versions"));
      c->bytes = yyjson_get_uint(yyjson_obj_get(x, "bytes"));
    }
    out->latest_until = yyjson_get_sint(yyjson_obj_get(o, "latestRetainUntil"));
  }
  yyjson_doc_free(d);
  return o != NULL;
}
