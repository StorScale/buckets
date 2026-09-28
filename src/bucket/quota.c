/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/quota.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yyjson.h>

static bool get_uint(yyjson_val *v, const char *field, uint64_t *out, char *err, size_t errlen) {
  if (!v || yyjson_is_null(v)) return true;
  if (yyjson_is_uint(v)) {
    *out = yyjson_get_uint(v);
    return true;
  }
  const char *kind = yyjson_is_str(v) ? "string" : yyjson_is_bool(v) ? "bool" : yyjson_is_arr(v) ? "array"
                     : yyjson_is_obj(v) ? "object" : "number";
  if (yyjson_is_num(v)) snprintf(err, errlen, "json: cannot unmarshal number %g into Go struct field BucketQuota.%s of type uint64",
                                 yyjson_get_num(v), field);
  else snprintf(err, errlen, "json: cannot unmarshal %s into Go struct field BucketQuota.%s of type uint64", kind, field);
  return false;
}

bool buckets_quota_parse(const char *json, size_t len, buckets_quota *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  yyjson_read_err re;
  yyjson_doc *d = yyjson_read_opts((char *)json, len, 0, NULL, &re);
  if (!d) {
    /* encoding/json's wording */
    if (!len || re.code == YYJSON_READ_ERROR_UNEXPECTED_END || re.code == YYJSON_READ_ERROR_EMPTY_CONTENT)
      snprintf(err, errlen, "unexpected end of JSON input");
    else if (re.pos < len)
      snprintf(err, errlen, "invalid character '%c' looking for beginning of value", json[re.pos]);
    else snprintf(err, errlen, "%s", re.msg);
    return false;
  }
  yyjson_val *root = yyjson_doc_get_root(d);
  bool ok = true;
  if (yyjson_is_obj(root)) {
    /* encoding/json: exact key first, else a case-insensitive match; the last one wins */
    yyjson_obj_iter it = yyjson_obj_iter_with(root);
    yyjson_val *k;
    while (ok && (k = yyjson_obj_iter_next(&it))) {
      const char *name = yyjson_get_str(k);
      yyjson_val *v = yyjson_obj_iter_get_val(k);
      if (strcasecmp(name, "quota") == 0) ok = get_uint(v, "quota", &out->quota, err, errlen);
      else if (strcasecmp(name, "size") == 0) ok = get_uint(v, "size", &out->size, err, errlen);
      else if (strcasecmp(name, "rate") == 0) ok = get_uint(v, "rate", &out->rate, err, errlen);
      else if (strcasecmp(name, "requests") == 0) ok = get_uint(v, "requests", &out->requests, err, errlen);
      else if (strcasecmp(name, "quotatype") == 0 && !yyjson_is_null(v)) {
        if (!yyjson_is_str(v)) {
          snprintf(err, errlen, "json: cannot unmarshal %s into Go struct field BucketQuota.quotatype of type madmin.QuotaType",
                   yyjson_is_num(v) ? "number" : yyjson_is_bool(v) ? "bool" : yyjson_is_arr(v) ? "array" : "object");
          ok = false;
        } else {
          snprintf(out->type, sizeof(out->type), "%s", yyjson_get_str(v));
        }
      }
    }
  } else if (!yyjson_is_null(root)) {
    const char *kind = yyjson_is_str(root) ? "string" : yyjson_is_num(root) ? "number" : yyjson_is_bool(root) ? "bool" : "array";
    snprintf(err, errlen, "json: cannot unmarshal %s into Go value of type madmin.BucketQuota", kind);
    ok = false;
  }
  yyjson_doc_free(d);
  if (ok && out->quota > 0 && strcmp(out->type, "hard") != 0) {
    if (strcmp(out->type, "fifo") == 0) snprintf(err, errlen, "invalid quota type 'fifo'");
    else snprintf(err, errlen, "Invalid quota config &madmin.BucketQuota{Quota:0x%llx, Size:0x%llx, Rate:0x%llx, Requests:0x%llx, Type:\"%s\"}",
                  (unsigned long long)out->quota, (unsigned long long)out->size, (unsigned long long)out->rate,
                  (unsigned long long)out->requests, out->type);
    ok = false;
  }
  return ok;
}

void buckets_quota_json(const buckets_quota *q, buckets_buf *out) {
  buckets_buf_appendf(out, "{\"quota\":%llu,\"size\":%llu,\"rate\":%llu,\"requests\":%llu", (unsigned long long)q->quota,
                      (unsigned long long)q->size, (unsigned long long)q->rate, (unsigned long long)q->requests);
  if (*q->type) {
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *s = yyjson_mut_str(d, q->type);
    size_t n;
    char *enc = yyjson_mut_val_write(s, 0, &n);
    buckets_buf_appendf(out, ",\"quotatype\":%s", enc ? enc : "\"\"");
    free(enc);
    yyjson_mut_doc_free(d);
  }
  buckets_buf_append_c(out, "}");
}

uint64_t buckets_quota_hard_limit(const buckets_quota *q) {
  if (strcmp(q->type, "hard") != 0) return 0;
  return q->size ? q->size : q->quota;
}

bool buckets_quota_exceeded(const buckets_quota *q, int64_t size, uint64_t used) {
  if (size < 0) return false;
  uint64_t limit = buckets_quota_hard_limit(q);
  if (!limit) return false;
  if ((uint64_t)size >= limit) return true; /* the object alone is too big */
  return used > 0 && used + (uint64_t)size >= limit;
}
