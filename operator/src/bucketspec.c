/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucketspec.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"

#define S3NS "http://s3.amazonaws.com/doc/2006-03-01/"

BUCKETS_PRINTF(3, 4) static bool fail(char *err, size_t errlen, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, errlen, fmt, ap);
  va_end(ap);
  return false;
}

bool bspec_size(const char *s, uint64_t *out) {
  *out = 0;
  if (!s || !*s) return true;
  char *end;
  double v = strtod(s, &end);
  if (end == s || v < 0) return false;
  static const struct {
    const char *suffix;
    double mul;
  } units[] = {{"", 1},
               {"K", 1e3},
               {"M", 1e6},
               {"G", 1e9},
               {"T", 1e12},
               {"P", 1e15},
               {"Ki", 1024.0},
               {"Mi", 1048576.0},
               {"Gi", 1073741824.0},
               {"Ti", 1099511627776.0},
               {"Pi", 1125899906842624.0},
               {"KiB", 1024.0},
               {"MiB", 1048576.0},
               {"GiB", 1073741824.0},
               {"TiB", 1099511627776.0},
               {"B", 1}};
  for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
    if (strcmp(end, units[i].suffix) == 0) {
      *out = (uint64_t)(v * units[i].mul);
      return true;
    }
  }
  return false;
}

static bool is_uint(yyjson_val *v) {
  return yyjson_is_uint(v) || (yyjson_is_sint(v) && yyjson_get_sint(v) >= 0);
}

bool bspec_check(yyjson_val *spec, char *err, size_t errlen) {
  yyjson_val *v;
  if ((v = yyjson_obj_get(spec, "versioning")) && !yyjson_is_bool(v) && !yyjson_is_null(v))
    return fail(err, errlen, "versioning is true or false");
  if ((v = yyjson_obj_get(spec, "objectLock")) && !yyjson_is_bool(v) && !yyjson_is_null(v)) {
    if (!yyjson_is_obj(v)) return fail(err, errlen, "objectLock is true, or {mode, days | years}");
    const char *mode = yyjson_get_str(yyjson_obj_get(v, "mode"));
    yyjson_val *days = yyjson_obj_get(v, "days"), *years = yyjson_obj_get(v, "years");
    if (mode || days || years) {
      if (!mode || (strcmp(mode, "GOVERNANCE") != 0 && strcmp(mode, "COMPLIANCE") != 0))
        return fail(err, errlen, "objectLock.mode is GOVERNANCE or COMPLIANCE");
      if (!days == !years) return fail(err, errlen, "objectLock needs days or years (one of them)");
      if (!is_uint(days ? days : years) || yyjson_get_uint(days ? days : years) == 0)
        return fail(err, errlen, "objectLock.%s must be a positive whole number", days ? "days" : "years");
    }
  }
  yyjson_val *lock = yyjson_obj_get(spec, "objectLock"), *ver = yyjson_obj_get(spec, "versioning");
  if ((yyjson_is_obj(lock) || yyjson_get_bool(lock)) && yyjson_is_bool(ver) && !yyjson_get_bool(ver))
    return fail(err, errlen, "object lock keeps versions, so versioning cannot be false with it");
  if ((v = yyjson_obj_get(spec, "quota")) && !yyjson_is_null(v)) {
    uint64_t b;
    if (!yyjson_is_str(v) || !bspec_size(yyjson_get_str(v), &b))
      return fail(err, errlen, "quota is a size such as 100Gi or 1T (\"%s\")",
                  yyjson_get_str(v) ? yyjson_get_str(v) : "");
  }
  if ((v = yyjson_obj_get(spec, "encryption")) && !yyjson_is_null(v) && !bspec_empty(v)) {
    const char *key = yyjson_get_str(yyjson_obj_get(v, "kmsKey")),
               *sse = yyjson_get_str(yyjson_obj_get(v, "sse"));
    if (!yyjson_is_obj(v) || !key == !sse)
      return fail(err, errlen, "encryption is {kmsKey: <key>}, {sse: S3}, or {} for none");
    if (sse && strcmp(sse, "S3") != 0) return fail(err, errlen, "encryption.sse is S3");
  }
  if ((v = yyjson_obj_get(spec, "lifecycle")) && !yyjson_is_null(v)) {
    if (!yyjson_is_arr(v)) return fail(err, errlen, "lifecycle is a list of rules");
    size_t i, max;
    yyjson_val *r;
    yyjson_arr_foreach(v, i, max, r) {
      const char *id = yyjson_get_str(yyjson_obj_get(r, "id"));
      if (!id || !*id) return fail(err, errlen, "lifecycle rule %zu needs an id", i + 1);
      for (size_t j = 0; j < i; j++)
        if (strcmp(yyjson_get_str(yyjson_obj_get(yyjson_arr_get(v, j), "id")), id) == 0)
          return fail(err, errlen, "lifecycle rule id %s is used twice", id);
      static const char *const days[] = {"expireDays", "noncurrentExpireDays", "abortIncompleteUploadDays"};
      bool any = yyjson_get_bool(yyjson_obj_get(r, "expireDeleteMarkers"));
      for (size_t k = 0; k < 3; k++) {
        yyjson_val *d = yyjson_obj_get(r, days[k]);
        if (!d) continue;
        if (!is_uint(d) || yyjson_get_uint(d) == 0)
          return fail(err, errlen, "lifecycle rule %s: %s must be a positive whole number", id, days[k]);
        any = true;
      }
      if (!any)
        return fail(err, errlen, "lifecycle rule %s does nothing: give it expireDays or another action", id);
      if (yyjson_obj_get(r, "expireDays") && yyjson_get_bool(yyjson_obj_get(r, "expireDeleteMarkers")))
        return fail(err, errlen,
                    "lifecycle rule %s: expireDeleteMarkers cannot go with expireDays in one rule (S3's "
                    "rule): use two",
                    id);
    }
  }
  if ((v = yyjson_obj_get(spec, "replication")) && !yyjson_is_null(v) && !bspec_empty(v)) {
    yyjson_val *t = yyjson_obj_get(v, "target");
    const char *cl = yyjson_get_str(yyjson_obj_get(t, "cluster")),
               *ep = yyjson_get_str(yyjson_obj_get(t, "endpoint"));
    if (!yyjson_is_obj(v) || !yyjson_is_obj(t) || !cl == !ep)
      return fail(
          err, errlen,
          "replication.target is {cluster} or {endpoint, bucket, credsSecret} ({} for no replication)");
    if (ep) {
      if (strncmp(ep, "http://", 7) != 0 && strncmp(ep, "https://", 8) != 0)
        return fail(err, errlen, "replication.target.endpoint is a URL, such as https://s3.example.com");
      if (!yyjson_get_str(yyjson_obj_get(t, "bucket")) ||
          !yyjson_get_str(yyjson_obj_get(yyjson_obj_get(t, "credsSecret"), "name")))
        return fail(err, errlen, "replication.target with an endpoint needs bucket and credsSecret.name");
    }
    if (!yyjson_get_bool(yyjson_obj_get(spec, "versioning")))
      return fail(err, errlen, "replication needs versioning: true (and the target keeps versions too)");
  }
  return true;
}

/* ---- the hash -------------------------------------------------------------------------- */

static void canon(yyjson_val *v, buckets_buf *out) {
  if (yyjson_is_obj(v)) { /* keys sorted */
    size_t n = yyjson_obj_size(v), i, max;
    const char **keys = buckets_xcalloc(n ? n : 1, sizeof(char *));
    yyjson_val *k, *x;
    size_t m = 0;
    yyjson_obj_foreach(v, i, max, k, x) keys[m++] = yyjson_get_str(k);
    for (size_t a = 1; a < m; a++)
      for (size_t b = a; b > 0 && strcmp(keys[b - 1], keys[b]) > 0; b--) {
        const char *t = keys[b];
        keys[b] = keys[b - 1], keys[b - 1] = t;
      }
    buckets_buf_append_char(out, '{');
    for (size_t a = 0; a < m; a++) {
      buckets_buf_appendf(out, "%s\"%s\":", a ? "," : "", keys[a]);
      canon(yyjson_obj_get(v, keys[a]), out);
    }
    buckets_buf_append_char(out, '}');
    free(keys);
  } else if (yyjson_is_arr(v)) {
    buckets_buf_append_char(out, '[');
    size_t i, max;
    yyjson_val *x;
    yyjson_arr_foreach(v, i, max, x) {
      if (i) buckets_buf_append_char(out, ',');
      canon(x, out);
    }
    buckets_buf_append_char(out, ']');
  } else {
    size_t n;
    char *s = yyjson_val_write(v, 0, &n);
    if (s) buckets_buf_append(out, s, n);
    free(s);
  }
}

void bspec_hash(yyjson_val *spec, char out[17]) {
  static const char *const managed[] = {"name",       "versioning", "objectLock", "quota",
                                        "encryption", "lifecycle",  "replication"};
  buckets_buf b = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < sizeof(managed) / sizeof(managed[0]); i++) {
    yyjson_val *v = yyjson_obj_get(spec, managed[i]);
    buckets_buf_appendf(&b, "%s=", managed[i]);
    if (v)
      canon(v, &b);
    else
      buckets_buf_append_c(&b, "-");
    buckets_buf_append_char(&b, ';');
  }
  uint8_t h[32];
  buckets_sha256(b.data, b.len, h);
  buckets_hex_encode(h, 8, out);
  out[16] = '\0';
  buckets_buf_free(&b);
}

/* ---- the documents --------------------------------------------------------------------------- */

static void xml_text(buckets_buf *out, const char *s) {
  for (; *s; s++) {
    if (*s == '&')
      buckets_buf_append_c(out, "&amp;");
    else if (*s == '<')
      buckets_buf_append_c(out, "&lt;");
    else if (*s == '>')
      buckets_buf_append_c(out, "&gt;");
    else
      buckets_buf_append_char(out, *s);
  }
}

void bspec_versioning_xml(bool on, buckets_buf *out) {
  buckets_buf_appendf(
      out, "<VersioningConfiguration xmlns=\"" S3NS "\"><Status>%s</Status></VersioningConfiguration>",
      on ? "Enabled" : "Suspended");
}

bool bspec_object_lock_xml(yyjson_val *lock, buckets_buf *out) {
  buckets_buf_append_c(
      out, "<ObjectLockConfiguration xmlns=\"" S3NS "\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>");
  const char *mode = yyjson_get_str(yyjson_obj_get(lock, "mode"));
  if (mode) {
    yyjson_val *d = yyjson_obj_get(lock, "days");
    buckets_buf_appendf(out, "<Rule><DefaultRetention><Mode>%s</Mode><%s>%llu</%s></DefaultRetention></Rule>",
                        mode, d ? "Days" : "Years",
                        (unsigned long long)yyjson_get_uint(d ? d : yyjson_obj_get(lock, "years")),
                        d ? "Days" : "Years");
  }
  buckets_buf_append_c(out, "</ObjectLockConfiguration>");
  return mode != NULL;
}

void bspec_quota_json(uint64_t bytes, buckets_buf *out) {
  buckets_buf_appendf(out, "{\"quota\":%llu,\"size\":%llu,\"quotatype\":\"hard\"}", (unsigned long long)bytes,
                      (unsigned long long)bytes);
}

bool bspec_empty(yyjson_val *v) { return yyjson_is_null(v) || (yyjson_is_obj(v) && !yyjson_obj_size(v)); }

bool bspec_encryption_xml(yyjson_val *enc, buckets_buf *out) {
  if (!yyjson_is_obj(enc) || bspec_empty(enc)) return false;
  const char *key = yyjson_get_str(yyjson_obj_get(enc, "kmsKey"));
  buckets_buf_append_c(out, "<ServerSideEncryptionConfiguration xmlns=\"" S3NS
                            "\"><Rule><ApplyServerSideEncryptionByDefault>");
  if (key) {
    buckets_buf_append_c(out, "<SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>");
    xml_text(out, key);
    buckets_buf_append_c(out, "</KMSMasterKeyID>");
  } else {
    buckets_buf_append_c(out, "<SSEAlgorithm>AES256</SSEAlgorithm>");
  }
  buckets_buf_append_c(out,
                       "</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>");
  return true;
}

bool bspec_lifecycle_xml(yyjson_val *rules, buckets_buf *out) {
  if (!yyjson_arr_size(rules)) return false;
  buckets_buf_append_c(out, "<LifecycleConfiguration xmlns=\"" S3NS "\">");
  size_t i, max;
  yyjson_val *r;
  yyjson_arr_foreach(rules, i, max, r) {
    buckets_buf_append_c(out, "<Rule><ID>");
    xml_text(out, yyjson_get_str(yyjson_obj_get(r, "id")));
    buckets_buf_append_c(out, "</ID><Status>Enabled</Status><Filter><Prefix>");
    const char *prefix = yyjson_get_str(yyjson_obj_get(r, "prefix"));
    xml_text(out, prefix ? prefix : "");
    buckets_buf_append_c(out, "</Prefix></Filter>");
    yyjson_val *exp = yyjson_obj_get(r, "expireDays");
    if (exp)
      buckets_buf_appendf(out, "<Expiration><Days>%llu</Days></Expiration>",
                          (unsigned long long)yyjson_get_uint(exp));
    else if (yyjson_get_bool(yyjson_obj_get(r, "expireDeleteMarkers")))
      buckets_buf_append_c(
          out, "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>");
    yyjson_val *nc = yyjson_obj_get(r, "noncurrentExpireDays");
    if (nc)
      buckets_buf_appendf(
          out,
          "<NoncurrentVersionExpiration><NoncurrentDays>%llu</NoncurrentDays></NoncurrentVersionExpiration>",
          (unsigned long long)yyjson_get_uint(nc));
    yyjson_val *ab = yyjson_obj_get(r, "abortIncompleteUploadDays");
    if (ab)
      buckets_buf_appendf(out,
                          "<AbortIncompleteMultipartUpload><DaysAfterInitiation>%llu</DaysAfterInitiation>"
                          "</AbortIncompleteMultipartUpload>",
                          (unsigned long long)yyjson_get_uint(ab));
    buckets_buf_append_c(out, "</Rule>");
  }
  buckets_buf_append_c(out, "</LifecycleConfiguration>");
  return true;
}

const char *const bspec_versioning_tags[] = {"Status", NULL};
const char *const bspec_object_lock_tags[] = {"ObjectLockEnabled", "Mode", "Days", "Years", NULL};
const char *const bspec_encryption_tags[] = {"SSEAlgorithm", "KMSMasterKeyID", NULL};
const char *const bspec_replication_tags[] = {"ID", "Status", "Priority", "Bucket", "Prefix", NULL};
const char *const bspec_lifecycle_tags[] = {
    "ID", "Status", "Prefix", "Days", "ExpiredObjectDeleteMarker", "NoncurrentDays", "DaysAfterInitiation",
    NULL};

void bspec_xml_sig(const char *xml, size_t n, const char *const *tags, buckets_buf *out) {
  for (size_t i = 0; i < n; i++) {
    if (xml[i] != '<' || i + 1 >= n || xml[i + 1] == '/' || xml[i + 1] == '?' || xml[i + 1] == '!') continue;
    size_t s = i + 1, e = s;
    while (e < n && xml[e] != '>' && xml[e] != ' ' && xml[e] != '/') e++;
    if (e >= n || xml[e] == '/') continue;
    const char *const *t;
    for (t = tags; *t; t++)
      if (strlen(*t) == e - s && memcmp(*t, xml + s, e - s) == 0) break;
    if (!*t) continue;
    const char *gt = memchr(xml + e, '>', n - e);
    if (!gt || gt[-1] == '/') continue;
    size_t v = (size_t)(gt - xml) + 1, ve = v;
    while (ve < n && xml[ve] != '<') ve++;
    if (ve + 1 >= n || xml[ve + 1] != '/') continue; /* not a text element */
    while (v < ve && isspace((unsigned char)xml[v])) v++;
    while (ve > v && isspace((unsigned char)xml[ve - 1])) ve--;
    buckets_buf_appendf(out, "%s=", *t);
    buckets_buf_append(out, xml + v, ve - v);
    buckets_buf_append_char(out, ';');
  }
}

static const char *on(yyjson_val *repl, const char *key, bool dflt) {
  yyjson_val *v = yyjson_obj_get(repl, key);
  return (v ? yyjson_get_bool(v) : dflt) ? "Enabled" : "Disabled";
}

/* In the order bucketsd writes it back, so the signatures compare; with replica modifications on, as
 * bucketsd (and MinIO) default them. */
void bspec_replication_xml(yyjson_val *repl, const char *arn, buckets_buf *out) {
  buckets_buf_appendf(
      out,
      "<ReplicationConfiguration xmlns=\"" S3NS
      "\"><Rule><ID>buckets-operator</ID><Status>Enabled</Status>"
      "<Priority>1</Priority><DeleteMarkerReplication><Status>%s</Status></DeleteMarkerReplication>"
      "<DeleteReplication><Status>%s</Status></DeleteReplication><Destination><Bucket>",
      on(repl, "deleteMarkers", true), on(repl, "deletes", true));
  xml_text(out, arn);
  buckets_buf_appendf(
      out,
      "</Bucket></Destination><SourceSelectionCriteria><ReplicaModifications><Status>Enabled</Status>"
      "</ReplicaModifications></SourceSelectionCriteria><Filter><Prefix></Prefix></Filter>"
      "<ExistingObjectReplication><Status>%s</Status></ExistingObjectReplication></Rule>"
      "<Role></Role></ReplicationConfiguration>",
      on(repl, "existingObjects", true));
}

void bspec_replication_policy(const char *bucket, buckets_buf *out) {
  /* MinIO's documented policy for a replication target's user */
  buckets_buf_appendf(
      out,
      "{\"Version\":\"2012-10-17\",\"Statement\":["
      "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetReplicationConfiguration\",\"s3:ListBucket\","
      "\"s3:ListBucketMultipartUploads\",\"s3:GetBucketLocation\",\"s3:GetBucketVersioning\","
      "\"s3:GetBucketObjectLockConfiguration\",\"s3:GetEncryptionConfiguration\"],"
      "\"Resource\":[\"arn:aws:s3:::%s\"]},"
      "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetReplicationConfiguration\",\"s3:ReplicateTags\","
      "\"s3:AbortMultipartUpload\",\"s3:GetObject\",\"s3:GetObjectVersion\",\"s3:GetObjectVersionTagging\","
      "\"s3:PutObject\",\"s3:PutObjectRetention\",\"s3:PutBucketObjectLockConfiguration\","
      "\"s3:PutObjectLegalHold\",\"s3:DeleteObject\",\"s3:ReplicateObject\",\"s3:ReplicateDelete\"],"
      "\"Resource\":[\"arn:aws:s3:::%s/*\"]}]}",
      bucket, bucket);
}

void bspec_replication_user(const char *ns, const char *cluster, const char *bucket,
                            const char *target_cluster, const char *target_bucket, const char *target_root_sk,
                            char ak[21], char sk[41]) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "%s/%s/%s->%s/%s", ns, cluster, bucket, target_cluster, target_bucket);
  uint8_t h[32];
  buckets_sha256(b.data, b.len, h);
  memcpy(ak, "bkrepl", 6);
  buckets_hex_encode(h, 7, ak + 6);
  ak[20] = '\0';
  buckets_buf_reset(&b);
  buckets_buf_appendf(&b, "buckets-replication:%s", ak);
  buckets_hmac_sha256(target_root_sk, strlen(target_root_sk), b.data, b.len, h);
  buckets_hex_encode(h, 20, sk);
  sk[40] = '\0';
  buckets_buf_free(&b);
}
