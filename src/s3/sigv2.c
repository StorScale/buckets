/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/sigv2.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/base64.h"
#include "crypto/sha1.h"

/* Sub-resources included in the V2 canonical resource, in this order. */
static const char *const k_resources[] = {
    "acl",           "cors",          "delete",       "encryption",
    "legal-hold",    "lifecycle",     "location",     "logging",
    "notification",  "partNumber",    "policy",       "requestPayment",
    "response-cache-control", "response-content-disposition", "response-content-encoding",
    "response-content-language", "response-content-type", "response-expires",
    "retention",     "select",        "select-type",  "tagging",
    "torrent",       "uploadId",      "uploads",      "versionId",
    "versioning",    "versions",      "website",
};

void buckets_sigv2_sign(const char *secret, const char *sts, size_t n, char *out) {
  uint8_t mac[BUCKETS_SHA1_LEN];
  buckets_hmac_sha1(secret, strlen(secret), sts, n, mac);
  buckets_base64_encode(mac, sizeof(mac), out);
}

/* compareSignatureV2: decode both base64 values, compare the bytes. */
static bool sig_equal(buckets_str got, const char *want) {
  uint8_t a[32], b[32];
  long an = got.n % 4 == 0 && got.n <= 40 ? buckets_base64_decode(got.p, got.n, a) : -1;
  long bn = buckets_base64_decode(want, strlen(want), b);
  if (an < 0 || bn < 0 || an != bn) return false;
  uint8_t diff = 0;
  for (long i = 0; i < an; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

/* url.QueryUnescape of each "&"-separated piece, preserving order. */
typedef struct {
  char **items;
  size_t n;
} pieces;

static void pieces_free(pieces *p) {
  for (size_t i = 0; i < p->n; i++) free(p->items[i]);
  free(p->items);
}

static bool unescape_queries(buckets_str raw, pieces *out) {
  memset(out, 0, sizeof(*out));
  if (raw.n == 0) {
    /* strings.Split("", "&") yields one empty piece. */
    out->items = buckets_xcalloc(1, sizeof(char *));
    out->items[0] = buckets_xstrdup("");
    out->n = 1;
    return true;
  }
  buckets_str rest = raw, part;
  for (bool more = true; more;) {
    more = buckets_str_cut(rest, '&', &part, &rest);
    char *dec = buckets_xmalloc(part.n + 1);
    long n = buckets_url_decode(part, dec, true);
    if (n < 0) {
      free(dec);
      pieces_free(out);
      return false;
    }
    dec[n] = '\0';
    out->items = buckets_xrealloc(out->items, (out->n + 1) * sizeof(char *));
    out->items[out->n++] = dec;
  }
  return true;
}

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* canonicalizedAmzHeadersV2: lower-cased x-amz-* headers, values joined with ','. */
static void amz_headers(const buckets_http_request *req, buckets_buf *out) {
  char **keys = NULL;
  size_t nkeys = 0;
  for (size_t i = 0; i < req->nheaders; i++) {
    buckets_str name = req->headers[i].name;
    if (name.n < 6) continue;
    char *lk = buckets_str_dup(name);
    for (char *c = lk; *c; c++) *c = (char)tolower((unsigned char)*c);
    if (strncmp(lk, "x-amz-", 6) != 0) {
      free(lk);
      continue;
    }
    bool dup = false;
    for (size_t k = 0; k < nkeys; k++) dup |= strcmp(keys[k], lk) == 0;
    if (dup) {
      free(lk);
      continue;
    }
    keys = buckets_xrealloc(keys, (nkeys + 1) * sizeof(char *));
    keys[nkeys++] = lk;
  }
  if (nkeys) qsort(keys, nkeys, sizeof(char *), str_cmp);
  for (size_t k = 0; k < nkeys; k++) {
    if (k) buckets_buf_append_char(out, '\n');
    buckets_buf_appendf(out, "%s:", keys[k]);
    bool first = true;
    for (size_t i = 0; i < req->nheaders; i++) {
      if (!buckets_str_ieq_c(req->headers[i].name, keys[k])) continue;
      if (!first) buckets_buf_append_char(out, ',');
      buckets_buf_append_str(out, req->headers[i].value);
      first = false;
    }
    free(keys[k]);
  }
  free(keys);
}

/* getStringToSignV2 */
static void string_to_sign(const buckets_http_request *req, const pieces *queries, const char *expires,
                           buckets_buf *out) {
  buckets_str md5 = buckets_http_header_get(req, "Content-MD5");
  buckets_str ctype = buckets_http_header_get(req, "Content-Type");
  buckets_str date = expires ? buckets_str_c(expires) : buckets_http_header_get(req, "Date");
  buckets_buf hdrs = BUCKETS_BUF_INIT;
  amz_headers(req, &hdrs);
  if (hdrs.len) buckets_buf_append_char(&hdrs, '\n');
  buckets_buf_appendf(out, BUCKETS_STR_FMT "\n" BUCKETS_STR_FMT "\n" BUCKETS_STR_FMT "\n" BUCKETS_STR_FMT "\n",
                      BUCKETS_STR_ARG(req->method), md5.p ? (int)md5.n : 0, md5.p ? md5.p : "",
                      ctype.p ? (int)ctype.n : 0, ctype.p ? ctype.p : "", date.p ? (int)date.n : 0,
                      date.p ? date.p : "");
  buckets_buf_append(out, hdrs.data, hdrs.len);
  buckets_buf_free(&hdrs);

  /* canonicalizedResourceV2: raw path + recognised sub-resources. */
  buckets_buf_append_str(out, req->path);
  bool first = true;
  for (size_t r = 0; r < BUCKETS_ARRAY_LEN(k_resources); r++) {
    const char *val = NULL;
    bool found = false;
    for (size_t i = 0; i < queries->n; i++) { /* last occurrence wins, like the Go map */
      const char *q = queries->items[i];
      size_t kl = strcspn(q, "=");
      if (kl == strlen(k_resources[r]) && strncmp(q, k_resources[r], kl) == 0) {
        found = true;
        val = q[kl] == '=' ? q + kl + 1 : "";
      }
    }
    if (!found) continue;
    buckets_buf_append_char(out, first ? '?' : '&');
    first = false;
    buckets_buf_append_c(out, k_resources[r]);
    if (*val) buckets_buf_appendf(out, "=%s", val);
  }
}

static void fill(buckets_sigv4_result *out, buckets_str ak) {
  memset(out, 0, sizeof(*out));
  snprintf(out->access_key, sizeof(out->access_key), BUCKETS_STR_FMT, BUCKETS_STR_ARG(ak));
}

buckets_s3_error buckets_sigv2_verify_header(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                             buckets_sigv4_result *out) {
  buckets_str auth = buckets_http_header_get(req, "Authorization");
  if (!auth.p || auth.n == 0) return BUCKETS_ERR_AUTH_HEADER_EMPTY;
  if (!buckets_str_has_prefix(auth, "AWS")) return BUCKETS_ERR_SIGNATURE_VERSION_NOT_SUPPORTED;
  /* strings.Split(auth, " ") must give exactly two fields. */
  buckets_str scheme, rest;
  if (!buckets_str_cut(auth, ' ', &scheme, &rest) || memchr(rest.p, ' ', rest.n)) return BUCKETS_ERR_MISSING_FIELDS;
  buckets_str kv = buckets_str_trim(rest), ak, sig;
  if (!buckets_str_cut(kv, ':', &ak, &sig) || memchr(sig.p, ':', sig.n)) return BUCKETS_ERR_MISSING_FIELDS;
  if (ak.n < 3) return BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
  const char *secret = cfg->lookup(cfg->lookup_ud, ak);
  if (!secret) return BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
  if (!buckets_str_eq_c(scheme, "AWS")) return BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;

  pieces q;
  if (!unescape_queries(req->query, &q)) return BUCKETS_ERR_INVALID_QUERY_PARAMS;
  buckets_buf sts = BUCKETS_BUF_INIT;
  string_to_sign(req, &q, NULL, &sts);
  pieces_free(&q);
  char want[32];
  buckets_sigv2_sign(secret, sts.data, sts.len, want);
  buckets_buf_free(&sts);
  if (!sig_equal(sig, want)) return BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;
  fill(out, ak);
  return BUCKETS_ERR_NONE;
}

buckets_s3_error buckets_sigv2_verify_presigned(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                                buckets_sigv4_result *out) {
  pieces q;
  if (!unescape_queries(req->query, &q)) return BUCKETS_ERR_INVALID_QUERY_PARAMS;
  pieces filtered = {0};
  char *ak = NULL, *sig = NULL, *expires = NULL;
  buckets_s3_error err = BUCKETS_ERR_NONE;
  for (size_t i = 0; i < q.n && !err; i++) {
    char *eq = strchr(q.items[i], '=');
    if (!eq) {
      err = BUCKETS_ERR_INVALID_QUERY_PARAMS;
      break;
    }
    size_t kl = (size_t)(eq - q.items[i]);
    if (kl == 14 && strncmp(q.items[i], "AWSAccessKeyId", 14) == 0) {
      ak = eq + 1;
    } else if (kl == 9 && strncmp(q.items[i], "Signature", 9) == 0) {
      sig = eq + 1;
    } else if (kl == 7 && strncmp(q.items[i], "Expires", 7) == 0) {
      expires = eq + 1;
    } else {
      filtered.items = buckets_xrealloc(filtered.items, (filtered.n + 1) * sizeof(char *));
      filtered.items[filtered.n++] = buckets_xstrdup(q.items[i]);
    }
  }
  if (!err && (!ak || !*ak || !sig || !*sig || !expires || !*expires)) err = BUCKETS_ERR_INVALID_QUERY_PARAMS;
  const char *secret = NULL;
  if (!err) {
    if (strlen(ak) < 3 || !(secret = cfg->lookup(cfg->lookup_ud, buckets_str_c(ak)))) {
      err = BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
    }
  }
  if (!err) {
    char *end;
    long long exp = strtoll(expires, &end, 10);
    if (*end) err = BUCKETS_ERR_MALFORMED_EXPIRES;
    else if (exp < (long long)cfg->now) err = BUCKETS_ERR_EXPIRED_PRESIGN_REQUEST;
  }
  if (!err) {
    buckets_buf sts = BUCKETS_BUF_INIT;
    string_to_sign(req, &filtered, expires, &sts);
    char want[32];
    buckets_sigv2_sign(secret, sts.data, sts.len, want);
    buckets_buf_free(&sts);
    if (!sig_equal(buckets_str_c(sig), want)) err = BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;
    else fill(out, buckets_str_c(ak));
  }
  pieces_free(&filtered);
  pieces_free(&q);
  return err;
}
