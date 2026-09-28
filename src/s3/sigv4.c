/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/sigv4.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/timefmt.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"

#define ACCESS_KEY_MIN_LEN 3

/* ---- classification ------------------------------------------------------ */

buckets_auth_type buckets_auth_classify(const buckets_http_request *req, const buckets_query *q) {
  buckets_str auth = buckets_http_header_get(req, "Authorization");
  if (auth.p) {
    if (buckets_str_has_prefix(auth, BUCKETS_SIGV4_ALGORITHM)) {
      buckets_str sha = buckets_http_header_get(req, "X-Amz-Content-Sha256");
      if (sha.p && buckets_str_has_prefix(sha, "STREAMING-")) return BUCKETS_AUTH_SIGV4_STREAMING;
      return BUCKETS_AUTH_SIGV4_HEADER;
    }
    if (buckets_str_has_prefix(auth, "AWS ")) return BUCKETS_AUTH_SIGV2;
    if (buckets_str_has_prefix(auth, "Bearer ")) return BUCKETS_AUTH_JWT;
    return BUCKETS_AUTH_UNKNOWN;
  }
  if (buckets_query_has(q, "X-Amz-Credential")) return BUCKETS_AUTH_SIGV4_PRESIGNED;
  if (buckets_query_has(q, "AWSAccessKeyId")) return BUCKETS_AUTH_SIGV2_PRESIGNED;
  if (buckets_str_eq_c(req->method, "POST")) {
    buckets_str ct = buckets_http_header_get(req, "Content-Type");
    if (ct.p && buckets_str_has_prefix(ct, "multipart/form-data")) return BUCKETS_AUTH_POST_POLICY;
  }
  return BUCKETS_AUTH_ANONYMOUS;
}

/* ---- canonicalization ---------------------------------------------------- */

static const char k_hex_upper[] = "0123456789ABCDEF";

static bool is_unreserved(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
         c == '_' || c == '.' || c == '~';
}

static void pct_encode(buckets_buf *out, const char *s, size_t n, bool keep_slash) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (is_unreserved(c) || (keep_slash && c == '/')) {
      buckets_buf_append_char(out, (char)c);
    } else {
      char esc[3] = {'%', k_hex_upper[c >> 4], k_hex_upper[c & 15]};
      buckets_buf_append(out, esc, 3);
    }
  }
}

bool buckets_sigv4_canonical_uri(buckets_str raw_path, buckets_buf *out) {
  char *decoded = buckets_xmalloc(raw_path.n + 1);
  long n = buckets_url_decode(raw_path, decoded, false);
  if (n < 0) {
    free(decoded);
    return false;
  }
  pct_encode(out, decoded, (size_t)n, true);
  free(decoded);
  return true;
}

typedef struct {
  const buckets_kv *kv;
  size_t order;
} kv_ref;

static int kv_ref_cmp(const void *a, const void *b) {
  const kv_ref *x = a, *y = b;
  int c = strcmp(x->kv->key, y->kv->key);
  if (c) return c;
  return x->order < y->order ? -1 : (x->order > y->order);
}

void buckets_sigv4_canonical_query(const buckets_query *q, bool skip_signature, buckets_buf *out) {
  kv_ref *refs = buckets_xcalloc(q->n ? q->n : 1, sizeof(kv_ref));
  size_t n = 0;
  for (size_t i = 0; i < q->n; i++) {
    if (skip_signature && strcmp(q->items[i].key, "X-Amz-Signature") == 0) continue;
    refs[n] = (kv_ref){&q->items[i], i};
    n++;
  }
  qsort(refs, n, sizeof(kv_ref), kv_ref_cmp);
  for (size_t i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(out, '&');
    pct_encode(out, refs[i].kv->key, strlen(refs[i].kv->key), false);
    buckets_buf_append_char(out, '=');
    pct_encode(out, refs[i].kv->value, strlen(refs[i].kv->value), false);
  }
  free(refs);
}

/* strings.Join(strings.Fields(v), " ") */
static void append_trim_all(buckets_buf *out, buckets_str v) {
  bool pending_space = false, any = false;
  for (size_t i = 0; i < v.n; i++) {
    if (isspace((unsigned char)v.p[i])) {
      pending_space = any;
      continue;
    }
    if (pending_space) buckets_buf_append_char(out, ' ');
    pending_space = false;
    any = true;
    buckets_buf_append_char(out, v.p[i]);
  }
}

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

typedef struct {
  char **names; /* lowercase, sorted, unique */
  size_t n;
} signed_headers;

static void signed_headers_free(signed_headers *sh) {
  for (size_t i = 0; i < sh->n; i++) free(sh->names[i]);
  free(sh->names);
  memset(sh, 0, sizeof(*sh));
}

static buckets_s3_error parse_signed_headers(buckets_str list, signed_headers *sh) {
  memset(sh, 0, sizeof(*sh));
  buckets_str rest = list, item;
  for (;;) { /* same pieces as Go's strings.Split, including empty ones */
    bool more = buckets_str_cut(rest, ';', &item, &rest);
    char *name = buckets_str_dup(item);
    for (char *c = name; *c; c++) *c = (char)tolower((unsigned char)*c);
    sh->names = buckets_xrealloc(sh->names, (sh->n + 1) * sizeof(char *));
    sh->names[sh->n++] = name;
    if (!more) break;
  }
  qsort(sh->names, sh->n, sizeof(char *), str_cmp);
  size_t w = 0;
  for (size_t i = 0; i < sh->n; i++) {
    if (w && strcmp(sh->names[w - 1], sh->names[i]) == 0) {
      free(sh->names[i]);
      continue;
    }
    sh->names[w++] = sh->names[i];
  }
  sh->n = w;
  for (size_t i = 0; i < sh->n; i++) {
    if (strcmp(sh->names[i], "host") == 0) return BUCKETS_ERR_NONE;
  }
  return BUCKETS_ERR_UNSIGNED_HEADERS;
}

static buckets_s3_error canonical_headers(const buckets_http_request *req, const buckets_query *q,
                                          const signed_headers *sh, buckets_buf *out) {
  for (size_t i = 0; i < sh->n; i++) {
    const char *name = sh->names[i];
    buckets_buf_append_c(out, name);
    buckets_buf_append_char(out, ':');
    bool found = false;
    for (size_t h = 0; h < req->nheaders; h++) {
      if (!buckets_str_ieq_c(req->headers[h].name, name)) continue;
      if (found) buckets_buf_append_char(out, ',');
      append_trim_all(out, req->headers[h].value);
      found = true;
    }
    if (!found) {
      const char *qv = buckets_query_get(q, name);
      if (qv) {
        append_trim_all(out, buckets_str_c(qv));
      } else if (strcmp(name, "expect") == 0) {
        buckets_buf_append_c(out, "100-continue");
      } else if (strcmp(name, "content-length") == 0) {
        buckets_buf_appendf(out, "%lld", (long long)req->body_len);
      } else if (strcmp(name, "transfer-encoding") == 0) {
        /* Go exposes TransferEncoding separately; an absent header joins to "". */
      } else {
        return BUCKETS_ERR_UNSIGNED_HEADERS;
      }
    }
    buckets_buf_append_char(out, '\n');
  }
  return BUCKETS_ERR_NONE;
}

void buckets_sigv4_signing_key(const char *secret, buckets_str date8, buckets_str region, const char *service,
                               uint8_t key[32]) {
  buckets_buf k = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&k, "AWS4%s", secret);
  uint8_t a[32], b[32];
  buckets_hmac_sha256(k.data, k.len, date8.p, date8.n, a);
  buckets_hmac_sha256(a, 32, region.p, region.n, b);
  buckets_hmac_sha256(b, 32, service, strlen(service), a);
  buckets_hmac_sha256(a, 32, "aws4_request", 12, key);
  buckets_buf_free(&k);
}

/* ---- credential scope ---------------------------------------------------- */

typedef struct {
  buckets_str access_key;
  buckets_str date8;
  buckets_str region;
  buckets_str service;
} credential;

static bool region_ok(buckets_str req_region, const char *conf) {
  if (!conf || !*conf) return true;
  const char *want = strcmp(conf, "US") == 0 ? "us-east-1" : conf;
  if (buckets_str_eq_c(req_region, "US")) req_region = buckets_str_c("us-east-1");
  return buckets_str_eq_c(req_region, want);
}

static bool valid_date8(buckets_str d) {
  if (d.n != 8) return false;
  char tmp[BUCKETS_TIME_AMZ_LEN + 1];
  snprintf(tmp, sizeof(tmp), "%.8sT000000Z", d.p);
  time_t t;
  return buckets_time_parse_amz(buckets_str_c(tmp), &t);
}

/* value is everything after "Credential=": AKID[/more]/YYYYMMDD/REGION/SERVICE/aws4_request */
static buckets_s3_error parse_credential(buckets_str value, const buckets_sigv4_config *cfg, credential *c) {
  value = buckets_str_trim(value);
  while (value.n && value.p[value.n - 1] == '/') value.n--;
  /* Walk from the right: the access key itself may contain '/'. */
  buckets_str parts[4];
  buckets_str rest = value;
  for (int i = 3; i >= 0; i--) {
    const char *slash = NULL;
    for (size_t j = rest.n; j > 0; j--) {
      if (rest.p[j - 1] == '/') {
        slash = rest.p + j - 1;
        break;
      }
    }
    if (!slash) return BUCKETS_ERR_CRED_MALFORMED;
    parts[i] = (buckets_str){slash + 1, (size_t)(rest.p + rest.n - slash - 1)};
    rest.n = (size_t)(slash - rest.p);
  }
  c->access_key = rest;
  if (c->access_key.n < ACCESS_KEY_MIN_LEN) return BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
  c->date8 = parts[0];
  if (!valid_date8(c->date8)) return BUCKETS_ERR_MALFORMED_CREDENTIAL_DATE;
  c->region = parts[1];
  if (!region_ok(c->region, cfg->region)) return BUCKETS_ERR_AUTHORIZATION_HEADER_MALFORMED;
  c->service = parts[2];
  if (!buckets_str_eq_c(c->service, cfg->service)) {
    return strcmp(cfg->service, "sts") == 0 ? BUCKETS_ERR_INVALID_SERVICE_STS : BUCKETS_ERR_INVALID_SERVICE_S3;
  }
  if (!buckets_str_eq_c(parts[3], "aws4_request")) return BUCKETS_ERR_INVALID_REQUEST_VERSION;
  return BUCKETS_ERR_NONE;
}

/* ---- verification core --------------------------------------------------- */

static buckets_s3_error compute_and_compare(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                            const buckets_query *q, bool presigned, const credential *cred,
                                            const signed_headers *sh, buckets_str amz_date, const char *secret,
                                            const char *payload_hash, buckets_str provided_sig,
                                            buckets_sigv4_result *out) {
  buckets_buf creq = BUCKETS_BUF_INIT;
  buckets_s3_error err = BUCKETS_ERR_NONE;

  buckets_buf_append_str(&creq, req->method);
  buckets_buf_append_char(&creq, '\n');
  if (!buckets_sigv4_canonical_uri(req->path, &creq)) {
    err = BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;
    goto done;
  }
  buckets_buf_append_char(&creq, '\n');
  buckets_sigv4_canonical_query(q, presigned, &creq);
  buckets_buf_append_char(&creq, '\n');
  if ((err = canonical_headers(req, q, sh, &creq)) != BUCKETS_ERR_NONE) goto done;
  buckets_buf_append_char(&creq, '\n');
  for (size_t i = 0; i < sh->n; i++) {
    if (i) buckets_buf_append_char(&creq, ';');
    buckets_buf_append_c(&creq, sh->names[i]);
  }
  buckets_buf_append_char(&creq, '\n');
  buckets_buf_append_c(&creq, payload_hash);

  uint8_t digest[32];
  char digest_hex[65];
  buckets_sha256(creq.data, creq.len, digest);
  buckets_hex_encode(digest, 32, digest_hex);

  buckets_buf sts = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&sts, "%s\n" BUCKETS_STR_FMT "\n" BUCKETS_STR_FMT "/" BUCKETS_STR_FMT "/%s/aws4_request\n%s",
                      BUCKETS_SIGV4_ALGORITHM, BUCKETS_STR_ARG(amz_date), BUCKETS_STR_ARG(cred->date8),
                      BUCKETS_STR_ARG(cred->region), cfg->service, digest_hex);

  uint8_t key[32], sig[32];
  char sig_hex[65];
  buckets_sigv4_signing_key(secret, cred->date8, cred->region, cfg->service, key);
  buckets_hmac_sha256(key, 32, sts.data, sts.len, sig);
  buckets_hex_encode(sig, 32, sig_hex);
  buckets_buf_free(&sts);

  if (provided_sig.n != 64 || !buckets_ct_equal(sig_hex, provided_sig.p, 64)) {
    err = BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;
  } else {
    snprintf(out->amz_date, sizeof(out->amz_date), BUCKETS_STR_FMT, BUCKETS_STR_ARG(amz_date));
    snprintf(out->scope, sizeof(out->scope), BUCKETS_STR_FMT "/" BUCKETS_STR_FMT "/%s/aws4_request",
             BUCKETS_STR_ARG(cred->date8), BUCKETS_STR_ARG(cred->region), cfg->service);
    memcpy(out->signing_key, key, 32);
    memcpy(out->seed_signature, sig_hex, 65);
  }

done:
  buckets_buf_free(&creq);
  return err;
}

static void fill_result(buckets_sigv4_result *out, const credential *cred, const char *payload_hash) {
  snprintf(out->access_key, sizeof(out->access_key), BUCKETS_STR_FMT, BUCKETS_STR_ARG(cred->access_key));
  snprintf(out->payload_hash, sizeof(out->payload_hash), "%s", payload_hash);
}

buckets_s3_error buckets_sigv4_verify_header(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                             const buckets_query *q, buckets_sigv4_result *out) {
  buckets_str auth = buckets_str_trim(buckets_http_header_get(req, "Authorization"));
  if (auth.n == 0) return BUCKETS_ERR_AUTH_HEADER_EMPTY;
  if (!buckets_str_has_prefix(auth, BUCKETS_SIGV4_ALGORITHM)) return BUCKETS_ERR_SIGNATURE_VERSION_NOT_SUPPORTED;

  /* MinIO strips every space before splitting into the three fields. */
  buckets_buf compact = BUCKETS_BUF_INIT;
  for (size_t i = sizeof(BUCKETS_SIGV4_ALGORITHM) - 1; i < auth.n; i++) {
    if (auth.p[i] != ' ') buckets_buf_append_char(&compact, auth.p[i]);
  }
  buckets_str fields[3], rest = buckets_buf_str(&compact);
  size_t nfields = 0;
  buckets_s3_error err = BUCKETS_ERR_NONE;
  for (bool more = true; more && nfields <= 3;) {
    buckets_str f;
    more = buckets_str_cut(rest, ',', &f, &rest);
    if (nfields < 3) fields[nfields] = f;
    nfields++;
  }
  if (nfields != 3) {
    err = BUCKETS_ERR_MISSING_FIELDS;
    goto done;
  }

  credential cred;
  buckets_str v;
  buckets_str k;
  if (!buckets_str_cut(fields[0], '=', &k, &v)) {
    err = BUCKETS_ERR_MISSING_FIELDS;
    goto done;
  }
  if (!buckets_str_eq_c(k, "Credential")) {
    err = BUCKETS_ERR_MISSING_CRED_TAG;
    goto done;
  }
  if ((err = parse_credential(v, cfg, &cred)) != BUCKETS_ERR_NONE) goto done;

  buckets_str sh_list, sig;
  if (!buckets_str_cut(fields[1], '=', &k, &sh_list) || sh_list.n == 0) {
    err = BUCKETS_ERR_MISSING_FIELDS;
    goto done;
  }
  if (!buckets_str_eq_c(k, "SignedHeaders")) {
    err = BUCKETS_ERR_MISSING_SIGN_HEADERS_TAG;
    goto done;
  }
  if (!buckets_str_cut(fields[2], '=', &k, &sig) || sig.n == 0) {
    err = BUCKETS_ERR_MISSING_FIELDS;
    goto done;
  }
  if (!buckets_str_eq_c(k, "Signature")) {
    err = BUCKETS_ERR_MISSING_SIGN_TAG;
    goto done;
  }

  signed_headers sh;
  if ((err = parse_signed_headers(sh_list, &sh)) != BUCKETS_ERR_NONE) {
    signed_headers_free(&sh);
    goto done;
  }

  const char *secret = cfg->lookup(cfg->lookup_ud, cred.access_key);
  if (!secret) {
    err = BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
    goto free_sh;
  }

  buckets_str date = buckets_http_header_get(req, "X-Amz-Date");
  if (!date.p || date.n == 0) date = buckets_http_header_get(req, "Date");
  if (!date.p || date.n == 0) {
    err = BUCKETS_ERR_MISSING_DATE_HEADER;
    goto free_sh;
  }
  time_t t;
  if (!buckets_time_parse_amz(date, &t)) {
    err = BUCKETS_ERR_MALFORMED_DATE;
    goto free_sh;
  }
  if (t > cfg->now + BUCKETS_MAX_SKEW_SECONDS || t < cfg->now - BUCKETS_MAX_SKEW_SECONDS) {
    err = BUCKETS_ERR_REQUEST_TIME_TOO_SKEWED;
    goto free_sh;
  }

  char payload[80];
  buckets_str ph = buckets_http_header_get(req, "X-Amz-Content-Sha256");
  snprintf(payload, sizeof(payload), BUCKETS_STR_FMT, ph.p ? (int)ph.n : (int)strlen(BUCKETS_EMPTY_SHA256),
           ph.p ? ph.p : BUCKETS_EMPTY_SHA256);

  err = compute_and_compare(cfg, req, q, false, &cred, &sh, date, secret, payload, sig, out);
  if (err == BUCKETS_ERR_NONE) fill_result(out, &cred, payload);

free_sh:
  signed_headers_free(&sh);
done:
  buckets_buf_free(&compact);
  return err;
}

buckets_s3_error buckets_sigv4_verify_presigned(const buckets_sigv4_config *cfg,
                                                const buckets_http_request *req, const buckets_query *q,
                                                buckets_sigv4_result *out) {
  const char *algo = buckets_query_get(q, "X-Amz-Algorithm");
  if (!algo || strcmp(algo, BUCKETS_SIGV4_ALGORITHM) != 0) return BUCKETS_ERR_INVALID_QUERY_SIGNATURE_ALGO;
  const char *cred_s = buckets_query_get(q, "X-Amz-Credential");
  const char *sig_s = buckets_query_get(q, "X-Amz-Signature");
  const char *date_s = buckets_query_get(q, "X-Amz-Date");
  const char *sh_s = buckets_query_get(q, "X-Amz-SignedHeaders");
  const char *exp_s = buckets_query_get(q, "X-Amz-Expires");
  if (!cred_s || !sig_s || !date_s || !sh_s || !exp_s) return BUCKETS_ERR_INVALID_QUERY_PARAMS;

  credential cred;
  buckets_s3_error err = parse_credential(buckets_str_c(cred_s), cfg, &cred);
  if (err != BUCKETS_ERR_NONE) return err;

  time_t t;
  if (!buckets_time_parse_amz(buckets_str_c(date_s), &t)) return BUCKETS_ERR_MALFORMED_PRESIGNED_DATE;

  char *endp = NULL;
  long long expires = strtoll(exp_s, &endp, 10);
  if (!*exp_s || *endp) return BUCKETS_ERR_MALFORMED_EXPIRES;
  if (expires < 0) return BUCKETS_ERR_NEGATIVE_EXPIRES;
  if (expires > BUCKETS_MAX_PRESIGN_EXPIRES) return BUCKETS_ERR_MAXIMUM_EXPIRES;

  if (*sh_s == '\0' || *sig_s == '\0') return BUCKETS_ERR_MISSING_FIELDS;
  signed_headers sh;
  if ((err = parse_signed_headers(buckets_str_c(sh_s), &sh)) != BUCKETS_ERR_NONE) {
    signed_headers_free(&sh);
    return err;
  }

  const char *secret = cfg->lookup(cfg->lookup_ud, cred.access_key);
  if (!secret) {
    err = BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
    goto done;
  }
  if (t > cfg->now + BUCKETS_MAX_SKEW_SECONDS) {
    err = BUCKETS_ERR_REQUEST_NOT_READY_YET;
    goto done;
  }
  if (cfg->now > t + expires) {
    err = BUCKETS_ERR_EXPIRED_PRESIGN_REQUEST;
    goto done;
  }

  const char *payload = buckets_query_get(q, "X-Amz-Content-Sha256");
  char hdr_payload[80];
  if (!payload) {
    buckets_str ph = buckets_http_header_get(req, "X-Amz-Content-Sha256");
    if (ph.p) {
      snprintf(hdr_payload, sizeof(hdr_payload), BUCKETS_STR_FMT, BUCKETS_STR_ARG(ph));
      payload = hdr_payload;
    } else {
      payload = BUCKETS_UNSIGNED_PAYLOAD;
    }
  }

  err = compute_and_compare(cfg, req, q, true, &cred, &sh, buckets_str_c(date_s), secret, payload,
                            buckets_str_c(sig_s), out);
  if (err == BUCKETS_ERR_NONE) fill_result(out, &cred, payload);

done:
  signed_headers_free(&sh);
  return err;
}
