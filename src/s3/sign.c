/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/sign.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "core/query.h"
#include "core/timefmt.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "s3/sigv4.h"

typedef struct {
  char *name; /* lowercase */
  const char *value;
} signed_hdr;

static int hdr_cmp(const void *a, const void *b) { return strcmp(((const signed_hdr *)a)->name, ((const signed_hdr *)b)->name); }

/* Trimmed, with inner runs of spaces folded, as canonical headers are. */
static void append_value(buckets_buf *b, const char *v) {
  while (*v == ' ' || *v == '\t') v++;
  size_t n = strlen(v);
  while (n && (v[n - 1] == ' ' || v[n - 1] == '\t')) n--;
  bool sp = false;
  for (size_t i = 0; i < n; i++) {
    if (v[i] == ' ' || v[i] == '\t') {
      sp = true;
      continue;
    }
    if (sp) buckets_buf_append_char(b, ' ');
    sp = false;
    buckets_buf_append_char(b, v[i]);
  }
}

bool buckets_sigv4_sign(const buckets_sigv4_creds *cr, const char *method, const char *path, const char *query,
                        const char *host, const buckets_http_kv *hdrs, size_t nhdrs, const char *payload_hash, time_t now,
                        buckets_sigv4_signed *out) {
  memset(out, 0, sizeof(*out));
  if (nhdrs + 4 > BUCKETS_SIGN_MAX_HEADERS) return false;
  const char *region = cr->region && *cr->region ? cr->region : "us-east-1";
  const char *service = cr->service && *cr->service ? cr->service : "s3";
  bool token = cr->session_token && *cr->session_token;
  buckets_time_amz(now, out->date);
  snprintf(out->payload, sizeof(out->payload), "%s", payload_hash);

  size_t ns = 0;
  signed_hdr *sh = buckets_xcalloc(nhdrs + 4, sizeof(signed_hdr));
  sh[ns++] = (signed_hdr){buckets_xstrdup("host"), host};
  sh[ns++] = (signed_hdr){buckets_xstrdup("x-amz-content-sha256"), out->payload};
  sh[ns++] = (signed_hdr){buckets_xstrdup("x-amz-date"), out->date};
  if (token) sh[ns++] = (signed_hdr){buckets_xstrdup("x-amz-security-token"), cr->session_token};
  for (size_t i = 0; i < nhdrs; i++) {
    char *nm = buckets_xstrdup(hdrs[i].name);
    for (char *p = nm; *p; p++) *p = (char)tolower((unsigned char)*p);
    sh[ns++] = (signed_hdr){nm, hdrs[i].value};
  }
  qsort(sh, ns, sizeof(signed_hdr), hdr_cmp);

  buckets_buf curi = BUCKETS_BUF_INIT, cq = BUCKETS_BUF_INIT, creq = BUCKETS_BUF_INIT, names = BUCKETS_BUF_INIT;
  buckets_sigv4_canonical_uri(buckets_str_c(path && *path ? path : "/"), &curi);
  buckets_query q = {0};
  if (query && *query) buckets_query_parse(buckets_str_c(query), &q);
  buckets_sigv4_canonical_query(&q, false, &cq);
  buckets_query_free(&q);
  buckets_buf_appendf(&creq, "%s\n%s\n%s\n", method, curi.data ? curi.data : "/", cq.data ? cq.data : "");
  for (size_t i = 0; i < ns; i++) {
    buckets_buf_appendf(&creq, "%s:", sh[i].name);
    append_value(&creq, sh[i].value);
    buckets_buf_append_char(&creq, '\n');
    if (i) buckets_buf_append_char(&names, ';');
    buckets_buf_append_c(&names, sh[i].name);
  }
  buckets_buf_appendf(&creq, "\n%s\n%s", names.data, payload_hash);

  char date8[9];
  memcpy(date8, out->date, 8);
  date8[8] = '\0';
  char scope[128];
  snprintf(scope, sizeof(scope), "%s/%s/%s/aws4_request", date8, region, service);
  uint8_t sum[32], key[32], mac[32];
  buckets_sha256(creq.data, creq.len, sum);
  char creq_hash[65], sig[65];
  buckets_hex_encode(sum, 32, creq_hash);
  char sts[512];
  snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s", out->date, scope, creq_hash);
  buckets_sigv4_signing_key(cr->secret_key, buckets_str_c(date8), buckets_str_c(region), service, key);
  buckets_hmac_sha256(key, 32, sts, strlen(sts), mac);
  buckets_hex_encode(mac, 32, sig);
  snprintf(out->auth, sizeof(out->auth), "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
           cr->access_key, scope, names.data, sig);

  for (size_t i = 0; i < nhdrs; i++) out->kv[out->n++] = hdrs[i];
  out->kv[out->n++] = (buckets_http_kv){"X-Amz-Date", out->date};
  out->kv[out->n++] = (buckets_http_kv){"X-Amz-Content-Sha256", out->payload};
  if (token) out->kv[out->n++] = (buckets_http_kv){"X-Amz-Security-Token", cr->session_token};
  out->kv[out->n++] = (buckets_http_kv){"Authorization", out->auth};

  for (size_t i = 0; i < ns; i++) free(sh[i].name);
  free(sh);
  buckets_buf_free(&curi);
  buckets_buf_free(&cq);
  buckets_buf_free(&creq);
  buckets_buf_free(&names);
  return true;
}

static void uri_escape(buckets_buf *b, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') buckets_buf_append_char(b, (char)*p);
    else buckets_buf_appendf(b, "%%%c%c", hex[*p >> 4], hex[*p & 15]);
  }
}

void buckets_sigv4_presign(const buckets_sigv4_creds *cr, const char *method, const char *path, const char *extra_query,
                           const char *host, int expires, time_t now, buckets_buf *query) {
  const char *region = cr->region && *cr->region ? cr->region : "us-east-1";
  const char *service = cr->service && *cr->service ? cr->service : "s3";
  char date[17], date8[9], scope[128], cred[512];
  buckets_time_amz(now, date);
  memcpy(date8, date, 8);
  date8[8] = '\0';
  snprintf(scope, sizeof(scope), "%s/%s/%s/aws4_request", date8, region, service);
  snprintf(cred, sizeof(cred), "%s/%s", cr->access_key, scope);
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&q, "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=");
  uri_escape(&q, cred);
  buckets_buf_appendf(&q, "&X-Amz-Date=%s&X-Amz-Expires=%d", date, expires);
  if (cr->session_token && *cr->session_token) {
    buckets_buf_append_c(&q, "&X-Amz-Security-Token=");
    uri_escape(&q, cr->session_token);
  }
  buckets_buf_append_c(&q, "&X-Amz-SignedHeaders=host");
  if (extra_query && *extra_query) buckets_buf_appendf(&q, "&%s", extra_query);

  buckets_buf curi = BUCKETS_BUF_INIT, cq = BUCKETS_BUF_INIT, creq = BUCKETS_BUF_INIT;
  buckets_sigv4_canonical_uri(buckets_str_c(path && *path ? path : "/"), &curi);
  buckets_query pq = {0};
  buckets_query_parse(buckets_str_c(q.data), &pq);
  buckets_sigv4_canonical_query(&pq, false, &cq);
  buckets_query_free(&pq);
  buckets_buf_appendf(&creq, "%s\n%s\n%s\nhost:%s\n\nhost\nUNSIGNED-PAYLOAD", method, curi.data ? curi.data : "/",
                      cq.data ? cq.data : "", host);
  uint8_t sum[32], key[32], mac[32];
  char creq_hash[65], sig[65], sts[512];
  buckets_sha256(creq.data, creq.len, sum);
  buckets_hex_encode(sum, 32, creq_hash);
  snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s", date, scope, creq_hash);
  buckets_sigv4_signing_key(cr->secret_key, buckets_str_c(date8), buckets_str_c(region), service, key);
  buckets_hmac_sha256(key, 32, sts, strlen(sts), mac);
  buckets_hex_encode(mac, 32, sig);
  buckets_buf_appendf(&q, "&X-Amz-Signature=%s", sig);
  buckets_buf_append(query, q.data, q.len);
  buckets_buf_free(&q);
  buckets_buf_free(&curi);
  buckets_buf_free(&cq);
  buckets_buf_free(&creq);
}
