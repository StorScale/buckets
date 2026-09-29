/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* HTTP trace records (MinIO's httpTracerMiddleware): one madmin.TraceInfo
 * per request, for mc admin trace. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "admin/info.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "metrics/stats.h"
#include "notify/event.h"
#include "s3/internal.h"
#include "trace/trace.h"

/* Handlers routed with traceHdrsS3HFlag: bodies are not traced ("<BLOB>"). */
static bool headers_only(const char *handler) {
  static const char *const k[] = {"DeleteObjectTagging", "GetObject", "GetObjectACL", "GetObjectAttributes",
                                  "GetObjectLambda", "GetObjectTagging", "ListenNotification", "PostPolicyBucket",
                                  "PutObject", "PutObjectACL", "PutObjectExtract", "PutObjectPart",
                                  "PutObjectTagging", "SelectObjectContent"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k); i++)
    if (strcmp(k[i], handler) == 0) return true;
  return false;
}

static void jstr(buckets_buf *b, const char *s, size_t n) { buckets_json_go_string(b, s, n); }

static void canonical(const char *k, size_t n, char *out, size_t cap) {
  bool up = true;
  size_t i = 0;
  for (; i < n && i + 1 < cap; i++) {
    char ch = k[i];
    out[i] = up ? (char)(ch >= 'a' && ch <= 'z' ? ch - 32 : ch) : (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
    up = ch == '-';
  }
  out[i] = '\0';
}

typedef struct {
  char *key;
  char **vals;
  size_t n;
} hdr;

static void hdr_add(hdr **h, size_t *n, const char *key, const char *val, size_t vn) {
  for (size_t i = 0; i < *n; i++) {
    if (strcmp((*h)[i].key, key) == 0) {
      (*h)[i].vals = buckets_xrealloc((*h)[i].vals, ((*h)[i].n + 1) * sizeof(char *));
      (*h)[i].vals[(*h)[i].n++] = buckets_xstrndup(val, vn);
      return;
    }
  }
  *h = buckets_xrealloc(*h, (*n + 1) * sizeof(**h));
  hdr *e = &(*h)[(*n)++];
  e->key = buckets_xstrdup(key);
  e->vals = buckets_xcalloc(1, sizeof(char *));
  e->vals[0] = buckets_xstrndup(val, vn);
  e->n = 1;
}

static void hdr_set(hdr **h, size_t *n, const char *key, const char *val) {
  for (size_t i = 0; i < *n; i++) {
    if (strcmp((*h)[i].key, key) == 0) {
      for (size_t j = 0; j < (*h)[i].n; j++) free((*h)[i].vals[j]);
      (*h)[i].n = 0;
      hdr_add(h, n, key, val, strlen(val));
      return;
    }
  }
  hdr_add(h, n, key, val, strlen(val));
}

static int hdr_cmp(const void *a, const void *b) { return strcmp(((const hdr *)a)->key, ((const hdr *)b)->key); }

/* http.Header as json.Marshal writes it: keys sorted, value arrays */
static void hdr_json(buckets_buf *b, hdr *h, size_t n) {
  qsort(h, n, sizeof(*h), hdr_cmp);
  buckets_buf_append_char(b, '{');
  for (size_t i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(b, ',');
    jstr(b, h[i].key, strlen(h[i].key));
    buckets_buf_append_c(b, ":[");
    for (size_t j = 0; j < h[i].n; j++) {
      if (j) buckets_buf_append_char(b, ',');
      jstr(b, h[i].vals[j], strlen(h[i].vals[j]));
    }
    buckets_buf_append_char(b, ']');
  }
  buckets_buf_append_char(b, '}');
}

static void hdr_free(hdr *h, size_t n) {
  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; j < h[i].n; j++) free(h[i].vals[j]);
    free(h[i].vals);
    free(h[i].key);
  }
  free(h);
}

/* []byte as json.Marshal writes it: base64 */
static void jbytes(buckets_buf *b, const char *data, size_t n) {
  char *enc = buckets_xmalloc(n / 3 * 4 + 8);
  buckets_base64_encode((const uint8_t *)data, n, enc);
  buckets_buf_appendf(b, "\"%s\"", enc);
  free(enc);
}

/* url.URL's Path when the request's encoding is Go's own (RawPath empty),
 * else the raw path: escape(path, encodePath) == raw */
static bool go_escaped_same(const char *decoded, size_t dn, const char *raw, size_t rn) {
  static const char hex[] = "0123456789ABCDEF";
  size_t j = 0;
  for (size_t i = 0; i < dn; i++) {
    unsigned char ch = (unsigned char)decoded[i];
    bool plain = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strchr("-_.~$&+,/:;=@", ch);
    if (ch == 0) plain = false;
    if (plain) {
      if (j >= rn || raw[j] != (char)ch) return false;
      j++;
    } else {
      if (j + 3 > rn || raw[j] != '%' || raw[j + 1] != hex[ch >> 4] || raw[j + 2] != hex[ch & 15]) return false;
      j += 3;
    }
  }
  return j == rn;
}

static void when(int64_t ns, char out[64]) { buckets_time_rfc3339_nano(ns / 1000000000LL, (long)(ns % 1000000000LL), out); }

void buckets_s3_trace_http(s3_ctx *c, int api, int64_t start_ns, int64_t end_ns, int64_t ttfb_ns, uint64_t tx) {
  if (!buckets_trace_wanted(BUCKETS_TRACE_S3 | BUCKETS_TRACE_INTERNAL)) return;
  const buckets_http_request *req = c->req;
  buckets_http_response *resp = c->resp;
  char func[128];
  const char *handler = api >= 0 ? buckets_api_handler_name(api) : "";
  if (*handler) snprintf(func, sizeof(func), "s3.%s", handler);
  else if (c->op_name && buckets_str_has_prefix(req->path, "/minio/admin/")) snprintf(func, sizeof(func), "admin.%s", c->op_name);
  else if (c->op_name) snprintf(func, sizeof(func), "%s", c->op_name);
  else snprintf(func, sizeof(func), "<unknown>");
  uint64_t type = strncmp(func, "s3.", 3) == 0 ? BUCKETS_TRACE_S3 : BUCKETS_TRACE_INTERNAL;
  if (!buckets_trace_wanted(type)) return;
  bool hdrs_only = *handler && headers_only(handler);

  /* the request's headers, with Host and Content-Length (or Transfer-Encoding) */
  hdr *rh = NULL;
  size_t nrh = 0;
  for (size_t i = 0; i < req->nheaders; i++) {
    char key[128];
    canonical(req->headers[i].name.p, req->headers[i].name.n, key, sizeof(key));
    if (strcmp(key, "Host") == 0 || strcmp(key, "Content-Length") == 0 || strcmp(key, "Transfer-Encoding") == 0) continue;
    hdr_add(&rh, &nrh, key, req->headers[i].value.p, req->headers[i].value.n);
  }
  if (c->audit_tagging) hdr_set(&rh, &nrh, "X-Amz-Tagging", c->audit_tagging);
  buckets_str host = buckets_http_header_get(req, "Host");
  char hostbuf[256];
  snprintf(hostbuf, sizeof(hostbuf), "%.*s", (int)host.n, host.p ? host.p : "");
  hdr_set(&rh, &nrh, "Host", hostbuf);
  buckets_str te = buckets_http_header_get(req, "Transfer-Encoding");
  if (te.p) {
    char v[64];
    snprintf(v, sizeof(v), "%.*s", (int)te.n, te.p);
    hdr_set(&rh, &nrh, "Transfer-Encoding", v);
  } else {
    char v[32];
    snprintf(v, sizeof(v), "%lld", (long long)(req->body_len > 0 ? req->body_len : 0));
    hdr_set(&rh, &nrh, "Content-Length", v);
  }
  size_t body_in = req->body_fd < 0 && !req->pipe ? req->body.n : (size_t)(req->body_len > 0 ? req->body_len : 0);
  size_t input = body_in;
  for (size_t i = 0; i < nrh; i++) input += strlen(rh[i].key) + rh[i].n; /* len(k) + len(v), as MinIO counts */

  /* the response's headers as set, with the Content-Length written */
  hdr *ph = NULL;
  size_t nph = 0;
  buckets_str rest = buckets_buf_str(&resp->headers), line;
  while (rest.n) {
    buckets_str_cut(rest, '\n', &line, &rest);
    buckets_str k, v;
    if (!buckets_str_cut(line, ':', &k, &v)) continue;
    v = buckets_str_trim(v);
    if (v.n && v.p[v.n - 1] == '\r') v.n--;
    char key[128];
    snprintf(key, sizeof(key), "%.*s", (int)k.n, k.p);
    hdr_add(&ph, &nph, key, v.p, v.n);
  }
  char clen[32];
  snprintf(clen, sizeof(clen), "%llu", (unsigned long long)(resp->content_length >= 0 ? (uint64_t)resp->content_length : resp->body.len));
  hdr_set(&ph, &nph, "Content-Length", clen);
  hdr_set(&ph, &nph, "Server", "Buckets");

  const buckets_cluster_info *ci = c->s->cluster;
  char node[256];
  snprintf(node, sizeof(node), "%s", ci && ci->distributed && ci->self ? ci->self : hostbuf);
  size_t nl = strlen(node);
  if (nl > 4 && (strcmp(node + nl - 4, ":443") == 0)) node[nl - 4] = '\0';
  else if (nl > 3 && strcmp(node + nl - 3, ":80") == 0) node[nl - 3] = '\0';

  char t0[64], t1[64];
  when(start_ns, t0);
  when(end_ns, t1);
  int64_t dur = end_ns - start_ns;
  char ip[128];
  buckets_s3_source_ip(req, ip, sizeof(ip));

  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "{\"type\":%llu,\"nodename\":", (unsigned long long)type);
  jstr(&b, node, strlen(node));
  buckets_buf_append_c(&b, ",\"funcname\":");
  jstr(&b, func, strlen(func));
  /* the path as MinIO reports it (RawPath, else Path) */
  char *decoded = buckets_xmalloc(req->path.n + 1);
  long dn = buckets_url_decode(req->path, decoded, false);
  const char *tp = req->path.p;
  size_t tn = req->path.n;
  if (dn >= 0 && go_escaped_same(decoded, (size_t)dn, req->path.p, req->path.n)) tp = decoded, tn = (size_t)dn;
  buckets_buf_appendf(&b, ",\"time\":\"%s\",\"path\":", t0);
  jstr(&b, tp, tn);
  buckets_buf_appendf(&b, ",\"dur\":%lld,\"bytes\":%llu,\"http\":{\"request\":{\"time\":\"%s\",\"proto\":\"HTTP/1.1\",\"method\":",
                      (long long)dur, (unsigned long long)(input + tx), t0);
  jstr(&b, req->method.p, req->method.n);
  buckets_buf_append_c(&b, ",\"path\":");
  jstr(&b, tp, tn);
  if (req->query.n) {
    buckets_buf_append_c(&b, ",\"rawquery\":");
    jstr(&b, req->query.p, req->query.n);
  }
  buckets_buf_append_c(&b, ",\"headers\":");
  hdr_json(&b, rh, nrh);
  /* RequestRecorder.Data: the body, or <BLOB> for header-only handlers */
  if (hdrs_only || req->body_fd >= 0 || req->pipe) buckets_buf_append_c(&b, ",\"body\":"), jbytes(&b, "<BLOB>", 6);
  else if (req->body.n) buckets_buf_append_c(&b, ",\"body\":"), jbytes(&b, req->body.p, req->body.n);
  buckets_buf_append_c(&b, ",\"client\":");
  jstr(&b, ip, strlen(ip));
  buckets_buf_appendf(&b, "},\"response\":{\"time\":\"%s\",\"headers\":", t1);
  hdr_json(&b, ph, nph);
  /* ResponseRecorder.Body: errors, and everything for handlers traced with bodies */
  bool err = resp->status >= 400;
  if (resp->stream || (hdrs_only && !err)) {
    buckets_buf_append_c(&b, ",\"body\":"), jbytes(&b, "<BLOB>", 6);
  } else if (resp->body.len) {
    buckets_buf_append_c(&b, ",\"body\":"), jbytes(&b, resp->body.data, resp->body.len);
  }
  if (resp->status) buckets_buf_appendf(&b, ",\"statuscode\":%d", resp->status);
  buckets_buf_appendf(&b, "},\"stats\":{\"inputbytes\":%zu,\"outputbytes\":%llu,\"latency\":%lld,\"timetofirstbyte\":%lld}}}",
                      input, (unsigned long long)tx, (long long)dur, (long long)ttfb_ns);
  free(decoded);
  buckets_trace_meta m = {.type = type, .dur_ns = dur, .http = true, .status = resp->status};
  char *path = buckets_str_dup(req->path);
  m.path = path;
  buckets_trace_publish(&m, b.data, b.len);
  free(path);
  buckets_buf_free(&b);
  hdr_free(rh, nrh);
  hdr_free(ph, nph);
}
