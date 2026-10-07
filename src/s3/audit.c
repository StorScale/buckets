/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Audit entries (MinIO's logger.AuditLog and madmin-go logger/audit.Entry),
 * one per S3 request, for the audit targets. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "core/query.h"
#include "core/timefmt.h"
#include "logger/logger.h"
#include "metrics/stats.h"
#include "notify/event.h"
#include "audit/store.h"
#include "s3/internal.h"
#include "usage/history.h"

static void jstr(buckets_buf *b, const char *s) { buckets_json_go_string(b, s ? s : "", s ? strlen(s) : 0); }
static void jstrn(buckets_buf *b, const char *s, size_t n) { buckets_json_go_string(b, s, n); }

/* textproto.CanonicalMIMEHeaderKey */
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
  char *k;
  buckets_buf v; /* values joined with "," */
} kv;

static int kv_cmp(const void *a, const void *b) { return strcmp(((const kv *)a)->k, ((const kv *)b)->k); }

/* A map[string]string as json.Marshal writes it (keys sorted); nothing when empty. */
static void jmap(buckets_buf *b, const char *field, kv *v, size_t n) {
  if (!n) return;
  qsort(v, n, sizeof(*v), kv_cmp);
  buckets_buf_appendf(b, ",\"%s\":{", field);
  for (size_t i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(b, ',');
    jstr(b, v[i].k);
    buckets_buf_append_char(b, ':');
    jstrn(b, v[i].v.data ? v[i].v.data : "", v[i].v.len);
  }
  buckets_buf_append_char(b, '}');
}

static void kv_add(kv **v, size_t *n, size_t *cap, const char *k, const char *val, size_t vn) {
  for (size_t i = 0; i < *n; i++) {
    if (strcmp((*v)[i].k, k) == 0) { /* repeated: joined */
      buckets_buf_append_char(&(*v)[i].v, ',');
      buckets_buf_append(&(*v)[i].v, val, vn);
      return;
    }
  }
  if (*n == *cap) {
    *cap = *cap ? *cap * 2 : 16;
    *v = buckets_xrealloc(*v, *cap * sizeof(**v));
  }
  kv *e = &(*v)[(*n)++];
  e->k = buckets_xstrdup(k);
  memset(&e->v, 0, sizeof(e->v));
  buckets_buf_append(&e->v, val, vn);
}

static void kv_free(kv *v, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(v[i].k);
    buckets_buf_free(&v[i].v);
  }
  free(v);
}

static const char *status_text(int code) {
  const char *t = buckets_http_status_text(code);
  return t ? t : "";
}

bool buckets_s3_audit_wanted(buckets_s3_server *s) {
  return s->audit_store || buckets_logger_audit_enabled(s->logger);
}

/* An entry to the audit targets, and to the local copy (audit/store.h), which leaves reads out when asked to. */
static void audit_out(buckets_s3_server *s, const buckets_buf *b, bool read) {
  if (buckets_logger_audit_enabled(s->logger)) buckets_logger_audit(s->logger, b->data, b->len);
  if (s->audit_store && (!read || buckets_audit_local_reads())) buckets_audit_store_put(s->audit_store, b->data, b->len);
}

void buckets_s3_audit(s3_ctx *c, int api, int64_t ttfb_ns, int64_t ttr_ns, uint64_t tx) {
  if (!buckets_s3_audit_wanted(c->s)) return;
  const buckets_http_request *req = c->req;
  buckets_http_response *resp = c->resp;
  buckets_buf b = BUCKETS_BUF_INIT;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  char when[64];
  buckets_time_rfc3339_nano((long long)now.tv_sec, now.tv_nsec, when);
  buckets_objlayer *L = c->s->layer;
  buckets_buf_append_c(&b, "{\"version\":\"1\"");
  if (L && *L->deployment_id_str) {
    buckets_buf_append_c(&b, ",\"deploymentid\":");
    jstr(&b, L->deployment_id_str);
  }
  buckets_buf_appendf(&b, ",\"time\":\"%s\",\"event\":\"\",\"trigger\":\"incoming\",\"api\":{", when);
  bool first = true;
#define FIELD(name) buckets_buf_appendf(&b, "%s\"" name "\":", first ? "" : ","), first = false
  const char *name = api >= 0 ? buckets_api_handler_name(api) : c->op_name ? c->op_name : ""; /* admin: the handler */
  if (*name) FIELD("name"), jstr(&b, name);
  /* what the request was last authorized for (MinIO's checkRequestAuthType
   * rewrites the request info, e.g. to a copy source) */
  const char *ab = c->err_bucket && *c->err_bucket ? c->err_bucket : c->bucket;
  const char *ao = c->err_object && *c->err_object ? c->err_object : c->object;
  if (api >= 0 && ab && *ab) FIELD("bucket"), jstr(&b, ab); /* admin calls have neither */
  if (api >= 0 && ao && *ao) FIELD("object"), jstr(&b, ao);
  if (c->audit_objects.len) FIELD("objects"), buckets_buf_appendf(&b, "[%.*s]", (int)c->audit_objects.len, c->audit_objects.data);
  if (resp->status) {
    FIELD("status"), jstr(&b, status_text(resp->status));
    FIELD("statusCode"), buckets_buf_appendf(&b, "%d", resp->status);
  }
  /* r.ContentLength: -1 when unknown (chunked) */
  buckets_str cl = buckets_http_header_get(req, "Content-Length");
  long long rx = cl.p ? strtoll(cl.p, NULL, 10) : (buckets_http_header_get(req, "Transfer-Encoding").p ? -1 : 0);
  FIELD("rx"), buckets_buf_appendf(&b, "%lld", rx);
  FIELD("tx"), buckets_buf_appendf(&b, "%llu", (unsigned long long)tx);
  /* writeHeaders: "<code> <text>\n" and "<name>: <first value>\n" each */
  size_t hbytes = (size_t)snprintf(NULL, 0, "%d %s\n", resp->status, status_text(resp->status));
  kv *rh = NULL;
  size_t nrh = 0, caprh = 0;
  buckets_str rest = buckets_buf_str(&resp->headers), line;
  while (rest.n) {
    buckets_str_cut(rest, '\n', &line, &rest);
    buckets_str k, v;
    if (!buckets_str_cut(line, ':', &k, &v)) continue;
    v = buckets_str_trim(v);
    if (v.n && v.p[v.n - 1] == '\r') v.n--;
    char key[128]; /* as set: MinIO assigns some keys directly, lowercase */
    snprintf(key, sizeof(key), "%.*s", (int)k.n, k.p);
    bool seen = false;
    for (size_t i = 0; i < nrh; i++) seen |= strcmp(rh[i].k, key) == 0;
    if (!seen) hbytes += strlen(key) + 2 + v.n + 1;
    if (strcmp(key, "ETag") == 0) { /* without its quotes */
      if (v.n >= 2 && v.p[0] == '"' && v.p[v.n - 1] == '"') v.p++, v.n -= 2;
    }
    kv_add(&rh, &nrh, &caprh, key, v.p, v.n);
  }
  /* written with the response: Content-Length (and our Server header) */
  char clen[32];
  snprintf(clen, sizeof(clen), "%llu", (unsigned long long)(resp->content_length >= 0 ? (uint64_t)resp->content_length : resp->body.len));
  kv_add(&rh, &nrh, &caprh, "Content-Length", clen, strlen(clen));
  hbytes += strlen("Content-Length: \n") + strlen(clen);
  kv_add(&rh, &nrh, &caprh, "Server", "Buckets", 7);
  hbytes += strlen("Server: Buckets\n");
  FIELD("txHeaders"), buckets_buf_appendf(&b, "%zu", hbytes);
  if (ttfb_ns > 0) {
    FIELD("timeToFirstByte"), buckets_buf_appendf(&b, "\"%lldns\"", (long long)ttfb_ns);
    FIELD("timeToFirstByteInNS"), buckets_buf_appendf(&b, "\"%lld\"", (long long)ttfb_ns);
  }
  FIELD("timeToResponse"), buckets_buf_appendf(&b, "\"%lldns\"", (long long)ttr_ns);
  FIELD("timeToResponseInNS"), buckets_buf_appendf(&b, "\"%lld\"", (long long)ttr_ns);
#undef FIELD
  buckets_buf_append_char(&b, '}');
  char ip[128];
  buckets_s3_source_ip(req, ip, sizeof(ip));
  if (*ip) buckets_buf_append_c(&b, ",\"remotehost\":"), jstr(&b, ip);
  buckets_buf_append_c(&b, ",\"requestID\":"), jstr(&b, c->request_id);
  buckets_str ua = buckets_http_header_get(req, "User-Agent");
  if (ua.p && ua.n) buckets_buf_append_c(&b, ",\"userAgent\":"), jstrn(&b, ua.p, ua.n);
  if (req->path.n) {
    char *path = buckets_xmalloc(req->path.n + 1);
    long pn = buckets_url_decode(req->path, path, false);
    buckets_buf_append_c(&b, ",\"requestPath\":");
    if (pn >= 0) jstrn(&b, path, (size_t)pn);
    else jstrn(&b, req->path.p, req->path.n);
    free(path);
  }
  buckets_str host = buckets_http_header_get(req, "Host");
  if (host.p && host.n) buckets_buf_append_c(&b, ",\"requestHost\":"), jstrn(&b, host.p, host.n);
  /* mustGetClaimsFromToken: the session token's claims */
  bool has_token = buckets_http_header_get(req, "X-Amz-Security-Token").p || buckets_query_has(&c->q, "X-Amz-Security-Token");
  if (has_token && c->ident && c->ident->claims) {
    char *cj = yyjson_val_write(yyjson_doc_get_root(c->ident->claims), YYJSON_WRITE_ESCAPE_UNICODE, NULL);
    /* (Go sorts map keys; yyjson keeps the token's order) */
    if (cj) buckets_buf_appendf(&b, ",\"requestClaims\":%s", cj);
    free(cj);
  }
  kv *q = NULL;
  size_t nq = 0, capq = 0;
  for (size_t i = 0; i < c->q.n; i++)
    kv_add(&q, &nq, &capq, c->q.items[i].key, c->q.items[i].value ? c->q.items[i].value : "",
           c->q.items[i].value ? strlen(c->q.items[i].value) : 0);
  jmap(&b, "requestQuery", q, nq);
  kv_free(q, nq);
  kv *h = NULL;
  size_t nh = 0, caph = 0;
  for (size_t i = 0; i < req->nheaders; i++) {
    char key[128];
    canonical(req->headers[i].name.p, req->headers[i].name.n, key, sizeof(key));
    if (strcmp(key, "Host") == 0 || strcmp(key, "Transfer-Encoding") == 0) continue; /* not in r.Header */
    if (c->audit_tagging && strcmp(key, "X-Amz-Tagging") == 0) continue; /* replaced below */
    kv_add(&h, &nh, &caph, key, req->headers[i].value.p, req->headers[i].value.n);
  }
  if (c->audit_tagging) kv_add(&h, &nh, &caph, "X-Amz-Tagging", c->audit_tagging, strlen(c->audit_tagging));
  jmap(&b, "requestHeader", h, nh);
  kv_free(h, nh);
  jmap(&b, "responseHeader", rh, nrh);
  kv_free(rh, nrh);
  if (c->tags.n) { /* reqInfo tags, as a map */
    kv *t = buckets_xcalloc(c->tags.n, sizeof(*t));
    for (size_t i = 0; i < c->tags.n; i++) {
      t[i].k = c->tags.keys[i];
      t[i].v = (buckets_buf){c->tags.values[i], strlen(c->tags.values[i]), strlen(c->tags.values[i])};
    }
    jmap(&b, "tags", t, c->tags.n);
    free(t);
  }
  if (c->ident) {
    buckets_buf_append_c(&b, ",\"accessKey\":"), jstr(&b, c->ident->access_key);
    if (c->ident->parent && *c->ident->parent) buckets_buf_append_c(&b, ",\"parentUser\":"), jstr(&b, c->ident->parent);
  } else if (*c->access_key) {
    buckets_buf_append_c(&b, ",\"accessKey\":"), jstr(&b, c->access_key);
  }
  buckets_buf_append_char(&b, '}');
  bool read = false;
  if (api >= 0) {
    char lower[64] = "";
    const char *n = buckets_api_handler_name(api);
    for (size_t i = 0; n && n[i] && i < sizeof(lower) - 1; i++) lower[i] = (char)tolower((unsigned char)n[i]);
    read = buckets_usage_kind_of(lower) == BUCKETS_USAGE_READ;
  }
  audit_out(c->s, &b, read);
  buckets_buf_free(&b);
}

/* auditLogInternal: an audit.Entry for what the server did on its own */
void buckets_s3_audit_internal(void *ud, const char *event, const char *api_name, const char *bucket, const char *object,
                               const char *version_id, const char *error, const char *const *keys,
                               const char *const *values, size_t ntags) {
  buckets_s3_server *s = ud;
  if (!buckets_s3_audit_wanted(s)) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  char when[64];
  buckets_time_rfc3339_nano((long long)now.tv_sec, now.tv_nsec, when);
  buckets_buf_append_c(&b, "{\"version\":\"1\"");
  if (s->layer && *s->layer->deployment_id_str) {
    buckets_buf_append_c(&b, ",\"deploymentid\":");
    jstr(&b, s->layer->deployment_id_str);
  }
  buckets_buf_appendf(&b, ",\"time\":\"%s\",\"event\":", when);
  jstr(&b, event);
  buckets_buf_append_c(&b, ",\"trigger\":");
  jstr(&b, event);
  buckets_buf_append_c(&b, ",\"api\":{");
  if (api_name && *api_name) {
    buckets_buf_append_c(&b, "\"name\":");
    jstr(&b, api_name);
    buckets_buf_append_char(&b, ',');
  }
  if (bucket && *bucket) {
    buckets_buf_append_c(&b, "\"bucket\":");
    jstr(&b, bucket);
    buckets_buf_append_char(&b, ',');
  }
  buckets_buf_append_c(&b, "\"objects\":[{\"objectName\":");
  jstr(&b, object);
  if (version_id && *version_id) {
    buckets_buf_append_c(&b, ",\"versionId\":");
    jstr(&b, version_id);
  }
  buckets_buf_append_c(&b, "}],\"rx\":0,\"tx\":0}");
  if (ntags) { /* a Go map: sorted keys */
    size_t *ord = buckets_xcalloc(ntags, sizeof(*ord));
    for (size_t i = 0; i < ntags; i++) {
      size_t j = i;
      for (; j > 0 && strcmp(keys[ord[j - 1]], keys[i]) > 0; j--) ord[j] = ord[j - 1];
      ord[j] = i;
    }
    buckets_buf_append_c(&b, ",\"tags\":{");
    for (size_t i = 0; i < ntags; i++) {
      if (i) buckets_buf_append_char(&b, ',');
      jstr(&b, keys[ord[i]]);
      buckets_buf_append_char(&b, ':');
      jstr(&b, values[ord[i]]);
    }
    buckets_buf_append_char(&b, '}');
    free(ord);
  }
  if (error && *error) {
    buckets_buf_append_c(&b, ",\"error\":");
    jstr(&b, error);
  }
  buckets_buf_append_char(&b, '}');
  audit_out(s, &b, false);
  buckets_buf_free(&b);
}
