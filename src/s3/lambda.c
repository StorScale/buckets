/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* GetObject through an object lambda (MinIO's object-lambda-handlers.go and
 * internal/config/lambda): GET /bucket/key?lambdaArn=arn:minio:s3-object-
 * lambda::<id>:webhook posts an event with a presigned URL of the object to
 * the lambda_webhook target <id>, whose answer (checked for the route and
 * token it was given) is the response. */
#include <ctype.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "config/config.h"
#include "config/sys.h"
#include "core/mime.h"
#include "core/uuid.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "net/fetch.h"
#include "notify/event.h"
#include "s3/internal.h"
#include "s3/sign.h"
#include "trace/trace.h"

/* textproto.CanonicalMIMEHeaderKey */
static void canonical(buckets_buf *out, const char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == ' ' || c >= 0x7f || c < 0x21) { /* not a token: kept as is */
      buckets_buf_append(out, s, n);
      return;
    }
  }
  bool up = true;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    buckets_buf_append_char(out, (char)(up ? toupper((unsigned char)c) : tolower((unsigned char)c)));
    up = c == '-';
  }
}

typedef struct {
  char *name;
  char **values;
  size_t n;
} hdr;

static int hdr_cmp(const void *a, const void *b) { return strcmp(((const hdr *)a)->name, ((const hdr *)b)->name); }

/* r.Header as encoding/json writes an http.Header: canonical names, sorted,
 * each with its values in order. */
static void request_headers_json(s3_ctx *c, buckets_buf *out) {
  hdr *h = NULL;
  size_t nh = 0;
  for (size_t i = 0; i < c->req->nheaders; i++) {
    if (buckets_str_ieq_c(c->req->headers[i].name, "Host")) continue; /* net/http keeps it in r.Host */
    buckets_buf nb = BUCKETS_BUF_INIT;
    canonical(&nb, c->req->headers[i].name.p, c->req->headers[i].name.n);
    buckets_buf_append_char(&nb, 0);
    size_t j = 0;
    while (j < nh && strcmp(h[j].name, nb.data)) j++;
    if (j == nh) {
      h = buckets_xrealloc(h, (nh + 1) * sizeof(hdr));
      h[nh++] = (hdr){buckets_buf_detach(&nb), NULL, 0};
    } else {
      buckets_buf_free(&nb);
    }
    h[j].values = buckets_xrealloc(h[j].values, (h[j].n + 1) * sizeof(char *));
    h[j].values[h[j].n++] = buckets_str_dup(c->req->headers[i].value);
  }
  qsort(h, nh, sizeof(hdr), hdr_cmp);
  buckets_buf_append_char(out, '{');
  for (size_t i = 0; i < nh; i++) {
    if (i) buckets_buf_append_char(out, ',');
    buckets_json_go_string(out, h[i].name, strlen(h[i].name));
    buckets_buf_append_c(out, ":[");
    for (size_t k = 0; k < h[i].n; k++) {
      if (k) buckets_buf_append_char(out, ',');
      buckets_json_go_string(out, h[i].values[k], strlen(h[i].values[k]));
      free(h[i].values[k]);
    }
    buckets_buf_append_char(out, ']');
    free(h[i].values);
    free(h[i].name);
  }
  buckets_buf_append_char(out, '}');
  free(h);
}

static void path_escape(buckets_buf *out, const char *s, bool keep_slash) { buckets_url_encode(out, s, keep_slash); }

/* The lambda_webhook target an ARN names: false with the S3 error written. */
static bool lookup_target(s3_ctx *c, const char *arn, char **endpoint, char **auth) {
  /* arn:minio:s3-object-lambda:<region>:<id>:<type> */
  const char *pfx = "arn:minio:s3-object-lambda:";
  char *tok[8] = {0};
  size_t nt = 0;
  bool valid = arn && strncmp(arn, pfx, strlen(pfx)) == 0;
  char *copy = valid ? buckets_xstrdup(arn) : NULL;
  if (valid) {
    char *save = copy, *field;
    while ((field = strsep(&save, ":")) != NULL && nt < 8) tok[nt++] = field;
    valid = nt == 6 && *tok[4] && *tok[5] && !save;
  }
  if (!valid) {
    free(copy);
    buckets_s3_write_custom_error(c, 400, "LambdaARNInvalid", "The specified lambda ARN is invalid");
    return false;
  }
  bool found = false;
  if (strcmp(tok[5], "webhook") == 0 && c->s->config) {
    char *en = buckets_config_sys_value(c->s->config, "lambda_webhook", tok[4], "enable");
    found = en && buckets_config_parse_bool(en) == 1;
    free(en);
    if (found) {
      *endpoint = buckets_config_sys_value(c->s->config, "lambda_webhook", tok[4], "endpoint");
      *auth = buckets_config_sys_value(c->s->config, "lambda_webhook", tok[4], "auth_token");
      if (!*endpoint || !**endpoint) {
        free(*endpoint), free(*auth);
        found = false;
      }
    }
  }
  free(copy);
  if (!found) {
    buckets_s3_write_custom_error(c, 404, "LambdaARNNotFound", "The specified lambda ARN does not exist");
    return false;
  }
  if (!*auth) *auth = buckets_xstrdup("");
  return true;
}

typedef struct {
  buckets_fetch_stream *fs;
  char pre[512];
  size_t npre, pos;
} lambda_out;

static long lambda_body(void *ud, char *buf, size_t n) {
  lambda_out *o = ud;
  if (o->pos < o->npre) {
    size_t k = o->npre - o->pos < n ? o->npre - o->pos : n;
    memcpy(buf, o->pre + o->pos, k);
    o->pos += k;
    return (long)k;
  }
  return buckets_fetch_read(o->fs, buf, n);
}

static void lambda_out_free(void *ud) {
  lambda_out *o = ud;
  if (!o) return;
  buckets_fetch_close(o->fs);
  free(o);
}

static bool has_type(const buckets_http_response *r) {
  size_t n;
  return buckets_http_headers_get(&r->headers, "Content-Type", &n) != NULL;
}

void buckets_s3_get_object_lambda(s3_ctx *c) {
  char *endpoint = NULL, *auth = NULL;
  if (!lookup_target(c, buckets_query_get(&c->q, "lambdaArn"), &endpoint, &auth)) return;
  /* a presigned GET of the object, as the caller, valid an hour */
  const char *ak = c->ident ? c->ident->access_key : "", *sk = c->ident ? c->ident->secret_key : "";
  const char *st = c->ident && c->ident->session_token ? c->ident->session_token : "";
  const char *parent = c->ident && c->ident->parent ? c->ident->parent : "";
  const char *origin = c->s->endpoint; /* scheme://host[:port] */
  const char *hostp = strstr(origin, "://");
  hostp = hostp ? hostp + 3 : origin;
  buckets_buf path = BUCKETS_BUF_INIT, extra = BUCKETS_BUF_INIT, qs = BUCKETS_BUF_INIT, url = BUCKETS_BUF_INIT;
  buckets_buf_append_char(&path, '/');
  path_escape(&path, c->bucket, false);
  buckets_buf_append_char(&path, '/');
  path_escape(&path, c->object, true);
  static const char *const params[] = {"partNumber",           "response-cache-control",   "response-content-disposition",
                                       "response-content-encoding", "response-content-language", "response-content-type",
                                       "response-expires"};
  for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
    const char *v = buckets_query_get(&c->q, params[i]);
    if (!v || !*v) continue;
    if (extra.len) buckets_buf_append_char(&extra, '&');
    buckets_buf_appendf(&extra, "%s=", params[i]);
    buckets_url_encode(&extra, v, false);
  }
  buckets_sigv4_creds cr = {.access_key = ak, .secret_key = sk, .session_token = st,
                            .region = c->s->region && *c->s->region ? c->s->region : "us-east-1"};
  buckets_sigv4_presign(&cr, "GET", path.data, extra.len ? extra.data : NULL, hostp, 3600, time(NULL), &qs);
  buckets_buf_appendf(&url, "%s%s?%s", origin, path.data, qs.data);
  /* the output token: sha256(access key + the URL's query) */
  buckets_buf tin = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&tin, ak);
  buckets_buf_append(&tin, qs.data, qs.len);
  uint8_t sum[32];
  buckets_sha256(tin.data, tin.len, sum);
  char token[65];
  buckets_hex_encode(sum, 32, token);
  buckets_buf_free(&tin);
  char route[32];
  buckets_shortuuid(route);
  /* the event, as levent.Event marshals */
  buckets_buf ev = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&ev, "{\"protocolVersion\":\"\",\"getObjectContext\":{\"outputRoute\":");
  buckets_json_go_string(&ev, route, strlen(route));
  buckets_buf_append_c(&ev, ",\"outputToken\":");
  buckets_json_go_string(&ev, token, strlen(token));
  buckets_buf_append_c(&ev, ",\"inputS3Url\":");
  buckets_json_go_string(&ev, url.data, url.len);
  buckets_buf_append_c(&ev, "},\"userIdentity\":{\"type\":\"IAMUser\",\"principalId\":");
  buckets_json_go_string(&ev, parent, strlen(parent));
  buckets_buf_append_c(&ev, ",\"accessKeyId\":");
  buckets_json_go_string(&ev, ak, strlen(ak));
  buckets_buf_append_c(&ev, "},\"userRequest\":{\"url\":");
  buckets_buf ru = BUCKETS_BUF_INIT;
  buckets_buf_append_str(&ru, c->req->path);
  if (c->req->query.n) {
    buckets_buf_append_char(&ru, '?');
    buckets_buf_append_str(&ru, c->req->query);
  }
  buckets_json_go_string(&ev, ru.data ? ru.data : "", ru.len);
  buckets_buf_free(&ru);
  buckets_buf_append_c(&ev, ",\"headers\":");
  request_headers_json(c, &ev);
  buckets_buf_append_c(&ev, "}}");
  /* to the webhook */
  buckets_http_kv h[2] = {{"Content-Type", "application/json"}};
  size_t nh = 1;
  char authz[4200];
  if (*auth) {
    bool two = strchr(auth, ' ') != NULL;
    snprintf(authz, sizeof(authz), two ? "%s" : "Bearer %s", auth);
    h[nh++] = (buckets_http_kv){"Authorization", authz};
  }
  int status = 0;
  buckets_buf rh = BUCKETS_BUF_INIT;
  char err[256];
  char ep_copy[1024];
  snprintf(ep_copy, sizeof(ep_copy), "%s", endpoint);
  buckets_fetch_stream *fs =
      buckets_fetch_open("POST", endpoint, NULL, h, nh, ev.data, ev.len, 0, &status, &rh, err, sizeof(err));
  buckets_buf_free(&ev);
  buckets_buf_free(&path);
  buckets_buf_free(&extra);
  buckets_buf_free(&qs);
  buckets_buf_free(&url);
  free(endpoint);
  free(auth);
  if (!fs) {
    char msg[600];
    /* Go's *url.Error: Post "URL": reason */
    const char *reason = strstr(err, "connection failed") ? "EOF" : err;
    snprintf(msg, sizeof(msg), "We encountered an internal error, please try again.: cause(Post \"%s\": %s)", ep_copy, reason);
    buckets_s3_write_custom_error(c, 500, "InternalError", msg);
    buckets_buf_free(&rh);
    return;
  }
  size_t vl;
  const char *v = buckets_http_headers_get(&rh, "X-Amz-Request-Route", &vl);
  if (!v || vl != strlen(route) || memcmp(v, route, vl)) {
    buckets_fetch_close(fs);
    buckets_buf_free(&rh);
    buckets_s3_write_custom_error(c, 400, "InvalidRequest", "The request route included in the request is invalid");
    return;
  }
  v = buckets_http_headers_get(&rh, "X-Amz-Request-Token", &vl);
  if (!v || vl != 64 || CRYPTO_memcmp(v, token, 64) != 0) {
    buckets_fetch_close(fs);
    buckets_buf_free(&rh);
    buckets_s3_write_custom_error(c, 403, "InvalidTokenId", "The request token included in the request is invalid");
    return;
  }
  v = buckets_http_headers_get(&rh, "X-Amz-Fwd-Status", &vl);
  if (v) {
    char sbuf[32];
    snprintf(sbuf, sizeof(sbuf), "%.*s", (int)(vl < 31 ? vl : 31), v);
    char *end;
    long sv = strtol(sbuf, &end, 10);
    if (!*sbuf || *end || vl > 31) {
      char msg[128];
      snprintf(msg, sizeof(msg), "strconv.Atoi: parsing \"%.*s\": invalid syntax", (int)vl, v);
      buckets_fetch_close(fs);
      buckets_buf_free(&rh);
      buckets_s3_write_custom_error(c, 400, "LambdaFunctionStatusError", msg);
      return;
    }
    status = (int)sv;
  }
  /* x-amz-fwd-header-* become the response's own */
  const char *p = rh.data, *end = rh.data + rh.len;
  char **set = NULL;
  size_t nset = 0;
  while (p && p < end) {
    const char *eol = memchr(p, '\n', (size_t)(end - p));
    const char *next = eol ? eol + 1 : end;
    const char *colon = memchr(p, ':', (size_t)(next - p));
    size_t pl = strlen("x-amz-fwd-header-");
    if (colon && (size_t)(colon - p) > pl && strncasecmp(p, "x-amz-fwd-header-", pl) == 0) {
      buckets_buf name = BUCKETS_BUF_INIT, val = BUCKETS_BUF_INIT;
      canonical(&name, p + pl, (size_t)(colon - p) - pl);
      buckets_buf_append_char(&name, 0);
      const char *vs = colon + 1, *ve = next;
      while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
      while (ve > vs && (ve[-1] == '\n' || ve[-1] == '\r' || ve[-1] == ' ')) ve--;
      buckets_buf_append(&val, vs, (size_t)(ve - vs));
      buckets_buf_append_char(&val, 0);
      bool seen = false;
      for (size_t i = 0; i < nset && !seen; i++) seen = !strcasecmp(set[i], name.data);
      if (!strcasecmp(name.data, "Content-Length")) {
        c->resp->content_length = strtoll(val.data, NULL, 10);
      } else {
        if (!seen) {
          buckets_http_resp_header_del(c->resp, name.data);
          set = buckets_xrealloc(set, (nset + 1) * sizeof(char *));
          set[nset++] = buckets_xstrdup(name.data);
        }
        buckets_http_resp_header(c->resp, name.data, val.data);
      }
      buckets_buf_free(&name);
      buckets_buf_free(&val);
    }
    p = next;
  }
  for (size_t i = 0; i < nset; i++) free(set[i]);
  free(set);
  if (status >= 400) {
    const char *desc = buckets_http_headers_get(&rh, "X-Amz-Fwd-Error-Message", &vl);
    char dbuf[1024], cbuf[128];
    snprintf(dbuf, sizeof(dbuf), "%.*s", desc ? (int)vl : 0, desc ? desc : "");
    size_t cl;
    const char *code = buckets_http_headers_get(&rh, "X-Amz-Fwd-Error-Code", &cl);
    snprintf(cbuf, sizeof(cbuf), "%.*s", code ? (int)cl : 0, code ? code : "");
    buckets_fetch_close(fs);
    buckets_buf_free(&rh);
    bool no_desc = !buckets_str_trim(buckets_str_c(dbuf)).n, no_code = !buckets_str_trim(buckets_str_c(cbuf)).n;
    if (no_desc) buckets_s3_write_error(c, BUCKETS_ERR_INVALID_REQUEST);
    else if (no_code) buckets_s3_write_error_msg(c, BUCKETS_ERR_INVALID_REQUEST, dbuf);
    else buckets_s3_write_custom_error(c, status, cbuf, dbuf);
    return;
  }
  const char *clen = buckets_http_headers_get(&rh, "Content-Length", &vl);
  if (c->resp->content_length < 0 && clen) c->resp->content_length = strtoll(clen, NULL, 10);
  buckets_buf_free(&rh);
  lambda_out *o = buckets_xcalloc(1, sizeof(*o));
  o->fs = fs;
  if (!has_type(c->resp)) {
    /* net/http sniffs a body sent without a Content-Type */
    while (o->npre < sizeof(o->pre)) {
      long k = buckets_fetch_read(fs, o->pre + o->npre, sizeof(o->pre) - o->npre);
      if (k <= 0) break;
      o->npre += (size_t)k;
    }
    buckets_http_resp_header(c->resp, "Content-Type", buckets_mime_sniff(o->pre, o->npre));
  }
  c->resp->status = status;
  if (c->resp->content_length < 0) c->resp->chunked = true;
  c->resp->stream = lambda_body;
  c->resp->stream_ud = o;
  c->resp->stream_free = lambda_out_free;
}
