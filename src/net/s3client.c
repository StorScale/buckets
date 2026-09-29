/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* A small S3 client (the parts of minio-go replication, tiering and batch
 * jobs use): path-style, SigV4, pooled keep-alive connections. */
#include "net/s3client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include <time.h>

#include "core/common.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "s3/sign.h"
#include "s3/xml.h"

struct buckets_s3c {
  char *endpoint; /* as configured */
  char *host;     /* without brackets */
  int port;
  char host_header[300];
  bool secure;
  char *access_key, *secret_key, *session_token, *region;
  char user_agent[512];
  buckets_tls_client *own_tls;
  buckets_http_client *http;
};

static char *dup0(const char *s) { return buckets_xstrdup(s ? s : ""); }

buckets_s3c *buckets_s3c_new(const buckets_s3c_config *cfg) {
  buckets_s3c *c = buckets_xcalloc(1, sizeof(*c));
  c->endpoint = dup0(cfg->endpoint);
  c->secure = cfg->secure;
  c->port = cfg->secure ? 443 : 80;
  const char *ep = c->endpoint, *colon = NULL;
  if (*ep == '[') {
    const char *rb = strchr(ep, ']');
    c->host = rb ? buckets_xstrndup(ep + 1, (size_t)(rb - ep - 1)) : dup0(ep);
    if (rb && rb[1] == ':') colon = rb + 1;
  } else {
    colon = strrchr(ep, ':');
    c->host = colon ? buckets_xstrndup(ep, (size_t)(colon - ep)) : dup0(ep);
  }
  if (colon && colon[1]) c->port = atoi(colon + 1);
  /* the client always sends the port; sign what goes out */
  if (strchr(c->host, ':')) snprintf(c->host_header, sizeof(c->host_header), "[%s]:%d", c->host, c->port);
  else snprintf(c->host_header, sizeof(c->host_header), "%s:%d", c->host, c->port);
  c->access_key = dup0(cfg->access_key);
  c->secret_key = dup0(cfg->secret_key);
  c->session_token = dup0(cfg->session_token);
  c->region = dup0(cfg->region && *cfg->region ? cfg->region : "us-east-1");
  struct utsname u;
  const char *os = "linux", *arch = "amd64";
  if (uname(&u) == 0) {
    os = strcasecmp(u.sysname, "Darwin") == 0 ? "darwin" : "linux";
    arch = strcmp(u.machine, "arm64") == 0 || strcmp(u.machine, "aarch64") == 0 ? "arm64" : "amd64";
  }
  snprintf(c->user_agent, sizeof(c->user_agent), "MinIO (%s; %s) minio-go/v7.0.91%s%s", os, arch,
           cfg->app_info ? " " : "", cfg->app_info ? cfg->app_info : "");
  buckets_tls_client *tls = cfg->tls;
  if (cfg->secure && !tls) {
    char err[256];
    tls = c->own_tls = buckets_tls_client_new(NULL, err, sizeof(err));
  }
  c->http = buckets_http_client_new(c->host, c->port, cfg->secure ? tls : NULL,
                                    cfg->timeout_ms > 0 ? cfg->timeout_ms : 5 * 60 * 1000);
  return c;
}

void buckets_s3c_free(buckets_s3c *c) {
  if (!c) return;
  buckets_http_client_free(c->http);
  if (c->own_tls) buckets_tls_client_free(c->own_tls);
  free(c->endpoint);
  free(c->host);
  free(c->access_key);
  free(c->secret_key);
  free(c->session_token);
  free(c->region);
  free(c);
}

const char *buckets_s3c_endpoint(const buckets_s3c *c) { return c->endpoint; }
bool buckets_s3c_secure(const buckets_s3c *c) { return c->secure; }

void buckets_s3c_result_free(buckets_s3c_result *r) {
  buckets_buf_free(&r->headers);
  buckets_buf_free(&r->body);
  memset(r, 0, sizeof(*r));
}

const char *buckets_s3c_header(const buckets_s3c_result *r, const char *name, size_t *len) {
  return buckets_http_headers_get(&r->headers, name, len);
}

void buckets_s3c_header_copy(const buckets_s3c_result *r, const char *name, char *out, size_t cap) {
  size_t n = 0;
  const char *v = buckets_s3c_header(r, name, &n);
  if (!v) n = 0;
  if (cap == 0) return;
  if (n >= cap) n = cap - 1;
  memcpy(out, v ? v : "", n);
  out[n] = '\0';
}

bool buckets_s3c_ok(const buckets_s3c_result *r) { return r->status >= 200 && r->status < 300; }

const char *buckets_s3c_error(const buckets_s3c_result *r) {
  if (r->message[0]) return r->message;
  return r->code[0] ? r->code : "unknown error";
}

static void build_path(buckets_buf *p, const char *bucket, const char *object) {
  buckets_buf_append_char(p, '/');
  if (bucket && *bucket) {
    buckets_url_encode(p, bucket, false);
    if (object && *object) {
      buckets_buf_append_char(p, '/');
      buckets_url_encode(p, object, true);
    }
  }
  buckets_buf_append_char(p, '\0');
  p->len--;
}

/* The error of a non-2xx response: the S3 XML body, or for bodiless replies
 * MinIO's x-minio-error-code / -desc headers, or minio-go's defaults. */
static void parse_error(buckets_s3c_result *r, const char *bucket, const char *object) {
  if (buckets_s3c_ok(r)) return;
  if (r->body.len) {
    buckets_xml_doc d = {0};
    if (buckets_xml_parse((buckets_str){r->body.data, r->body.len}, &d) && d.count) {
      size_t code = buckets_xml_child(&d, 0, "Code"), msg = buckets_xml_child(&d, 0, "Message");
      buckets_buf t = BUCKETS_BUF_INIT;
      if (code && buckets_xml_unescape(d.nodes[code].text, &t))
        snprintf(r->code, sizeof(r->code), "%.*s", (int)t.len, t.data ? t.data : "");
      buckets_buf_reset(&t);
      if (msg && buckets_xml_unescape(d.nodes[msg].text, &t))
        snprintf(r->message, sizeof(r->message), "%.*s", (int)t.len, t.data ? t.data : "");
      buckets_buf_free(&t);
    }
    buckets_xml_doc_free(&d);
  }
  if (!r->code[0]) buckets_s3c_header_copy(r, "x-minio-error-code", r->code, sizeof(r->code));
  if (!r->message[0]) buckets_s3c_header_copy(r, "x-minio-error-desc", r->message, sizeof(r->message));
  if (r->message[0] == '"') { /* x-minio-error-desc is quoted */
    size_t n = strlen(r->message);
    if (n >= 2 && r->message[n - 1] == '"') {
      memmove(r->message, r->message + 1, n - 2);
      r->message[n - 2] = '\0';
    }
  }
  if (!r->code[0]) { /* minio-go httpRespToErrorResponse */
    switch (r->status) {
    case 404:
      snprintf(r->code, sizeof(r->code), "%s",
               object && *object ? "NoSuchKey" : bucket && *bucket ? "NoSuchBucket" : "NotFound");
      break;
    case 403: snprintf(r->code, sizeof(r->code), "AccessDenied"); break;
    case 409: snprintf(r->code, sizeof(r->code), "Conflict"); break;
    case 412: snprintf(r->code, sizeof(r->code), "PreconditionFailed"); break;
    case 405: snprintf(r->code, sizeof(r->code), "MethodNotAllowed"); break;
    case 501: snprintf(r->code, sizeof(r->code), "MethodNotAllowed"); break;
    default: snprintf(r->code, sizeof(r->code), "%d", r->status);
    }
  }
  if (!r->message[0]) {
    if (strcmp(r->code, "NoSuchKey") == 0) snprintf(r->message, sizeof(r->message), "The specified key does not exist.");
    else if (strcmp(r->code, "NoSuchBucket") == 0) snprintf(r->message, sizeof(r->message), "The specified bucket does not exist");
    else if (strcmp(r->code, "AccessDenied") == 0) snprintf(r->message, sizeof(r->message), "Access Denied.");
    else snprintf(r->message, sizeof(r->message), "%s", r->code);
  }
}

typedef struct {
  const uint8_t *p;
  size_t n, off;
} memrd;

static long mem_read(void *ud, void *buf, size_t n) {
  memrd *m = ud;
  size_t k = BUCKETS_MIN(n, m->n - m->off);
  memcpy(buf, m->p + m->off, k);
  m->off += k;
  return (long)k;
}

static buckets_http_stream *send_req(buckets_s3c *c, const char *method, const char *bucket, const char *object,
                                     const char *query, const buckets_http_kv *hdrs, size_t nhdrs,
                                     const char *payload_hash, buckets_http_read_fn rd, void *rd_ud, int64_t body_len,
                                     buckets_s3c_result *res) {
  memset(res, 0, sizeof(*res));
  buckets_buf path = BUCKETS_BUF_INIT;
  build_path(&path, bucket, object);
  buckets_http_kv all[BUCKETS_SIGN_MAX_HEADERS];
  size_t n = 0;
  all[n++] = (buckets_http_kv){"User-Agent", c->user_agent};
  for (size_t i = 0; i < nhdrs && n < BUCKETS_SIGN_MAX_HEADERS - 8; i++) all[n++] = hdrs[i];
  buckets_sigv4_creds cr = {c->access_key, c->secret_key, c->session_token, c->region, "s3"};
  buckets_sigv4_signed sg;
  buckets_http_stream *s = NULL;
  if (!buckets_sigv4_sign(&cr, method, path.data, query, c->host_header, all, n, payload_hash, time(NULL), &sg)) {
    snprintf(res->message, sizeof(res->message), "too many request headers");
    goto out;
  }
  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_append(&target, path.data, path.len);
  if (query && *query) {
    buckets_buf_append_char(&target, '?');
    buckets_buf_append_c(&target, query);
  }
  buckets_buf_append_char(&target, '\0');
  s = buckets_http_client_open(c->http, method, target.data, sg.kv, sg.n, rd, rd_ud, body_len, &res->status,
                               &res->headers);
  buckets_buf_free(&target);
  if (!s) {
    res->status = 0;
    res->network = true;
    const char *de = buckets_http_client_dial_error(c->http);
    if (de && *de) snprintf(res->message, sizeof(res->message), "%s", de);
    else snprintf(res->message, sizeof(res->message), "connection to %s failed", c->endpoint);
  }
out:
  buckets_buf_free(&path);
  return s;
}

static bool read_all(buckets_http_stream *s, buckets_s3c_result *res) {
  char buf[65536];
  for (;;) {
    long r = buckets_http_stream_read(s, buf, sizeof(buf));
    if (r == 0) break;
    if (r < 0) {
      res->network = true;
      snprintf(res->message, sizeof(res->message), "unexpected EOF");
      buckets_http_stream_free(s);
      return false;
    }
    buckets_buf_append(&res->body, buf, (size_t)r);
  }
  buckets_http_stream_free(s);
  if (res->body.data) res->body.data[res->body.len] = '\0';
  return true;
}

bool buckets_s3c_do(buckets_s3c *c, const char *method, const char *bucket, const char *object, const char *query,
                    const buckets_http_kv *hdrs, size_t nhdrs, const void *body, size_t body_len,
                    buckets_s3c_result *res) {
  uint8_t dg[32];
  char hash[65];
  buckets_sha256(body ? body : "", body_len, dg);
  buckets_hex_encode(dg, 32, hash);
  memrd m = {body, body_len, 0};
  buckets_http_stream *s = send_req(c, method, bucket, object, query, hdrs, nhdrs, hash, body_len ? mem_read : NULL,
                                    &m, (int64_t)body_len, res);
  if (!s) return false;
  if (!read_all(s, res)) {
    res->status = 0;
    return false;
  }
  parse_error(res, bucket, object);
  return buckets_s3c_ok(res);
}

bool buckets_s3c_do_stream(buckets_s3c *c, const char *method, const char *bucket, const char *object,
                           const char *query, const buckets_http_kv *hdrs, size_t nhdrs, buckets_http_read_fn rd,
                           void *rd_ud, int64_t body_len, buckets_s3c_result *res) {
  buckets_http_stream *s =
      send_req(c, method, bucket, object, query, hdrs, nhdrs, "UNSIGNED-PAYLOAD", rd, rd_ud, body_len, res);
  if (!s) return false;
  if (!read_all(s, res)) {
    res->status = 0;
    return false;
  }
  parse_error(res, bucket, object);
  return buckets_s3c_ok(res);
}

buckets_http_stream *buckets_s3c_open(buckets_s3c *c, const char *method, const char *bucket, const char *object,
                                      const char *query, const buckets_http_kv *hdrs, size_t nhdrs,
                                      buckets_s3c_result *res) {
  static const char empty_hash[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  buckets_http_stream *s = send_req(c, method, bucket, object, query, hdrs, nhdrs, empty_hash, NULL, NULL, 0, res);
  if (!s) return NULL;
  if (!buckets_s3c_ok(res)) {
    read_all(s, res);
    parse_error(res, bucket, object);
    return NULL;
  }
  return s;
}

bool buckets_s3c_health(buckets_s3c *c, const char *which, int timeout_ms, buckets_s3c_result *res) {
  memset(res, 0, sizeof(*res));
  (void)timeout_ms; /* bounded by the client's socket timeout */
  char target[128];
  snprintf(target, sizeof(target), "/minio/health/%s", which);
  buckets_http_kv h[] = {{"User-Agent", c->user_agent}};
  buckets_http_stream *s = buckets_http_client_open(c->http, "GET", target, h, 1, NULL, NULL, 0, &res->status, &res->headers);
  if (!s) {
    res->status = 0;
    res->network = true;
    const char *de = buckets_http_client_dial_error(c->http);
    snprintf(res->message, sizeof(res->message), "%s", de && *de ? de : "connection failed");
    return false;
  }
  read_all(s, res);
  return res->status == 200;
}
