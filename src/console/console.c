/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "console/console.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/log.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/madmin.h"
#include "crypto/sha256.h"
#include "s3/sign.h"

#define COOKIE_NAME "buckets-session"
#define COOKIE_AD "buckets-console-v1"
#define MAX_JSON_BODY (1 << 20)

struct buckets_console {
  buckets_console_config cfg;
  buckets_http_client *http;
  char host_header[300];
  uint8_t key[32];
};

buckets_console *buckets_console_new(const buckets_console_config *cfg) {
  buckets_console *c = buckets_xcalloc(1, sizeof(*c));
  c->cfg = *cfg;
  if (c->cfg.sts_duration <= 0) c->cfg.sts_duration = 3600;
  if (!c->cfg.region || !*c->cfg.region) c->cfg.region = "us-east-1";
  c->http = buckets_http_client_new(cfg->upstream_host, cfg->upstream_port, cfg->upstream_tls, 5 * 60 * 1000);
  snprintf(c->host_header, sizeof(c->host_header), "%s:%d", cfg->upstream_host, cfg->upstream_port);
  /* MinIO console: the cookie key comes from CONSOLE_PBKDF_PASSPHRASE/SALT;
   * without them every restart (and every replica) gets its own key. */
  if (cfg->passphrase && *cfg->passphrase) {
    const char *salt = cfg->salt && *cfg->salt ? cfg->salt : "buckets-console";
    PKCS5_PBKDF2_HMAC(cfg->passphrase, (int)strlen(cfg->passphrase), (const unsigned char *)salt, (int)strlen(salt),
                      4096, EVP_sha256(), 32, c->key);
  } else {
    buckets_random(c->key, sizeof(c->key));
    buckets_log_warn("console: CONSOLE_PBKDF_PASSPHRASE is not set; sessions end when this process does");
  }
  return c;
}

void buckets_console_free(buckets_console *c) {
  if (!c) return;
  buckets_http_client_free(c->http);
  OPENSSL_cleanse(c->key, sizeof(c->key));
  free(c);
}

/* ---- sessions ---------------------------------------------------------------- */

bool buckets_console_seal(const buckets_console *c, const buckets_console_session *s, buckets_buf *cookie) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "ak", s->access_key);
  yyjson_mut_obj_add_str(d, o, "sk", s->secret_key);
  yyjson_mut_obj_add_str(d, o, "st", s->session_token);
  yyjson_mut_obj_add_str(d, o, "user", s->user);
  yyjson_mut_obj_add_int(d, o, "exp", s->expires);
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  if (!json) return false;
  size_t total = BUCKETS_AEAD_NONCE + n + BUCKETS_AEAD_TAG;
  uint8_t *raw = buckets_xmalloc(total);
  buckets_random(raw, BUCKETS_AEAD_NONCE);
  bool ok = buckets_aead_seal1(BUCKETS_AEAD_AES_256_GCM, c->key, raw, COOKIE_AD, strlen(COOKIE_AD), json, n,
                               raw + BUCKETS_AEAD_NONCE);
  OPENSSL_cleanse(json, n);
  free(json);
  if (ok) {
    char *enc = buckets_xmalloc(total * 4 / 3 + 8);
    buckets_base64url_raw_encode(raw, total, enc);
    buckets_buf_append_c(cookie, enc);
    free(enc);
  }
  free(raw);
  return ok;
}

static void copy_str(yyjson_val *o, const char *k, char *out, size_t cap) {
  const char *v = yyjson_get_str(yyjson_obj_get(o, k));
  snprintf(out, cap, "%s", v ? v : "");
}

bool buckets_console_open(const buckets_console *c, const char *cookie, size_t n, buckets_console_session *s) {
  memset(s, 0, sizeof(*s));
  if (n > 16384) return false;
  uint8_t *raw = buckets_xmalloc(n + 4);
  long rn = buckets_base64url_raw_decode(cookie, n, raw);
  bool ok = rn > BUCKETS_AEAD_NONCE + BUCKETS_AEAD_TAG;
  char *json = NULL;
  size_t jn = 0;
  if (ok) {
    jn = (size_t)rn - BUCKETS_AEAD_NONCE - BUCKETS_AEAD_TAG;
    json = buckets_xmalloc(jn + 1);
    ok = buckets_aead_open1(BUCKETS_AEAD_AES_256_GCM, c->key, raw, COOKIE_AD, strlen(COOKIE_AD), raw + BUCKETS_AEAD_NONCE,
                            (size_t)rn - BUCKETS_AEAD_NONCE, (uint8_t *)json);
  }
  yyjson_doc *d = ok ? yyjson_read(json, jn, 0) : NULL;
  yyjson_val *o = d ? yyjson_doc_get_root(d) : NULL;
  if (yyjson_is_obj(o)) {
    copy_str(o, "ak", s->access_key, sizeof(s->access_key));
    copy_str(o, "sk", s->secret_key, sizeof(s->secret_key));
    copy_str(o, "st", s->session_token, sizeof(s->session_token));
    copy_str(o, "user", s->user, sizeof(s->user));
    s->expires = yyjson_get_sint(yyjson_obj_get(o, "exp"));
    ok = *s->access_key && *s->secret_key && s->expires > (int64_t)time(NULL);
  } else {
    ok = false;
  }
  yyjson_doc_free(d);
  if (json) OPENSSL_cleanse(json, jn), free(json);
  free(raw);
  if (!ok) memset(s, 0, sizeof(*s));
  return ok;
}

/* The session cookie of a request, if valid. */
static bool request_session(const buckets_console *c, const buckets_http_request *req, buckets_console_session *s) {
  for (size_t i = 0; i < req->nheaders; i++) {
    if (!buckets_str_ieq_c(req->headers[i].name, "Cookie")) continue;
    buckets_str rest = req->headers[i].value, part;
    while (rest.n) {
      buckets_str_cut(rest, ';', &part, &rest);
      part = buckets_str_trim(part);
      buckets_str k, v;
      if (buckets_str_cut(part, '=', &k, &v) && buckets_str_eq_c(k, COOKIE_NAME))
        return buckets_console_open(c, v.p, v.n, s);
    }
  }
  return false;
}

static void set_cookie(const buckets_console *c, buckets_http_response *resp, const char *value, int max_age) {
  buckets_http_resp_headerf(resp, "Set-Cookie", COOKIE_NAME "=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s", value,
                            max_age, c->cfg.secure_cookie ? "; Secure" : "");
}

/* ---- responses ------------------------------------------------------------------ */

static void json_error(buckets_http_response *resp, int status, const char *code, const char *message) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "code", code);
  yyjson_mut_obj_add_str(d, o, "message", message);
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

/* The text of <tag>...</tag> in an XML document. */
static bool xml_text(const char *doc, size_t n, const char *tag, char *out, size_t cap) {
  char open[64], close[64];
  snprintf(open, sizeof(open), "<%s>", tag);
  snprintf(close, sizeof(close), "</%s>", tag);
  const char *a = memmem(doc, n, open, strlen(open));
  if (!a) return false;
  a += strlen(open);
  const char *b = memmem(a, n - (size_t)(a - doc), close, strlen(close));
  if (!b || (size_t)(b - a) >= cap) return false;
  memcpy(out, a, (size_t)(b - a));
  out[b - a] = '\0';
  return true;
}

/* A signed request whose whole reply is buffered (login, admin). */
static bool upstream_call(buckets_console *c, const buckets_sigv4_creds *cr, const char *method, const char *path,
                          const char *query, const buckets_http_kv *hdrs, size_t nhdrs, const void *body, size_t n,
                          buckets_http_result *res) {
  uint8_t sum[32];
  char hash[65];
  buckets_sha256(body ? body : "", n, sum);
  buckets_hex_encode(sum, 32, hash);
  buckets_sigv4_signed sg;
  if (!buckets_sigv4_sign(cr, method, path, query, c->host_header, hdrs, nhdrs, hash, time(NULL), &sg)) return false;
  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&target, path);
  if (query && *query) buckets_buf_appendf(&target, "?%s", query);
  bool ok = buckets_http_client_do(c->http, method, target.data, sg.kv, sg.n, body, n, res);
  buckets_buf_free(&target);
  return ok;
}

/* ---- login ------------------------------------------------------------------------ */

static void handle_login(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp) {
  if (req->body_len > MAX_JSON_BODY || req->body_fd >= 0 || req->pipe) {
    json_error(resp, 400, "InvalidRequest", "request too large");
    return;
  }
  yyjson_doc *d = yyjson_read(req->body.p ? req->body.p : "", req->body.n, 0);
  yyjson_val *o = d ? yyjson_doc_get_root(d) : NULL;
  const char *ak = yyjson_get_str(yyjson_obj_get(o, "accessKey"));
  const char *sk = yyjson_get_str(yyjson_obj_get(o, "secretKey"));
  if (!ak || !sk || !*ak || !*sk) {
    yyjson_doc_free(d);
    json_error(resp, 400, "InvalidRequest", "accessKey and secretKey are required");
    return;
  }
  /* STS AssumeRole with the user's own keys proves them and yields
   * credentials the console can hold instead. */
  char body[128];
  int bn = snprintf(body, sizeof(body), "Action=AssumeRole&Version=2011-06-15&DurationSeconds=%d", c->cfg.sts_duration);
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_sigv4_creds cr = {.access_key = ak, .secret_key = sk, .region = c->cfg.region, .service = "sts"};
  buckets_http_result res;
  bool ok = upstream_call(c, &cr, "POST", "/", NULL, h, 1, body, (size_t)bn, &res);
  if (!ok) {
    yyjson_doc_free(d);
    json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
    return;
  }
  const char *xml = res.body.data ? res.body.data : "";
  buckets_console_session s = {0};
  char exp[64] = "";
  if (res.status == 200 && xml_text(xml, res.body.len, "AccessKeyId", s.access_key, sizeof(s.access_key)) &&
      xml_text(xml, res.body.len, "SecretAccessKey", s.secret_key, sizeof(s.secret_key)) &&
      xml_text(xml, res.body.len, "SessionToken", s.session_token, sizeof(s.session_token))) {
    xml_text(xml, res.body.len, "Expiration", exp, sizeof(exp));
    snprintf(s.user, sizeof(s.user), "%s", ak);
    s.expires = (int64_t)time(NULL) + c->cfg.sts_duration;
    buckets_buf cookie = BUCKETS_BUF_INIT;
    if (buckets_console_seal(c, &s, &cookie)) {
      set_cookie(c, resp, cookie.data, c->cfg.sts_duration);
      resp->status = 204;
    } else {
      json_error(resp, 500, "InternalError", "could not create the session");
    }
    buckets_buf_free(&cookie);
  } else {
    char code[128] = "AccessDenied", msg[512] = "Invalid login";
    xml_text(xml, res.body.len, "Code", code, sizeof(code));
    xml_text(xml, res.body.len, "Message", msg, sizeof(msg));
    json_error(resp, res.status >= 500 ? 502 : 401, code, msg);
  }
  OPENSSL_cleanse(&s, sizeof(s));
  buckets_http_result_free(&res);
  yyjson_doc_free(d);
}

static void handle_session(buckets_http_response *resp, const buckets_console_session *s) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "accessKey", s->user);
  yyjson_mut_obj_add_int(d, o, "expiresAt", s->expires);
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = 200;
  buckets_http_resp_header(resp, "Content-Type", "application/json");
  buckets_http_resp_header(resp, "Cache-Control", "no-store");
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

/* ---- the proxy -------------------------------------------------------------------------- */

/* Request headers passed to bucketsd (the rest, including cookies, stay here). */
static bool forward_request_header(buckets_str name) {
  static const char *const allow[] = {"Content-Type", "Content-MD5", "Range", "If-Match", "If-None-Match",
                                      "If-Modified-Since", "If-Unmodified-Since", "Cache-Control", "Content-Disposition",
                                      "Content-Encoding", "Content-Language", "Expires"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(allow); i++)
    if (buckets_str_ieq_c(name, allow[i])) return true;
  if (name.n > 6 && strncasecmp(name.p, "x-amz-", 6) == 0) {
    static const char *const own[] = {"x-amz-date", "x-amz-content-sha256", "x-amz-security-token"};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(own); i++)
      if (buckets_str_ieq_c(name, own[i])) return false;
    return true;
  }
  return name.n > 8 && strncasecmp(name.p, "x-minio-", 8) == 0;
}

/* Response headers passed back to the browser. */
static bool forward_response_header(const char *name, size_t n) {
  static const char *const allow[] = {"Content-Type", "ETag", "Last-Modified", "Content-Range", "Accept-Ranges",
                                      "Content-Disposition", "Content-Encoding", "Content-Language", "Cache-Control",
                                      "Expires"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(allow); i++)
    if (strlen(allow[i]) == n && strncasecmp(name, allow[i], n) == 0) return true;
  return (n > 6 && strncasecmp(name, "x-amz-", 6) == 0) || (n > 8 && strncasecmp(name, "x-minio-", 8) == 0);
}

static void copy_response_headers(const buckets_buf *headers, buckets_http_response *resp) {
  const char *p = headers->data, *end = p ? p + headers->len : NULL;
  while (p && p < end) {
    const char *eol = memchr(p, '\n', (size_t)(end - p));
    if (!eol) eol = end;
    const char *colon = memchr(p, ':', (size_t)(eol - p));
    if (colon && forward_response_header(p, (size_t)(colon - p))) {
      const char *v = colon + 1, *ve = eol;
      while (v < ve && *v == ' ') v++;
      while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ')) ve--;
      char name[128], value[4096];
      snprintf(name, sizeof(name), "%.*s", (int)(colon - p), p);
      snprintf(value, sizeof(value), "%.*s", (int)(ve - v), v);
      buckets_http_resp_header(resp, name, value);
    }
    p = eol + 1;
  }
}

typedef struct {
  buckets_http_body_cursor cur;
} body_src;

static long body_read(void *ud, void *buf, size_t n) { return buckets_http_body_read(&((body_src *)ud)->cur, buf, n); }

static long stream_body(void *ud, char *buf, size_t cap) { return buckets_http_stream_read(ud, buf, cap); }

static void proxy(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp,
                  const buckets_console_session *s, const char *upstream_path) {
  char method[16];
  snprintf(method, sizeof(method), "%.*s", (int)req->method.n, req->method.p);
  char *query = buckets_str_dup(req->query);
  buckets_http_kv hdrs[BUCKETS_SIGN_MAX_HEADERS];
  size_t nh = 0;
  char *owned[BUCKETS_SIGN_MAX_HEADERS * 2];
  size_t no = 0;
  bool encrypt = false, decrypt = false;
  for (size_t i = 0; i < req->nheaders; i++) {
    buckets_str nm = req->headers[i].name;
    if (buckets_str_ieq_c(nm, "X-Console-Encrypt")) encrypt = buckets_str_eq_c(req->headers[i].value, "1");
    if (buckets_str_ieq_c(nm, "X-Console-Decrypt")) decrypt = buckets_str_eq_c(req->headers[i].value, "1");
    if (!forward_request_header(nm) || nh >= BUCKETS_SIGN_MAX_HEADERS - 5) continue;
    owned[no++] = buckets_str_dup(nm);
    owned[no++] = buckets_str_dup(req->headers[i].value);
    hdrs[nh++] = (buckets_http_kv){owned[no - 2], owned[no - 1]};
  }
  buckets_sigv4_creds cr = {.access_key = s->access_key, .secret_key = s->secret_key,
                            .session_token = s->session_token, .region = c->cfg.region};
  bool in_memory = req->body_fd < 0 && !req->pipe;
  if (encrypt || decrypt || (in_memory && req->body_len <= MAX_JSON_BODY)) {
    /* Small bodies (and every admin call that needs madmin encryption) are
     * signed over their hash and answered from memory. */
    buckets_buf enc = BUCKETS_BUF_INIT;
    const void *body = req->body.p;
    size_t bn = req->body.n;
    if (!in_memory) {
      json_error(resp, 413, "EntityTooLarge", "request body too large");
      goto done;
    }
    if (encrypt) {
      if (!buckets_madmin_encrypt(s->secret_key, body ? body : "", bn, &enc)) {
        json_error(resp, 500, "InternalError", "encryption failed");
        goto done;
      }
      body = enc.data, bn = enc.len;
    }
    if (!encrypt && !decrypt) {
      /* Plain small requests still stream the reply (downloads). */
      uint8_t sum[32];
      char hash[65];
      buckets_sha256(body ? body : "", bn, sum);
      buckets_hex_encode(sum, 32, hash);
      buckets_sigv4_signed sg;
      buckets_buf target = BUCKETS_BUF_INIT, rh = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&target, upstream_path);
      if (*query) buckets_buf_appendf(&target, "?%s", query);
      int status = 0;
      buckets_http_stream *st = NULL;
      if (buckets_sigv4_sign(&cr, method, upstream_path, query, c->host_header, hdrs, nh, hash, time(NULL), &sg)) {
        body_src src = {{.req = req}};
        st = buckets_http_client_open(c->http, method, target.data, sg.kv, sg.n, bn ? body_read : NULL, &src,
                                      (int64_t)bn, &status, &rh);
      }
      if (!st) {
        json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
      } else {
        resp->status = status;
        copy_response_headers(&rh, resp);
        int64_t len = buckets_http_stream_length(st);
        bool head = strcmp(method, "HEAD") == 0;
        if (head) {
          resp->head_only = true;
          const char *cl = buckets_http_headers_get(&rh, "Content-Length", NULL);
          resp->content_length = cl ? strtoll(cl, NULL, 10) : 0;
          resp->stream = stream_body, resp->stream_ud = st, resp->stream_free = buckets_http_stream_free;
        } else if (len >= 0) {
          resp->content_length = len;
          resp->stream = stream_body, resp->stream_ud = st, resp->stream_free = buckets_http_stream_free;
        } else { /* chunked or close-delimited: buffer it */
          char buf[65536];
          long k;
          while ((k = buckets_http_stream_read(st, buf, sizeof(buf))) > 0) buckets_buf_append(&resp->body, buf, (size_t)k);
          buckets_http_stream_free(st);
        }
      }
      buckets_buf_free(&target);
      buckets_buf_free(&rh);
      buckets_buf_free(&enc);
      goto done;
    }
    buckets_http_result res;
    if (!upstream_call(c, &cr, method, upstream_path, query, hdrs, nh, body, bn, &res)) {
      json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
    } else {
      resp->status = res.status;
      if (decrypt && res.status == 200) {
        buckets_buf plain = BUCKETS_BUF_INIT;
        if (buckets_madmin_decrypt(s->secret_key, res.body.data ? res.body.data : "", res.body.len, &plain)) {
          buckets_http_resp_header(resp, "Content-Type", "application/json");
          buckets_buf_append(&resp->body, plain.data ? plain.data : "", plain.len);
        } else {
          json_error(resp, 502, "DecryptionFailed", "could not decrypt the storage service's reply");
        }
        buckets_buf_free(&plain);
      } else {
        copy_response_headers(&res.headers, resp);
        buckets_buf_append(&resp->body, res.body.data ? res.body.data : "", res.body.len);
      }
      buckets_http_result_free(&res);
    }
    buckets_buf_free(&enc);
    goto done;
  }
  {
    /* Large uploads stream through unsigned (UNSIGNED-PAYLOAD). */
    buckets_sigv4_signed sg;
    buckets_buf target = BUCKETS_BUF_INIT, rh = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&target, upstream_path);
    if (*query) buckets_buf_appendf(&target, "?%s", query);
    int status = 0;
    buckets_http_stream *st = NULL;
    body_src src = {{.req = req}};
    if (buckets_sigv4_sign(&cr, method, upstream_path, query, c->host_header, hdrs, nh, "UNSIGNED-PAYLOAD", time(NULL),
                           &sg))
      st = buckets_http_client_open(c->http, method, target.data, sg.kv, sg.n, body_read, &src, req->body_len, &status, &rh);
    if (!st) {
      json_error(resp, 502, "UpstreamUnavailable", "the storage service did not answer");
    } else {
      resp->status = status;
      copy_response_headers(&rh, resp);
      char buf[65536];
      long k;
      while ((k = buckets_http_stream_read(st, buf, sizeof(buf))) > 0) buckets_buf_append(&resp->body, buf, (size_t)k);
      buckets_http_stream_free(st);
    }
    buckets_buf_free(&target);
    buckets_buf_free(&rh);
  }
done:
  for (size_t i = 0; i < no; i++) free(owned[i]);
  free(query);
}

/* ---- static files -------------------------------------------------------------------------- */

static const char *content_type(const char *path) {
  static const struct {
    const char *ext, *type;
  } types[] = {{".html", "text/html; charset=utf-8"}, {".js", "text/javascript; charset=utf-8"},
               {".css", "text/css; charset=utf-8"},   {".json", "application/json"},
               {".svg", "image/svg+xml"},             {".png", "image/png"},
               {".ico", "image/x-icon"},              {".woff2", "font/woff2"},
               {".woff", "font/woff"},                {".txt", "text/plain; charset=utf-8"},
               {".map", "application/json"}};
  const char *dot = strrchr(path, '.');
  for (size_t i = 0; dot && i < BUCKETS_ARRAY_LEN(types); i++)
    if (strcasecmp(dot, types[i].ext) == 0) return types[i].type;
  return "application/octet-stream";
}

static bool read_file(const char *path, buckets_buf *out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return false;
  }
  char buf[65536];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) buckets_buf_append(out, buf, (size_t)n);
  close(fd);
  return n == 0;
}

static void serve_static(buckets_console *c, const buckets_http_request *req, buckets_http_response *resp) {
  if (!c->cfg.web_dir) {
    json_error(resp, 404, "NotFound", "no web console is installed");
    return;
  }
  char rel[1024];
  snprintf(rel, sizeof(rel), "%.*s", (int)req->path.n, req->path.p);
  bool bad = strstr(rel, "..") != NULL || strchr(rel, '\\') != NULL;
  char path[2048];
  snprintf(path, sizeof(path), "%s%s", c->cfg.web_dir, bad || strcmp(rel, "/") == 0 ? "/index.html" : rel);
  buckets_buf body = BUCKETS_BUF_INIT;
  bool asset = strncmp(rel, "/assets/", 8) == 0;
  if (bad || !read_file(path, &body)) {
    buckets_buf_reset(&body);
    /* Client-side routes fall back to the SPA; missing assets are 404. */
    snprintf(path, sizeof(path), "%s/index.html", c->cfg.web_dir);
    if (asset || !read_file(path, &body)) {
      buckets_buf_free(&body);
      json_error(resp, 404, "NotFound", "not found");
      return;
    }
  }
  resp->status = 200;
  buckets_http_resp_header(resp, "Content-Type", content_type(path));
  buckets_http_resp_header(resp, "Cache-Control", asset ? "public, max-age=31536000, immutable" : "no-cache");
  buckets_http_resp_header(resp, "X-Content-Type-Options", "nosniff");
  buckets_http_resp_header(resp, "X-Frame-Options", "DENY");
  buckets_http_resp_header(resp, "Referrer-Policy", "same-origin");
  if (strcmp(content_type(path), "text/html; charset=utf-8") == 0)
    buckets_http_resp_header(resp, "Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; frame-ancestors 'none'");
  resp->head_only = buckets_str_eq_c(req->method, "HEAD");
  buckets_buf_append(&resp->body, body.data ? body.data : "", body.len);
  buckets_buf_free(&body);
}

/* ---- routing -------------------------------------------------------------------------------------- */

void buckets_console_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_console *c = ud;
  buckets_str path = req->path;
  if (buckets_str_eq_c(path, "/healthz")) {
    resp->status = 200;
    buckets_buf_append_c(&resp->body, "ok");
    return;
  }
  if (!buckets_str_has_prefix(path, "/api/")) {
    if (!buckets_str_eq_c(req->method, "GET") && !buckets_str_eq_c(req->method, "HEAD")) {
      json_error(resp, 405, "MethodNotAllowed", "method not allowed");
      return;
    }
    serve_static(c, req, resp);
    return;
  }
  buckets_http_resp_header(resp, "Cache-Control", "no-store");
  bool safe = buckets_str_eq_c(req->method, "GET") || buckets_str_eq_c(req->method, "HEAD");
  if (!safe && !buckets_str_eq_c(buckets_http_header_get(req, "X-Console-Request"), "1")) {
    json_error(resp, 403, "Forbidden", "missing X-Console-Request header");
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/login")) {
    if (!buckets_str_eq_c(req->method, "POST")) json_error(resp, 405, "MethodNotAllowed", "use POST");
    else handle_login(c, req, resp);
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/logout")) {
    set_cookie(c, resp, "", 0);
    resp->status = 204;
    return;
  }
  buckets_console_session s;
  if (!request_session(c, req, &s)) {
    json_error(resp, 401, "Unauthorized", "not logged in");
    return;
  }
  if (buckets_str_eq_c(path, "/api/v1/session")) {
    handle_session(resp, &s);
  } else if (buckets_str_has_prefix(path, "/api/v1/s3/") || buckets_str_eq_c(path, "/api/v1/s3")) {
    char up[4096];
    snprintf(up, sizeof(up), "/%.*s", (int)(path.n > 11 ? path.n - 11 : 0), path.p + 11);
    proxy(c, req, resp, &s, up);
  } else if (buckets_str_has_prefix(path, "/api/v1/admin/")) {
    char up[4096];
    snprintf(up, sizeof(up), "/minio/admin/v3/%.*s", (int)(path.n - 14), path.p + 14);
    proxy(c, req, resp, &s, up);
  } else {
    json_error(resp, 404, "NotFound", "unknown API");
  }
  OPENSSL_cleanse(&s, sizeof(s));
}
