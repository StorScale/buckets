/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/query.h"
#include "core/timefmt.h"
#include "crypto/hex.h"
#include "crypto/madmin.h"
#include "crypto/sha256.h"
#include "net/client.h"
#include "s3/sigv4.h"

#define REGION "us-east-1"

struct s3c {
  buckets_http_client *http;
  buckets_tls_client *tls;
  char *host; /* as sent in Host: host:port */
  char *ak, *sk;
};

s3c *s3c_new(const char *url, const char *ca_file, const char *access_key, const char *secret_key, char *err,
             size_t errlen) {
  bool secure = strncmp(url, "https://", 8) == 0;
  if (!secure && strncmp(url, "http://", 7) != 0) {
    snprintf(err, errlen, "unsupported endpoint %s", url);
    return NULL;
  }
  const char *h = url + (secure ? 8 : 7);
  size_t hl = strcspn(h, "/");
  char hostport[256];
  snprintf(hostport, sizeof(hostport), "%.*s", (int)hl, h);
  char *colon = strrchr(hostport, ':');
  int port = secure ? 443 : 80;
  if (colon && !strchr(colon, ']')) {
    port = atoi(colon + 1);
    *colon = '\0';
  }
  s3c *c = buckets_xcalloc(1, sizeof(*c));
  if (secure && !(c->tls = buckets_tls_client_new(ca_file, err, errlen))) {
    free(c);
    return NULL;
  }
  c->http = buckets_http_client_new(hostport, port, c->tls, 15000);
  char hp[300];
  snprintf(hp, sizeof(hp), "%s:%d", hostport, port);
  c->host = buckets_xstrdup(hp);
  c->ak = buckets_xstrdup(access_key);
  c->sk = buckets_xstrdup(secret_key);
  return c;
}

void s3c_free(s3c *c) {
  if (!c) return;
  buckets_http_client_free(c->http);
  buckets_tls_client_free(c->tls);
  free(c->host);
  free(c->ak);
  free(c->sk);
  free(c);
}

int s3c_request(s3c *c, const char *method, const char *path, const char *query, const char *content_type,
                const void *body, size_t len, buckets_buf *out) {
  time_t now = time(NULL);
  char amz[BUCKETS_TIME_AMZ_LEN + 1];
  buckets_time_amz(now, amz);
  uint8_t sum[32];
  char payload[65];
  buckets_sha256(body ? body : "", len, sum);
  buckets_hex_encode(sum, 32, payload);

  buckets_buf curi = BUCKETS_BUF_INIT, cq = BUCKETS_BUF_INIT, creq = BUCKETS_BUF_INIT;
  buckets_sigv4_canonical_uri(buckets_str_c(path), &curi);
  buckets_query q = {0};
  if (query && *query) buckets_query_parse(buckets_str_c(query), &q);
  buckets_sigv4_canonical_query(&q, false, &cq);
  buckets_query_free(&q);
  buckets_buf_appendf(&creq, "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\n"
                             "host;x-amz-content-sha256;x-amz-date\n%s",
                      method, curi.data ? curi.data : "/", cq.data ? cq.data : "", c->host, payload, amz, payload);
  char date8[9];
  memcpy(date8, amz, 8);
  date8[8] = '\0';
  char scope[64];
  snprintf(scope, sizeof(scope), "%s/" REGION "/s3/aws4_request", date8);
  buckets_sha256(creq.data, creq.len, sum);
  char creq_hash[65];
  buckets_hex_encode(sum, 32, creq_hash);
  char sts[256];
  snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amz, scope, creq_hash);
  uint8_t key[32], mac[32];
  buckets_sigv4_signing_key(c->sk, buckets_str_c(date8), buckets_str_c(REGION), "s3", key);
  buckets_hmac_sha256(key, 32, sts, strlen(sts), mac);
  char sig[65];
  buckets_hex_encode(mac, 32, sig);
  char auth[512];
  snprintf(auth, sizeof(auth),
           "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", c->ak,
           scope, sig);

  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&target, path);
  if (query && *query) buckets_buf_appendf(&target, "?%s", query);
  buckets_http_kv h[4] = {{"Authorization", auth}, {"X-Amz-Date", amz}, {"X-Amz-Content-Sha256", payload}};
  size_t nh = 3;
  if (content_type) h[nh++] = (buckets_http_kv){"Content-Type", content_type};
  buckets_http_result r;
  int status = 0;
  if (buckets_http_client_do(c->http, method, target.data, h, nh, body, len, &r)) {
    status = r.status;
    if (out) {
      buckets_buf_reset(out);
      buckets_buf_append(out, r.body.data ? r.body.data : "", r.body.len);
    }
    buckets_http_result_free(&r);
  }
  buckets_buf_free(&target);
  buckets_buf_free(&curi);
  buckets_buf_free(&cq);
  buckets_buf_free(&creq);
  return status;
}

int s3c_admin(s3c *c, const char *method, const char *api, const char *query, const void *body, size_t len,
              bool encrypt, bool decrypt, buckets_buf *out) {
  char path[256];
  snprintf(path, sizeof(path), "/minio/admin/v3/%s", api);
  buckets_buf enc = BUCKETS_BUF_INIT;
  if (encrypt && !buckets_madmin_encrypt(c->sk, body ? body : "", len, &enc)) return 0;
  buckets_buf raw = BUCKETS_BUF_INIT;
  int st = s3c_request(c, method, path, query, encrypt ? "application/octet-stream" : NULL, encrypt ? enc.data : body,
                       encrypt ? enc.len : len, &raw);
  buckets_buf_free(&enc);
  if (out) {
    buckets_buf_reset(out);
    if (st == 200 && decrypt) {
      if (!buckets_madmin_decrypt(c->sk, raw.data, raw.len, out)) st = 0;
    } else {
      buckets_buf_append(out, raw.data ? raw.data : "", raw.len);
    }
  }
  buckets_buf_free(&raw);
  return st;
}

void s3c_error_code(const buckets_buf *body, char *out, size_t cap) {
  *out = '\0';
  if (!body || !body->len) return;
  yyjson_doc *d = yyjson_read(body->data, body->len, 0);
  const char *code = d ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "Code")) : NULL;
  if (code) {
    snprintf(out, cap, "%s", code);
  } else {
    const char *a = strstr(body->data, "<Code>"), *b = a ? strstr(a, "</Code>") : NULL;
    if (a && b) snprintf(out, cap, "%.*s", (int)(b - a - 6), a + 6);
  }
  yyjson_doc_free(d);
}
