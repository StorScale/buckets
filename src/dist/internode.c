/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/internode.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"

#define MAX_SKEW_SECONDS (15 * 60)

static uint8_t g_key[32];

void buckets_internode_set_secret(const char *root_user, const char *root_password) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "buckets-internode-v1\n%s\n%s", root_user, root_password);
  buckets_sha256(b.data, b.len, g_key);
  buckets_buf_free(&b);
}

static void mac(long long ts, const char *method, size_t mlen, const char *target, size_t tlen, char hex[65]) {
  buckets_buf msg = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&msg, "%lld\n%.*s\n%.*s", ts, (int)mlen, method, (int)tlen, target);
  uint8_t h[32];
  buckets_hmac_sha256(g_key, sizeof(g_key), msg.data, msg.len, h);
  buckets_hex_encode(h, 32, hex);
  buckets_buf_free(&msg);
}

void buckets_internode_sign(const char *method, const char *target, char out[96]) {
  long long ts = (long long)time(NULL);
  char hex[65];
  mac(ts, method, strlen(method), target, strlen(target), hex);
  snprintf(out, 96, "%lld:%s", ts, hex);
}

static _Atomic uint64_t g_in_msgs, g_in_bytes;

void buckets_internode_incoming(uint64_t *msgs, uint64_t *bytes) {
  *msgs = atomic_load(&g_in_msgs);
  *bytes = atomic_load(&g_in_bytes);
}

bool buckets_internode_verify(const buckets_http_request *req) {
  buckets_str v = buckets_http_header_get(req, BUCKETS_INTERNODE_AUTH);
  if (!v.p || v.n < 66 || v.n > 90) return false;
  char tmp[96];
  memcpy(tmp, v.p, v.n);
  tmp[v.n] = '\0';
  char *colon = strchr(tmp, ':');
  if (!colon || strlen(colon + 1) != 64) return false;
  *colon = '\0';
  char *end;
  long long ts = strtoll(tmp, &end, 10);
  if (*end) return false;
  long long now = (long long)time(NULL);
  if (ts < now - MAX_SKEW_SECONDS || ts > now + MAX_SKEW_SECONDS) return false;
  char want[65];
  mac(ts, req->method.p, req->method.n, req->target.p, req->target.n, want);
  bool ok = buckets_ct_equal(want, colon + 1, 64);
  if (ok) {
    atomic_fetch_add(&g_in_msgs, 1);
    if (req->body_len > 0) atomic_fetch_add(&g_in_bytes, (uint64_t)req->body_len);
  }
  return ok;
}
