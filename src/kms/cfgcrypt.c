/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "kms/cfgcrypt.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "core/common.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/estream.h"
#include "notify/event.h"

#define META_BUCKET ".minio.sys"

static void context_of(const char *value, buckets_buf *out) {
  const char *keys[] = {META_BUCKET}, *vals[] = {value};
  buckets_kms_context_text(keys, vals, 1, out);
}

bool buckets_cfgcrypt_seal(buckets_kms *k, const char *path, const void *data, size_t n, buckets_buf *out) {
  buckets_buf ctx = BUCKETS_BUF_INIT, full = BUCKETS_BUF_INIT, ct = BUCKETS_BUF_INIT, meta = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&full, META_BUCKET "/%s", path);
  context_of(full.data, &ctx);
  uint8_t key[32], nonce[8];
  char key_id[256];
  bool ok = buckets_kms_generate(k, NULL, ctx.data, key, &ct, key_id, sizeof(key_id)) == BUCKETS_KMS_OK;
  if (ok) {
    buckets_random(nonce, sizeof(nonce));
    char *kb = buckets_xmalloc(4 * (ct.len / 3 + 2) + 1), nb[16];
    buckets_base64_encode((const uint8_t *)ct.data, ct.len, kb);
    buckets_base64_encode(nonce, sizeof(nonce), nb);
    buckets_buf_append_c(&meta, "{\"keyid\":");
    buckets_json_go_string(&meta, key_id, strlen(key_id));
    buckets_buf_appendf(&meta, ",\"kmskey\":\"%s\",\"algorithm\":\"AES-256-GCM\",\"nonce\":\"%s\"}", kb, nb);
    free(kb);
    uint8_t hdr[5] = {1, (uint8_t)meta.len, (uint8_t)(meta.len >> 8), (uint8_t)(meta.len >> 16),
                      (uint8_t)(meta.len >> 24)};
    buckets_buf_append(out, hdr, sizeof(hdr));
    buckets_buf_append(out, meta.data, meta.len);
    buckets_sio_stream_seal(key, nonce, data, n, out);
    OPENSSL_cleanse(key, sizeof(key));
  }
  buckets_buf_free(&ctx);
  buckets_buf_free(&full);
  buckets_buf_free(&ct);
  buckets_buf_free(&meta);
  return ok;
}

static bool open_with(buckets_kms *k, const char *ctxval, const char *key_id, const uint8_t *kmskey, size_t kn,
                      int alg, const uint8_t nonce[8], const uint8_t *body, size_t bn, buckets_buf *out) {
  buckets_buf ctx = BUCKETS_BUF_INIT;
  context_of(ctxval, &ctx);
  uint8_t key[32];
  bool ok = buckets_kms_decrypt(k, key_id, kmskey, kn, ctx.data, key) == BUCKETS_KMS_OK;
  buckets_buf_free(&ctx);
  if (!ok) return false;
  buckets_buf plain = BUCKETS_BUF_INIT;
  ok = buckets_sio_stream_open(alg, key, nonce, body, bn, &plain);
  OPENSSL_cleanse(key, sizeof(key));
  if (ok) buckets_buf_append(out, plain.data ? plain.data : "", plain.len);
  if (plain.data) OPENSSL_cleanse(plain.data, plain.len);
  buckets_buf_free(&plain);
  return ok;
}

bool buckets_cfgcrypt_open(buckets_kms *k, const char *path, const void *data, size_t n, buckets_buf *out) {
  const uint8_t *p = data;
  if (n < 5 || p[0] != 1) return false;
  uint32_t ml = (uint32_t)p[1] | (uint32_t)p[2] << 8 | (uint32_t)p[3] << 16 | (uint32_t)p[4] << 24;
  if (ml > (1u << 20) || 5 + (size_t)ml > n) return false;
  yyjson_doc *d = yyjson_read((const char *)p + 5, ml, 0);
  yyjson_val *r = d ? yyjson_doc_get_root(d) : NULL;
  const char *key_id = yyjson_get_str(yyjson_obj_get(r, "keyid")), *kb = yyjson_get_str(yyjson_obj_get(r, "kmskey"));
  const char *alg = yyjson_get_str(yyjson_obj_get(r, "algorithm")), *nb = yyjson_get_str(yyjson_obj_get(r, "nonce"));
  bool ok = false;
  if (key_id && kb && alg && nb) {
    int a = !strcmp(alg, "AES-256-GCM") ? BUCKETS_AEAD_AES_256_GCM
            : !strcmp(alg, "ChaCha20-Poly1305") ? BUCKETS_AEAD_CHACHA20_POLY1305
                                                 : -1;
    size_t kl = strlen(kb);
    uint8_t *kmskey = buckets_xmalloc(kl + 3), nonce[16];
    long kn = buckets_base64_decode(kb, kl, kmskey);
    long nn = strlen(nb) < 20 ? buckets_base64_decode(nb, strlen(nb), nonce) : -1;
    if (a >= 0 && kn >= 0 && nn == 8) {
      buckets_buf full = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&full, META_BUCKET "/%s", path);
      ok = open_with(k, full.data, key_id, kmskey, (size_t)kn, a, nonce, p + 5 + ml, n - 5 - ml, out) ||
           open_with(k, path, key_id, kmskey, (size_t)kn, a, nonce, p + 5 + ml, n - 5 - ml, out);
      buckets_buf_free(&full);
    }
    free(kmskey);
  }
  yyjson_doc_free(d);
  return ok;
}
