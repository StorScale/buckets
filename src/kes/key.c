/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "kes/key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__linux__) && defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

#include <openssl/crypto.h>
#include <yyjson.h>

#include "core/msgpack.h"
#include "core/timefmt.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/sha256.h"

#define IV_SIZE 16
#define NONCE_SIZE 12
#define RAND_SIZE (IV_SIZE + NONCE_SIZE)

/* ---- keys ------------------------------------------------------------------------ */

static void set_creator(buckets_kes_key *k, const char *created_by) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  k->created_sec = ts.tv_sec;
  k->created_nsec = (int32_t)ts.tv_nsec;
  snprintf(k->created_by, sizeof(k->created_by), "%s", created_by ? created_by : "");
}

/* crypto.DetermineSecretKeyType: AES-256 where Go has AES-GCM in hardware
 * (x86 AES-NI and PCLMULQDQ; arm64 AES and PMULL, as golang.org/x/sys/cpu
 * sees them, which it does not on macOS), else ChaCha20. */
static buckets_kes_cipher default_cipher(void) {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_cpu_init();
  if (__builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul")) return BUCKETS_KES_AES256;
#elif defined(__linux__) && defined(__aarch64__)
  unsigned long hw = getauxval(AT_HWCAP);
  if ((hw & HWCAP_AES) && (hw & HWCAP_PMULL)) return BUCKETS_KES_AES256;
#endif
  return BUCKETS_KES_CHACHA20;
}

void buckets_kes_key_new(buckets_kes_key *k, const char *created_by) {
  memset(k, 0, sizeof(*k));
  k->cipher = default_cipher();
  buckets_random(k->key, 32);
  k->has_hmac = true;
  buckets_random(k->hmac, 32);
  set_creator(k, created_by);
}

static bool parse_cipher(const char *s, buckets_kes_cipher *c) {
  if (!s || !*s || strcmp(s, "AES256") == 0 || strcmp(s, "AES256-GCM_SHA256") == 0) *c = BUCKETS_KES_AES256;
  else if (strcmp(s, "ChaCha20") == 0 || strcmp(s, "XCHACHA20-POLY1305") == 0) *c = BUCKETS_KES_CHACHA20;
  else return false;
  return true;
}

bool buckets_kes_key_import(buckets_kes_key *k, const char *cipher, const uint8_t bytes[32], const char *created_by) {
  memset(k, 0, sizeof(*k));
  if (!cipher || !*cipher || !parse_cipher(cipher, &k->cipher)) return false;
  memcpy(k->key, bytes, 32);
  k->has_hmac = true;
  buckets_random(k->hmac, 32);
  set_creator(k, created_by);
  return true;
}

void buckets_kes_key_wipe(buckets_kes_key *k) { OPENSSL_cleanse(k, sizeof(*k)); }

const char *buckets_kes_cipher_name(buckets_kes_cipher c) { return c == BUCKETS_KES_CHACHA20 ? "ChaCha20" : "AES256"; }

/* ---- protobuf (the few wire types KeyVersion uses) ----------------------------------- */

static void pb_varint(buckets_buf *b, uint64_t v) {
  while (v >= 0x80) {
    buckets_buf_append_char(b, (char)(v | 0x80));
    v >>= 7;
  }
  buckets_buf_append_char(b, (char)v);
}
static void pb_tag(buckets_buf *b, int field, int wire) { pb_varint(b, (uint64_t)(field << 3 | wire)); }
static void pb_bytes(buckets_buf *b, int field, const void *p, size_t n) {
  pb_tag(b, field, 2);
  pb_varint(b, n);
  buckets_buf_append(b, p, n);
}
static void pb_uint(buckets_buf *b, int field, uint64_t v) { /* proto3: zero is left out */
  if (!v) return;
  pb_tag(b, field, 0);
  pb_varint(b, v);
}

void buckets_kes_key_encode(const buckets_kes_key *k, buckets_buf *out) {
  buckets_buf sk = BUCKETS_BUF_INIT, hk = BUCKETS_BUF_INIT, ts = BUCKETS_BUF_INIT, kv = BUCKETS_BUF_INIT;
  pb_bytes(&sk, 1, k->key, 32);
  pb_uint(&sk, 2, (uint64_t)k->cipher);
  if (k->has_hmac) {
    pb_bytes(&hk, 1, k->hmac, 32);
    pb_uint(&hk, 2, 1); /* SHA256 */
  }
  pb_uint(&ts, 1, (uint64_t)k->created_sec);
  pb_uint(&ts, 2, (uint64_t)(uint32_t)k->created_nsec);
  pb_bytes(&kv, 1, sk.data, sk.len);
  pb_bytes(&kv, 2, hk.data ? hk.data : "", hk.len); /* Go writes the (empty) message even without an HMAC key */
  pb_bytes(&kv, 3, ts.data ? ts.data : "", ts.len);
  if (k->created_by[0]) pb_bytes(&kv, 4, k->created_by, strlen(k->created_by));
  size_t at = out->len;
  buckets_buf_reserve(out, kv.len * 4 / 3 + 8);
  buckets_base64_encode((const uint8_t *)kv.data, kv.len, out->data + at);
  out->len = at + strlen(out->data + at);
  OPENSSL_cleanse(sk.data, sk.len);
  OPENSSL_cleanse(hk.data, hk.len);
  OPENSSL_cleanse(kv.data, kv.len);
  buckets_buf_free(&sk);
  buckets_buf_free(&hk);
  buckets_buf_free(&ts);
  buckets_buf_free(&kv);
}

typedef struct {
  const uint8_t *p, *end;
} pbr;

static bool pb_read_varint(pbr *r, uint64_t *v) {
  *v = 0;
  for (int shift = 0; shift < 64 && r->p < r->end; shift += 7) {
    uint8_t c = *r->p++;
    *v |= (uint64_t)(c & 0x7f) << shift;
    if (!(c & 0x80)) return true;
  }
  return false;
}

/* The next field: its number, and either a varint or a length-delimited slice. */
static bool pb_next(pbr *r, int *field, uint64_t *v, pbr *sub) {
  uint64_t tag;
  if (!pb_read_varint(r, &tag)) return false;
  *field = (int)(tag >> 3);
  switch (tag & 7) {
  case 0: return pb_read_varint(r, v);
  case 2:
    if (!pb_read_varint(r, v) || *v > (uint64_t)(r->end - r->p)) return false;
    sub->p = r->p, sub->end = r->p + *v;
    r->p += *v;
    return true;
  case 1:
    if (r->end - r->p < 8) return false;
    r->p += 8, *v = 0;
    return true;
  case 5:
    if (r->end - r->p < 4) return false;
    r->p += 4, *v = 0;
    return true;
  default: return false;
  }
}

static bool pb_key(pbr r, uint8_t key[32], uint64_t *type, bool *have) {
  int f;
  uint64_t v;
  pbr sub;
  while (r.p < r.end) {
    if (!pb_next(&r, &f, &v, &sub)) return false;
    if (f == 1) {
      if (sub.end - sub.p != 32) return false;
      memcpy(key, sub.p, 32);
      *have = true;
    } else if (f == 2) {
      *type = v;
    }
  }
  return true;
}

static bool decode_pb(const uint8_t *p, size_t n, buckets_kes_key *k, char *err, size_t errlen) {
  pbr r = {p, p + n};
  int f;
  uint64_t v;
  pbr sub;
  bool have_key = false;
  while (r.p < r.end) {
    if (!pb_next(&r, &f, &v, &sub)) return snprintf(err, errlen, "malformed key"), false;
    if (f == 1) {
      uint64_t t = 0;
      if (!pb_key(sub, k->key, &t, &have_key)) return snprintf(err, errlen, "malformed secret key"), false;
      if (t != BUCKETS_KES_AES256 && t != BUCKETS_KES_CHACHA20)
        return snprintf(err, errlen, "unsupported secret key type %llu", (unsigned long long)t), false;
      k->cipher = (buckets_kes_cipher)t;
    } else if (f == 2) {
      uint64_t h = 0;
      bool have = false;
      if (!pb_key(sub, k->hmac, &h, &have)) return snprintf(err, errlen, "malformed HMAC key"), false;
      if (have && h != 1) return snprintf(err, errlen, "unsupported HMAC hash %llu", (unsigned long long)h), false;
      k->has_hmac = have;
    } else if (f == 3) {
      while (sub.p < sub.end) {
        int tf;
        uint64_t tv;
        pbr tsub;
        if (!pb_next(&sub, &tf, &tv, &tsub)) return snprintf(err, errlen, "malformed timestamp"), false;
        if (tf == 1) k->created_sec = (int64_t)tv;
        else if (tf == 2) k->created_nsec = (int32_t)tv;
      }
    } else if (f == 4) {
      snprintf(k->created_by, sizeof(k->created_by), "%.*s", (int)(sub.end - sub.p), (const char *)sub.p);
    }
  }
  if (!have_key) return snprintf(err, errlen, "the key has no secret key"), false;
  return true;
}

/* The JSON form before KES 2024. */
static bool decode_json(const char *s, size_t n, buckets_kes_key *k, char *err, size_t errlen) {
  yyjson_doc *d = yyjson_read(s, n, 0);
  yyjson_val *o = yyjson_doc_get_root(d);
  bool ok = false;
  const char *b64 = yyjson_get_str(yyjson_obj_get(o, "bytes"));
  const char *alg = yyjson_get_str(yyjson_obj_get(o, "algorithm"));
  uint8_t raw[64];
  long kn = b64 && strlen(b64) <= 64 ? buckets_base64_decode(b64, strlen(b64), raw) : -1;
  if (!yyjson_is_obj(o)) snprintf(err, errlen, "malformed key");
  else if (kn != 32) snprintf(err, errlen, "invalid key length");
  else if (!parse_cipher(alg, &k->cipher)) snprintf(err, errlen, "unsupported key algorithm '%s'", alg);
  else {
    memcpy(k->key, raw, 32);
    const char *at = yyjson_get_str(yyjson_obj_get(o, "created_at")), *by = yyjson_get_str(yyjson_obj_get(o, "created_by"));
    long long sec;
    long nsec;
    if (at && buckets_time_parse_rfc3339(at, &sec, &nsec)) k->created_sec = sec, k->created_nsec = (int32_t)nsec;
    if (by) snprintf(k->created_by, sizeof(k->created_by), "%s", by);
    ok = true;
  }
  OPENSSL_cleanse(raw, sizeof(raw));
  yyjson_doc_free(d);
  return ok;
}

bool buckets_kes_key_decode(const char *s, size_t n, buckets_kes_key *k, char *err, size_t errlen) {
  memset(k, 0, sizeof(*k));
  while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ')) n--;
  if (n && s[0] == '{') return decode_json(s, n, k, err, errlen);
  uint8_t *raw = buckets_xmalloc(n * 3 / 4 + 4);
  long rn = buckets_base64_decode(s, n, raw);
  bool ok = rn > 0 ? decode_pb(raw, (size_t)rn, k, err, errlen) : (snprintf(err, errlen, "malformed key"), false);
  OPENSSL_cleanse(raw, n * 3 / 4 + 4);
  free(raw);
  if (!ok) buckets_kes_key_wipe(k);
  return ok;
}

/* ---- encryption ----------------------------------------------------------------------- */

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d)                                                                                                 \
  a += b, d ^= a, d = ROTL(d, 16), c += d, b ^= c, b = ROTL(b, 12), a += b, d ^= a, d = ROTL(d, 8), c += d, b ^= c,   \
      b = ROTL(b, 7)

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* HChaCha20 (draft-irtf-cfrg-xchacha): a subkey from key and a 16-byte nonce. */
static void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]) {
  uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  for (int i = 0; i < 8; i++) x[4 + i] = le32(key + 4 * i);
  for (int i = 0; i < 4; i++) x[12 + i] = le32(nonce + 4 * i);
  for (int i = 0; i < 10; i++) {
    QR(x[0], x[4], x[8], x[12]), QR(x[1], x[5], x[9], x[13]), QR(x[2], x[6], x[10], x[14]), QR(x[3], x[7], x[11], x[15]);
    QR(x[0], x[5], x[10], x[15]), QR(x[1], x[6], x[11], x[12]), QR(x[2], x[7], x[8], x[13]), QR(x[3], x[4], x[9], x[14]);
  }
  const int idx[8] = {0, 1, 2, 3, 12, 13, 14, 15};
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 4; j++) out[4 * i + j] = (uint8_t)(x[idx[i]] >> (8 * j));
  OPENSSL_cleanse(x, sizeof(x));
}

static buckets_aead_alg subkey(const buckets_kes_key *k, const uint8_t iv[16], uint8_t key[32]) {
  if (k->cipher == BUCKETS_KES_CHACHA20) {
    hchacha20(k->key, iv, key);
    return BUCKETS_AEAD_CHACHA20_POLY1305;
  }
  buckets_hmac_sha256(k->key, 32, iv, IV_SIZE, key);
  return BUCKETS_AEAD_AES_256_GCM;
}

void buckets_kes_encrypt(const buckets_kes_key *k, const void *pt, size_t n, const void *ctx, size_t nctx,
                         buckets_buf *out) {
  uint8_t rnd[RAND_SIZE], key[32];
  buckets_random(rnd, sizeof(rnd));
  buckets_aead_alg alg = subkey(k, rnd, key);
  size_t at = out->len;
  buckets_buf_reserve(out, n + BUCKETS_AEAD_TAG + RAND_SIZE);
  buckets_aead_seal1(alg, key, rnd + IV_SIZE, ctx, nctx, pt, n, (uint8_t *)out->data + at);
  out->len = at + n + BUCKETS_AEAD_TAG;
  buckets_buf_append(out, rnd, RAND_SIZE);
  OPENSSL_cleanse(key, sizeof(key));
}

/* The older ciphertexts, as bytes || iv || nonce; false if b is neither. */
static bool legacy(const uint8_t *b, size_t n, buckets_buf *out) {
  if (n && b[0] == 0x95) { /* msgpack [algorithm, id, iv, nonce, bytes] */
    buckets_mp_reader r = buckets_mp_reader_init(b, n);
    uint32_t items;
    buckets_str alg, id, iv, nonce, bytes;
    if (!buckets_mp_read_array(&r, &items) || items != 5 || !buckets_mp_read_str(&r, &alg) ||
        !buckets_mp_read_str(&r, &id) || !buckets_mp_read_bin(&r, &iv) || iv.n != IV_SIZE ||
        !buckets_mp_read_bin(&r, &nonce) || nonce.n != NONCE_SIZE || !buckets_mp_read_bin(&r, &bytes) ||
        buckets_mp_remaining(&r) != 0)
      return false;
    buckets_buf_append(out, bytes.p, bytes.n);
    buckets_buf_append(out, iv.p, iv.n);
    buckets_buf_append(out, nonce.p, nonce.n);
    return true;
  }
  if (n && b[0] == '{') { /* JSON {"aead", "id", "iv", "nonce", "bytes"} */
    yyjson_doc *d = yyjson_read((const char *)b, n, 0);
    yyjson_val *o = yyjson_doc_get_root(d);
    const char *alg = yyjson_get_str(yyjson_obj_get(o, "aead"));
    const char *fields[3] = {yyjson_get_str(yyjson_obj_get(o, "bytes")), yyjson_get_str(yyjson_obj_get(o, "iv")),
                             yyjson_get_str(yyjson_obj_get(o, "nonce"))};
    bool ok = alg && (strcmp(alg, "AES-256-GCM-HMAC-SHA-256") == 0 || strcmp(alg, "ChaCha20Poly1305") == 0);
    size_t want[3] = {0, IV_SIZE, NONCE_SIZE};
    for (int i = 0; ok && i < 3; i++) {
      if (!fields[i]) {
        ok = false;
        break;
      }
      size_t fl = strlen(fields[i]);
      uint8_t *raw = buckets_xmalloc(fl * 3 / 4 + 4);
      long rn = buckets_base64_decode(fields[i], fl, raw);
      ok = rn >= 0 && (!want[i] || (size_t)rn == want[i]);
      if (ok) buckets_buf_append(out, raw, (size_t)rn);
      free(raw);
    }
    yyjson_doc_free(d);
    return ok;
  }
  return false;
}

bool buckets_kes_decrypt(const buckets_kes_key *k, const void *ct, size_t n, const void *ctx, size_t nctx,
                         buckets_buf *out) {
  buckets_buf conv = BUCKETS_BUF_INIT;
  const uint8_t *b = ct;
  if (legacy(b, n, &conv)) b = (const uint8_t *)conv.data, n = conv.len;
  bool ok = false;
  if (n >= RAND_SIZE + BUCKETS_AEAD_TAG) {
    const uint8_t *rnd = b + n - RAND_SIZE;
    size_t cn = n - RAND_SIZE;
    if (cn >= BUCKETS_AEAD_TAG) {
      uint8_t key[32];
      buckets_aead_alg alg = subkey(k, rnd, key);
      size_t at = out->len;
      buckets_buf_reserve(out, cn);
      ok = buckets_aead_open1(alg, key, rnd + IV_SIZE, ctx, nctx, b, cn, (uint8_t *)out->data + at);
      if (ok) out->len = at + cn - BUCKETS_AEAD_TAG;
      OPENSSL_cleanse(key, sizeof(key));
    }
  }
  buckets_buf_free(&conv);
  return ok;
}

void buckets_kes_hmac(const buckets_kes_key *k, const void *msg, size_t n, uint8_t out[32]) {
  buckets_hmac_sha256(k->hmac, 32, msg, n, out);
}
