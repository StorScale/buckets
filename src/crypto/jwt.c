/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/jwt.h"

#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/base64.h"

static const char k_header[] = "{\"alg\":\"HS512\",\"typ\":\"JWT\"}";

static void b64url(buckets_buf *out, const void *p, size_t n) {
  char *tmp = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
  buckets_base64url_raw_encode(p, n, tmp);
  buckets_buf_append_c(out, tmp);
  free(tmp);
}

void buckets_jwt_sign(const char *claims_json, size_t n, const char *key, buckets_buf *out) {
  buckets_buf_reset(out);
  b64url(out, k_header, sizeof(k_header) - 1);
  buckets_buf_append_c(out, ".");
  b64url(out, claims_json, n);
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int maclen = 0;
  HMAC(EVP_sha512(), key, (int)strlen(key), (const unsigned char *)out->data, out->len, mac, &maclen);
  buckets_buf_append_c(out, ".");
  b64url(out, mac, maclen);
}

/* Decodes one unpadded base64url segment into a NUL-terminated buffer. */
static uint8_t *seg_decode(const char *p, size_t n, size_t *outlen) {
  uint8_t *buf = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64url_raw_decode(p, n, buf);
  if (k < 0) {
    free(buf);
    return NULL;
  }
  buf[k] = '\0';
  *outlen = (size_t)k;
  return buf;
}

/* jwt-go v4 MapClaims.Verify*: a present claim must be a number (or a
 * json.Number); absent claims pass. */
static bool time_claim_ok(yyjson_val *root, const char *name, long long now, int want_cmp) {
  yyjson_val *v = yyjson_obj_get(root, name);
  if (!v || yyjson_is_null(v)) return true;
  if (!yyjson_is_num(v)) return false;
  double t = yyjson_get_num(v);
  /* exp: now < exp; iat and nbf: now >= claim. */
  if (want_cmp > 0) return (double)now < t;
  return (double)now >= floor(t);
}

yyjson_doc *buckets_jwt_verify(const char *token, const char *key, long long now) {
  if (!token || !*token || !key || !*key) return NULL;
  const char *d1 = strchr(token, '.');
  const char *d2 = strrchr(token, '.');
  if (!d1 || d1 == d2 || memchr(d1 + 1, '.', (size_t)(d2 - d1 - 1))) return NULL;

  size_t hlen;
  uint8_t *hdr = seg_decode(token, (size_t)(d1 - token), &hlen);
  if (!hdr) return NULL;
  const EVP_MD *md = NULL;
  yyjson_doc *hd = yyjson_read((const char *)hdr, hlen, 0);
  free(hdr);
  const char *alg = hd ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(hd), "alg")) : NULL;
  if (alg && strcmp(alg, "HS256") == 0) md = EVP_sha256();
  else if (alg && strcmp(alg, "HS384") == 0) md = EVP_sha384();
  else if (alg && strcmp(alg, "HS512") == 0) md = EVP_sha512();
  yyjson_doc_free(hd);
  if (!md) return NULL;

  size_t clen;
  uint8_t *cl = seg_decode(d1 + 1, (size_t)(d2 - d1 - 1), &clen);
  if (!cl) return NULL;
  yyjson_doc *claims = yyjson_read((const char *)cl, clen, 0);
  free(cl);
  if (!claims || !yyjson_is_obj(yyjson_doc_get_root(claims))) goto fail;

  size_t slen;
  uint8_t *sig = seg_decode(d2 + 1, strlen(d2 + 1), &slen);
  if (!sig) goto fail;
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int maclen = 0;
  HMAC(md, key, (int)strlen(key), (const unsigned char *)token, (size_t)(d2 - token), mac, &maclen);
  bool sig_ok = slen == maclen && CRYPTO_memcmp(sig, mac, maclen) == 0;
  free(sig);
  if (!sig_ok) goto fail;

  yyjson_val *root = yyjson_doc_get_root(claims);
  if (!time_claim_ok(root, "exp", now, 1) || !time_claim_ok(root, "iat", now, -1) ||
      !time_claim_ok(root, "nbf", now, -1)) {
    goto fail;
  }
  const char *ak = yyjson_get_str(yyjson_obj_get(root, "accessKey"));
  if (!ak) ak = yyjson_get_str(yyjson_obj_get(root, "sub"));
  if (!ak || !*ak) goto fail;
  return claims;

fail:
  yyjson_doc_free(claims);
  return NULL;
}
