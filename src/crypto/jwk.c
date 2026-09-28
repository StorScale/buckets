/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/jwk.h"

#include <math.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/base64.h"

typedef struct {
  char *kid;
  EVP_PKEY *pkey;   /* asymmetric key */
  char *secret;     /* or an HMAC secret */
  char kind[8];     /* "RSA", "EC", "OKP", "oct" */
} jwk;

struct buckets_jwk_set {
  jwk *k;
  size_t n;
};

buckets_jwk_set *buckets_jwk_set_new(void) { return buckets_xcalloc(1, sizeof(buckets_jwk_set)); }

void buckets_jwk_set_free(buckets_jwk_set *s) {
  if (!s) return;
  for (size_t i = 0; i < s->n; i++) {
    free(s->k[i].kid);
    EVP_PKEY_free(s->k[i].pkey);
    free(s->k[i].secret);
  }
  free(s->k);
  free(s);
}

size_t buckets_jwk_set_count(const buckets_jwk_set *s) { return s->n; }

static void add(buckets_jwk_set *s, const char *kid, EVP_PKEY *pkey, const char *secret, const char *kind) {
  /* A later key with the same kid replaces the earlier one (map semantics). */
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->k[i].kid, kid) == 0) {
      EVP_PKEY_free(s->k[i].pkey);
      free(s->k[i].secret);
      s->k[i].pkey = pkey;
      s->k[i].secret = secret ? buckets_xstrdup(secret) : NULL;
      snprintf(s->k[i].kind, sizeof(s->k[i].kind), "%s", kind);
      return;
    }
  }
  s->k = buckets_xrealloc(s->k, (s->n + 1) * sizeof(jwk));
  jwk *k = &s->k[s->n++];
  k->kid = buckets_xstrdup(kid);
  k->pkey = pkey;
  k->secret = secret ? buckets_xstrdup(secret) : NULL;
  snprintf(k->kind, sizeof(k->kind), "%s", kind);
}

void buckets_jwk_set_add_secret(buckets_jwk_set *s, const char *kid, const char *secret) {
  add(s, kid, NULL, secret, "oct");
}

static uint8_t *b64url(const char *s, size_t *n) {
  if (!s) return NULL;
  size_t len = strlen(s);
  uint8_t *out = buckets_xmalloc(len * 3 / 4 + 4);
  long k = buckets_base64url_raw_decode(s, len, out);
  if (k < 0) {
    free(out);
    return NULL;
  }
  *n = (size_t)k;
  return out;
}

static EVP_PKEY *rsa_key(const char *n64, const char *e64) {
  size_t nn, en;
  uint8_t *n = b64url(n64, &nn), *e = b64url(e64, &en);
  EVP_PKEY *pkey = NULL;
  if (n && e) {
    BIGNUM *bn = BN_bin2bn(n, (int)nn, NULL), *be = BN_bin2bn(e, (int)en, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn);
    BN_free(be);
  }
  free(n);
  free(e);
  return pkey;
}

static EVP_PKEY *ec_key(const char *crv, const char *x64, const char *y64) {
  const char *group = !crv ? NULL
                      : strcmp(crv, "P-224") == 0 ? "P-224"
                      : strcmp(crv, "P-256") == 0 ? "prime256v1"
                      : strcmp(crv, "P-384") == 0 ? "secp384r1"
                      : strcmp(crv, "P-521") == 0 ? "secp521r1"
                                                  : NULL;
  if (!group) return NULL;
  size_t xn, yn;
  uint8_t *x = b64url(x64, &xn), *y = b64url(y64, &yn);
  EVP_PKEY *pkey = NULL;
  if (x && y && xn <= 66 && yn <= 66) {
    /* Uncompressed point: 04 || X || Y, each padded to the field size. */
    size_t fs = strcmp(crv, "P-224") == 0 ? 28 : strcmp(crv, "P-256") == 0 ? 32 : strcmp(crv, "P-384") == 0 ? 48 : 66;
    uint8_t pt[1 + 2 * 66] = {4};
    if (xn <= fs && yn <= fs) {
      memcpy(pt + 1 + fs - xn, x, xn);
      memcpy(pt + 1 + 2 * fs - yn, y, yn);
      OSSL_PARAM params[] = {
          OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0),
          OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pt, 1 + 2 * fs),
          OSSL_PARAM_construct_end(),
      };
      EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
      if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
      EVP_PKEY_CTX_free(ctx);
    }
  }
  free(x);
  free(y);
  return pkey;
}

bool buckets_jwk_set_add_json(buckets_jwk_set *s, const char *json, size_t len, char *err, size_t errlen) {
  yyjson_doc *d = yyjson_read(json, len, 0);
  yyjson_val *keys = d ? yyjson_obj_get(yyjson_doc_get_root(d), "keys") : NULL;
  if (!yyjson_is_arr(keys)) {
    yyjson_doc_free(d);
    snprintf(err, errlen, "malformed JWKS document");
    return false;
  }
  size_t i, max;
  yyjson_val *k;
  bool ok = true;
  yyjson_arr_foreach(keys, i, max, k) {
    const char *kty = yyjson_get_str(yyjson_obj_get(k, "kty"));
    const char *kid = yyjson_get_str(yyjson_obj_get(k, "kid"));
    const char *alg = yyjson_get_str(yyjson_obj_get(k, "alg"));
    const char *crv = yyjson_get_str(yyjson_obj_get(k, "crv"));
    EVP_PKEY *pkey = NULL;
    const char *kind = "";
    if (kty && strcmp(kty, "RSA") == 0) {
      pkey = rsa_key(yyjson_get_str(yyjson_obj_get(k, "n")), yyjson_get_str(yyjson_obj_get(k, "e")));
      kind = "RSA";
      if (!pkey) snprintf(err, errlen, "malformed JWK RSA key");
    } else if (kty && strcmp(kty, "EC") == 0) {
      pkey = ec_key(crv, yyjson_get_str(yyjson_obj_get(k, "x")), yyjson_get_str(yyjson_obj_get(k, "y")));
      kind = "EC";
      if (!pkey) snprintf(err, errlen, "malformed JWK EC key");
    } else if (alg && strcmp(alg, "EdDSA") == 0 && crv && strcmp(crv, "Ed25519") == 0) {
      size_t xn;
      uint8_t *x = b64url(yyjson_get_str(yyjson_obj_get(k, "x")), &xn);
      if (x && xn == 32) pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, x, xn);
      free(x);
      kind = "OKP";
      if (!pkey) snprintf(err, errlen, "malformed JWK EC key");
    } else {
      snprintf(err, errlen, "Unknown JWK key type %s", kty ? kty : "");
    }
    /* DecodePublicKey errors fail the whole document, as in MinIO. */
    if (!pkey) {
      ok = false;
      break;
    }
    add(s, kid ? kid : "", pkey, NULL, kind);
  }
  yyjson_doc_free(d);
  return ok;
}

static const jwk *find(const buckets_jwk_set *s, const char *kid) {
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->k[i].kid, kid) == 0) return &s->k[i];
  }
  return NULL;
}

static uint8_t *seg(const char *p, size_t n, size_t *out) {
  uint8_t *buf = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64url_raw_decode(p, n, buf);
  if (k < 0) {
    free(buf);
    return NULL;
  }
  buf[k] = '\0';
  *out = (size_t)k;
  return buf;
}

/* jwt-go v4 MapClaims.Valid: exp, iat, nbf (when present). */
static bool times_ok(yyjson_val *root, long long now) {
  yyjson_val *v;
  if ((v = yyjson_obj_get(root, "exp")) && !yyjson_is_null(v)) {
    if (!yyjson_is_num(v) || !((double)now < yyjson_get_num(v))) return false;
  }
  if ((v = yyjson_obj_get(root, "iat")) && !yyjson_is_null(v)) {
    if (!yyjson_is_num(v) || (double)now < floor(yyjson_get_num(v))) return false;
  }
  if ((v = yyjson_obj_get(root, "nbf")) && !yyjson_is_null(v)) {
    if (!yyjson_is_num(v) || (double)now < floor(yyjson_get_num(v))) return false;
  }
  return true;
}

/* ES* signatures are R || S; OpenSSL wants DER. */
static unsigned char *ecdsa_der(const uint8_t *sig, size_t n, size_t *der_len) {
  if (n % 2) return NULL;
  ECDSA_SIG *es = ECDSA_SIG_new();
  BIGNUM *r = BN_bin2bn(sig, (int)(n / 2), NULL), *s = BN_bin2bn(sig + n / 2, (int)(n / 2), NULL);
  ECDSA_SIG_set0(es, r, s);
  unsigned char *der = NULL;
  int len = i2d_ECDSA_SIG(es, &der);
  ECDSA_SIG_free(es);
  if (len <= 0) return NULL;
  *der_len = (size_t)len;
  return der;
}

buckets_jwt_status buckets_jwt_verify_jwks(const char *token, const buckets_jwk_set *keys, long long now,
                                           yyjson_doc **claims, char *err, size_t errlen) {
  *claims = NULL;
  const char *d1 = strchr(token, '.'), *d2 = strrchr(token, '.');
  if (!d1 || d1 == d2 || memchr(d1 + 1, '.', (size_t)(d2 - d1 - 1))) {
    snprintf(err, errlen, "token contains an invalid number of segments");
    return BUCKETS_JWT_MALFORMED;
  }
  size_t hn, cn, sn;
  uint8_t *h = seg(token, (size_t)(d1 - token), &hn);
  yyjson_doc *hd = h ? yyjson_read((char *)h, hn, 0) : NULL;
  free(h);
  const char *alg = hd ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(hd), "alg")) : NULL;
  const char *kid = hd ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(hd), "kid")) : NULL;
  buckets_jwt_status st = BUCKETS_JWT_OK;
  char algs[16] = "", kids[256] = "";
  if (alg) snprintf(algs, sizeof(algs), "%s", alg);
  if (kid) snprintf(kids, sizeof(kids), "%s", kid);
  yyjson_doc_free(hd);
  if (!*algs) {
    snprintf(err, errlen, "malformed token header");
    return BUCKETS_JWT_MALFORMED;
  }
  /* The method: family and digest. */
  char fam = 0;
  const EVP_MD *md = NULL;
  if (strcmp(algs, "EdDSA") == 0) {
    fam = 'D';
  } else if (strlen(algs) == 5 && (algs[0] == 'R' || algs[0] == 'E' || algs[0] == 'H') && algs[1] == 'S') {
    fam = algs[0];
    md = strcmp(algs + 2, "256") == 0 ? EVP_sha256() : strcmp(algs + 2, "384") == 0 ? EVP_sha384()
         : strcmp(algs + 2, "512") == 0 ? EVP_sha512() : NULL;
  } else if (strlen(algs) == 6 && (algs[0] == 'R' || algs[0] == 'E') && algs[1] == 'S' && algs[2] == '3') {
    fam = algs[0];
    md = strcmp(algs + 3, "256") == 0 ? EVP_sha3_256() : strcmp(algs + 3, "384") == 0 ? EVP_sha3_384()
         : strcmp(algs + 3, "512") == 0 ? EVP_sha3_512() : NULL;
  }
  if (!fam || (fam != 'D' && !md)) {
    snprintf(err, errlen, "signing method %s is invalid", algs);
    return BUCKETS_JWT_BAD_ALG;
  }
  if (!kid) {
    snprintf(err, errlen, "Invalid kid value <nil>");
    return BUCKETS_JWT_NO_KEY;
  }
  const jwk *k = find(keys, kids);
  if (!k) {
    snprintf(err, errlen, "No public key found for kid %s", kids);
    return BUCKETS_JWT_NO_KEY;
  }
  uint8_t *sig = seg(d2 + 1, strlen(d2 + 1), &sn);
  if (!sig) {
    snprintf(err, errlen, "malformed signature");
    return BUCKETS_JWT_MALFORMED;
  }
  const unsigned char *msg = (const unsigned char *)token;
  size_t mlen = (size_t)(d2 - token);
  bool good = false;
  bool key_ok = (fam == 'H' && k->secret) || (fam == 'R' && strcmp(k->kind, "RSA") == 0) ||
                (fam == 'E' && strcmp(k->kind, "EC") == 0) || (fam == 'D' && strcmp(k->kind, "OKP") == 0);
  if (!key_ok) {
    snprintf(err, errlen, "key is of invalid type");
    st = BUCKETS_JWT_BAD_SIGNATURE;
  } else if (fam == 'H') {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int ml = 0;
    HMAC(md, k->secret, (int)strlen(k->secret), msg, mlen, mac, &ml);
    good = ml == sn && CRYPTO_memcmp(mac, sig, ml) == 0;
  } else {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const unsigned char *s = sig;
    size_t slen = sn;
    unsigned char *der = NULL;
    if (fam == 'E') {
      der = ecdsa_der(sig, sn, &slen);
      s = der;
    }
    if (s && EVP_DigestVerifyInit(ctx, NULL, fam == 'D' ? NULL : md, NULL, k->pkey) == 1) {
      good = EVP_DigestVerify(ctx, s, slen, msg, mlen) == 1;
    }
    OPENSSL_free(der);
    EVP_MD_CTX_free(ctx);
  }
  free(sig);
  if (st) return st;
  if (!good) {
    snprintf(err, errlen, "crypto/rsa: verification error");
    return BUCKETS_JWT_BAD_SIGNATURE;
  }
  uint8_t *c = seg(d1 + 1, (size_t)(d2 - d1 - 1), &cn);
  yyjson_doc *cd = c ? yyjson_read((char *)c, cn, 0) : NULL;
  free(c);
  if (!cd || !yyjson_is_obj(yyjson_doc_get_root(cd))) {
    yyjson_doc_free(cd);
    snprintf(err, errlen, "malformed claims");
    return BUCKETS_JWT_MALFORMED;
  }
  if (!times_ok(yyjson_doc_get_root(cd), now)) {
    yyjson_doc_free(cd);
    snprintf(err, errlen, "token expired");
    return BUCKETS_JWT_EXPIRED;
  }
  *claims = cd;
  return BUCKETS_JWT_OK;
}
