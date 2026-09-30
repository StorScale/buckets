/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ftp/sshcert.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/base64.h"

typedef struct {
  const uint8_t *p;
  size_t n;
} span;

static bool get_u32(span *s, uint32_t *v) {
  if (s->n < 4) return false;
  *v = (uint32_t)s->p[0] << 24 | (uint32_t)s->p[1] << 16 | (uint32_t)s->p[2] << 8 | s->p[3];
  s->p += 4, s->n -= 4;
  return true;
}

static bool get_u64(span *s, uint64_t *v) {
  uint32_t hi, lo;
  if (!get_u32(s, &hi) || !get_u32(s, &lo)) return false;
  *v = (uint64_t)hi << 32 | lo;
  return true;
}

static bool get_str(span *s, span *out) {
  uint32_t n;
  if (!get_u32(s, &n) || s->n < n) return false;
  out->p = s->p, out->n = n;
  s->p += n, s->n -= n;
  return true;
}

static bool str_eq(span s, const char *c) { return s.n == strlen(c) && memcmp(s.p, c, s.n) == 0; }

/* the key's wire blob (ssh_pki_export_pubkey_base64, decoded) */
static uint8_t *key_blob(ssh_key k, size_t *n) {
  char *b64 = NULL;
  if (ssh_pki_export_pubkey_base64(k, &b64) != SSH_OK || !b64) return NULL;
  size_t len = strlen(b64);
  uint8_t *out = malloc(len);
  long r = out ? buckets_base64_decode(b64, len, out) : -1;
  ssh_string_free_char(b64);
  if (r < 0) {
    free(out);
    return NULL;
  }
  *n = (size_t)r;
  return out;
}

static EVP_PKEY *pkey_from_blob(span b, const char **md_curve) {
  span type;
  if (!get_str(&b, &type)) return NULL;
  EVP_PKEY *pk = NULL;
  if (str_eq(type, "ssh-ed25519")) {
    span k;
    if (get_str(&b, &k) && k.n == 32) pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, k.p, 32);
    *md_curve = NULL;
  } else if (str_eq(type, "ssh-rsa")) {
    span e, n;
    if (!get_str(&b, &e) || !get_str(&b, &n)) return NULL;
    BIGNUM *be = BN_bin2bn(e.p, (int)e.n, NULL), *bn = BN_bin2bn(n.p, (int)n.n, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(be), BN_free(bn);
    *md_curve = "rsa";
  } else if (type.n > 11 && !memcmp(type.p, "ecdsa-sha2-", 11)) {
    span curve, q;
    if (!get_str(&b, &curve) || !get_str(&b, &q)) return NULL;
    const char *group = str_eq(curve, "nistp256")   ? "prime256v1"
                        : str_eq(curve, "nistp384") ? "secp384r1"
                        : str_eq(curve, "nistp521") ? "secp521r1"
                                                    : NULL;
    if (!group) return NULL;
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0),
                           OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)q.p, q.n),
                           OSSL_PARAM_construct_end()};
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    *md_curve = str_eq(curve, "nistp256") ? "SHA256" : str_eq(curve, "nistp384") ? "SHA384" : "SHA512";
  }
  return pk;
}

/* PublicKey.Verify(data, sig) of an ssh signature blob */
static bool verify(span ca_blob, span data, span sig) {
  span fmt, raw;
  if (!get_str(&sig, &fmt) || !get_str(&sig, &raw)) return false;
  const char *mdc = NULL;
  EVP_PKEY *pk = pkey_from_blob(ca_blob, &mdc);
  if (!pk) return false;
  const EVP_MD *md = NULL;
  uint8_t *der = NULL;
  size_t derlen = 0;
  const uint8_t *s = raw.p;
  size_t slen = raw.n;
  if (mdc && !strcmp(mdc, "rsa")) {
    md = str_eq(fmt, "rsa-sha2-512") ? EVP_sha512() : str_eq(fmt, "rsa-sha2-256") ? EVP_sha256() : EVP_sha1();
  } else if (mdc) {
    md = EVP_get_digestbyname(mdc);
    /* (mpint r, mpint s) -> DER */
    span rs = raw, r, ss;
    if (!get_str(&rs, &r) || !get_str(&rs, &ss)) {
      EVP_PKEY_free(pk);
      return false;
    }
    ECDSA_SIG *es = ECDSA_SIG_new();
    ECDSA_SIG_set0(es, BN_bin2bn(r.p, (int)r.n, NULL), BN_bin2bn(ss.p, (int)ss.n, NULL));
    int l = i2d_ECDSA_SIG(es, &der);
    ECDSA_SIG_free(es);
    if (l <= 0) {
      EVP_PKEY_free(pk);
      return false;
    }
    derlen = (size_t)l, s = der, slen = derlen;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok = ctx && EVP_DigestVerifyInit(ctx, NULL, md, NULL, pk) == 1 &&
            EVP_DigestVerify(ctx, s, slen, data.p, data.n) == 1;
  EVP_MD_CTX_free(ctx);
  OPENSSL_free(der);
  EVP_PKEY_free(pk);
  return ok;
}

bool buckets_sshcert_trusted(ssh_key key, ssh_key ca, const char *user, const char *remote_ip) {
  (void)remote_ip; /* source-address: MinIO's permissions carry none, so x/crypto never checks it */
  if (!key || !ca) return false;
  size_t n = 0, can = 0;
  uint8_t *blob = key_blob(key, &n), *cab = key_blob(ca, &can);
  bool ok = false;
  if (!blob || !cab) goto out;
  span s = {blob, n}, type, nonce, f1, f2;
  if (!get_str(&s, &type)) goto out;
  if (type.n < 21 || memcmp(type.p + type.n - 21, "-cert-v01@openssh.com", 21) != 0) goto out;
  if (!get_str(&s, &nonce)) goto out;
  /* the certified key's fields */
  if (!memcmp(type.p, "ssh-ed25519", 11)) {
    if (!get_str(&s, &f1)) goto out;
  } else if (!memcmp(type.p, "ssh-rsa", 7) || !memcmp(type.p, "rsa-sha2", 8)) {
    if (!get_str(&s, &f1) || !get_str(&s, &f2)) goto out;
  } else if (!memcmp(type.p, "ecdsa-sha2-", 11)) {
    if (!get_str(&s, &f1) || !get_str(&s, &f2)) goto out;
  } else {
    goto out;
  }
  uint64_t serial, after, before;
  uint32_t ctype;
  span keyid, principals, crit, ext, reserved, sigkey, sig;
  if (!get_u64(&s, &serial) || !get_u32(&s, &ctype) || !get_str(&s, &keyid) || !get_str(&s, &principals) ||
      !get_u64(&s, &after) || !get_u64(&s, &before) || !get_str(&s, &crit) || !get_str(&s, &ext) ||
      !get_str(&s, &reserved) || !get_str(&s, &sigkey))
    goto out;
  span signed_part = {blob, (size_t)(s.p - blob)};
  if (!get_str(&s, &sig)) goto out;
  /* IsUserAuthority: the signing key is the CA */
  if (sigkey.n != can || memcmp(sigkey.p, cab, can) != 0) goto out;
  if (ctype != 1) goto out; /* a user certificate */
  if (!principals.n) goto out; /* errSftpCertWithoutPrincipals */
  bool found = false;
  for (span pr = principals, one; pr.n && get_str(&pr, &one);)
    if (str_eq(one, user)) found = true;
  if (!found) goto out;
  for (span c = crit, name, val; c.n && get_str(&c, &name) && get_str(&c, &val);)
    if (!str_eq(name, "source-address")) goto out; /* unsupported critical option */
  uint64_t now = (uint64_t)time(NULL);
  if (now < after) goto out;
  if (before != UINT64_MAX && now >= before) goto out;
  ok = verify((span){cab, can}, signed_part, sig);
out:
  free(blob);
  free(cab);
  return ok;
}
