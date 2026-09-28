/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_JWK_H
#define BUCKETS_CRYPTO_JWK_H

#include <yyjson.h>

#include "core/common.h"

/* JSON Web Keys and asymmetric JWT verification, for OpenID Connect
 * (MinIO's internal/config/identity/openid/jwks.go and jwt.go). */

typedef struct buckets_jwk_set buckets_jwk_set;

buckets_jwk_set *buckets_jwk_set_new(void);
void buckets_jwk_set_free(buckets_jwk_set *s);
/* Adds every usable key of a JWKS document ({"keys": [...]}): RSA, EC
 * (P-224..P-521) and Ed25519. Returns false for a malformed document. */
bool buckets_jwk_set_add_json(buckets_jwk_set *s, const char *json, size_t len, char *err, size_t errlen);
/* An HMAC key (MinIO registers the OpenID client secret under the client id). */
void buckets_jwk_set_add_secret(buckets_jwk_set *s, const char *kid, const char *secret);
size_t buckets_jwk_set_count(const buckets_jwk_set *s);

typedef enum {
  BUCKETS_JWT_OK = 0,
  BUCKETS_JWT_MALFORMED,
  BUCKETS_JWT_NO_KEY,      /* no key for the header's kid (refetching the JWKS may help) */
  BUCKETS_JWT_BAD_SIGNATURE,
  BUCKETS_JWT_EXPIRED,     /* exp, iat or nbf out of range */
  BUCKETS_JWT_BAD_ALG,
} buckets_jwt_status;

/* jwt-go's ParseWithClaims with ValidMethods RS/ES/HS 256-512, the SHA-3
 * RS3xxx/ES3xxx variants and EdDSA; the key is looked up by the header's
 * kid. On success *claims gets the claims document. */
buckets_jwt_status buckets_jwt_verify_jwks(const char *token, const buckets_jwk_set *keys, long long now,
                                           yyjson_doc **claims, char *err, size_t errlen);

#endif
