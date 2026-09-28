/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_JWT_H
#define BUCKETS_CRYPTO_JWT_H

#include <yyjson.h>

#include "core/buf.h"

/* HMAC JSON Web Tokens, as MinIO's internal/jwt uses them for STS session
 * tokens and service-account claims: HS256/HS384/HS512, compact form,
 * unpadded base64url. */

/* Signs claims (a JSON object) with HS512, as jwt-go's SignedString. */
void buckets_jwt_sign(const char *claims_json, size_t n, const char *key, buckets_buf *out);

/* ParseWithClaims: checks the signature with key, then the claims' exp, iat
 * and nbf against now (unix seconds), and that accessKey or sub is set.
 * Returns the claims document, or NULL. */
yyjson_doc *buckets_jwt_verify(const char *token, const char *key, long long now);

#endif
