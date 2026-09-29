/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_BASE64_H
#define BUCKETS_CRYPTO_BASE64_H

#include "core/common.h"

/* Standard alphabet with padding. out must hold 4*ceil(n/3)+1 bytes. */
void buckets_base64_encode(const uint8_t *in, size_t n, char *out);
/* Strict decode (padding required). Returns decoded length or -1.
 * out must hold 3*(n/4) bytes. */
long buckets_base64_decode(const char *in, size_t n, uint8_t *out);

/* Go's base64.RawURLEncoding (MinIO upload IDs). out: 4*ceil(n/3)+1 bytes. */
void buckets_base64url_raw_encode(const uint8_t *in, size_t n, char *out);
long buckets_base64url_raw_decode(const char *in, size_t n, uint8_t *out);
/* Go's base64.URLEncoding (padded): out must hold 4*ceil(n/3)+1 bytes. */
void buckets_base64url_encode(const uint8_t *in, size_t n, char *out);
long buckets_base64url_decode(const char *in, size_t n, uint8_t *out);

#endif
