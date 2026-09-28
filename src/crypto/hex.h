/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_HEX_H
#define BUCKETS_CRYPTO_HEX_H

#include "core/common.h"

/* Writes 2*n lowercase hex chars plus a NUL into out. */
void buckets_hex_encode(const uint8_t *in, size_t n, char *out);
/* Constant-time comparison; returns true when equal. */
bool buckets_ct_equal(const void *a, const void *b, size_t n);

#endif
