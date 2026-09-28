/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/hex.h"

void buckets_hex_encode(const uint8_t *in, size_t n, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = digits[in[i] >> 4];
    out[2 * i + 1] = digits[in[i] & 0xf];
  }
  out[2 * n] = '\0';
}

bool buckets_ct_equal(const void *a, const void *b, size_t n) {
  const volatile uint8_t *x = a, *y = b;
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) diff |= x[i] ^ y[i];
  return diff == 0;
}
