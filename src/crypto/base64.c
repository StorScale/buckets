/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/base64.h"

static const char k_alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void buckets_base64_encode(const uint8_t *in, size_t n, char *out) {
  size_t o = 0, i = 0;
  for (; i + 2 < n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
    out[o++] = k_alpha[v >> 18];
    out[o++] = k_alpha[(v >> 12) & 63];
    out[o++] = k_alpha[(v >> 6) & 63];
    out[o++] = k_alpha[v & 63];
  }
  if (i < n) {
    uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0);
    out[o++] = k_alpha[v >> 18];
    out[o++] = k_alpha[(v >> 12) & 63];
    out[o++] = i + 1 < n ? k_alpha[(v >> 6) & 63] : '=';
    out[o++] = '=';
  }
  out[o] = '\0';
}

static int val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

long buckets_base64_decode(const char *in, size_t n, uint8_t *out) {
  if (n % 4 != 0) return -1;
  size_t o = 0;
  for (size_t i = 0; i < n; i += 4) {
    bool last = i + 4 == n;
    int a = val(in[i]), b = val(in[i + 1]);
    int c = (last && in[i + 2] == '=') ? -2 : val(in[i + 2]);
    int d = (last && in[i + 3] == '=') ? -2 : val(in[i + 3]);
    if (a < 0 || b < 0 || c == -1 || d == -1 || (c == -2 && d != -2)) return -1;
    uint32_t v = (uint32_t)a << 18 | (uint32_t)b << 12 | (uint32_t)(c < 0 ? 0 : c) << 6 |
                 (uint32_t)(d < 0 ? 0 : d);
    out[o++] = (uint8_t)(v >> 16);
    if (c >= 0) out[o++] = (uint8_t)(v >> 8);
    if (d >= 0) out[o++] = (uint8_t)v;
  }
  return (long)o;
}
