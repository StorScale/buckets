/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/uuid.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

void buckets_random_bytes(void *buf, size_t n) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  arc4random_buf(buf, n);
#else
  unsigned char *p = buf;
  while (n) {
    ssize_t r = getrandom(p, n, 0);
    if (r < 0) buckets_fatal("getrandom failed");
    p += r;
    n -= (size_t)r;
  }
#endif
}

void buckets_uuid_v4(char *out) {
  uint8_t b[16];
  buckets_random_bytes(b, sizeof(b));
  b[6] = (uint8_t)((b[6] & 0x0f) | 0x40);
  b[8] = (uint8_t)((b[8] & 0x3f) | 0x80);
  snprintf(out, BUCKETS_UUID_STR_LEN + 1,
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1], b[2], b[3],
           b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

void buckets_shortuuid(char *out) {
  static const char alphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  uint8_t u[16];
  buckets_random_bytes(u, sizeof(u));
  u[6] = (uint8_t)((u[6] & 0x0f) | 0x40); /* version 4 */
  u[8] = (uint8_t)((u[8] & 0x3f) | 0x80); /* RFC 4122 variant */
  unsigned __int128 num = 0;
  for (int i = 0; i < 16; i++) num = num << 8 | u[i];
  int n = 0; /* least significant digit first, as shortuuid writes them */
  while ((uint64_t)num > 0 && n < 22) {
    out[n++] = alphabet[(int)(num % 57)];
    num /= 57;
  }
  while (n < 22) out[n++] = alphabet[0];
  out[22] = 0;
}
