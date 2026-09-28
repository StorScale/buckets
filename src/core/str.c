/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/str.h"

#include <string.h>

static inline char lower_ascii(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

buckets_str buckets_str_c(const char *cstr) {
  return (buckets_str){cstr, cstr ? strlen(cstr) : 0};
}

bool buckets_str_eq(buckets_str a, buckets_str b) {
  return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}

bool buckets_str_eq_c(buckets_str a, const char *b) { return buckets_str_eq(a, buckets_str_c(b)); }

bool buckets_str_ieq_c(buckets_str a, const char *b) {
  size_t n = strlen(b);
  if (a.n != n) return false;
  for (size_t i = 0; i < n; i++) {
    if (lower_ascii(a.p[i]) != lower_ascii(b[i])) return false;
  }
  return true;
}

bool buckets_str_has_prefix(buckets_str s, const char *prefix) {
  size_t n = strlen(prefix);
  return s.n >= n && memcmp(s.p, prefix, n) == 0;
}

buckets_str buckets_str_trim(buckets_str s) {
  while (s.n && (s.p[0] == ' ' || s.p[0] == '\t')) {
    s.p++;
    s.n--;
  }
  while (s.n && (s.p[s.n - 1] == ' ' || s.p[s.n - 1] == '\t')) s.n--;
  return s;
}

bool buckets_str_cut(buckets_str s, char sep, buckets_str *head, buckets_str *tail) {
  const char *hit = s.n ? memchr(s.p, sep, s.n) : NULL;
  if (!hit) {
    *head = s;
    *tail = (buckets_str){s.p + s.n, 0};
    return false;
  }
  *head = (buckets_str){s.p, (size_t)(hit - s.p)};
  *tail = (buckets_str){hit + 1, s.n - (size_t)(hit - s.p) - 1};
  return true;
}

char *buckets_str_dup(buckets_str s) { return buckets_xstrndup(s.p ? s.p : "", s.n); }

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

long buckets_url_decode(buckets_str src, char *dst, bool plus_is_space) {
  size_t o = 0;
  for (size_t i = 0; i < src.n; i++) {
    char c = src.p[i];
    if (c == '%') {
      if (i + 2 >= src.n) return -1;
      int hi = hexval(src.p[i + 1]), lo = hexval(src.p[i + 2]);
      if (hi < 0 || lo < 0) return -1;
      dst[o++] = (char)((hi << 4) | lo);
      i += 2;
    } else if (c == '+' && plus_is_space) {
      dst[o++] = ' ';
    } else {
      dst[o++] = c;
    }
  }
  return (long)o;
}
