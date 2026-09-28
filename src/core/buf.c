/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/buf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buckets_buf_free(buckets_buf *b) {
  free(b->data);
  *b = BUCKETS_BUF_INIT;
}

void buckets_buf_reset(buckets_buf *b) {
  b->len = 0;
  if (b->data) b->data[0] = '\0';
}

void buckets_buf_reserve(buckets_buf *b, size_t extra) {
  size_t need = b->len + extra + 1; /* +1 for the trailing NUL */
  if (need <= b->cap) return;
  size_t cap = b->cap ? b->cap : 64;
  while (cap < need) cap *= 2;
  b->data = buckets_xrealloc(b->data, cap);
  b->cap = cap;
}

void buckets_buf_append(buckets_buf *b, const void *data, size_t n) {
  buckets_buf_reserve(b, n);
  if (n) memcpy(b->data + b->len, data, n);
  b->len += n;
  b->data[b->len] = '\0';
}

void buckets_buf_append_c(buckets_buf *b, const char *s) { buckets_buf_append(b, s, strlen(s)); }

void buckets_buf_append_str(buckets_buf *b, buckets_str s) { buckets_buf_append(b, s.p, s.n); }

void buckets_buf_append_char(buckets_buf *b, char c) { buckets_buf_append(b, &c, 1); }

void buckets_buf_appendf(buckets_buf *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0) {
    va_end(ap2);
    return;
  }
  buckets_buf_reserve(b, (size_t)n);
  vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2);
  va_end(ap2);
  b->len += (size_t)n;
}

void buckets_buf_consume(buckets_buf *b, size_t n) {
  if (n >= b->len) {
    buckets_buf_reset(b);
    return;
  }
  memmove(b->data, b->data + n, b->len - n);
  b->len -= n;
  b->data[b->len] = '\0';
}

void buckets_url_encode(buckets_buf *out, const char *s, bool keep_slash) {
  static const char hex[] = "0123456789ABCDEF";
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
        c == '_' || c == '~' || (keep_slash && c == '/')) {
      buckets_buf_append_char(out, (char)c);
    } else {
      char e[3] = {'%', hex[c >> 4], hex[c & 15]};
      buckets_buf_append(out, e, 3);
    }
  }
}
