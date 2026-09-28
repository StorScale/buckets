/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/common.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buckets_fatal(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("buckets: fatal: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  abort();
}

void *buckets_xmalloc(size_t n) {
  void *p = malloc(n ? n : 1);
  if (!p) buckets_fatal("out of memory allocating %zu bytes", n);
  return p;
}

void *buckets_xcalloc(size_t count, size_t n) {
  void *p = calloc(count ? count : 1, n ? n : 1);
  if (!p) buckets_fatal("out of memory allocating %zu x %zu bytes", count, n);
  return p;
}

void *buckets_xrealloc(void *p, size_t n) {
  void *q = realloc(p, n ? n : 1);
  if (!q) buckets_fatal("out of memory reallocating %zu bytes", n);
  return q;
}

char *buckets_xstrndup(const char *s, size_t n) {
  char *d = buckets_xmalloc(n + 1);
  memcpy(d, s, n);
  d[n] = '\0';
  return d;
}

char *buckets_xstrdup(const char *s) { return buckets_xstrndup(s, strlen(s)); }
