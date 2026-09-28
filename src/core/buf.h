/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_BUF_H
#define BUCKETS_CORE_BUF_H

#include "core/common.h"
#include "core/str.h"

/* Growable byte buffer. data is always NUL-terminated (not counted in len)
 * once anything has been appended, so it can be used as a C string. */
typedef struct {
  char *data;
  size_t len;
  size_t cap;
} buckets_buf;

#define BUCKETS_BUF_INIT ((buckets_buf){NULL, 0, 0})

void buckets_buf_free(buckets_buf *b);
void buckets_buf_reset(buckets_buf *b); /* len = 0, keeps capacity */
void buckets_buf_reserve(buckets_buf *b, size_t extra);
void buckets_buf_append(buckets_buf *b, const void *data, size_t n);
void buckets_buf_append_c(buckets_buf *b, const char *s);
void buckets_buf_append_str(buckets_buf *b, buckets_str s);
void buckets_buf_append_char(buckets_buf *b, char c);
void buckets_buf_appendf(buckets_buf *b, const char *fmt, ...) BUCKETS_PRINTF(2, 3);
/* Returns the NUL-terminated contents (never NULL) and resets b; the
 * caller frees them. */
char *buckets_buf_detach(buckets_buf *b);
/* Removes the first n bytes. */
void buckets_buf_consume(buckets_buf *b, size_t n);
static inline buckets_str buckets_buf_str(const buckets_buf *b) {
  return (buckets_str){b->data, b->len};
}

/* Appends s percent-encoded: everything except A-Z a-z 0-9 - . _ ~ (and '/'
 * when keep_slash). */
void buckets_url_encode(buckets_buf *out, const char *s, bool keep_slash);

#endif
