/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_STR_H
#define BUCKETS_CORE_STR_H

#include "core/common.h"

/* Non-owning byte slice. Not NUL-terminated. */
typedef struct {
  const char *p;
  size_t n;
} buckets_str;

#define BUCKETS_STR_LIT(lit) ((buckets_str){(lit), sizeof(lit) - 1})
#define BUCKETS_STR_NULL ((buckets_str){NULL, 0})
#define BUCKETS_STR_FMT "%.*s"
#define BUCKETS_STR_ARG(s) (int)(s).n, (s).p

buckets_str buckets_str_c(const char *cstr);
bool buckets_str_eq(buckets_str a, buckets_str b);
bool buckets_str_eq_c(buckets_str a, const char *b);
bool buckets_str_ieq_c(buckets_str a, const char *b); /* ASCII case-insensitive */
bool buckets_str_has_prefix(buckets_str s, const char *prefix);
buckets_str buckets_str_trim(buckets_str s); /* trims ASCII spaces and tabs */
/* Splits s at the first occurrence of sep. Returns false if sep is absent,
 * in which case *head = s and *tail is empty. */
bool buckets_str_cut(buckets_str s, char sep, buckets_str *head, buckets_str *tail);
char *buckets_str_dup(buckets_str s); /* NUL-terminated heap copy */

/* Percent-decodes src into dst (dst must hold src.n bytes). When plus_is_space
 * is set, '+' decodes to ' ' (form/query encoding). Returns decoded length, or
 * -1 on a malformed escape. */
long buckets_url_decode(buckets_str src, char *dst, bool plus_is_space);

#endif
