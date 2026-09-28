/* Buckets - S3-compatible object storage.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_COMMON_H
#define BUCKETS_CORE_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BUCKETS_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define BUCKETS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define BUCKETS_MAX(a, b) ((a) > (b) ? (a) : (b))

#if defined(__GNUC__) || defined(__clang__)
#define BUCKETS_PRINTF(fmt_idx, args_idx) __attribute__((format(printf, fmt_idx, args_idx)))
#define BUCKETS_NORETURN __attribute__((noreturn))
#else
#define BUCKETS_PRINTF(fmt_idx, args_idx)
#define BUCKETS_NORETURN
#endif

/* Allocation helpers. A storage server cannot meaningfully continue after an
 * allocation failure, so these abort instead of returning NULL. */
void *buckets_xmalloc(size_t n);
void *buckets_xcalloc(size_t count, size_t n);
void *buckets_xrealloc(void *p, size_t n);
char *buckets_xstrdup(const char *s);
char *buckets_xstrndup(const char *s, size_t n);
BUCKETS_NORETURN void buckets_fatal(const char *fmt, ...) BUCKETS_PRINTF(1, 2);

#endif
