/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_STRMAP_H
#define BUCKETS_CORE_STRMAP_H

#include <stddef.h>

#include "core/common.h"

/* A string-keyed hash map (open addressing, linear probing). Keys are
 * copied; values are opaque pointers the caller owns. Not thread-safe. */
typedef struct {
  char *key; /* NULL = empty slot, BUCKETS_STRMAP_TOMB = deleted */
  void *value;
} buckets_strmap_slot;

typedef struct {
  buckets_strmap_slot *slots;
  size_t cap;  /* power of two, or 0 */
  size_t n;    /* live entries */
  size_t used; /* live + tombstones */
} buckets_strmap;

#define BUCKETS_STRMAP_INIT {0}

void buckets_strmap_free(buckets_strmap *m);
void *buckets_strmap_get(const buckets_strmap *m, const char *key);
/* Inserts or replaces; returns the previous value (or NULL). */
void *buckets_strmap_put(buckets_strmap *m, const char *key, void *value);
/* Removes key; returns its value (or NULL). */
void *buckets_strmap_del(buckets_strmap *m, const char *key);

/* Iteration: for (size_t i = 0; buckets_strmap_next(m, &i, &k, &v);) ... */
bool buckets_strmap_next(const buckets_strmap *m, size_t *iter, const char **key, void **value);

#endif
