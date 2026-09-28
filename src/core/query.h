/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_QUERY_H
#define BUCKETS_CORE_QUERY_H

#include "core/str.h"

/* Decoded URL query parameters, in the order they appeared. Mirrors Go's
 * url.ParseQuery (which MinIO relies on): '+' decodes to space, a key without
 * '=' has an empty value, and pairs with bad escapes or ';' are rejected. */
typedef struct {
  char *key;
  char *value;
} buckets_kv;

typedef struct {
  buckets_kv *items;
  size_t n;
} buckets_query;

/* Returns false if any pair is malformed; q is still usable (bad pairs dropped). */
bool buckets_query_parse(buckets_str raw, buckets_query *q);
void buckets_query_free(buckets_query *q);
/* First value for key, or NULL if absent. */
const char *buckets_query_get(const buckets_query *q, const char *key);
bool buckets_query_has(const buckets_query *q, const char *key);

#endif
