/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/query.h"

#include <stdlib.h>
#include <string.h>

static char *decode(buckets_str s, bool *ok) {
  char *out = buckets_xmalloc(s.n + 1);
  long n = buckets_url_decode(s, out, true);
  if (n < 0) {
    free(out);
    *ok = false;
    return NULL;
  }
  out[n] = '\0';
  return out;
}

bool buckets_query_parse(buckets_str raw, buckets_query *q) {
  memset(q, 0, sizeof(*q));
  bool all_ok = true;
  buckets_str rest = raw;
  while (rest.n > 0) {
    buckets_str pair;
    buckets_str_cut(rest, '&', &pair, &rest);
    if (pair.n == 0) continue;
    if (memchr(pair.p, ';', pair.n)) {
      all_ok = false;
      continue;
    }
    buckets_str k, v;
    buckets_str_cut(pair, '=', &k, &v);
    bool ok = true;
    char *key = decode(k, &ok);
    char *val = ok ? decode(v, &ok) : NULL;
    if (!ok) {
      free(key);
      all_ok = false;
      continue;
    }
    q->items = buckets_xrealloc(q->items, (q->n + 1) * sizeof(buckets_kv));
    q->items[q->n++] = (buckets_kv){key, val};
  }
  return all_ok;
}

void buckets_query_free(buckets_query *q) {
  for (size_t i = 0; i < q->n; i++) {
    free(q->items[i].key);
    free(q->items[i].value);
  }
  free(q->items);
  memset(q, 0, sizeof(*q));
}

const char *buckets_query_get(const buckets_query *q, const char *key) {
  for (size_t i = 0; i < q->n; i++) {
    if (strcmp(q->items[i].key, key) == 0) return q->items[i].value;
  }
  return NULL;
}

bool buckets_query_has(const buckets_query *q, const char *key) { return buckets_query_get(q, key) != NULL; }
