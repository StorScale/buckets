/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/auditctx.h"

#include <stdlib.h>
#include <string.h>

#include "core/common.h"

static _Thread_local buckets_audit_tags *g_tags;

void buckets_audit_tags_set(buckets_audit_tags *t) { g_tags = t; }
buckets_audit_tags *buckets_audit_tags_current(void) { return g_tags; }

void buckets_audit_tag(const char *key, const char *value) {
  buckets_audit_tags *t = g_tags;
  if (!t || t->paused) return;
  for (size_t i = 0; i < t->n; i++) {
    if (strcmp(t->keys[i], key) == 0) {
      free(t->values[i]);
      t->values[i] = buckets_xstrdup(value);
      return;
    }
  }
  if (t->n == t->cap) {
    t->cap = t->cap ? t->cap * 2 : 8;
    t->keys = buckets_xrealloc(t->keys, t->cap * sizeof(char *));
    t->values = buckets_xrealloc(t->values, t->cap * sizeof(char *));
  }
  t->keys[t->n] = buckets_xstrdup(key);
  t->values[t->n++] = buckets_xstrdup(value);
}

void buckets_audit_tags_free(buckets_audit_tags *t) {
  for (size_t i = 0; i < t->n; i++) {
    free(t->keys[i]);
    free(t->values[i]);
  }
  free(t->keys);
  free(t->values);
  memset(t, 0, sizeof(*t));
}

static buckets_audit_internal_fn g_internal;
static void *g_internal_ud;

void buckets_audit_internal_set(buckets_audit_internal_fn fn, void *ud) {
  g_internal_ud = ud;
  g_internal = fn;
}

void buckets_audit_internal(const char *event, const char *api_name, const char *bucket, const char *object,
                            const char *version_id, const char *error, const char *const *keys,
                            const char *const *values, size_t ntags) {
  buckets_audit_internal_fn fn = g_internal;
  if (fn) fn(g_internal_ud, event, api_name, bucket, object, version_id, error, keys, values, ntags);
}
