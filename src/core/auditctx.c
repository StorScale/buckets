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
