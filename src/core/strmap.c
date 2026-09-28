/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/strmap.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static char tomb_marker;
#define TOMB (&tomb_marker)

static uint64_t hash(const char *s) {
  uint64_t h = 1469598103934665603ull; /* FNV-1a */
  for (; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211ull;
  return h;
}

void buckets_strmap_free(buckets_strmap *m) {
  for (size_t i = 0; i < m->cap; i++) {
    if (m->slots[i].key && m->slots[i].key != TOMB) free(m->slots[i].key);
  }
  free(m->slots);
  memset(m, 0, sizeof(*m));
}

static buckets_strmap_slot *find(const buckets_strmap *m, const char *key) {
  if (!m->cap) return NULL;
  size_t mask = m->cap - 1;
  for (size_t i = hash(key) & mask;; i = (i + 1) & mask) {
    buckets_strmap_slot *s = &m->slots[i];
    if (!s->key) return NULL;
    if (s->key != TOMB && strcmp(s->key, key) == 0) return s;
  }
}

void *buckets_strmap_get(const buckets_strmap *m, const char *key) {
  buckets_strmap_slot *s = find(m, key);
  return s ? s->value : NULL;
}

static void grow(buckets_strmap *m) {
  size_t cap = m->cap ? m->cap * 2 : 16;
  while (m->n * 2 >= cap) cap *= 2;
  buckets_strmap_slot *old = m->slots;
  size_t oldcap = m->cap;
  m->slots = buckets_xcalloc(cap, sizeof(*m->slots));
  m->cap = cap;
  m->used = m->n;
  for (size_t i = 0; i < oldcap; i++) {
    if (!old[i].key || old[i].key == TOMB) continue;
    size_t j = hash(old[i].key) & (cap - 1);
    while (m->slots[j].key) j = (j + 1) & (cap - 1);
    m->slots[j] = old[i];
  }
  free(old);
}

void *buckets_strmap_put(buckets_strmap *m, const char *key, void *value) {
  buckets_strmap_slot *s = find(m, key);
  if (s) {
    void *prev = s->value;
    s->value = value;
    return prev;
  }
  if ((m->used + 1) * 4 >= m->cap * 3) grow(m);
  size_t mask = m->cap - 1;
  size_t i = hash(key) & mask;
  while (m->slots[i].key && m->slots[i].key != TOMB) i = (i + 1) & mask;
  if (!m->slots[i].key) m->used++;
  m->slots[i].key = buckets_xstrdup(key);
  m->slots[i].value = value;
  m->n++;
  return NULL;
}

void *buckets_strmap_del(buckets_strmap *m, const char *key) {
  buckets_strmap_slot *s = find(m, key);
  if (!s) return NULL;
  void *prev = s->value;
  free(s->key);
  s->key = TOMB;
  s->value = NULL;
  m->n--;
  return prev;
}

bool buckets_strmap_next(const buckets_strmap *m, size_t *iter, const char **key, void **value) {
  for (; *iter < m->cap; (*iter)++) {
    buckets_strmap_slot *s = &m->slots[*iter];
    if (s->key && s->key != TOMB) {
      if (key) *key = s->key;
      if (value) *value = s->value;
      (*iter)++;
      return true;
    }
  }
  return false;
}
