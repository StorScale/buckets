/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "object/sysconfig.h"

#include <stdlib.h>
#include <string.h>

#include "storage/drive.h"

buckets_obj_err buckets_sysconfig_read(buckets_objlayer *L, const char *path, buckets_buf *out, int64_t *mod_time_ns) {
  buckets_obj_reader *r;
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_open(L, BUCKETS_META_BUCKET, path, NULL, 0, INT64_MAX, &r, &oi);
  if (err) return err;
  buckets_buf_reset(out);
  buckets_buf_reserve(out, (size_t)oi.size + 1);
  char tmp[16384];
  long n;
  while ((n = buckets_obj_read(r, tmp, sizeof(tmp))) > 0) buckets_buf_append(out, tmp, (size_t)n);
  buckets_obj_reader_free(r);
  if (mod_time_ns) *mod_time_ns = oi.mod_time_ns;
  bool deleted = oi.delete_marker;
  buckets_object_info_free(&oi);
  if (n < 0) return BUCKETS_OBJ_ERR_CORRUPT;
  if (out->len == 0 || deleted) return BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  return BUCKETS_OBJ_OK;
}

static long mem_read(void *ud, void *buf, size_t n) {
  buckets_str *s = ud;
  size_t take = BUCKETS_MIN(n, s->n);
  memcpy(buf, s->p, take);
  s->p += take;
  s->n -= take;
  return (long)take;
}

buckets_obj_err buckets_sysconfig_write(buckets_objlayer *L, const char *path, const void *data, size_t n) {
  buckets_str src = {data, n};
  return buckets_obj_put(L, BUCKETS_META_BUCKET, path, mem_read, &src, (int64_t)n, NULL, NULL);
}

buckets_obj_err buckets_sysconfig_delete(buckets_objlayer *L, const char *path) {
  return buckets_obj_delete(L, BUCKETS_META_BUCKET, path, NULL);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

buckets_obj_err buckets_sysconfig_list(buckets_objlayer *L, const char *prefix, bool dirs, char ***names, size_t *n) {
  *names = NULL;
  *n = 0;
  size_t cap = 0, plen = strlen(prefix);
  char *marker = NULL;
  for (;;) {
    buckets_obj_listing l;
    buckets_obj_err err = buckets_obj_list(L, BUCKETS_META_BUCKET, prefix, marker, dirs ? "/" : NULL, 1000, &l);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET || err == BUCKETS_OBJ_ERR_NO_SUCH_KEY) break;
    if (err) {
      free(marker);
      buckets_sysconfig_names_free(*names, *n);
      *names = NULL;
      *n = 0;
      return err;
    }
    size_t total = l.nobjects + l.nprefixes;
    for (size_t i = 0; i < total; i++) {
      const char *key = i < l.nobjects ? l.objects[i].name : l.prefixes[i - l.nobjects];
      if (strncmp(key, prefix, plen) != 0) continue;
      const char *rest = key + plen;
      size_t len = strlen(rest);
      if (dirs) {
        const char *slash = strchr(rest, '/');
        if (!slash) continue; /* a stray object directly under prefix */
        len = (size_t)(slash - rest);
      }
      if (!len) continue;
      if (*n == cap) {
        cap = cap ? cap * 2 : 16;
        *names = buckets_xrealloc(*names, cap * sizeof(char *));
      }
      (*names)[(*n)++] = buckets_xstrndup(rest, len);
    }
    bool more = l.truncated && l.next_marker;
    free(marker);
    marker = more ? buckets_xstrdup(l.next_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!more) break;
  }
  free(marker);
  if (*n) qsort(*names, *n, sizeof(char *), cmp_str);
  return BUCKETS_OBJ_OK;
}

void buckets_sysconfig_names_free(char **names, size_t n) {
  for (size_t i = 0; i < n; i++) free(names[i]);
  free(names);
}
