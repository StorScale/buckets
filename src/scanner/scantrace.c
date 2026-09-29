/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "scanner/scantrace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/timefmt.h"
#include "notify/event.h"
#include "trace/trace.h"

#define COMPACT_LEAST_OBJECTS 500 /* dataScannerCompactLeastObject */

typedef struct {
  char *path; /* <bucket>/<folder> */
  int64_t start;
  uint64_t objects, size;
  bool kids_small; /* every child folder compacted to at most one object */
} folder;

struct buckets_scantrace {
  char **prev, **cur; /* folder paths: the last cycle's (sorted) and this one's */
  size_t nprev, ncur, capcur;
  /* the bucket being walked */
  buckets_objlayer *L;
  char *bucket;
  const char *drive;
  int64_t bstart;
  folder *st;
  size_t n, cap;
};

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

buckets_scantrace *buckets_scantrace_new(void) { return buckets_xcalloc(1, sizeof(buckets_scantrace)); }

static void free_list(char **v, size_t n) {
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
}

void buckets_scantrace_free(buckets_scantrace *t) {
  if (!t) return;
  free_list(t->prev, t->nprev);
  free_list(t->cur, t->ncur);
  free(t->bucket);
  for (size_t i = 0; i < t->n; i++) free(t->st[i].path);
  free(t->st);
  free(t);
}

/* scannerTrace: custom holds npairs key/value pairs, already in key order. */
static void publish(const char *func, int64_t start, const char *drive, const char *path, const char *const *custom,
                    size_t npairs) {
  int64_t dur = now_ns() - start;
  char when[64];
  buckets_time_rfc3339_nano((long long)(start / 1000000000LL), (long)(start % 1000000000LL), when);
  buckets_buf b = BUCKETS_BUF_INIT, p = BUCKETS_BUF_INIT;
  if (drive) buckets_buf_appendf(&p, "%s %s", drive, path);
  else buckets_buf_append_c(&p, path);
  buckets_buf_appendf(&b, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_SCANNER);
  const char *node = buckets_trace_node();
  buckets_json_go_string(&b, node, strlen(node));
  buckets_buf_appendf(&b, ",\"funcname\":\"scanner.%s\",\"time\":\"%s\",\"path\":", func, when);
  buckets_json_go_string(&b, p.len ? p.data : "", p.len);
  buckets_buf_appendf(&b, ",\"dur\":%lld", (long long)dur);
  if (npairs) {
    buckets_buf_append_c(&b, ",\"custom\":{");
    for (size_t i = 0; i < npairs; i++) {
      if (i) buckets_buf_append_char(&b, ',');
      buckets_json_go_string(&b, custom[2 * i], strlen(custom[2 * i]));
      buckets_buf_append_char(&b, ':');
      buckets_json_go_string(&b, custom[2 * i + 1], strlen(custom[2 * i + 1]));
    }
    buckets_buf_append_char(&b, '}');
  }
  buckets_buf_append_char(&b, '}');
  buckets_trace_meta m = {.type = BUCKETS_TRACE_SCANNER, .dur_ns = dur};
  buckets_trace_publish(&m, b.data, b.len);
  buckets_buf_free(&b);
  buckets_buf_free(&p);
}

void buckets_scantrace_cycle(uint64_t cycle, int64_t start_ns) {
  if (!buckets_trace_wanted(BUCKETS_TRACE_SCANNER)) return;
  char c[24];
  snprintf(c, sizeof(c), "%llu", (unsigned long long)cycle);
  const char *custom[] = {"cycle", c};
  publish("ScanCycle", start_ns, NULL, "", custom, 1);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static bool existed(const buckets_scantrace *t, const char *path) {
  return t->nprev && bsearch(&path, t->prev, t->nprev, sizeof(char *), cmp_str) != NULL;
}

bool buckets_scantrace_bucket_begin(buckets_scantrace *t, buckets_objlayer *L, const char *bucket) {
  if (!buckets_trace_wanted(BUCKETS_TRACE_SCANNER)) return false;
  t->L = L;
  free(t->bucket);
  t->bucket = buckets_xstrdup(bucket);
  t->drive = buckets_obj_scan_drive(L, bucket, "", NULL);
  t->bstart = now_ns();
  return true;
}

static void close_top(buckets_scantrace *t) {
  folder f = t->st[--t->n];
  char objs[24], size[24];
  snprintf(objs, sizeof(objs), "%llu", (unsigned long long)f.objects);
  snprintf(size, sizeof(size), "%llu", (unsigned long long)f.size);
  /* scanFolder's compaction of small folders (never the bucket itself) */
  bool compact = f.objects < COMPACT_LEAST_OBJECTS || f.kids_small;
  if (compact) {
    const char *custom[] = {"objects", objs, "size", size};
    publish("CompactFolder", now_ns(), NULL, f.path, custom, 2);
  }
  const char *type[] = {"type", existed(t, f.path) ? "existing" : "new"};
  publish("ScanFolder", f.start, t->drive, f.path, type, 1);
  if (t->n) t->st[t->n - 1].kids_small &= compact && f.objects <= 1;
  if (t->ncur == t->capcur) {
    t->capcur = t->capcur ? t->capcur * 2 : 64;
    t->cur = buckets_xrealloc(t->cur, t->capcur * sizeof(char *));
  }
  t->cur[t->ncur++] = f.path; /* taken over */
}

void buckets_scantrace_key(buckets_scantrace *t, const char *key, int64_t start_ns, uint64_t size, uint64_t versions) {
  size_t blen = strlen(t->bucket);
  /* close the folders this key is not under */
  while (t->n) {
    const char *fp = t->st[t->n - 1].path + blen + 1;
    size_t fl = strlen(fp);
    if (strncmp(key, fp, fl) == 0 && key[fl] == '/') break;
    close_top(t);
  }
  /* open the folders between the innermost open one and the key */
  size_t done = t->n ? strlen(t->st[t->n - 1].path) - blen : 0; /* "/<folder>" */
  for (const char *p = key + (done ? done : 0); (p = strchr(p, '/')) != NULL; p++) {
    if (!p[1]) break; /* a trailing slash: the key's own folder */
    if (t->n == t->cap) {
      t->cap = t->cap ? t->cap * 2 : 8;
      t->st = buckets_xrealloc(t->st, t->cap * sizeof(folder));
    }
    buckets_buf fp = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&fp, "%s/%.*s", t->bucket, (int)(p - key), key);
    t->st[t->n++] = (folder){fp.data, start_ns, 0, 0, true};
  }
  for (size_t i = 0; i < t->n; i++) t->st[i].objects++, t->st[i].size += size;
  /* the key's own folder: its xl.meta, compacted at once */
  int64_t meta_size;
  const char *drive = buckets_obj_scan_drive(t->L, t->bucket, key, &meta_size);
  char ms[24], sz[24], vs[24], objs[] = "1";
  snprintf(ms, sizeof(ms), "%lld", (long long)meta_size);
  snprintf(sz, sizeof(sz), "%llu", (unsigned long long)size);
  snprintf(vs, sizeof(vs), "%llu", (unsigned long long)versions);
  buckets_buf path = BUCKETS_BUF_INIT, meta = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "%s/%s", t->bucket, key);
  buckets_buf_appendf(&meta, "%s/xl.meta", path.data);
  const char *oc[] = {"metasize", ms, "size", sz, "versions", vs};
  publish("ScanObject", start_ns, drive, meta.data, oc, versions ? 3 : 2);
  const char *cc[] = {"objects", objs, "size", sz};
  publish("CompactFolder", now_ns(), NULL, path.data, cc, 2);
  const char *type[] = {"type", "new"};
  publish("ScanFolder", start_ns, drive, path.data, type, 1);
  buckets_buf_free(&path);
  buckets_buf_free(&meta);
}

void buckets_scantrace_bucket_end(buckets_scantrace *t) {
  while (t->n) close_top(t);
  publish("ScanBucketDrive", t->bstart, t->drive, t->bucket, NULL, 0);
}

void buckets_scantrace_cycle_done(buckets_scantrace *t) {
  free_list(t->prev, t->nprev);
  t->prev = t->cur, t->nprev = t->ncur;
  t->cur = NULL, t->ncur = t->capcur = 0;
  if (t->nprev) qsort(t->prev, t->nprev, sizeof(char *), cmp_str);
}
