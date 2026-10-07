/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "audit/store.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libdeflate.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "core/common.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "usage/history.h"

#define SEGMENT_MAX (64ULL << 20) /* a segment closes at this size, or at the end of its hour */
#define QUEUE_MAX_BYTES (64ULL << 20)
#define RETAIN_EVERY_S 300

static bool env_off(const char *name) {
  const char *v = getenv(name);
  return v && (!strcasecmp(v, "off") || !strcmp(v, "0") || !strcasecmp(v, "false") || !strcasecmp(v, "no"));
}
bool buckets_audit_local_enabled(void) { return !env_off("BUCKETS_AUDIT_LOCAL"); }
bool buckets_audit_local_reads(void) { return !env_off("BUCKETS_AUDIT_LOCAL_READS"); }

static int retain_days(void) {
  const char *v = getenv("BUCKETS_AUDIT_LOCAL_DAYS");
  long n = v ? strtol(v, NULL, 10) : 0;
  return n >= 1 && n <= 3650 ? (int)n : 30;
}

static uint64_t retain_bytes(void) {
  const char *v = getenv("BUCKETS_AUDIT_LOCAL_MAX");
  if (!v || !*v) return 10ULL << 30;
  char *end;
  double n = strtod(v, &end);
  uint64_t mul = 1;
  if (*end == 'K' || *end == 'k')
    mul = 1ULL << 10;
  else if (*end == 'M' || *end == 'm')
    mul = 1ULL << 20;
  else if (*end == 'G' || *end == 'g')
    mul = 1ULL << 30;
  else if (*end == 'T' || *end == 't')
    mul = 1ULL << 40;
  return n > 0 ? (uint64_t)(n * (double)mul) : 10ULL << 30;
}

/* ---- matching (pure) ---------------------------------------------------------------------------------------- */

int64_t buckets_audit_time_ns(yyjson_val *e) {
  const char *t = yyjson_get_str(yyjson_obj_get(e, "time"));
  long long sec;
  long nsec;
  if (!t || !buckets_time_parse_rfc3339(t, &sec, &nsec)) return 0;
  return (int64_t)sec * 1000000000LL + nsec;
}

const char *buckets_audit_kind(yyjson_val *e) {
  const char *path = yyjson_get_str(yyjson_obj_get(e, "requestPath"));
  if (path && !strncmp(path, "/minio/admin/", 13)) return "admin";
  const char *name = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(e, "api"), "name"));
  char lower[64] = "";
  for (size_t i = 0; name && name[i] && i < sizeof(lower) - 1; i++)
    lower[i] = (char)tolower((unsigned char)name[i]);
  switch (buckets_usage_kind_of(lower)) {
    case BUCKETS_USAGE_DELETE: return "delete";
    case BUCKETS_USAGE_WRITE: return "write";
    default: return "read";
  }
}

static bool empty(const char *s) { return !s || !*s; }
static bool str_eq(yyjson_val *v, const char *s) {
  const char *x = yyjson_get_str(v);
  return x && !strcmp(x, s);
}

bool buckets_audit_match(yyjson_val *e, const buckets_audit_query *q) {
  int64_t t = buckets_audit_time_ns(e);
  if (q->from_ns && t < q->from_ns) return false;
  if (q->to_ns && t > q->to_ns) return false;
  if (q->before_ns && t >= q->before_ns) return false;
  yyjson_val *api = yyjson_obj_get(e, "api");
  if (!empty(q->user)) { /* the parent, or the name an OpenID token gave (its parent is a hash) */
    const char *parent = yyjson_get_str(yyjson_obj_get(e, "parentUser"));
    yyjson_val *claims = yyjson_obj_get(e, "requestClaims");
    if (!(parent && *parent ? !strcmp(parent, q->user) : str_eq(yyjson_obj_get(e, "accessKey"), q->user)) &&
        !str_eq(yyjson_obj_get(claims, "preferred_username"), q->user) &&
        !str_eq(yyjson_obj_get(claims, "upn"), q->user) && !str_eq(yyjson_obj_get(claims, "email"), q->user))
      return false;
  }
  if (!empty(q->access_key) && !str_eq(yyjson_obj_get(e, "accessKey"), q->access_key)) return false;
  if (!empty(q->bucket) && !str_eq(yyjson_obj_get(api, "bucket"), q->bucket)) return false;
  if (!empty(q->prefix)) {
    const char *o = yyjson_get_str(yyjson_obj_get(api, "object"));
    if (!o || strncmp(o, q->prefix, strlen(q->prefix)) != 0) return false;
  }
  if (!empty(q->api)) {
    const char *n = yyjson_get_str(yyjson_obj_get(api, "name"));
    if (!n || strcasecmp(n, q->api) != 0) return false;
  }
  if (!empty(q->kind) && strcmp(buckets_audit_kind(e), q->kind) != 0) return false;
  if (!empty(q->status)) {
    int64_t code = yyjson_get_sint(yyjson_obj_get(api, "statusCode"));
    const char *st = code == 401 || code == 403 ? "denied" : code >= 400 ? "failed" : "ok";
    if (strcmp(st, q->status) != 0) return false;
  }
  if (!empty(q->ip)) {
    const char *ip = yyjson_get_str(yyjson_obj_get(e, "remotehost"));
    if (!ip || strncmp(ip, q->ip, strlen(q->ip)) != 0) return false;
  }
  return true;
}

/* ---- segments ------------------------------------------------------------------------------------------------- */

typedef struct {
  char day[11];
  int hour, seq;
  bool gz;
  char path[4400];
  uint64_t size;
} segment;

/* "HH-SSSS.jsonl[.gz]" */
static bool parse_segment(const char *name, int *hour, int *seq, bool *gz) {
  int h, sq, used = 0;
  if (sscanf(name, "%2d-%4d.jsonl%n", &h, &sq, &used) != 2 || used == 0) return false;
  const char *rest = name + used;
  if (*rest && strcmp(rest, ".gz") != 0) return false;
  *hour = h, *seq = sq, *gz = *rest != '\0';
  return h >= 0 && h < 24;
}

static int seg_cmp(const void *a, const void *b) { /* oldest first */
  const segment *x = a, *y = b;
  int c = strcmp(x->day, y->day);
  if (c) return c;
  if (x->hour != y->hour) return x->hour - y->hour;
  return x->seq - y->seq;
}

/* Every segment under root, oldest first. */
static size_t list_segments(const char *root, segment **out) {
  segment *v = NULL;
  size_t n = 0;
  DIR *d = opendir(root);
  struct dirent *de;
  while (d && (de = readdir(d))) {
    int64_t t;
    if (!buckets_usage_day_parse(de->d_name, &t)) continue;
    char dp[4200];
    snprintf(dp, sizeof(dp), "%s/%s", root, de->d_name);
    DIR *dd = opendir(dp);
    struct dirent *fe;
    while (dd && (fe = readdir(dd))) {
      int h, sq;
      bool gz;
      if (!parse_segment(fe->d_name, &h, &sq, &gz)) continue;
      v = buckets_xrealloc(v, (n + 1) * sizeof(*v));
      segment *s = &v[n++];
      snprintf(s->day, sizeof(s->day), "%.10s", de->d_name); /* a day: checked above */
      s->hour = h, s->seq = sq, s->gz = gz;
      snprintf(s->path, sizeof(s->path), "%.4000s/%.255s", dp, fe->d_name);
      struct stat st;
      s->size = stat(s->path, &st) == 0 ? (uint64_t)st.st_size : 0;
    }
    if (dd) closedir(dd);
  }
  if (d) closedir(d);
  if (n) qsort(v, n, sizeof(*v), seg_cmp);
  *out = v;
  return n;
}

static int64_t segment_start_ns(const segment *s) {
  int64_t t = 0;
  buckets_usage_day_parse(s->day, &t);
  return (t + (int64_t)s->hour * 3600) * 1000000000LL;
}

/* A segment's text: read, and decompressed when gzip (its size is in the trailer: segments are < 4 GiB). */
static bool read_segment(const segment *s, buckets_buf *out) {
  FILE *f = fopen(s->path, "rb");
  if (!f) return false;
  buckets_buf raw = BUCKETS_BUF_INIT;
  char tmp[65536];
  size_t k;
  while ((k = fread(tmp, 1, sizeof(tmp), f)) > 0) buckets_buf_append(&raw, tmp, k);
  fclose(f);
  if (!s->gz) {
    buckets_buf_append(out, raw.data ? raw.data : "", raw.len);
    buckets_buf_free(&raw);
    return true;
  }
  bool ok = false;
  if (raw.len >= 18) {
    const uint8_t *p = (const uint8_t *)raw.data + raw.len - 4;
    size_t isize = (size_t)p[0] | (size_t)p[1] << 8 | (size_t)p[2] << 16 | (size_t)p[3] << 24;
    buckets_buf_reserve(out, isize + 1);
    struct libdeflate_decompressor *dz = libdeflate_alloc_decompressor();
    size_t got = 0;
    ok = dz && libdeflate_gzip_decompress(dz, raw.data, raw.len, out->data + out->len, isize, &got) ==
                   LIBDEFLATE_SUCCESS;
    if (ok) {
      out->len += got;
      out->data[out->len] = '\0';
    }
    if (dz) libdeflate_free_decompressor(dz);
  }
  buckets_buf_free(&raw);
  return ok;
}

/* ---- querying ------------------------------------------------------------------------------------------------- */

size_t buckets_audit_query_dir(const char *root, const buckets_audit_query *q, buckets_buf *out,
                               int64_t *oldest_ns) {
  segment *segs;
  size_t ns = list_segments(root, &segs), limit = q->limit ? q->limit : 100, found = 0;
  *oldest_ns = 0;
  if (ns) { /* the oldest kept: the first entry of the oldest segment */
    buckets_buf t = BUCKETS_BUF_INIT;
    if (read_segment(&segs[0], &t) && t.len) {
      size_t l = strcspn(t.data, "\n");
      yyjson_doc *d = yyjson_read(t.data, l, 0);
      *oldest_ns = buckets_audit_time_ns(yyjson_doc_get_root(d));
      yyjson_doc_free(d);
    }
    buckets_buf_free(&t);
  }
  int64_t hi = q->to_ns ? q->to_ns : INT64_MAX;
  if (q->before_ns && q->before_ns < hi) hi = q->before_ns;
  buckets_buf_append_char(out, '[');
  bool first = true;
  for (size_t i = ns; i-- > 0 && found < limit;) { /* newest first */
    int64_t start = segment_start_ns(&segs[i]), end = start + 3600LL * 1000000000LL;
    if (start > hi || (q->from_ns && end < q->from_ns)) continue;
    buckets_buf text = BUCKETS_BUF_INIT;
    if (!read_segment(&segs[i], &text)) {
      buckets_buf_free(&text);
      continue;
    }
    /* the segment's matches, in its (time) order; then taken newest first */
    size_t *off = NULL, *len = NULL, nm = 0;
    for (size_t p = 0; p < text.len;) {
      size_t l = strcspn(text.data + p, "\n");
      if (l) {
        yyjson_doc *d = yyjson_read(text.data + p, l, 0);
        if (d && buckets_audit_match(yyjson_doc_get_root(d), q)) {
          off = buckets_xrealloc(off, (nm + 1) * sizeof(*off));
          len = buckets_xrealloc(len, (nm + 1) * sizeof(*len));
          off[nm] = p, len[nm++] = l;
        }
        yyjson_doc_free(d);
      }
      p += l + 1;
    }
    for (size_t m = nm; m-- > 0 && found < limit;) {
      if (!first) buckets_buf_append_char(out, ',');
      buckets_buf_append(out, text.data + off[m], len[m]);
      first = false;
      found++;
    }
    free(off);
    free(len);
    buckets_buf_free(&text);
  }
  buckets_buf_append_char(out, ']');
  free(segs);
  return found;
}

/* ---- retention ------------------------------------------------------------------------------------------------ */

uint64_t buckets_audit_retain(const char *root, int days, uint64_t max_bytes, int64_t now) {
  segment *segs;
  size_t ns = list_segments(root, &segs);
  char keep_from[11];
  buckets_usage_day(now - (int64_t)(days - 1) * 86400, keep_from);
  uint64_t total = 0;
  for (size_t i = 0; i < ns; i++) total += segs[i].size;
  for (size_t i = 0; i < ns; i++) {
    bool old = strcmp(segs[i].day, keep_from) < 0;
    bool over = total > max_bytes && i + 1 < ns; /* never the segment being written */
    if (!old && !over) break;
    if (unlink(segs[i].path) == 0 || errno == ENOENT) total -= segs[i].size;
    char dir[4200];
    snprintf(dir, sizeof(dir), "%s/%s", root, segs[i].day);
    rmdir(dir); /* once empty */
  }
  free(segs);
  return total;
}

/* ---- the writer ----------------------------------------------------------------------------------------------- */

typedef struct qentry {
  struct qentry *next;
  size_t n;
  char json[];
} qentry;

struct buckets_audit_store {
  char *root;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  qentry *head, *tail;
  size_t qbytes;
  bool stop, flush_now;
  int flushed; /* bumped after each flush, for buckets_audit_store_flush */
  pthread_t writer;
  bool started;
  _Atomic uint64_t dropped;
  _Atomic uint64_t kept; /* bytes on the drive: at the last retention pass, plus what was written since */
  /* the writer's own */
  FILE *f;
  segment cur;
  uint64_t cur_size;
  int64_t last_retain;
};

/* Compresses a closed segment in place (.jsonl -> .jsonl.gz). */
static void compress_segment(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return;
  buckets_buf raw = BUCKETS_BUF_INIT;
  char tmp[65536];
  size_t k;
  while ((k = fread(tmp, 1, sizeof(tmp), f)) > 0) buckets_buf_append(&raw, tmp, k);
  fclose(f);
  struct libdeflate_compressor *z = libdeflate_alloc_compressor(6);
  size_t bound = z ? libdeflate_gzip_compress_bound(z, raw.len) : 0;
  uint8_t *gz = bound ? buckets_xmalloc(bound) : NULL;
  size_t gn = gz ? libdeflate_gzip_compress(z, raw.data ? raw.data : "", raw.len, gz, bound) : 0;
  if (z) libdeflate_free_compressor(z);
  buckets_buf_free(&raw);
  if (!gn) {
    free(gz);
    return; /* left as it is: still readable */
  }
  char out[4500], part[4600];
  snprintf(out, sizeof(out), "%s.gz", path);
  snprintf(part, sizeof(part), "%s.gz.tmp", path);
  FILE *o = fopen(part, "wb");
  bool ok = o && fwrite(gz, 1, gn, o) == gn;
  if (o) ok = fclose(o) == 0 && ok;
  free(gz);
  if (ok && rename(part, out) == 0)
    unlink(path);
  else
    unlink(part);
}

static void close_segment(buckets_audit_store *s) {
  if (!s->f) return;
  fclose(s->f);
  s->f = NULL;
  compress_segment(s->cur.path);
}

/* The segment for now: the open one, or a new one (a new hour, or the open one full). */
static bool open_segment(buckets_audit_store *s, int64_t now) {
  char day[11];
  buckets_usage_day(now, day);
  int hour = (int)((now % 86400) / 3600);
  if (s->f && !strcmp(s->cur.day, day) && s->cur.hour == hour && s->cur_size < SEGMENT_MAX) return true;
  close_segment(s);
  char dir[4200];
  snprintf(dir, sizeof(dir), "%s/%s", s->root, day);
  mkdir(s->root, 0700);
  if (mkdir(dir, 0700) != 0 && errno != EEXIST) return false;
  int seq = 0; /* after any segment of this hour already there (a restart) */
  segment *segs;
  size_t ns = list_segments(s->root, &segs);
  for (size_t i = 0; i < ns; i++)
    if (!strcmp(segs[i].day, day) && segs[i].hour == hour && segs[i].seq >= seq) seq = segs[i].seq + 1;
  free(segs);
  memset(&s->cur, 0, sizeof(s->cur));
  snprintf(s->cur.day, sizeof(s->cur.day), "%s", day);
  s->cur.hour = hour, s->cur.seq = seq;
  snprintf(s->cur.path, sizeof(s->cur.path), "%s/%02d-%04d.jsonl", dir, hour, seq);
  s->f = fopen(s->cur.path, "ab");
  s->cur_size = 0;
  return s->f != NULL;
}

/* Segments a previous run left open: compressed now. */
static void compress_leftovers(buckets_audit_store *s) {
  segment *segs;
  size_t ns = list_segments(s->root, &segs);
  for (size_t i = 0; i < ns; i++)
    if (!segs[i].gz) compress_segment(segs[i].path);
  free(segs);
}

static void *writer_main(void *arg) {
  buckets_audit_store *s = arg;
  compress_leftovers(s);
  pthread_mutex_lock(&s->mu);
  for (;;) {
    if (!s->head && !s->stop && !s->flush_now) {
      struct timespec until;
      clock_gettime(CLOCK_REALTIME, &until);
      until.tv_sec += 1;
      pthread_cond_timedwait(&s->cv, &s->mu, &until);
    }
    qentry *batch = s->head;
    s->head = s->tail = NULL;
    s->qbytes = 0;
    bool stop = s->stop;
    pthread_mutex_unlock(&s->mu);
    int64_t now = (int64_t)time(NULL);
    for (qentry *e = batch, *nx; e; e = nx) {
      nx = e->next;
      if (open_segment(s, now) && fwrite(e->json, 1, e->n, s->f) == e->n && fputc('\n', s->f) != EOF)
        s->cur_size += e->n + 1, s->kept += e->n + 1;
      else
        s->dropped++;
      free(e);
    }
    if (s->f) fflush(s->f);
    if (s->f && (int64_t)(now / 3600) != (segment_start_ns(&s->cur) / 1000000000LL) / 3600) close_segment(s);
    if (now - s->last_retain >= RETAIN_EVERY_S) {
      s->kept = buckets_audit_retain(s->root, retain_days(), retain_bytes(), now);
      s->last_retain = now;
    }
    pthread_mutex_lock(&s->mu);
    s->flush_now = false;
    s->flushed++;
    pthread_cond_broadcast(&s->cv);
    if (stop && !s->head) break;
  }
  pthread_mutex_unlock(&s->mu);
  if (s->f) {
    fclose(s->f); /* left open: compressed at the next start, which may append to its hour */
    s->f = NULL;
  }
  return NULL;
}

buckets_audit_store *buckets_audit_store_new(const char *root) {
  buckets_audit_store *s = buckets_xcalloc(1, sizeof(*s));
  s->root = buckets_xstrdup(root);
  pthread_mutex_init(&s->mu, NULL);
  pthread_cond_init(&s->cv, NULL);
  if (mkdir(root, 0700) != 0 && errno != EEXIST) buckets_log_warn("audit: %s: %s", root, strerror(errno));
  s->started = pthread_create(&s->writer, NULL, writer_main, s) == 0;
  return s;
}

void buckets_audit_store_free(buckets_audit_store *s) {
  if (!s) return;
  pthread_mutex_lock(&s->mu);
  s->stop = true;
  pthread_cond_broadcast(&s->cv);
  pthread_mutex_unlock(&s->mu);
  if (s->started) pthread_join(s->writer, NULL);
  for (qentry *e = s->head, *nx; e; e = nx) nx = e->next, free(e);
  pthread_mutex_destroy(&s->mu);
  pthread_cond_destroy(&s->cv);
  free(s->root);
  free(s);
}

bool buckets_audit_store_put(buckets_audit_store *s, const char *json, size_t n) {
  if (!s || !n) return false;
  while (n && (json[n - 1] == '\n' || json[n - 1] == '\r')) n--; /* one line each */
  pthread_mutex_lock(&s->mu);
  if (s->stop || s->qbytes + n > QUEUE_MAX_BYTES) {
    pthread_mutex_unlock(&s->mu);
    s->dropped++;
    return false;
  }
  qentry *e = buckets_xmalloc(sizeof(*e) + n);
  e->next = NULL, e->n = n;
  memcpy(e->json, json, n);
  for (size_t i = 0; i < n; i++)
    if (e->json[i] == '\n') e->json[i] = ' ';
  if (s->tail)
    s->tail->next = e;
  else
    s->head = e;
  s->tail = e;
  s->qbytes += n;
  pthread_mutex_unlock(&s->mu);
  return true;
}

void buckets_audit_store_flush(buckets_audit_store *s) {
  pthread_mutex_lock(&s->mu);
  int target =
      s->flushed + 2; /* a whole round after this call: the one under way may have missed what was put */
  s->flush_now = true;
  pthread_cond_broadcast(&s->cv);
  while (s->flushed < target && s->started) pthread_cond_wait(&s->cv, &s->mu);
  pthread_mutex_unlock(&s->mu);
}

uint64_t buckets_audit_store_dropped(buckets_audit_store *s) { return s ? s->dropped : 0; }
uint64_t buckets_audit_store_kept(buckets_audit_store *s) { return s ? s->kept : 0; }
const char *buckets_audit_store_root(const buckets_audit_store *s) { return s ? s->root : ""; }
