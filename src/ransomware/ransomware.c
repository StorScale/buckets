/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ransomware/ransomware.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "core/strmap.h"

#define SLOTS 60 /* minutes kept */
#define MAX_CHANGES 1000

static const char *const k_changes[] = {"versioning-suspended", "noncurrent-expiry", "retention-bypassed",
                                        "bucket-deleted", "public-write"};
const char *buckets_rw_change_name(buckets_rw_change c) {
  return (unsigned)c < BUCKETS_RW_NCHANGES ? k_changes[c] : "";
}

static const char *const k_kinds[] = {"mass-delete", "mass-overwrite", "protection-removed"};
const char *buckets_rw_kind_name(buckets_rw_incident_kind k) { return (unsigned)k < 3 ? k_kinds[k] : ""; }

/* ---- counting -------------------------------------------------------------------------------------------- */

typedef struct {
  char *bucket, *ak, *user, *type;
  int64_t minute[SLOTS]; /* the minute (unix seconds / 60) each slot counts */
  uint64_t n[SLOTS][BUCKETS_RW_NKINDS];
} entry;

typedef struct {
  uint64_t seq;
  char *bucket, *ak, *user, *type, *detail;
  buckets_rw_change change;
  int64_t at;
} change;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static buckets_strmap g_entries; /* "bucket\nak" -> entry */
static buckets_strmap g_totals;  /* bucket -> buckets_rw_total */
static change *g_changes;
static size_t g_nchanges;
static uint64_t g_seq;

static char *dupz(const char *s) { return buckets_xstrdup(s ? s : ""); }

static buckets_rw_total *total_of(const char *bucket) {
  buckets_rw_total *t = buckets_strmap_get(&g_totals, bucket);
  if (!t) {
    t = buckets_xcalloc(1, sizeof(*t));
    t->bucket = buckets_xstrdup(bucket);
    buckets_strmap_put(&g_totals, bucket, t);
  }
  return t;
}

void buckets_rw_note(const char *bucket, const char *access_key, const char *user, const char *cred_type,
                     buckets_rw_kind kind, uint64_t n, int64_t now) {
  if (!bucket || !*bucket || !n || (unsigned)kind >= BUCKETS_RW_NKINDS) return;
  char key[1200];
  snprintf(key, sizeof(key), "%s\n%s", bucket, access_key ? access_key : "");
  int64_t minute = now / 60;
  pthread_mutex_lock(&g_mu);
  entry *e = buckets_strmap_get(&g_entries, key);
  if (!e) {
    e = buckets_xcalloc(1, sizeof(*e));
    e->bucket = dupz(bucket), e->ak = dupz(access_key), e->user = dupz(user), e->type = dupz(cred_type);
    buckets_strmap_put(&g_entries, key, e);
  }
  int s = (int)(minute % SLOTS);
  if (e->minute[s] != minute) {
    e->minute[s] = minute;
    memset(e->n[s], 0, sizeof(e->n[s]));
  }
  e->n[s][kind] += n;
  total_of(bucket)->n[kind] += n;
  pthread_mutex_unlock(&g_mu);
}

void buckets_rw_protection(const char *bucket, const char *access_key, const char *user,
                           const char *cred_type, buckets_rw_change change_, const char *detail,
                           int64_t now) {
  if (!bucket || (unsigned)change_ >= BUCKETS_RW_NCHANGES) return;
  pthread_mutex_lock(&g_mu);
  if (g_nchanges == MAX_CHANGES) { /* the leader is far behind or gone: the oldest go */
    change *o = &g_changes[0];
    free(o->bucket), free(o->ak), free(o->user), free(o->type), free(o->detail);
    memmove(g_changes, g_changes + 1, (MAX_CHANGES - 1) * sizeof(change));
    g_nchanges--;
  }
  g_changes = buckets_xrealloc(g_changes, (g_nchanges + 1) * sizeof(change));
  g_changes[g_nchanges++] = (change){++g_seq,         dupz(bucket), dupz(access_key), dupz(user),
                                     dupz(cred_type), dupz(detail), change_,          now};
  total_of(bucket)->changes[change_]++;
  pthread_mutex_unlock(&g_mu);
}

static int total_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_rw_total *)a)->bucket, ((const buckets_rw_total *)b)->bucket);
}

size_t buckets_rw_totals(buckets_rw_total **out) {
  pthread_mutex_lock(&g_mu);
  size_t n = 0, it = 0;
  void *v;
  while (buckets_strmap_next(&g_totals, &it, NULL, &v)) n++;
  buckets_rw_total *t = buckets_xcalloc(n ? n : 1, sizeof(*t));
  size_t i = 0;
  it = 0;
  while (buckets_strmap_next(&g_totals, &it, NULL, &v)) {
    t[i] = *(buckets_rw_total *)v;
    t[i].bucket = buckets_xstrdup(t[i].bucket);
    i++;
  }
  pthread_mutex_unlock(&g_mu);
  if (n) qsort(t, n, sizeof(*t), total_cmp);
  *out = t;
  return n;
}

void buckets_rw_totals_free(buckets_rw_total *t, size_t n) {
  for (size_t i = 0; i < n; i++) free(t[i].bucket);
  free(t);
}

static void entry_free(entry *e) {
  free(e->bucket), free(e->ak), free(e->user), free(e->type);
  free(e);
}

void buckets_rw_snapshot(const char *node, int window_min, uint64_t since, int64_t now, buckets_buf *out) {
  if (window_min < 1) window_min = 1;
  if (window_min > SLOTS) window_min = SLOTS;
  int64_t minute = now / 60;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *rows = yyjson_mut_arr(d), *chs = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  pthread_mutex_lock(&g_mu);
  yyjson_mut_obj_add_strcpy(d, root, "node", node ? node : "");
  yyjson_mut_obj_add_uint(d, root, "seq", g_seq);
  size_t it = 0;
  const char *key;
  void *v;
  char **stale = NULL;
  size_t nstale = 0;
  while (buckets_strmap_next(&g_entries, &it, &key, &v)) {
    entry *e = v;
    uint64_t sum[BUCKETS_RW_NKINDS] = {0};
    bool live = false;
    for (int s = 0; s < SLOTS; s++) {
      if (e->minute[s] > minute - SLOTS) live = true;
      if (e->minute[s] <= minute - window_min || e->minute[s] > minute) continue;
      for (int k = 0; k < BUCKETS_RW_NKINDS; k++) sum[k] += e->n[s][k];
    }
    if (!live) { /* nothing in the last hour: forgotten */
      stale = buckets_xrealloc(stale, (nstale + 1) * sizeof(*stale));
      stale[nstale++] = buckets_xstrdup(key);
      continue;
    }
    if (!sum[0] && !sum[1] && !sum[2]) continue;
    yyjson_mut_val *r = yyjson_mut_arr_add_obj(d, rows);
    yyjson_mut_obj_add_strcpy(d, r, "b", e->bucket);
    yyjson_mut_obj_add_strcpy(d, r, "k", e->ak);
    yyjson_mut_obj_add_strcpy(d, r, "u", e->user);
    yyjson_mut_obj_add_strcpy(d, r, "t", e->type);
    yyjson_mut_val *nn = yyjson_mut_obj_add_arr(d, r, "n");
    for (int k = 0; k < BUCKETS_RW_NKINDS; k++) yyjson_mut_arr_add_uint(d, nn, sum[k]);
  }
  for (size_t i = 0; i < nstale; i++) {
    entry_free(buckets_strmap_del(&g_entries, stale[i]));
    free(stale[i]);
  }
  free(stale);
  for (size_t i = 0; i < g_nchanges; i++) {
    const change *c = &g_changes[i];
    if (c->seq <= since) continue;
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, chs);
    yyjson_mut_obj_add_uint(d, o, "seq", c->seq);
    yyjson_mut_obj_add_strcpy(d, o, "b", c->bucket);
    yyjson_mut_obj_add_strcpy(d, o, "k", c->ak);
    yyjson_mut_obj_add_strcpy(d, o, "u", c->user);
    yyjson_mut_obj_add_strcpy(d, o, "t", c->type);
    yyjson_mut_obj_add_str(d, o, "change", buckets_rw_change_name(c->change));
    yyjson_mut_obj_add_strcpy(d, o, "detail", c->detail);
    yyjson_mut_obj_add_sint(d, o, "at", c->at);
  }
  pthread_mutex_unlock(&g_mu);
  yyjson_mut_obj_add_val(d, root, "rows", rows);
  yyjson_mut_obj_add_val(d, root, "changes", chs);
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  if (j) buckets_buf_append(out, j, len);
  free(j);
  yyjson_mut_doc_free(d);
}

void buckets_rw_reset(void) {
  pthread_mutex_lock(&g_mu);
  size_t it = 0;
  void *v;
  while (buckets_strmap_next(&g_entries, &it, NULL, &v)) entry_free(v);
  buckets_strmap_free(&g_entries);
  it = 0;
  while (buckets_strmap_next(&g_totals, &it, NULL, &v)) {
    free(((buckets_rw_total *)v)->bucket);
    free(v);
  }
  buckets_strmap_free(&g_totals);
  memset(&g_entries, 0, sizeof(g_entries));
  memset(&g_totals, 0, sizeof(g_totals));
  for (size_t i = 0; i < g_nchanges; i++) {
    change *c = &g_changes[i];
    free(c->bucket), free(c->ak), free(c->user), free(c->type), free(c->detail);
  }
  free(g_changes);
  g_changes = NULL;
  g_nchanges = 0;
  g_seq = 0;
  pthread_mutex_unlock(&g_mu);
}

/* ---- detection ------------------------------------------------------------------------------------------- */

void buckets_rw_rows_add(buckets_rw_row **rows, size_t *n, yyjson_val *snapshot) {
  size_t i, max;
  yyjson_val *r;
  yyjson_arr_foreach(yyjson_obj_get(snapshot, "rows"), i, max, r) {
    const char *b = yyjson_get_str(yyjson_obj_get(r, "b")), *k = yyjson_get_str(yyjson_obj_get(r, "k"));
    if (!b || !k) continue;
    buckets_rw_row *row = NULL;
    for (size_t j = 0; j < *n && !row; j++)
      if (!strcmp((*rows)[j].bucket, b) && !strcmp((*rows)[j].access_key, k)) row = &(*rows)[j];
    if (!row) {
      *rows = buckets_xrealloc(*rows, (*n + 1) * sizeof(**rows));
      row = &(*rows)[(*n)++];
      memset(row, 0, sizeof(*row));
      row->bucket = buckets_xstrdup(b);
      row->access_key = buckets_xstrdup(k);
      row->user = dupz(yyjson_get_str(yyjson_obj_get(r, "u")));
      row->cred_type = dupz(yyjson_get_str(yyjson_obj_get(r, "t")));
    }
    yyjson_val *nn = yyjson_obj_get(r, "n");
    for (int kk = 0; kk < BUCKETS_RW_NKINDS; kk++)
      row->n[kk] += yyjson_get_uint(yyjson_arr_get(nn, (size_t)kk));
  }
}

void buckets_rw_rows_free(buckets_rw_row *rows, size_t n) {
  for (size_t i = 0; i < n; i++)
    free(rows[i].bucket), free(rows[i].access_key), free(rows[i].user), free(rows[i].cred_type);
  free(rows);
}

static long env_long(const char *name, long def, long lo, long hi) {
  const char *v = getenv(name);
  if (!v || !*v) return def;
  char *end;
  long n = strtol(v, &end, 10);
  if (*end == 'm' && end[1] == '\0') end++; /* "5m" */
  return *end || n < lo || n > hi ? def : n;
}

void buckets_rw_rule_from_env(buckets_rw_rule *r) {
  r->floor = (uint64_t)env_long("BUCKETS_RANSOMWARE_FLOOR", 1000, 1, 1000000000L);
  r->factor = (double)env_long("BUCKETS_RANSOMWARE_FACTOR", 10, 1, 1000000);
  r->window_min = (int)env_long("BUCKETS_RANSOMWARE_WINDOW", 5, 1, SLOTS);
}

bool buckets_rw_excluded(const char *bucket) {
  const char *v = getenv("BUCKETS_RANSOMWARE_EXCLUDE");
  size_t bl = strlen(bucket);
  for (const char *p = v; p && *p;) {
    size_t len = strcspn(p, ",");
    while (len && *p == ' ') p++, len--;
    size_t l = len;
    while (l && p[l - 1] == ' ') l--;
    if (l == bl && !strncmp(p, bucket, bl)) return true;
    p += len;
    if (*p == ',') p++;
  }
  return false;
}

static int kind_index(buckets_rw_incident_kind k) {
  return k == BUCKETS_RW_MASS_DELETE ? BUCKETS_RW_DELETED : BUCKETS_RW_OVERWRITTEN;
}

static bool is_burst(uint64_t count, uint64_t usual, const buckets_rw_rule *r) {
  return count >= r->floor && (double)count > r->factor * (double)usual;
}

/* the top contributors among rows[idx[0..m)] for kind k (largest first, up to 3), into b */
static void top_who(const buckets_rw_row *rows, const size_t *idx, size_t m, int k, buckets_rw_burst *b) {
  b->nwho = 0;
  for (size_t j = 0; j < m; j++) {
    const buckets_rw_row *r = &rows[idx[j]];
    uint64_t c = r->n[k];
    if (!c || (b->nwho == 3 && c <= b->who_n[2])) continue;
    size_t pos = 0;
    while (pos < b->nwho && b->who_n[pos] >= c) pos++;
    size_t end = b->nwho < 3 ? b->nwho : 2; /* the last kept slot moves down, or drops off */
    for (size_t s = end; s > pos; s--) b->who[s] = b->who[s - 1], b->who_n[s] = b->who_n[s - 1];
    b->who[pos] = r, b->who_n[pos] = c;
    if (b->nwho < 3) b->nwho++;
  }
}

size_t buckets_rw_detect(const buckets_rw_row *rows, size_t n, const buckets_rw_rule *rule,
                         buckets_rw_usual_fn usual, void *ud, buckets_rw_burst **out) {
  buckets_rw_burst *bursts = NULL;
  size_t nb = 0;
  size_t *idx = buckets_xcalloc(n ? n : 1, sizeof(size_t));
  bool *seen = buckets_xcalloc(n ? n : 1, sizeof(bool));
  static const buckets_rw_incident_kind kinds[] = {BUCKETS_RW_MASS_DELETE, BUCKETS_RW_MASS_OVERWRITE};
  for (size_t kk = 0; kk < 2; kk++) {
    buckets_rw_incident_kind kind = kinds[kk];
    int k = kind_index(kind);
    size_t first_of_kind = nb;
    /* per bucket */
    memset(seen, 0, n * sizeof(bool));
    for (size_t i = 0; i < n; i++) {
      if (seen[i] || buckets_rw_excluded(rows[i].bucket)) continue;
      size_t m = 0;
      uint64_t count = 0;
      for (size_t j = i; j < n; j++) {
        if (seen[j] || strcmp(rows[j].bucket, rows[i].bucket) != 0) continue;
        seen[j] = true;
        idx[m++] = j;
        count += rows[j].n[k];
      }
      uint64_t u = usual ? usual(ud, rows[i].bucket, kind) : 0;
      if (!is_burst(count, u, rule)) continue;
      bursts = buckets_xrealloc(bursts, (nb + 1) * sizeof(*bursts));
      buckets_rw_burst *b = &bursts[nb++];
      memset(b, 0, sizeof(*b));
      b->kind = kind, b->bucket = rows[i].bucket, b->count = count, b->usual = u;
      top_who(rows, idx, m, k, b);
    }
    /* per credential, over several buckets, when no bucket's burst names it */
    memset(seen, 0, n * sizeof(bool));
    for (size_t i = 0; i < n; i++) {
      if (seen[i]) continue;
      size_t m = 0, nbuckets = 0;
      uint64_t count = 0, u = 0;
      for (size_t j = i; j < n; j++) {
        if (seen[j] || strcmp(rows[j].access_key, rows[i].access_key) != 0) continue;
        seen[j] = true;
        if (buckets_rw_excluded(rows[j].bucket) || !rows[j].n[k]) continue;
        idx[m++] = j;
        count += rows[j].n[k];
        u += usual ? usual(ud, rows[j].bucket, kind) : 0;
        nbuckets++;
      }
      if (nbuckets < 2 || !is_burst(count, u, rule)) continue;
      bool named = false;
      for (size_t b = first_of_kind; b < nb && !named; b++)
        for (size_t w = 0; w < bursts[b].nwho && !named; w++)
          named = !strcmp(bursts[b].who[w]->access_key, rows[i].access_key);
      if (named) continue;
      bursts = buckets_xrealloc(bursts, (nb + 1) * sizeof(*bursts));
      buckets_rw_burst *b = &bursts[nb++];
      memset(b, 0, sizeof(*b));
      b->kind = kind, b->bucket = NULL, b->count = count, b->usual = u;
      b->who[0] = &rows[idx[0]], b->who_n[0] = count, b->nwho = 1;
    }
  }
  free(idx);
  free(seen);
  *out = bursts;
  return nb;
}

uint64_t buckets_rw_usual_from_history(const buckets_buf *records, const int *day, size_t n,
                                       const char *bucket, buckets_rw_incident_kind kind, int window_min) {
  uint64_t hours[14][24];
  memset(hours, 0, sizeof(hours));
  const char *key = kind == BUCKETS_RW_MASS_DELETE ? "dh" : "oh";
  for (size_t i = 0; i < n; i++) {
    if (day[i] < 0 || day[i] >= 14 || !records[i].len) continue;
    yyjson_doc *d = yyjson_read(records[i].data, records[i].len, 0);
    yyjson_val *h =
        yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(d), "buckets"), bucket), key);
    for (size_t x = 0; x < 24 && x < yyjson_arr_size(h); x++)
      hours[day[i]][x] += yyjson_get_uint(yyjson_arr_get(h, x));
    yyjson_doc_free(d);
  }
  /* each day's busiest hour; the median over the 14 days (a day without records counts 0): an attack, or any
   * other one-off, moves it not at all, while a clean-up that runs every night sets it */
  uint64_t top[14];
  for (int dd = 0; dd < 14; dd++) {
    top[dd] = 0;
    for (int x = 0; x < 24; x++)
      if (hours[dd][x] > top[dd]) top[dd] = hours[dd][x];
  }
  for (int a = 1; a < 14; a++) /* insertion sort, ascending */
    for (int b = a; b > 0 && top[b - 1] > top[b]; b--) {
      uint64_t t = top[b];
      top[b] = top[b - 1], top[b - 1] = t;
    }
  uint64_t median = top[7]; /* the upper median of 14 */
  return (uint64_t)ceil((double)median * (window_min > 0 ? window_min : 5) / 60.0);
}

/* ---- incidents ------------------------------------------------------------------------------------------- */

yyjson_mut_doc *buckets_rw_incidents_parse(const char *json, size_t len) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_doc *in = json && len ? yyjson_read(json, len, 0) : NULL;
  yyjson_val *arr = yyjson_obj_get(yyjson_doc_get_root(in), "incidents");
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_val(d, root, "incidents",
                         yyjson_is_arr(arr) ? yyjson_val_mut_copy(d, arr) : yyjson_mut_arr(d));
  yyjson_doc_free(in);
  return d;
}

static yyjson_mut_val *incidents(yyjson_mut_doc *d) {
  return yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents");
}

static bool str_is(yyjson_mut_val *v, const char *s) {
  const char *x = yyjson_mut_get_str(v);
  return s ? x && !strcmp(x, s) : yyjson_mut_is_null(v);
}

yyjson_mut_val *buckets_rw_incident_open(yyjson_mut_doc *d, buckets_rw_incident_kind kind, const char *bucket,
                                         const char *access_key) {
  size_t i, max;
  yyjson_mut_val *x;
  yyjson_mut_arr_foreach(incidents(d), i, max, x) {
    if (yyjson_mut_get_sint(yyjson_mut_obj_get(x, "closed")) != 0) continue;
    if (!str_is(yyjson_mut_obj_get(x, "kind"), buckets_rw_kind_name(kind))) continue;
    if (!str_is(yyjson_mut_obj_get(x, "bucket"), bucket)) continue;
    if (!bucket) {
      yyjson_mut_val *c0 = yyjson_mut_arr_get_first(yyjson_mut_obj_get(x, "credentials"));
      if (!str_is(yyjson_mut_obj_get(c0, "accessKey"), access_key)) continue;
    }
    return x;
  }
  return NULL;
}

static void set_uint(yyjson_mut_doc *d, yyjson_mut_val *o, const char *k, uint64_t v) {
  yyjson_mut_obj_remove_key(o, k);
  yyjson_mut_obj_add_uint(d, o, k, v);
}

static void set_credentials(yyjson_mut_doc *d, yyjson_mut_val *o, const buckets_rw_burst *b) {
  yyjson_mut_obj_remove_key(o, "credentials");
  yyjson_mut_val *cs = yyjson_mut_obj_add_arr(d, o, "credentials");
  for (size_t w = 0; w < b->nwho; w++) {
    yyjson_mut_val *c = yyjson_mut_arr_add_obj(d, cs);
    yyjson_mut_obj_add_strcpy(d, c, "accessKey", b->who[w]->access_key);
    yyjson_mut_obj_add_strcpy(d, c, "user", b->who[w]->user);
    yyjson_mut_obj_add_strcpy(d, c, "type", b->who[w]->cred_type);
    yyjson_mut_obj_add_uint(d, c, "count", b->who_n[w]);
  }
}

yyjson_mut_val *buckets_rw_incident_record(yyjson_mut_doc *d, const buckets_rw_burst *b, const char *id,
                                           int64_t now, bool *opened) {
  const char *who = b->nwho ? b->who[0]->access_key : "";
  yyjson_mut_val *x = buckets_rw_incident_open(d, b->kind, b->bucket, who);
  *opened = x == NULL;
  if (!x) {
    x = yyjson_mut_arr_add_obj(d, incidents(d));
    yyjson_mut_obj_add_strcpy(d, x, "id", id);
    yyjson_mut_obj_add_str(d, x, "kind", buckets_rw_kind_name(b->kind));
    if (b->bucket)
      yyjson_mut_obj_add_strcpy(d, x, "bucket", b->bucket);
    else
      yyjson_mut_obj_add_null(d, x, "bucket");
    yyjson_mut_obj_add_sint(d, x, "opened", now);
    yyjson_mut_obj_add_sint(d, x, "closed", 0);
    yyjson_mut_obj_add_null(d, x, "action");
    yyjson_mut_obj_add_bool(d, x, "undone", false);
    yyjson_mut_obj_add_bool(d, x, "falseAlarm", false);
    yyjson_mut_obj_add_obj(d, x, "counts");
  }
  yyjson_mut_obj_remove_key(x, "lastSeen");
  yyjson_mut_obj_add_sint(d, x, "lastSeen", now);
  set_uint(d, x, "usual", b->usual);
  /* the largest window count seen while open */
  yyjson_mut_val *counts = yyjson_mut_obj_get(x, "counts");
  const char *ck = b->kind == BUCKETS_RW_MASS_DELETE ? "deleted" : "overwritten";
  if (b->count > yyjson_mut_get_uint(yyjson_mut_obj_get(counts, ck))) {
    set_uint(d, counts, ck, b->count);
    set_credentials(d, x, b);
  }
  return x;
}

void buckets_rw_incidents_age(yyjson_mut_doc *d, int64_t now, int64_t quiet, int64_t keep) {
  yyjson_mut_val *arr = incidents(d);
  for (size_t i = yyjson_mut_arr_size(arr); i-- > 0;) {
    yyjson_mut_val *x = yyjson_mut_arr_get(arr, i);
    int64_t closed = yyjson_mut_get_sint(yyjson_mut_obj_get(x, "closed"));
    if (!closed && now - yyjson_mut_get_sint(yyjson_mut_obj_get(x, "lastSeen")) >= quiet) {
      yyjson_mut_obj_remove_key(x, "closed");
      yyjson_mut_obj_add_sint(d, x, "closed", now);
    } else if (closed && now - closed > keep) {
      yyjson_mut_arr_remove(arr, i);
    }
  }
}

bool buckets_rw_incident_has_source(yyjson_mut_doc *d, const char *source) {
  size_t i, max;
  yyjson_mut_val *x;
  yyjson_mut_arr_foreach(incidents(d), i, max, x) {
    if (str_is(yyjson_mut_obj_get(x, "source"), source)) return true;
  }
  return false;
}
