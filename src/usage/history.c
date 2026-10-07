/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "usage/history.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/common.h"

/* ---- days ------------------------------------------------------------------------------------- */

static int64_t days_from_civil(int y, unsigned m, unsigned d) { /* Howard Hinnant's */
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = (unsigned)(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (int64_t)doe - 719468;
}

void buckets_usage_day(int64_t unix_s, char out[11]) {
  time_t t = (time_t)unix_s;
  struct tm tm;
  gmtime_r(&t, &tm);
  snprintf(out, 11, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

bool buckets_usage_day_parse(const char *day, int64_t *unix_s) {
  int y, m, d;
  char rest;
  if (!day || strlen(day) != 10 || sscanf(day, "%4d-%2d-%2d%c", &y, &m, &d, &rest) != 3) return false;
  if (m < 1 || m > 12 || d < 1 || d > 31 || y < 1970) return false;
  *unix_s = days_from_civil(y, (unsigned)m, (unsigned)d) * 86400;
  char back[11];
  buckets_usage_day(*unix_s, back);
  return strcmp(back, day) == 0; /* no 2026-02-31 */
}

int buckets_usage_days_in_month(const char *day) {
  int y = atoi(day), m = atoi(day + 5);
  static const int len[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
  return m == 2 && leap ? 29 : len[(m - 1) % 12];
}

void buckets_usage_keep_from(const char *today, int keep, char out[11]) {
  int64_t t = 0;
  buckets_usage_day_parse(today, &t);
  buckets_usage_day(t - (int64_t)(keep - 1) * 86400, out);
}

int buckets_usage_history_days(void) {
  const char *e = getenv("BUCKETS_USAGE_HISTORY_DAYS");
  long n = e ? strtol(e, NULL, 10) : 0;
  return n >= 1 && n <= 100000 ? (int)n : 396;
}

void buckets_usage_today(char out[11]) {
  const char *t = getenv("BUCKETS_USAGE_TEST_DAY");
  int64_t s;
  if (t && buckets_usage_day_parse(t, &s))
    snprintf(out, 11, "%s", t);
  else
    buckets_usage_day((int64_t)time(NULL), out);
}

/* ---- what is counted -------------------------------------------------------------------------- */

static bool starts(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

buckets_usage_kind buckets_usage_kind_of(const char *api) {
  if (starts(api, "delete")) return BUCKETS_USAGE_DELETE;
  static const char *const writes[] = {"put", "post", "copy", "new", "complete", "abort", "reset"};
  for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++)
    if (starts(api, writes[i])) return BUCKETS_USAGE_WRITE;
  return BUCKETS_USAGE_READ; /* get, head, list, select, validate */
}

static yyjson_mut_val *bucket_obj(yyjson_mut_doc *d, yyjson_mut_val *buckets, const char *name) {
  yyjson_mut_val *o = yyjson_mut_obj_get(buckets, name);
  if (!o) {
    o = yyjson_mut_obj(d);
    yyjson_mut_obj_add(buckets, yyjson_mut_strcpy(d, name), o);
  }
  return o;
}

static uint64_t mut_u(yyjson_mut_val *o, const char *k) {
  return yyjson_mut_get_uint(yyjson_mut_obj_get(o, k));
}
static double mut_d(yyjson_mut_val *o, const char *k) {
  yyjson_mut_val *v = yyjson_mut_obj_get(o, k);
  return yyjson_mut_is_real(v) ? yyjson_mut_get_real(v) : (double)yyjson_mut_get_uint(v);
}
static void set_u(yyjson_mut_doc *d, yyjson_mut_val *o, const char *k, uint64_t v) {
  yyjson_mut_obj_remove_key(o, k);
  yyjson_mut_obj_add_uint(d, o, k, v);
}

/* The record parsed into a mutable document with a "buckets" object. */
static yyjson_mut_doc *record(const char *json, size_t len, yyjson_mut_val **buckets) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_doc *in = json && len ? yyjson_read(json, len, 0) : NULL;
  yyjson_mut_val *root = in && yyjson_is_obj(yyjson_doc_get_root(in))
                             ? yyjson_val_mut_copy(d, yyjson_doc_get_root(in))
                             : yyjson_mut_obj(d);
  yyjson_doc_free(in);
  yyjson_mut_doc_set_root(d, root);
  *buckets = yyjson_mut_obj_get(root, "buckets");
  if (!yyjson_mut_is_obj(*buckets)) {
    yyjson_mut_obj_remove_key(root, "buckets");
    *buckets = yyjson_mut_obj_add_obj(d, root, "buckets");
  }
  return d;
}

static void write_doc(yyjson_mut_doc *d, buckets_buf *out) {
  size_t n;
  char *j = yyjson_mut_write(d, 0, &n);
  if (j) buckets_buf_append(out, j, n);
  free(j);
  yyjson_mut_doc_free(d);
}

void buckets_usage_traffic_merge(const char *json, size_t len, const buckets_usage_traffic_add *add, size_t n,
                                 buckets_buf *out) {
  yyjson_mut_val *bs;
  yyjson_mut_doc *d = record(json, len, &bs);
  static const char *const keys[] = {"in", "out", "read", "write", "delete"};
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *o = bucket_obj(d, bs, add[i].bucket);
    const uint64_t v[] = {add[i].t.in, add[i].t.out, add[i].t.read, add[i].t.write, add[i].t.del};
    for (size_t k = 0; k < 5; k++) set_u(d, o, keys[k], mut_u(o, keys[k]) + v[k]);
  }
  write_doc(d, out);
}

void buckets_usage_storage_merge(const char *json, size_t len, const buckets_usage_sample *s, size_t n,
                                 buckets_buf *out) {
  yyjson_mut_val *bs;
  yyjson_mut_doc *d = record(json, len, &bs);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *o = bucket_obj(d, bs, s[i].bucket);
    uint64_t count = mut_u(o, "count") + 1, peak = mut_u(o, "peak");
    double avg = mut_d(o, "avg");
    avg += ((double)s[i].bytes - avg) / (double)count; /* a running mean: no sum to overflow */
    yyjson_mut_obj_remove_key(o, "avg");
    yyjson_mut_obj_add_real(d, o, "avg", avg);
    set_u(d, o, "count", count);
    set_u(d, o, "peak", s[i].bytes > peak ? s[i].bytes : peak);
    set_u(d, o, "last", s[i].bytes);
  }
  write_doc(d, out);
}

/* ---- teams ------------------------------------------------------------------------------------- */

const char *buckets_usage_team_of(yyjson_val *teams, const char *bucket, bool *named_twice) {
  *named_twice = false;
  const char *named = NULL, *best = NULL;
  size_t best_len = 0, i, max, j, jm;
  yyjson_val *t, *x;
  yyjson_arr_foreach(teams, i, max, t) {
    const char *name = yyjson_get_str(yyjson_obj_get(t, "name"));
    if (!name) continue;
    yyjson_arr_foreach(yyjson_obj_get(t, "buckets"), j, jm, x) {
      if (!yyjson_equals_str(x, bucket)) continue;
      if (named)
        *named_twice = true;
      else
        named = name;
    }
    yyjson_arr_foreach(yyjson_obj_get(t, "prefixes"), j, jm, x) {
      const char *p = yyjson_get_str(x);
      size_t pl = p ? strlen(p) : 0;
      if (pl && strncmp(bucket, p, pl) == 0 && pl > best_len) best = name, best_len = pl;
    }
  }
  return named ? named : best;
}

/* ---- a period ---------------------------------------------------------------------------------- */

typedef struct {
  char *name;
  double byte_months; /* sum of daily averages / days in their month */
  uint64_t peak, last;
  bool have_last;
  buckets_usage_traffic t;
  uint64_t *daily_bytes, *daily_in, *daily_out;
  bool seen; /* in a record of the period */
} row;

typedef struct {
  row *r;
  size_t n, days;
} rows;

static row *row_of(rows *rs, const char *name) {
  for (size_t i = 0; i < rs->n; i++)
    if (strcmp(rs->r[i].name, name) == 0) return &rs->r[i];
  rs->r = buckets_xrealloc(rs->r, (rs->n + 1) * sizeof(row));
  row *r = &rs->r[rs->n++];
  memset(r, 0, sizeof(*r));
  r->name = buckets_xstrdup(name);
  r->daily_bytes = buckets_xcalloc(rs->days, sizeof(uint64_t));
  r->daily_in = buckets_xcalloc(rs->days, sizeof(uint64_t));
  r->daily_out = buckets_xcalloc(rs->days, sizeof(uint64_t));
  return r;
}

static int row_cmp(const void *a, const void *b) {
  return strcmp(((const row *)a)->name, ((const row *)b)->name);
}

static void add_traffic_json(yyjson_mut_doc *d, yyjson_mut_val *o, const buckets_usage_traffic *t) {
  yyjson_mut_obj_add_uint(d, o, "dataIn", t->in);
  yyjson_mut_obj_add_uint(d, o, "dataOut", t->out);
  yyjson_mut_val *rq = yyjson_mut_obj_add_obj(d, o, "requests");
  yyjson_mut_obj_add_uint(d, rq, "read", t->read);
  yyjson_mut_obj_add_uint(d, rq, "write", t->write);
  yyjson_mut_obj_add_uint(d, rq, "delete", t->del);
}

typedef struct {
  char *name;
  double byte_months;
  uint64_t peak;
  buckets_usage_traffic t;
  yyjson_mut_val *buckets;
} team_total;

bool buckets_usage_report(const buckets_usage_source *src, const char *from, const char *to,
                          yyjson_val *teams, yyjson_val *rates, buckets_buf *out, char *err, size_t errlen) {
  int64_t a, b;
  if (!buckets_usage_day_parse(from, &a) || !buckets_usage_day_parse(to, &b)) {
    snprintf(err, errlen, "from and to are days, as YYYY-MM-DD");
    return false;
  }
  if (b < a || (b - a) / 86400 >= 400) {
    snprintf(err, errlen, "the period is from 1 to 400 days, from before to");
    return false;
  }
  rows rs = {NULL, 0, (size_t)((b - a) / 86400 + 1)};
  buckets_buf rec = BUCKETS_BUF_INIT;
  /* the sizes known before from: the latest record in the 31 days before it */
  yyjson_doc *carry = NULL;
  for (int k = 1; k <= 31 && !carry; k++) {
    char day[11];
    buckets_usage_day(a - (int64_t)k * 86400, day);
    buckets_buf_reset(&rec);
    if (src->storage(src->ud, day, &rec)) carry = yyjson_read(rec.data, rec.len, 0);
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *missing = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < rs.days; i++) {
    char day[11];
    buckets_usage_day(a + (int64_t)i * 86400, day);
    int month = buckets_usage_days_in_month(day);
    buckets_buf_reset(&rec);
    yyjson_doc *sd = src->storage(src->ud, day, &rec) ? yyjson_read(rec.data, rec.len, 0) : NULL;
    if (sd) {
      yyjson_doc_free(carry);
      carry = sd;
      size_t j, jm;
      yyjson_val *k, *v;
      yyjson_obj_foreach(yyjson_obj_get(yyjson_doc_get_root(sd), "buckets"), j, jm, k, v) {
        row *r = row_of(&rs, yyjson_get_str(k));
        r->seen = true;
        yyjson_val *av = yyjson_obj_get(v, "avg");
        double avg = yyjson_is_real(av) ? yyjson_get_real(av) : (double)yyjson_get_uint(av);
        uint64_t peak = yyjson_get_uint(yyjson_obj_get(v, "peak"));
        r->byte_months += avg / month;
        if (peak > r->peak) r->peak = peak;
        r->last = yyjson_get_uint(yyjson_obj_get(v, "last"));
        r->have_last = true;
        r->daily_bytes[i] = (uint64_t)(avg + 0.5);
      }
    } else if (carry) { /* no cycle that day: the last known sizes */
      size_t j, jm;
      yyjson_val *k, *v;
      yyjson_obj_foreach(yyjson_obj_get(yyjson_doc_get_root(carry), "buckets"), j, jm, k, v) {
        row *r = row_of(&rs, yyjson_get_str(k));
        uint64_t last = yyjson_get_uint(yyjson_obj_get(v, "last"));
        r->byte_months += (double)last / month;
        if (last > r->peak) r->peak = last;
        r->last = last;
        r->have_last = true;
        r->daily_bytes[i] = last;
      }
    } else {
      yyjson_mut_arr_add_strcpy(d, missing, day);
    }
    buckets_buf *tr = NULL;
    size_t nt = src->traffic(src->ud, day, &tr);
    for (size_t s = 0; s < nt; s++) {
      yyjson_doc *td = yyjson_read(tr[s].data ? tr[s].data : "", tr[s].len, 0);
      size_t j, jm;
      yyjson_val *k, *v;
      yyjson_obj_foreach(yyjson_obj_get(yyjson_doc_get_root(td), "buckets"), j, jm, k, v) {
        row *r = row_of(&rs, yyjson_get_str(k));
        r->seen = true;
        uint64_t in = yyjson_get_uint(yyjson_obj_get(v, "in")), o = yyjson_get_uint(yyjson_obj_get(v, "out"));
        r->t.in += in;
        r->t.out += o;
        r->t.read += yyjson_get_uint(yyjson_obj_get(v, "read"));
        r->t.write += yyjson_get_uint(yyjson_obj_get(v, "write"));
        r->t.del += yyjson_get_uint(yyjson_obj_get(v, "delete"));
        r->daily_in[i] += in;
        r->daily_out[i] += o;
      }
      yyjson_doc_free(td);
      buckets_buf_free(&tr[s]);
    }
    free(tr);
  }
  yyjson_doc_free(carry);
  buckets_buf_free(&rec);
  if (rs.n) qsort(rs.r, rs.n, sizeof(row), row_cmp);

  yyjson_mut_obj_add_strcpy(d, root, "from", from);
  yyjson_mut_obj_add_strcpy(d, root, "to", to);
  yyjson_mut_obj_add_uint(d, root, "days", rs.days);
  yyjson_mut_obj_add_val(d, root, "rates", rates ? yyjson_val_mut_copy(d, rates) : yyjson_mut_null(d));
  yyjson_mut_val *barr = yyjson_mut_obj_add_arr(d, root, "buckets");
  team_total *tt = NULL;
  size_t ntt = 0;
  for (size_t i = 0; i < rs.n; i++) {
    row *r = &rs.r[i];
    bool twice;
    const char *team = buckets_usage_team_of(teams, r->name, &twice);
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, barr);
    yyjson_mut_obj_add_strcpy(d, o, "name", r->name);
    if (team)
      yyjson_mut_obj_add_strcpy(d, o, "team", team);
    else
      yyjson_mut_obj_add_null(d, o, "team");
    if (twice) yyjson_mut_obj_add_bool(d, o, "namedByTwoTeams", true);
    yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, o, "storage");
    yyjson_mut_obj_add_real(d, st, "gbMonths", r->byte_months / 1e9);
    yyjson_mut_obj_add_uint(d, st, "peakBytes", r->peak);
    yyjson_mut_obj_add_uint(d, st, "lastBytes", r->last);
    add_traffic_json(d, o, &r->t);
    yyjson_mut_val *daily = yyjson_mut_obj_add_arr(d, o, "daily");
    for (size_t k = 0; k < rs.days; k++) {
      char day[11];
      buckets_usage_day(a + (int64_t)k * 86400, day);
      yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, daily);
      yyjson_mut_obj_add_strcpy(d, e, "day", day);
      yyjson_mut_obj_add_uint(d, e, "bytes", r->daily_bytes[k]);
      yyjson_mut_obj_add_uint(d, e, "in", r->daily_in[k]);
      yyjson_mut_obj_add_uint(d, e, "out", r->daily_out[k]);
    }
    /* the team's totals; buckets in no team under "" (the page's No team) */
    const char *tn = team ? team : "";
    team_total *t = NULL;
    for (size_t k = 0; k < ntt && !t; k++)
      if (strcmp(tt[k].name, tn) == 0) t = &tt[k];
    if (!t) {
      tt = buckets_xrealloc(tt, (ntt + 1) * sizeof(*tt));
      t = &tt[ntt++];
      memset(t, 0, sizeof(*t));
      t->name = buckets_xstrdup(tn);
      t->buckets = yyjson_mut_arr(d);
    }
    t->byte_months += r->byte_months;
    t->peak += r->peak; /* the sum of the buckets' peaks: an upper bound */
    t->t.in += r->t.in, t->t.out += r->t.out, t->t.read += r->t.read, t->t.write += r->t.write,
        t->t.del += r->t.del;
    yyjson_mut_arr_add_strcpy(d, t->buckets, r->name);
    free(r->name);
    free(r->daily_bytes);
    free(r->daily_in);
    free(r->daily_out);
  }
  free(rs.r);
  yyjson_mut_val *tarr = yyjson_mut_obj_add_arr(d, root, "teams");
  for (size_t k = 0; k < ntt; k++) {
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, tarr);
    if (*tt[k].name)
      yyjson_mut_obj_add_strcpy(d, o, "name", tt[k].name);
    else
      yyjson_mut_obj_add_null(d, o, "name");
    yyjson_mut_obj_add_val(d, o, "buckets", tt[k].buckets);
    yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, o, "storage");
    yyjson_mut_obj_add_real(d, st, "gbMonths", tt[k].byte_months / 1e9);
    yyjson_mut_obj_add_uint(d, st, "peakBytes", tt[k].peak);
    add_traffic_json(d, o, &tt[k].t);
    free(tt[k].name);
  }
  free(tt);
  yyjson_mut_obj_add_val(d, root, "missingDays", missing);
  write_doc(d, out);
  return true;
}

bool buckets_usage_rates_check(yyjson_val *rates, char *err, size_t errlen) {
  if (!yyjson_is_obj(rates)) {
    snprintf(err, errlen, "the rates are an object");
    return false;
  }
  const char *cur = yyjson_get_str(yyjson_obj_get(rates, "currency"));
  if (!cur || !*cur || strlen(cur) > 8) {
    snprintf(err, errlen, "a currency of 1 to 8 characters, such as USD or EUR");
    return false;
  }
  static const char *const nums[] = {"storageGbMonth", "outGb",       "inGb",
                                     "per10kRead",     "per10kWrite", "per10kDelete"};
  for (size_t i = 0; i < sizeof(nums) / sizeof(nums[0]); i++) {
    yyjson_val *v = yyjson_obj_get(rates, nums[i]);
    if (v && (!yyjson_is_num(v) || yyjson_get_num(v) < 0)) {
      snprintf(err, errlen, "%s is a price from 0", nums[i]);
      return false;
    }
  }
  return true;
}
