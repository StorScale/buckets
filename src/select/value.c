/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Values, time and output records of S3 Select (MinIO's sql/value.go,
 * sql/timestampfuncs.go, json/record.go and csv/record.go), with Go's number
 * formatting and parsing. */
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "notify/event.h"
#include "select/sel.h"

/* ---- arena ---- */

struct sel_chunk {
  sel_chunk *next;
  size_t cap, used;
  _Alignas(16) unsigned char data[];
};

#define CHUNK_MIN (64 * 1024)

void *sel_alloc(sel_arena *a, size_t n) {
  n = (n + 15) & ~(size_t)15;
  if (!a->head || a->head->cap - a->head->used < n) {
    size_t cap = n > CHUNK_MIN ? n : CHUNK_MIN;
    sel_chunk *c = buckets_xmalloc(sizeof(*c) + cap);
    c->cap = cap;
    c->used = 0;
    c->next = a->head;
    a->head = c;
  }
  void *p = a->head->data + a->head->used;
  a->head->used += n;
  memset(p, 0, n);
  return p;
}

char *sel_strndup(sel_arena *a, const char *s, size_t n) {
  char *p = sel_alloc(a, n + 1);
  if (n) memcpy(p, s, n);
  p[n] = 0;
  return p;
}

void sel_arena_reset(sel_arena *a) {
  if (!a->head) return;
  sel_chunk *c = a->head;
  /* keep the oldest (first) chunk, the one steady-state use fits in */
  while (c->next) {
    sel_chunk *n = c->next;
    free(c);
    c = n;
  }
  c->used = 0;
  a->head = c;
}

void sel_arena_free(sel_arena *a) {
  for (sel_chunk *c = a->head, *n; c; c = n) {
    n = c->next;
    free(c);
  }
  a->head = NULL;
}

bool sel_fail(sel_err *e, const char *code, const char *fmt, ...) {
  if (e && !e->code) {
    e->code = code;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
    va_end(ap);
    if (!e->status) e->status = 400;
  }
  return false;
}

/* ---- UTF-8 ---- */

static size_t utf8_dec(const unsigned char *p, size_t n, uint32_t *cp) {
  if (!n) return 0;
  unsigned char c = p[0];
  if (c < 0x80) return *cp = c, 1;
  size_t len;
  uint32_t v, min;
  if ((c & 0xe0) == 0xc0) len = 2, v = c & 0x1f, min = 0x80;
  else if ((c & 0xf0) == 0xe0) len = 3, v = c & 0x0f, min = 0x800;
  else if ((c & 0xf8) == 0xf0) len = 4, v = c & 0x07, min = 0x10000;
  else return 0;
  if (n < len) return 0;
  for (size_t i = 1; i < len; i++) {
    if ((p[i] & 0xc0) != 0x80) return 0;
    v = v << 6 | (p[i] & 0x3f);
  }
  if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) return 0;
  *cp = v;
  return len;
}

bool sel_utf8_valid(const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s;
  for (size_t i = 0; i < n;) {
    uint32_t cp;
    size_t k = utf8_dec(p + i, n - i, &cp);
    if (!k) return false;
    i += k;
  }
  return true;
}

/* Runes as Go counts them (an invalid byte is one rune). */
size_t sel_utf8_count(const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s;
  size_t count = 0;
  for (size_t i = 0; i < n; count++) {
    uint32_t cp;
    size_t k = utf8_dec(p + i, n - i, &cp);
    i += k ? k : 1;
  }
  return count;
}

/* ---- Go number formatting ---- */

/* The shortest decimal digits that read back as f (f > 0, finite): the
 * digits and the decimal point's position. */
static int shortest_digits(double f, char dig[24], int *dp) {
  char buf[40];
  for (int p = 1; p <= 17; p++) {
    snprintf(buf, sizeof(buf), "%.*e", p - 1, f);
    if (p == 17 || strtod(buf, NULL) == f) break;
  }
  int nd = 0;
  const char *s = buf;
  for (; *s && *s != 'e'; s++)
    if (isdigit((unsigned char)*s)) dig[nd++] = *s;
  int exp = *s == 'e' ? atoi(s + 1) : 0;
  while (nd > 1 && dig[nd - 1] == '0') nd--;
  dig[nd] = 0;
  *dp = exp + 1;
  return nd;
}

static void fmt_e(buckets_buf *out, const char *dig, int nd, int dp) {
  buckets_buf_append_char(out, dig[0]);
  if (nd > 1) {
    buckets_buf_append_char(out, '.');
    buckets_buf_append(out, dig + 1, (size_t)nd - 1);
  }
  int exp = dp - 1;
  buckets_buf_appendf(out, "e%c%02d", exp < 0 ? '-' : '+', exp < 0 ? -exp : exp);
}

static void fmt_f(buckets_buf *out, const char *dig, int nd, int dp) {
  if (dp <= 0) {
    buckets_buf_append_char(out, '0');
  } else {
    for (int i = 0; i < dp; i++) buckets_buf_append_char(out, i < nd ? dig[i] : '0');
  }
  if (nd > dp) {
    buckets_buf_append_char(out, '.');
    for (int i = dp; i < 0; i++) buckets_buf_append_char(out, '0');
    for (int i = dp > 0 ? dp : 0; i < nd; i++) buckets_buf_append_char(out, dig[i]);
  }
}

static bool special(buckets_buf *out, double f, bool json) {
  if (isnan(f)) {
    buckets_buf_append_c(out, json ? "null" : "NaN");
    return true;
  }
  if (isinf(f)) {
    buckets_buf_append_c(out, json ? "null" : f > 0 ? "+Inf" : "-Inf");
    return true;
  }
  if (f == 0) {
    buckets_buf_append_c(out, signbit(f) ? "-0" : "0");
    return true;
  }
  return false;
}

void sel_fmt_float_g(buckets_buf *out, double f) {
  if (special(out, f, false)) return;
  if (f < 0) buckets_buf_append_char(out, '-'), f = -f;
  char dig[24];
  int dp, nd = shortest_digits(f, dig, &dp);
  int exp = dp - 1;
  if (exp < -4 || exp >= 6) fmt_e(out, dig, nd, dp);
  else fmt_f(out, dig, nd, dp);
}

/* NaN and infinities cannot be JSON; encoding/json fails on them, this
 * writes null. */
void sel_fmt_float_json(buckets_buf *out, double f) {
  if (special(out, f, true)) return;
  double abs = fabs(f);
  if (f < 0) buckets_buf_append_char(out, '-');
  char dig[24];
  int dp, nd = shortest_digits(abs, dig, &dp);
  if (abs < 1e-6 || abs >= 1e21) {
    size_t start = out->len;
    fmt_e(out, dig, nd, dp);
    /* e-09 -> e-9 */
    size_t n = out->len - start;
    char *b = out->data + start;
    if (n >= 4 && b[n - 4] == 'e' && b[n - 3] == '-' && b[n - 2] == '0') {
      b[n - 2] = b[n - 1];
      out->len--;
    }
  } else {
    fmt_f(out, dig, nd, dp);
  }
}

bool sel_parse_int(const char *s, size_t n, int64_t *out) {
  size_t i = 0;
  bool neg = false;
  if (i < n && (s[i] == '+' || s[i] == '-')) neg = s[i++] == '-';
  if (i == n) return false;
  uint64_t v = 0, lim = neg ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
  for (; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return false;
    uint64_t d = (uint64_t)(s[i] - '0');
    if (v > (lim - d) / 10) return false;
    v = v * 10 + d;
  }
  *out = neg ? (int64_t)(0 - v) : (int64_t)v;
  return true;
}

static bool ieq_word(const char *s, size_t n, const char *w) { return strlen(w) == n && strncasecmp(s, w, n) == 0; }

bool sel_parse_float(const char *s, size_t n, double *out) {
  if (n == 0 || n > 800) return false;
  size_t i = 0;
  bool neg = false;
  if (s[i] == '+' || s[i] == '-') neg = s[i++] == '-';
  const char *r = s + i;
  size_t rn = n - i;
  if (ieq_word(r, rn, "inf") || ieq_word(r, rn, "infinity")) return *out = neg ? -INFINITY : INFINITY, true;
  if (i == 0 && ieq_word(r, rn, "nan")) return *out = NAN, true;
  char buf[832];
  size_t k = 0;
  bool hex = rn > 2 && r[0] == '0' && (r[1] == 'x' || r[1] == 'X');
  size_t j = hex ? 2 : 0;
  int digits = 0;
  bool dot = false, exp = false;
  if (hex) buf[k++] = '0', buf[k++] = 'x';
  for (; j < rn; j++) {
    char c = r[j];
    if (c == '_' && hex) continue; /* digit separators, with a base prefix only */
    if ((hex ? isxdigit((unsigned char)c) : isdigit((unsigned char)c))) {
      digits++;
      buf[k++] = c;
    } else if (c == '.' && !dot) {
      dot = true;
      buf[k++] = c;
    } else {
      break;
    }
  }
  if (!digits) return false;
  if (j < rn && (hex ? (r[j] == 'p' || r[j] == 'P') : (r[j] == 'e' || r[j] == 'E'))) {
    exp = true;
    buf[k++] = r[j++];
    if (j < rn && (r[j] == '+' || r[j] == '-')) buf[k++] = r[j++];
    int ed = 0;
    for (; j < rn && isdigit((unsigned char)r[j]); j++) buf[k++] = r[j], ed++;
    if (!ed) return false;
  }
  if (j != rn || (hex && !exp)) return false;
  buf[k] = 0;
  errno = 0;
  double v = strtod(buf, NULL);
  if (isinf(v)) return false; /* ErrRange */
  *out = neg ? -v : v;
  return true;
}

/* ---- time ---- */

static int64_t days_from_civil(int64_t y, int64_t m, int64_t d) {
  y -= m <= 2;
  int64_t era = (y >= 0 ? y : y - 399) / 400;
  int64_t yoe = y - era * 400;
  int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, int *m, int *d) {
  z += 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  int64_t doe = z - era * 146097;
  int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t yy = yoe + era * 400;
  int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  int64_t mp = (5 * doy + 2) / 153;
  *d = (int)(doy - (153 * mp + 2) / 5 + 1);
  *m = (int)(mp < 10 ? mp + 3 : mp - 9);
  *y = yy + (*m <= 2);
}

static int64_t floordiv(int64_t a, int64_t b) { return a / b - (a % b != 0 && (a < 0) != (b < 0)); }

void sel_time_civil(sel_time t, sel_civil *c) {
  int64_t local = t.sec + t.off;
  int64_t days = floordiv(local, 86400);
  int64_t rem = local - days * 86400;
  civil_from_days(days, &c->year, &c->month, &c->day);
  c->hour = (int)(rem / 3600);
  c->min = (int)(rem % 3600 / 60);
  c->sec = (int)(rem % 60);
}

sel_time sel_time_from_civil(int64_t year, int64_t month, int64_t day, int64_t hour, int64_t min, int64_t sec, int32_t nsec,
                             int32_t off) {
  int64_t m0 = month - 1;
  year += floordiv(m0, 12);
  m0 -= floordiv(m0, 12) * 12;
  int64_t total = days_from_civil(year, m0 + 1, 1) + (day - 1);
  int64_t s = total * 86400 + hour * 3600 + min * 60 + sec - off;
  int64_t ns = nsec;
  s += floordiv(ns, 1000000000);
  ns -= floordiv(ns, 1000000000) * 1000000000;
  return (sel_time){s, (int32_t)ns, off};
}

int sel_time_cmp(sel_time a, sel_time b) {
  if (a.sec != b.sec) return a.sec < b.sec ? -1 : 1;
  if (a.nsec != b.nsec) return a.nsec < b.nsec ? -1 : 1;
  return 0;
}

static bool is_leap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static int days_in(int m, int64_t y) {
  static const int d[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  return m == 2 && is_leap(y) ? 29 : d[m - 1];
}

static bool num_fixed(const char **p, const char *end, int w, int *v) {
  if (end - *p < w) return false;
  int x = 0;
  for (int i = 0; i < w; i++) {
    char c = (*p)[i];
    if (c < '0' || c > '9') return false;
    x = x * 10 + (c - '0');
  }
  *p += w;
  *v = x;
  return true;
}

/* One layout: which parts it has (month, day, clock, seconds). */
static bool parse_layout(const char *s, const char *end, int parts, sel_time *t) {
  const char *p = s;
  int y, mo = 1, d = 1, h = 0, mi = 0, se = 0, ns = 0, off = 0;
  if (!num_fixed(&p, end, 4, &y)) return false;
  if (parts >= 1) {
    if (p == end || *p++ != '-' || !num_fixed(&p, end, 2, &mo) || mo < 1 || mo > 12) return false;
  }
  if (parts >= 2) {
    if (p == end || *p++ != '-' || !num_fixed(&p, end, 2, &d)) return false;
  }
  if (p == end || *p++ != 'T') return false;
  if (parts >= 3) {
    /* "15": one or two digits */
    if (p == end || *p < '0' || *p > '9') return false;
    h = *p++ - '0';
    if (p < end && *p >= '0' && *p <= '9') h = h * 10 + (*p++ - '0');
    if (h > 23) return false;
    if (p == end || *p++ != ':' || !num_fixed(&p, end, 2, &mi) || mi > 59) return false;
    if (parts >= 4) {
      if (p == end || *p++ != ':' || !num_fixed(&p, end, 2, &se) || se > 59) return false;
      if (end - p >= 2 && (*p == '.' || *p == ',') && p[1] >= '0' && p[1] <= '9') {
        p++;
        int digits = 0;
        while (p < end && *p >= '0' && *p <= '9') {
          if (digits < 9) ns = ns * 10 + (*p - '0');
          digits++;
          p++;
        }
        for (; digits < 9; digits++) ns *= 10;
      }
    }
    if (p == end) return false;
    if (*p == 'Z') {
      p++;
    } else {
      if (end - p < 6 || (*p != '+' && *p != '-')) return false;
      int sign = *p++ == '-' ? -1 : 1, oh, om;
      if (!num_fixed(&p, end, 2, &oh) || *p++ != ':' || !num_fixed(&p, end, 2, &om) || oh > 24 || om > 60) return false;
      off = sign * (oh * 3600 + om * 60);
    }
  }
  if (p != end) return false;
  if (d < 1 || d > days_in(mo, y)) return false;
  *t = sel_time_from_civil(y, mo, d, h, mi, se, ns, off);
  return true;
}

bool sel_time_parse(const char *s, size_t n, sel_time *t) {
  for (int parts = 0; parts <= 4; parts++)
    if (parse_layout(s, s + n, parts, t)) return true;
  return false;
}

static void fmt_zone(buckets_buf *out, int32_t off) {
  if (off == 0) {
    buckets_buf_append_char(out, 'Z');
    return;
  }
  int32_t a = off < 0 ? -off : off;
  buckets_buf_appendf(out, "%c%02d:%02d", off < 0 ? '-' : '+', a / 3600, a % 3600 / 60);
}

static void fmt_year(buckets_buf *out, int64_t y) {
  if (y < 0) buckets_buf_appendf(out, "-%04" PRId64, -y);
  else buckets_buf_appendf(out, "%04" PRId64, y);
}

void sel_time_format(buckets_buf *out, sel_time t) {
  sel_civil c;
  sel_time_civil(t, &c);
  fmt_year(out, c.year);
  if (t.nsec || c.sec || c.hour || c.min || t.off) {
    buckets_buf_appendf(out, "-%02d-%02dT%02d:%02d", c.month, c.day, c.hour, c.min);
    if (t.nsec || c.sec) {
      buckets_buf_appendf(out, ":%02d", c.sec);
      if (t.nsec) {
        char frac[16];
        snprintf(frac, sizeof(frac), "%09d", (int)t.nsec);
        int k = 9;
        while (k > 0 && frac[k - 1] == '0') k--;
        buckets_buf_append_char(out, '.');
        buckets_buf_append(out, frac, (size_t)k);
      }
    }
    fmt_zone(out, t.off);
  } else if (c.day != 1) {
    buckets_buf_appendf(out, "-%02d-%02dT", c.month, c.day);
  } else if (c.month != 1) {
    buckets_buf_appendf(out, "-%02dT", c.month);
  } else {
    buckets_buf_append_char(out, 'T');
  }
}

/* time.Time's JSON form (RFC 3339 with nanoseconds). */
static void fmt_rfc3339nano(buckets_buf *out, sel_time t) {
  sel_civil c;
  sel_time_civil(t, &c);
  buckets_buf_append_char(out, '"');
  fmt_year(out, c.year);
  buckets_buf_appendf(out, "-%02d-%02dT%02d:%02d:%02d", c.month, c.day, c.hour, c.min, c.sec);
  if (t.nsec) {
    char frac[16];
    snprintf(frac, sizeof(frac), "%09d", (int)t.nsec);
    int k = 9;
    while (k > 0 && frac[k - 1] == '0') k--;
    buckets_buf_append_char(out, '.');
    buckets_buf_append(out, frac, (size_t)k);
  }
  fmt_zone(out, t.off);
  buckets_buf_append_char(out, '"');
}

/* ---- values ---- */

const char *sv_type_name(const sel_value *v) {
  switch (v->t) {
  case SV_NULL: return "NULL";
  case SV_BOOL: return "BOOL";
  case SV_STR: return "STRING";
  case SV_INT: return "INT";
  case SV_FLOAT: return "FLOAT";
  case SV_TIME: return "TIMESTAMP";
  case SV_BYTES: return "BYTES";
  case SV_ARR: return "ARRAY";
  case SV_MISSING: return "MISSING";
  }
  return "--";
}

bool sv_is_numeric(const sel_value *v) { return v->t == SV_INT || v->t == SV_FLOAT; }

bool sv_to_float(const sel_value *v, double *f) {
  if (v->t == SV_FLOAT) return *f = v->f, true;
  if (v->t == SV_INT) return *f = (double)v->i, true;
  return false;
}

/* strings.TrimSpace */
static void trim_space(const char **p, size_t *n) {
  while (*n && isspace((unsigned char)**p)) (*p)++, (*n)--;
  while (*n && isspace((unsigned char)(*p)[*n - 1])) (*n)--;
}

bool sv_bytes_to_int(const sel_value *v, int64_t *i) {
  const char *p = v->s.p;
  size_t n = v->s.n;
  trim_space(&p, &n);
  return sel_parse_int(p, n, i);
}

bool sv_bytes_to_float(const sel_value *v, double *f) {
  const char *p = v->s.p;
  size_t n = v->s.n;
  trim_space(&p, &n);
  return sel_parse_float(p, n, f);
}

bool sv_bytes_to_bool(const sel_value *v, bool *b) {
  const char *p = v->s.p;
  size_t n = v->s.n;
  trim_space(&p, &n);
  if (ieq_word(p, n, "t") || ieq_word(p, n, "true") || ieq_word(p, n, "1")) return *b = true, true;
  if (ieq_word(p, n, "f") || ieq_word(p, n, "false") || ieq_word(p, n, "0")) return *b = false, true;
  return false;
}

bool sv_infer_arith(sel_value *a, sel_err *e) {
  if (a->t != SV_BYTES) return true;
  int64_t i;
  double f;
  if (sv_bytes_to_int(a, &i)) return *a = sv_int(i), true;
  if (sv_bytes_to_float(a, &f)) return *a = sv_float(f), true;
  (void)e;
  return sel_fail(e, "InvalidDataType", "The SQL expression contains an invalid data type.");
}

void sv_infer_string(sel_value *v) {
  if (v->t == SV_BYTES) v->t = SV_STR;
}

bool sv_infer_timestamp(sel_value *v, sel_err *e) {
  if (v->t == SV_STR || v->t == SV_BYTES) {
    sel_time t;
    if (!sel_time_parse(v->s.p, v->s.n, &t))
      return sel_fail(e, "InternalError", "parsing time \"%.*s\": cannot parse as a timestamp", (int)v->s.n, v->s.p);
    *v = sv_time(t);
  }
  return true;
}

bool sv_infer_cmp(sel_value *a, sel_value *b, sel_err *e) {
  bool ua = a->t == SV_BYTES, ub = b->t == SV_BYTES;
  if (!ua && !ub) return true;
  if (ua && ub) {
    int64_t ia, ib;
    double fa, fb;
    bool oai = sv_bytes_to_int(a, &ia), obi = sv_bytes_to_int(b, &ib);
    if (oai && obi) return *a = sv_int(ia), *b = sv_int(ib), true;
    bool oaf = sv_bytes_to_float(a, &fa), obf = sv_bytes_to_float(b, &fb);
    if (oaf && obf) return *a = sv_float(fa), *b = sv_float(fb), true;
    /* an int and a float (MinIO sets b from a's float here; kept) */
    if (oai && obf) return *a = sv_int(ia), *b = sv_float(fa), true;
    if (obi && oaf) return *a = sv_float(fa), *b = sv_int(ib), true;
    bool ba, bb;
    if (sv_bytes_to_bool(a, &ba) && sv_bytes_to_bool(b, &bb)) return *a = sv_bool(ba), *b = sv_bool(bb), true;
    a->t = SV_STR;
    b->t = SV_STR;
    return true;
  }
  if (!ua) return sv_infer_cmp(b, a, e);
  switch (b->t) {
  case SV_STR:
    a->t = SV_STR;
    return true;
  case SV_INT:
  case SV_FLOAT: {
    int64_t i;
    double f;
    if (sv_bytes_to_int(a, &i)) return *a = sv_int(i), true;
    if (sv_bytes_to_float(a, &f)) return *a = sv_float(f), true;
    return sel_fail(e, "InternalError", "Could not convert %.*s to a number", (int)a->s.n, a->s.p);
  }
  case SV_BOOL: {
    bool x;
    if (sv_bytes_to_bool(a, &x)) return *a = sv_bool(x), true;
    return sel_fail(e, "InternalError", "Could not convert %.*s to a boolean", (int)a->s.n, a->s.p);
  }
  default:
    return sel_fail(e, "InternalError", "cannot compare values of different types");
  }
}

static bool bool_compare(const char *op, bool l, bool r, bool *res, sel_err *e) {
  if (!strcmp(op, "=")) return *res = l == r, true;
  if (!strcmp(op, "!=")) return *res = l != r, true;
  return sel_fail(e, "InternalError", "invalid comparison operator for boolean arguments");
}

static int str_cmp(const sel_value *a, const sel_value *b) {
  size_t n = a->s.n < b->s.n ? a->s.n : b->s.n;
  int c = n ? memcmp(a->s.p, b->s.p, n) : 0;
  if (c) return c;
  return a->s.n < b->s.n ? -1 : a->s.n > b->s.n;
}

static bool ord(const char *op, int c) {
  if (!strcmp(op, "<")) return c < 0;
  if (!strcmp(op, "<=")) return c <= 0;
  if (!strcmp(op, ">")) return c > 0;
  if (!strcmp(op, ">=")) return c >= 0;
  if (!strcmp(op, "=")) return c == 0;
  return c != 0;
}

#define FLOAT_TOL 0.000001

bool sv_compare(sel_value *v, const char *op, sel_value *a, bool *res, sel_err *e) {
  if (!strcmp(op, "<>")) op = "!="; /* lexed and parsed but rejected by MinIO; SQL's not-equal here */
  if (!strcmp(op, "IS")) {
    if (a->t == SV_NULL) return *res = v->t == SV_NULL || v->t == SV_MISSING, true;
    if (a->t == SV_MISSING) return *res = v->t == SV_MISSING, true;
    op = "=";
  } else if (!strcmp(op, "ISNOT")) {
    if (a->t == SV_NULL) return *res = v->t != SV_NULL && v->t != SV_MISSING, true;
    if (a->t == SV_MISSING) return *res = v->t != SV_MISSING, true;
    op = "!=";
  } else if (strcmp(op, "<") && strcmp(op, "<=") && strcmp(op, ">") && strcmp(op, ">=") && strcmp(op, "=") &&
             strcmp(op, "!=")) {
    return sel_fail(e, "InternalError", "invalid arithmetic operator");
  }
  if (!sv_infer_cmp(v, a, e)) return false;
  if (v->t == SV_NULL || a->t == SV_NULL) return bool_compare(op, v->t == SV_NULL, a->t == SV_NULL, res, e);
  if (v->t == SV_MISSING || a->t == SV_MISSING)
    return bool_compare(op, v->t == SV_MISSING, a->t == SV_MISSING, res, e);
  if (v->t == SV_ARR && a->t == SV_ARR) {
    /* arrayCompare(op, a, v) */
    sel_value *l = a->a.v, *r = v->a.v;
    size_t ln = a->a.n, rn = v->a.n;
    if (!strcmp(op, "=")) {
      if (ln != rn) return *res = false, true;
      for (size_t i = 0; i < ln; i++) {
        bool eq;
        if (!sv_compare(&l[i], op, &r[i], &eq, e)) return false;
        if (!eq) return *res = false, true;
      }
      return *res = true, true;
    }
    if (!strcmp(op, "!=")) {
      for (size_t i = 0; i < ln && i < rn; i++) {
        bool ne;
        if (!sv_compare(&l[i], op, &r[i], &ne, e)) return false;
        if (ne) return *res = true, true;
      }
      return *res = false, true;
    }
    return sel_fail(e, "InternalError", "invalid comparison operator for boolean arguments");
  }
  if (sv_is_numeric(v) && sv_is_numeric(a)) {
    if (v->t == SV_INT && a->t == SV_INT) return *res = ord(op, v->i < a->i ? -1 : v->i > a->i), true;
    double l, r;
    sv_to_float(v, &l);
    sv_to_float(a, &r);
    double diff = fabs(l - r);
    if (!strcmp(op, "=")) return *res = diff < FLOAT_TOL, true;
    if (!strcmp(op, "!=")) return *res = diff > FLOAT_TOL, true;
    return *res = ord(op, l < r ? -1 : l > r), true;
  }
  if (v->t == SV_STR && a->t == SV_STR) return *res = ord(op, str_cmp(v, a)), true;
  if (v->t == SV_BOOL && a->t == SV_BOOL) return bool_compare(op, v->b, a->b, res, e);
  if (v->t == SV_TIME && a->t == SV_TIME) return *res = ord(op, sel_time_cmp(v->ts, a->ts)), true;
  if (!strcmp(op, "=")) return *res = false, true;
  if (!strcmp(op, "!=")) return *res = true, true;
  return sel_fail(e, "InternalError", "invalid comparison operator for boolean arguments");
}

bool sv_equals(const sel_value *a, const sel_value *b) {
  if (a->t != b->t) return false;
  switch (a->t) {
  case SV_NULL:
  case SV_MISSING: return true;
  case SV_BOOL: return a->b == b->b;
  case SV_INT: return a->i == b->i;
  case SV_FLOAT: return a->f == b->f;
  case SV_STR:
  case SV_BYTES: return a->s.n == b->s.n && (!a->s.n || !memcmp(a->s.p, b->s.p, a->s.n));
  case SV_TIME: return a->ts.sec == b->ts.sec && a->ts.nsec == b->ts.nsec && a->ts.off == b->ts.off;
  case SV_ARR:
    if (a->a.n != b->a.n) return false;
    for (size_t i = 0; i < a->a.n; i++)
      if (!sv_equals(&a->a.v[i], &b->a.v[i])) return false;
    return true;
  }
  return false;
}

bool sv_arith(sel_value *v, char op, sel_value *a, sel_err *e) {
  if (!sv_infer_arith(v, e) || !sv_infer_arith(a, e)) return false;
  if (!sv_is_numeric(v) || !sv_is_numeric(a))
    return sel_fail(e, "InvalidDataType", "The SQL expression contains an invalid data type.");
  if (v->t == SV_INT && a->t == SV_INT) {
    int64_t l = v->i, r = a->i, x = 0;
    switch (op) {
    case '+': x = (int64_t)((uint64_t)l + (uint64_t)r); break;
    case '-': x = (int64_t)((uint64_t)l - (uint64_t)r); break;
    case '*': x = (int64_t)((uint64_t)l * (uint64_t)r); break;
    case '/':
    case '%':
      if (r == 0) {
        *v = sv_int(0);
        return sel_fail(e, "InternalError", "cannot divide by 0");
      }
      if (r == -1) x = op == '/' ? (int64_t)(0 - (uint64_t)l) : 0;
      else x = op == '/' ? l / r : l % r;
      break;
    }
    *v = sv_int(x);
    return true;
  }
  double l, r, x = 0;
  sv_to_float(v, &l);
  sv_to_float(a, &r);
  switch (op) {
  case '+': x = l + r; break;
  case '-': x = l - r; break;
  case '*': x = l * r; break;
  case '/':
  case '%':
    if (r == 0) {
      *v = sv_float(0);
      return sel_fail(e, "InternalError", "cannot divide by 0");
    }
    x = op == '/' ? l / r : fmod(l, r);
    break;
  }
  *v = sv_float(x);
  return true;
}

bool sv_minmax(sel_value *v, sel_value *a, bool is_max, bool first, sel_err *e) {
  if (!sv_infer_arith(a, e)) return false;
  if (!sv_is_numeric(a)) return sel_fail(e, "InternalError", "cannot perform arithmetic on mismatched types");
  if (first) {
    *v = *a;
    return true;
  }
  if (v->t == SV_INT && a->t == SV_INT) {
    if (is_max ? a->i > v->i : a->i < v->i) v->i = a->i;
    return true;
  }
  double l, r;
  sv_to_float(v, &l);
  sv_to_float(a, &r);
  *v = sv_float(is_max ? fmax(l, r) : fmin(l, r));
  return true;
}

void sv_csv_string(buckets_buf *out, const sel_value *v) {
  switch (v->t) {
  case SV_NULL:
  case SV_MISSING: break;
  case SV_BOOL: buckets_buf_append_c(out, v->b ? "true" : "false"); break;
  case SV_STR:
  case SV_BYTES: buckets_buf_append(out, v->s.p, v->s.n); break;
  case SV_INT: buckets_buf_appendf(out, "%" PRId64, v->i); break;
  case SV_FLOAT: sel_fmt_float_g(out, v->f); break;
  case SV_TIME: sel_time_format(out, v->ts); break;
  case SV_ARR: sv_marshal_json(out, v); break;
  }
}

void sv_marshal_json(buckets_buf *out, const sel_value *v) {
  switch (v->t) {
  case SV_NULL: buckets_buf_append_c(out, "null"); break;
  case SV_MISSING: buckets_buf_append_c(out, "{}"); break; /* Missing{} marshals as an empty struct */
  case SV_BOOL: buckets_buf_append_c(out, v->b ? "true" : "false"); break;
  case SV_INT: buckets_buf_appendf(out, "%" PRId64, v->i); break;
  case SV_FLOAT: sel_fmt_float_json(out, v->f); break;
  case SV_STR: buckets_json_go_string(out, v->s.p, v->s.n); break;
  case SV_BYTES:
    /* raw JSON as it is; other untyped bytes (CSV fields) as strings */
    if (v->s.n && (v->s.p[0] == '{' || v->s.p[0] == '[')) buckets_buf_append(out, v->s.p, v->s.n);
    else buckets_json_go_string(out, v->s.p, v->s.n);
    break;
  case SV_TIME: fmt_rfc3339nano(out, v->ts); break;
  case SV_ARR:
    buckets_buf_append_char(out, '[');
    for (size_t i = 0; i < v->a.n; i++) {
      if (i) buckets_buf_append_char(out, ',');
      sv_marshal_json(out, &v->a.v[i]);
    }
    buckets_buf_append_char(out, ']');
    break;
  }
}

void jv_marshal(buckets_buf *out, const jv *v) {
  switch (v->t) {
  case JV_NULL: buckets_buf_append_c(out, "null"); break;
  case JV_BOOL: buckets_buf_append_c(out, v->b ? "true" : "false"); break;
  case JV_FLOAT: sel_fmt_float_json(out, v->f); break;
  case JV_INT: buckets_buf_appendf(out, "%" PRId64, v->i); break;
  case JV_STR: buckets_json_go_string(out, v->s.p, v->s.n); break;
  case JV_ARR:
    buckets_buf_append_char(out, '[');
    for (size_t i = 0; i < v->a.n; i++) {
      if (i) buckets_buf_append_char(out, ',');
      jv_marshal(out, &v->a.v[i]);
    }
    buckets_buf_append_char(out, ']');
    break;
  case JV_OBJ:
    buckets_buf_append_char(out, '{');
    for (size_t i = 0; i < v->o.n; i++) {
      if (i) buckets_buf_append_char(out, ',');
      buckets_json_go_string(out, v->o.kv[i].k, v->o.kv[i].kn);
      buckets_buf_append_char(out, ':');
      jv_marshal(out, &v->o.kv[i].v);
    }
    buckets_buf_append_char(out, '}');
    break;
  }
}

sel_value sv_from_jv(sel_arena *a, const jv *v) {
  switch (v->t) {
  case JV_NULL: return sv_null();
  case JV_BOOL: return sv_bool(v->b);
  case JV_FLOAT: return sv_float(v->f);
  case JV_INT: return sv_int(v->i);
  case JV_STR: return sv_str(v->s.p, v->s.n);
  case JV_OBJ: {
    buckets_buf b = BUCKETS_BUF_INIT;
    jv_marshal(&b, v);
    sel_value r = sv_bytes(sel_strndup(a, b.data ? b.data : "", b.len), b.len);
    buckets_buf_free(&b);
    return r;
  }
  case JV_ARR: {
    sel_value r = {.t = SV_ARR};
    r.a.n = v->a.n;
    r.a.v = sel_alloc(a, (v->a.n ? v->a.n : 1) * sizeof(sel_value));
    for (size_t i = 0; i < v->a.n; i++) r.a.v[i] = sv_from_jv(a, &v->a.v[i]);
    return r;
  }
  }
  return sv_null();
}

/* ---- output records ---- */

void sel_orec_add(sel_orec *r, sel_arena *a, const char *name, size_t nlen, sel_oval v) {
  if (r->n == r->cap) {
    size_t cap = r->cap ? r->cap * 2 : 16;
    sel_okv *kv = sel_alloc(a, cap * sizeof(*kv));
    if (r->n) memcpy(kv, r->kv, r->n * sizeof(*kv));
    r->kv = kv;
    r->cap = cap;
  }
  r->kv[r->n++] = (sel_okv){name, nlen, v};
}

static sel_oval ov_str(sel_arena *a, buckets_buf *b) {
  sel_oval o = {.t = OV_STR};
  o.s.n = b->len;
  o.s.p = sel_strndup(a, b->data ? b->data : "", b->len);
  return o;
}

bool sel_orec_set(sel_orec *r, sel_arena *a, const char *name, size_t nlen, const sel_value *v, sel_err *e) {
  (void)e;
  if (r->csv) {
    buckets_buf b = BUCKETS_BUF_INIT;
    sv_csv_string(&b, v);
    sel_orec_add(r, a, name, nlen, ov_str(a, &b));
    buckets_buf_free(&b);
    return true;
  }
  sel_oval o;
  switch (v->t) {
  case SV_BOOL: o = (sel_oval){.t = OV_BOOL, .b = v->b}; break;
  case SV_INT: o = (sel_oval){.t = OV_FLOAT, .f = (double)v->i}; break; /* ToFloat takes ints too */
  case SV_FLOAT: o = (sel_oval){.t = OV_FLOAT, .f = v->f}; break;
  case SV_TIME: {
    buckets_buf b = BUCKETS_BUF_INIT;
    sel_time_format(&b, v->ts);
    o = ov_str(a, &b);
    buckets_buf_free(&b);
    break;
  }
  case SV_STR: o = (sel_oval){.t = OV_STR, .s = {v->s.p, v->s.n}}; break;
  case SV_NULL: o = (sel_oval){.t = OV_NULL}; break;
  case SV_MISSING: return true;
  case SV_BYTES:
    o = (sel_oval){.t = v->s.n && (v->s.p[0] == '{' || v->s.p[0] == '[') ? OV_RAW : OV_STR, .s = {v->s.p, v->s.n}};
    break;
  case SV_ARR: o = (sel_oval){.t = OV_VARR, .arr = *v}; break;
  default: o = (sel_oval){.t = OV_NULL}; break;
  }
  /* "*" in a JSON column name */
  if (memchr(name, '*', nlen)) {
    buckets_buf b = BUCKETS_BUF_INIT;
    for (size_t i = 0; i < nlen; i++) {
      if (name[i] == '*') buckets_buf_append_c(&b, "__ALL__");
      else buckets_buf_append_char(&b, name[i]);
    }
    nlen = b.len;
    name = sel_strndup(a, b.data, b.len);
    buckets_buf_free(&b);
  }
  sel_orec_add(r, a, name, nlen, o);
  return true;
}

void sel_orec_clone(sel_orec *r, sel_arena *a, const sel_record *in) {
  r->n = 0;
  if (in->fmt == SEL_FMT_CSV) {
    extern void sel_csv_clone(sel_orec * r, sel_arena * a, const sel_record *in);
    sel_csv_clone(r, a, in);
    return;
  }
  r->csv = false;
  if (in->obj.t != JV_OBJ) return;
  for (size_t i = 0; i < in->obj.o.n; i++) {
    const jv_kv *kv = &in->obj.o.kv[i];
    sel_orec_add(r, a, kv->k, kv->kn, (sel_oval){.t = OV_JV, .j = &kv->v});
  }
}

/* A json.Record's value as JSON. */
static void ov_marshal(buckets_buf *out, const sel_oval *v) {
  switch (v->t) {
  case OV_NULL: buckets_buf_append_c(out, "null"); break;
  case OV_BOOL: buckets_buf_append_c(out, v->b ? "true" : "false"); break;
  case OV_INT: buckets_buf_appendf(out, "%" PRId64, v->i); break;
  case OV_FLOAT: sel_fmt_float_json(out, v->f); break;
  case OV_STR: buckets_json_go_string(out, v->s.p, v->s.n); break;
  case OV_RAW: buckets_buf_append(out, v->s.p, v->s.n); break;
  case OV_JV: jv_marshal(out, v->j); break;
  case OV_VARR: sv_marshal_json(out, &v->arr); break;
  }
}

void sel_orec_write_json(buckets_buf *out, const sel_orec *r) {
  buckets_buf_append_char(out, '{');
  bool first = true;
  for (size_t i = 0; i < r->n; i++) {
    if (r->csv && !r->kv[i].name) continue; /* a CSV field past the header's columns */
    if (!first) buckets_buf_append_char(out, ',');
    first = false;
    buckets_json_go_string(out, r->kv[i].name, r->kv[i].nlen);
    buckets_buf_append_char(out, ':');
    ov_marshal(out, &r->kv[i].v);
  }
  buckets_buf_append_char(out, '}');
}

/* json.Record.WriteCSV's column text. */
void sel_oval_csv_text(buckets_buf *out, const sel_oval *v);
void sel_oval_csv_text(buckets_buf *out, const sel_oval *v) {
  switch (v->t) {
  case OV_NULL: break;
  case OV_BOOL: buckets_buf_append_c(out, v->b ? "true" : "false"); break;
  case OV_INT: buckets_buf_appendf(out, "%" PRId64, v->i); break;
  case OV_FLOAT: sel_fmt_float_json(out, v->f); break;
  case OV_STR:
  case OV_RAW: buckets_buf_append(out, v->s.p, v->s.n); break;
  case OV_JV:
    switch (v->j->t) {
    case JV_NULL: break;
    case JV_STR: buckets_buf_append(out, v->j->s.p, v->j->s.n); break;
    default: jv_marshal(out, v->j); break; /* numbers, booleans; nested values as JSON */
    }
    break;
  case OV_VARR: sv_marshal_json(out, &v->arr); break;
  }
}
