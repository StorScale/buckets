/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "metrics/expo.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"

#include "metrics/catalog.inc"

static int def_cmp(const void *key, const void *elem) {
  return strcmp(key, ((const buckets_metric_def *)elem)->name);
}

static const buckets_metric_def *table(buckets_metric_catalog_kind k, size_t *n) {
  switch (k) {
  case BUCKETS_CATALOG_V2_RESOURCE: *n = BUCKETS_ARRAY_LEN(k_catalog_v2_resource); return k_catalog_v2_resource;
  case BUCKETS_CATALOG_V3: *n = BUCKETS_ARRAY_LEN(k_catalog_v3); return k_catalog_v3;
  default: *n = BUCKETS_ARRAY_LEN(k_catalog_v2); return k_catalog_v2;
  }
}

const buckets_metric_def *buckets_metric_lookup(buckets_metric_catalog_kind k, const char *name) {
  size_t n;
  const buckets_metric_def *t = table(k, &n);
  return bsearch(name, t, n, sizeof(*t), def_cmp);
}

const buckets_metric_def *buckets_metric_catalog(buckets_metric_catalog_kind k, size_t *n) { return table(k, n); }

/* ---- Go's float formatting ------------------------------------------------ */

void buckets_go_float(double v, char out[40]) {
  const char *special = v == 1 ? "1" : v == 0 ? "0" : v == -1 ? "-1" : isnan(v) ? "NaN" : isinf(v) ? (v > 0 ? "+Inf" : "-Inf") : NULL;
  if (special) {
    snprintf(out, 40, "%s", special);
    return;
  }
  /* the shortest digits that read back as v */
  char e[40];
  int prec = 1;
  for (; prec <= 17; prec++) {
    snprintf(e, sizeof(e), "%.*e", prec - 1, v);
    if (strtod(e, NULL) == v) break;
  }
  bool neg = e[0] == '-';
  const char *p = e + neg;
  char digs[24];
  int nd = 0;
  for (; *p && *p != 'e'; p++)
    if (*p >= '0' && *p <= '9') digs[nd++] = *p;
  while (nd > 1 && digs[nd - 1] == '0') nd--; /* %e pads; Go's shortest does not */
  digs[nd] = '\0';
  int exp = atoi(p + 1); /* of the first digit */
  int dp = exp + 1;       /* digits before the decimal point */
  char *o = out;
  if (neg) *o++ = '-';
  if (exp < -4 || exp >= 6) { /* %e (shortest: eprec 6) */
    *o++ = digs[0];
    if (nd > 1) {
      *o++ = '.';
      memcpy(o, digs + 1, (size_t)nd - 1);
      o += nd - 1;
    }
    snprintf(o, 12, "e%c%02d", exp < 0 ? '-' : '+', exp < 0 ? -exp : exp);
    return;
  }
  if (dp <= 0) { /* 0.000ddd */
    *o++ = '0';
    *o++ = '.';
    for (int i = 0; i < -dp; i++) *o++ = '0';
    memcpy(o, digs, (size_t)nd);
    o += nd;
  } else {
    for (int i = 0; i < dp; i++) *o++ = i < nd ? digs[i] : '0';
    if (nd > dp) {
      *o++ = '.';
      memcpy(o, digs + dp, (size_t)(nd - dp));
      o += nd - dp;
    }
  }
  *o = '\0';
}

/* ---- families and samples ----------------------------------------------- */

typedef struct {
  char *text;     /* rendered: name{labels} value\n */
  char *sort_key; /* label values in label-name order, \x01-separated; then the suffix */
} sample;

typedef struct {
  const buckets_metric_def *def;
  sample *s;
  size_t n, cap;
} family;

struct buckets_expo {
  buckets_metric_catalog_kind kind;
  bool v3;
  family *f;
  size_t n, cap;
  size_t dropped;
};

buckets_expo *buckets_expo_new(buckets_metric_catalog_kind k) {
  buckets_expo *e = buckets_xcalloc(1, sizeof(*e));
  e->kind = k;
  e->v3 = k == BUCKETS_CATALOG_V3;
  return e;
}

void buckets_expo_free(buckets_expo *e) {
  if (!e) return;
  for (size_t i = 0; i < e->n; i++) {
    for (size_t j = 0; j < e->f[i].n; j++) {
      free(e->f[i].s[j].text);
      free(e->f[i].s[j].sort_key);
    }
    free(e->f[i].s);
  }
  free(e->f);
  free(e);
}

static family *family_of(buckets_expo *e, const buckets_metric_def *def) {
  for (size_t i = 0; i < e->n; i++)
    if (e->f[i].def == def) return &e->f[i];
  if (e->n == e->cap) {
    e->cap = e->cap ? e->cap * 2 : 64;
    e->f = buckets_xrealloc(e->f, e->cap * sizeof(*e->f));
  }
  family *f = &e->f[e->n++];
  memset(f, 0, sizeof(*f));
  f->def = def;
  return f;
}

/* label value escaping: backslash, double quote, newline */
static void label_value(buckets_buf *b, const char *v) {
  for (; *v; v++) {
    if (*v == '\\') buckets_buf_append_c(b, "\\\\");
    else if (*v == '"') buckets_buf_append_c(b, "\\\"");
    else if (*v == '\n') buckets_buf_append_c(b, "\\n");
    else buckets_buf_append_char(b, *v);
  }
}

typedef struct {
  const char *k, *v;
} lpair;

static int lpair_cmp(const void *a, const void *b) { return strcmp(((const lpair *)a)->k, ((const lpair *)b)->k); }

static void add(buckets_expo *e, const char *name, const char *suffix, double v, const char *const *labels, size_t n) {
  const buckets_metric_def *def = buckets_metric_lookup(e->kind, name);
  if (!def) {
    e->dropped++;
    return;
  }
  family *f = family_of(e, def);
  lpair *lp = buckets_xcalloc(n ? n : 1, sizeof(*lp));
  for (size_t i = 0; i < n; i++) lp[i] = (lpair){labels[2 * i], labels[2 * i + 1] ? labels[2 * i + 1] : ""};
  qsort(lp, n, sizeof(*lp), lpair_cmp);
  buckets_buf t = BUCKETS_BUF_INIT, k = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&t, def->name);
  if (suffix) buckets_buf_append_c(&t, suffix);
  if (n) {
    buckets_buf_append_char(&t, '{');
    for (size_t i = 0; i < n; i++) {
      if (i) buckets_buf_append_char(&t, ',');
      buckets_buf_appendf(&t, "%s=\"", lp[i].k);
      label_value(&t, lp[i].v);
      buckets_buf_append_char(&t, '"');
      buckets_buf_append_c(&k, lp[i].v);
      buckets_buf_append_char(&k, '\x01');
    }
    buckets_buf_append_char(&t, '}');
  }
  /* a summary's quantiles come before its _sum and _count */
  buckets_buf_append_char(&k, suffix ? (strcmp(suffix, "_sum") == 0 ? '\x02' : '\x03') : '\x00');
  char num[40];
  buckets_go_float(v, num);
  buckets_buf_appendf(&t, " %s\n", num);
  free(lp);
  if (f->n == f->cap) {
    f->cap = f->cap ? f->cap * 2 : 8;
    f->s = buckets_xrealloc(f->s, f->cap * sizeof(*f->s));
  }
  f->s[f->n++] = (sample){t.data, k.data ? k.data : buckets_xstrdup("")};
}

void buckets_expo_add(buckets_expo *e, const char *name, double v, const char *const *labels, size_t n) {
  add(e, name, NULL, v, labels, n);
}

void buckets_expo_add_suffixed(buckets_expo *e, const char *name, const char *suffix, double v,
                               const char *const *labels, size_t n) {
  add(e, name, suffix, v, labels, n);
}

void buckets_expo_addl(buckets_expo *e, const char *name, double v, ...) {
  const char *l[32];
  size_t n = 0;
  va_list ap;
  va_start(ap, v);
  for (const char *k; n + 2 <= BUCKETS_ARRAY_LEN(l) && (k = va_arg(ap, const char *));) {
    l[n++] = k;
    l[n++] = va_arg(ap, const char *);
  }
  va_end(ap);
  add(e, name, NULL, v, l, n / 2);
}

size_t buckets_expo_dropped(const buckets_expo *e) { return e->dropped; }

static int fam_cmp(const void *a, const void *b) {
  return strcmp(((const family *)a)->def->name, ((const family *)b)->def->name);
}

/* metricSorter: label values in order; our key ends with the sample kind */
static int sample_cmp(const void *a, const void *b) {
  const char *x = ((const sample *)a)->sort_key, *y = ((const sample *)b)->sort_key;
  /* compare value by value (a shorter value sorts first, as Go's string compare) */
  for (;;) {
    const char *ex = x + strcspn(x, "\x01"), *ey = y + strcspn(y, "\x01");
    size_t lx = (size_t)(ex - x), ly = (size_t)(ey - y);
    int c = memcmp(x, y, lx < ly ? lx : ly);
    if (c) return c;
    if (lx != ly) return lx < ly ? -1 : 1;
    if (!*ex || !*ey) return (unsigned char)*ex - (unsigned char)*ey;
    x = ex + 1;
    y = ey + 1;
  }
}

size_t buckets_expo_names(const buckets_expo *e, const char ***out) {
  const char **v = buckets_xcalloc(e->n ? e->n : 1, sizeof(*v));
  for (size_t i = 0; i < e->n; i++) v[i] = e->f[i].def->name;
  if (e->n) qsort(v, e->n, sizeof(*v), (int (*)(const void *, const void *))strcmp);
  *out = v;
  return e->n;
}

static void help_text(buckets_buf *b, const char *h) {
  for (; *h; h++) {
    if (*h == '\\') buckets_buf_append_c(b, "\\\\");
    else if (*h == '\n') buckets_buf_append_c(b, "\\n");
    else buckets_buf_append_char(b, *h);
  }
}

void buckets_expo_write(buckets_expo *e, buckets_buf *out) {
  if (e->n) qsort(e->f, e->n, sizeof(*e->f), fam_cmp); /* none: e->f may be NULL */
  for (size_t i = 0; i < e->n; i++) {
    family *f = &e->f[i];
    if (f->n) qsort(f->s, f->n, sizeof(*f->s), sample_cmp);
    const char *type = "gauge";
    switch (f->def->type) {
    case BUCKETS_MT_COUNTER: type = "counter"; break;
    case BUCKETS_MT_SUMMARY: type = "summary"; break;
    case BUCKETS_MT_HISTOGRAM: type = e->v3 ? "histogram" : "gauge"; break; /* v2 writes buckets as gauges */
    default: break;
    }
    buckets_buf_appendf(out, "# HELP %s ", f->def->name);
    help_text(out, f->def->help);
    buckets_buf_appendf(out, "\n# TYPE %s %s\n", f->def->name, type);
    for (size_t j = 0; j < f->n; j++) buckets_buf_append_c(out, f->s[j].text);
  }
}
