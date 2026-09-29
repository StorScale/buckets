/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Evaluation of S3 Select statements: MinIO's sql/evaluate.go,
 * sql/funceval.go, sql/aggregation.go, sql/jsonpath.go, sql/stringfuncs.go
 * and sql/statement.go. Errors here end the response with an InternalError
 * event carrying the message. */
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/common.h"
#include "select/ast.h"

typedef struct {
  sel_stmt *st;
  sel_arena *a;
  const sel_record *r; /* NULL while aggregating results */
} ctx;

static bool fail(sel_err *e, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static bool fail(sel_err *e, const char *fmt, ...) {
  if (e && !e->code) {
    e->code = "InternalError";
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
    va_end(ap);
    e->status = 400;
  }
  return false;
}

static bool ev_expr(ctx *c, sel_expr *x, sel_value *out, sel_err *e);
static bool ev_operand(ctx *c, sel_operand *o, sel_value *out, sel_err *e);
static bool ev_primary(ctx *c, sel_primary *p, sel_value *out, sel_err *e);

/* ---- JSON paths ---- */

typedef enum { JR_JV, JR_ARR, JR_MISSING, JR_NULL } jr_kind;
typedef struct jres jres;
struct jres {
  jr_kind k;
  const jv *v;
  jres *items;
  size_t n;
};

static bool key_eq(const jv_kv *kv, sel_ident id) { return kv->kn == id.n && (!id.n || !memcmp(kv->k, id.s, id.n)); }

/* jsonpathEval: *flat when wildcards made the array. */
static bool jpath_eval(ctx *c, const sel_pelem *p, size_t n, jres v, jres *out, bool *flat, sel_err *e) {
  *flat = false;
  if (n == 0 || v.k == JR_NULL || (v.k == JR_JV && v.v->t == JV_NULL)) {
    *out = v.k == JR_JV && v.v->t == JV_NULL ? (jres){.k = JR_NULL} : v;
    return true;
  }
  switch (p[0].kind) {
  case PE_KEY:
    if (v.k != JR_JV || v.v->t != JV_OBJ) return fail(e, "Cannot look up key in non-object value");
    for (size_t i = 0; i < v.v->o.n; i++)
      if (key_eq(&v.v->o.kv[i], p[0].key)) return jpath_eval(c, p + 1, n - 1, (jres){.k = JR_JV, .v = &v.v->o.kv[i].v}, out, flat, e);
    *out = (jres){.k = JR_MISSING}; /* the rest of the path is not looked at */
    return true;
  case PE_INDEX: {
    if (v.k == JR_ARR) { /* a wildcard's result indexed further */
      if (p[0].index < 0 || (size_t)p[0].index >= v.n) return *out = (jres){.k = JR_NULL}, true;
      return jpath_eval(c, p + 1, n - 1, v.items[p[0].index], out, flat, e);
    }
    if (v.k != JR_JV || v.v->t != JV_ARR) return fail(e, "Cannot look up array index in non-array value");
    if (p[0].index < 0 || (size_t)p[0].index >= v.v->a.n) return *out = (jres){.k = JR_NULL}, true;
    return jpath_eval(c, p + 1, n - 1, (jres){.k = JR_JV, .v = &v.v->a.v[p[0].index]}, out, flat, e);
  }
  case PE_OBJWILD:
    if (v.k != JR_JV || v.v->t != JV_OBJ) return fail(e, "Object wildcard used on non-object value");
    if (n > 1) return fail(e, "Invalid usage of object wildcard");
    *out = v;
    return true;
  case PE_ARRWILD: {
    if (v.k != JR_JV || v.v->t != JV_ARR) return fail(e, "Array wildcard used on non-array value");
    size_t cap = v.v->a.n ? v.v->a.n : 1, k = 0;
    jres *items = sel_alloc(c->a, cap * sizeof(jres));
    for (size_t i = 0; i < v.v->a.n; i++) {
      jres r;
      bool fl;
      if (!jpath_eval(c, p + 1, n - 1, (jres){.k = JR_JV, .v = &v.v->a.v[i]}, &r, &fl, e)) return false;
      jres *add = &r;
      size_t nadd = 1;
      jres tmp[1];
      if (fl && r.k == JR_ARR) add = r.items, nadd = r.n;
      else if (fl && r.k == JR_JV && r.v->t == JV_ARR) {
        /* a flattened plain array: its elements */
        for (size_t j = 0; j < r.v->a.n; j++) {
          if (k == cap) {
            jres *ni = sel_alloc(c->a, (cap *= 2) * sizeof(jres));
            memcpy(ni, items, k * sizeof(jres));
            items = ni;
          }
          items[k++] = (jres){.k = JR_JV, .v = &r.v->a.v[j]};
        }
        continue;
      } else {
        tmp[0] = r;
        add = tmp;
      }
      for (size_t j = 0; j < nadd; j++) {
        if (k == cap) {
          jres *ni = sel_alloc(c->a, (cap *= 2) * sizeof(jres));
          memcpy(ni, items, k * sizeof(jres));
          items = ni;
        }
        items[k++] = add[j];
      }
    }
    *out = (jres){.k = JR_ARR, .items = items, .n = k};
    *flat = true;
    return true;
  }
  }
  return fail(e, "invalid AST Node");
}

static sel_value jres_value(ctx *c, const jres *r) {
  switch (r->k) {
  case JR_JV: return sv_from_jv(c->a, r->v);
  case JR_MISSING: return sv_missing();
  case JR_NULL: return sv_null();
  case JR_ARR: {
    sel_value v = {.t = SV_ARR};
    v.a.n = r->n;
    v.a.v = sel_alloc(c->a, (r->n ? r->n : 1) * sizeof(sel_value));
    for (size_t i = 0; i < r->n; i++) v.a.v[i] = jres_value(c, &r->items[i]);
    return v;
  }
  }
  return sv_null();
}

static bool ident_ieq(sel_ident id, const char *s) { return id.n == strlen(s) && !strncasecmp(id.s, s, id.n); }

/* StripTableAlias */
static void strip_alias(ctx *c, sel_jpath *j, const sel_pelem **p, size_t *n) {
  const char *alias = c->st->table_alias_n ? c->st->table_alias : "s3object";
  size_t an = c->st->table_alias_n ? c->st->table_alias_n : 8;
  if (j->stripped && j->strip_alias == alias) {
    *p = j->stripped, *n = j->nstripped;
    return;
  }
  bool has = (j->base.n == an && !memcmp(j->base.s, alias, an)) || ident_ieq(j->base, "s3object");
  if (has) {
    j->stripped = j->el;
    j->nstripped = j->n;
  } else {
    j->stripped = sel_alloc(&c->st->arena, (j->n + 1) * sizeof(sel_pelem));
    j->stripped[0] = (sel_pelem){.kind = PE_KEY, .key = j->base};
    if (j->n) memcpy(j->stripped + 1, j->el, j->n * sizeof(sel_pelem));
    j->nstripped = j->n + 1;
  }
  j->strip_alias = alias;
  *p = j->stripped, *n = j->nstripped;
}

extern bool sel_csv_get(const sel_record *r, const char *name, size_t n, sel_value *out, sel_err *e);

static bool ev_path(ctx *c, sel_jpath *j, sel_value *out, sel_err *e) {
  if (!c->r) return fail(e, "invalid AST Node");
  const sel_pelem *p;
  size_t n;
  strip_alias(c, j, &p, &n);
  if (c->r->fmt != SEL_FMT_CSV) {
    sel_pelem one;
    if (n == 0) {
      one = (sel_pelem){.kind = PE_KEY, .key = j->base};
      p = &one;
      n = 1;
    }
    jres r;
    bool flat;
    if (!jpath_eval(c, p, n, (jres){.k = JR_JV, .v = &c->r->obj}, &r, &flat, e)) return false;
    *out = jres_value(c, &r);
    return true;
  }
  if (n == 0 || p[n - 1].kind != PE_KEY) return fail(e, "A provided keypath is invalid");
  return sel_csv_get(c->r, p[n - 1].key.s, p[n - 1].key.n, out, e);
}

/* ---- literals, lists, arithmetic ---- */

static sel_value ev_lit(const sel_lit *l) {
  switch (l->kind) {
  case LIT_INT:
    if (l->num < 9223372036854775807.0 && l->num > -9223372036854775808.0) return sv_int((int64_t)l->num);
    return sv_float(l->num);
  case LIT_FLOAT: return sv_float(l->num);
  case LIT_STR: return sv_str(l->s, l->sn);
  case LIT_BOOL: return sv_bool(l->b);
  case LIT_MISSING: return sv_missing();
  case LIT_NULL: return sv_null();
  }
  return sv_null();
}

static bool ev_list(ctx *c, sel_list *l, sel_value *out, sel_err *e) {
  if (l->n == 1) return ev_expr(c, l->el[0], out, e);
  sel_value v = {.t = SV_ARR};
  v.a.n = l->n;
  v.a.v = sel_alloc(c->a, l->n * sizeof(sel_value));
  for (size_t i = 0; i < l->n; i++)
    if (!ev_expr(c, l->el[i], &v.a.v[i], e)) return false;
  *out = v;
  return true;
}

static bool arith(sel_value *l, char op, sel_value *r, sel_err *e) {
  if (!sv_arith(l, op, r, e)) {
    /* the Go error text, whatever the inference said */
    if (e->code && !strcmp(e->code, "InvalidDataType")) e->code = "InternalError";
    else if (e->code) e->code = "InternalError";
    return false;
  }
  return true;
}

static bool ev_unary(ctx *c, sel_unary *u, sel_value *out, sel_err *e) {
  if (!ev_primary(c, u->p, out, e)) return false;
  if (!u->neg) return true;
  sel_err ignore = {0};
  sv_infer_arith(out, &ignore);
  if (out->t == SV_INT) out->i = (int64_t)(0 - (uint64_t)out->i);
  else if (out->t == SV_FLOAT) out->f = -out->f;
  else return fail(e, "cannot perform arithmetic on mismatched types");
  return true;
}

static bool ev_multop(ctx *c, sel_multop *m, sel_value *out, sel_err *e) {
  if (!ev_unary(c, m->left, out, e)) return false;
  for (size_t i = 0; i < m->n; i++) {
    sel_value r;
    if (!ev_unary(c, m->right[i], &r, e) || !arith(out, m->ops[i], &r, e)) return false;
  }
  return true;
}

static bool ev_operand(ctx *c, sel_operand *o, sel_value *out, sel_err *e) {
  if (!ev_multop(c, o->left, out, e)) return false;
  for (size_t i = 0; i < o->n; i++) {
    sel_value r;
    if (!ev_multop(c, o->right[i], &r, e) || !arith(out, o->ops[i], &r, e)) return false;
  }
  return true;
}

/* ---- LIKE ---- */

static size_t rune_at(const char *s, size_t n, uint32_t *cp) {
  const unsigned char *p = (const unsigned char *)s;
  if (!n) return 0;
  if (p[0] < 0x80) return *cp = p[0], 1;
  size_t len = (p[0] & 0xe0) == 0xc0 ? 2 : (p[0] & 0xf0) == 0xe0 ? 3 : (p[0] & 0xf8) == 0xf0 ? 4 : 1;
  if (len > n) len = 1;
  uint32_t v = len == 2 ? p[0] & 0x1f : len == 3 ? p[0] & 0x0f : len == 4 ? p[0] & 0x07 : p[0];
  for (size_t i = 1; i < len; i++) {
    if ((p[i] & 0xc0) != 0x80) return *cp = 0xfffd, 1;
    v = v << 6 | (p[i] & 0x3f);
  }
  *cp = len == 1 && p[0] >= 0x80 ? 0xfffd : v;
  return len;
}

/* A pattern element: a literal rune, % or _. */
typedef struct {
  int kind; /* 0 literal, 1 %, 2 _ */
  uint32_t cp;
} lpat;

static bool like_match(const uint32_t *t, size_t tn, const lpat *p, size_t pn) {
  /* iterative wildcard matching with one backtrack point per % */
  size_t ti = 0, pi = 0, star_p = (size_t)-1, star_t = 0;
  while (ti < tn) {
    if (pi < pn && (p[pi].kind == 2 || (p[pi].kind == 0 && p[pi].cp == t[ti]))) {
      ti++, pi++;
    } else if (pi < pn && p[pi].kind == 1) {
      star_p = pi++;
      star_t = ti;
    } else if (star_p != (size_t)-1) {
      pi = star_p + 1;
      ti = ++star_t;
    } else {
      return false;
    }
  }
  while (pi < pn && p[pi].kind == 1) pi++;
  return pi == pn;
}

static uint32_t *runes(ctx *c, const char *s, size_t n, size_t *count) {
  uint32_t *r = sel_alloc(c->a, (n + 1) * sizeof(uint32_t));
  size_t k = 0;
  for (size_t i = 0; i < n;) {
    uint32_t cp;
    i += rune_at(s + i, n - i, &cp);
    r[k++] = cp;
  }
  *count = k;
  return r;
}

static bool ev_like(ctx *c, sel_rhs *h, sel_value *arg, sel_value *out, sel_err *e) {
  static const char *bad = "Invalid argument given to the LIKE clause in the SQL expression.";
  sv_infer_string(arg);
  if (arg->t != SV_STR) return fail(e, "%s", bad);
  sel_value pat;
  if (!ev_operand(c, h->pattern, &pat, e)) return false;
  sv_infer_string(&pat);
  if (pat.t != SV_STR) return fail(e, "%s", bad);
  uint32_t esc = 0;
  bool has_esc = false;
  if (h->escape) {
    sel_value ev;
    if (!ev_operand(c, h->escape, &ev, e)) return false;
    sv_infer_string(&ev);
    if (ev.t != SV_STR) return fail(e, "%s", bad);
    size_t en;
    uint32_t *er = runes(c, ev.s.p, ev.s.n, &en);
    if (en > 1) return fail(e, "%s", bad);
    if (en == 1) esc = er[0], has_esc = true;
  }
  size_t pn, tn;
  uint32_t *pr = runes(c, pat.s.p, pat.s.n, &pn), *tr = runes(c, arg->s.p, arg->s.n, &tn);
  lpat *lp = sel_alloc(c->a, (pn + 1) * sizeof(lpat));
  size_t k = 0;
  for (size_t i = 0; i < pn; i++) {
    if (has_esc && pr[i] == esc) {
      if (i + 1 == pn || (pr[i + 1] != '%' && pr[i + 1] != '_' && pr[i + 1] != esc))
        return fail(e, "Malformed escape sequence in LIKE clause");
      lp[k++] = (lpat){0, pr[++i]};
    } else {
      lp[k++] = (lpat){pr[i] == '%' ? 1 : pr[i] == '_' ? 2 : 0, pr[i]};
    }
  }
  bool m = like_match(tr, tn, lp, k);
  *out = sv_bool(h->not_ ? !m : m);
  return true;
}

/* ---- IN ---- */

static bool in_cmp(sel_value a, sel_value b) {
  sel_err ignore = {0};
  sv_infer_cmp(&a, &b, &ignore);
  if (sv_equals(&a, &b)) return true;
  if (a.t == SV_ARR && b.t == SV_ARR) {
    if (a.a.n != b.a.n) return false;
    for (size_t i = 0; i < a.a.n; i++)
      if (!in_cmp(a.a.v[i], b.a.v[i])) return false;
    return true;
  }
  double fa, fb;
  bool oa = sv_to_float(&a, &fa), ob = sv_to_float(&b, &fb);
  return oa && ob && fabs(fa - fb) < 0.000001;
}

static bool ev_in(ctx *c, sel_rhs *h, sel_value *lhs, sel_value *out, sel_err *e) {
  sel_value rhs;
  if (h->in_path ? !ev_path(c, h->in_path, &rhs, e) : !ev_list(c, h->in_list, &rhs, e)) return false;
  if (rhs.t == SV_ARR) {
    for (size_t i = 0; i < rhs.a.n; i++)
      if (in_cmp(rhs.a.v[i], *lhs)) return *out = sv_bool(true), true;
    return *out = sv_bool(false), true;
  }
  *out = sv_bool(in_cmp(rhs, *lhs));
  return true;
}

/* ---- conditions ---- */

static bool cmp(sel_value *l, const char *op, sel_value *r, bool *res, sel_err *e) {
  if (!sv_compare(l, op, r, res, e)) {
    if (e->code) e->code = "InternalError";
    return false;
  }
  return true;
}

static bool ev_cond(ctx *c, sel_cond *x, sel_value *out, sel_err *e) {
  if (!x->operand) {
    sel_value v;
    if (!ev_cond(c, x->not_, &v, e)) return false;
    if (v.t != SV_BOOL) return fail(e, "expected bool");
    *out = sv_bool(!v.b);
    return true;
  }
  if (!ev_operand(c, x->operand->operand, out, e)) return false;
  sel_rhs *h = x->operand->rhs;
  if (!h) return true;
  switch (h->kind) {
  case RHS_CMP: {
    sel_value r;
    bool b;
    if (!ev_operand(c, h->operand, &r, e) || !cmp(out, h->op, &r, &b, e)) return false;
    *out = sv_bool(b);
    return true;
  }
  case RHS_BETWEEN: {
    sel_value st, en;
    bool b1, b2;
    if (!ev_operand(c, h->start, &st, e) || !ev_operand(c, h->end, &en, e)) return false;
    if (!cmp(&st, "<=", out, &b1, e) || !cmp(out, "<=", &en, &b2, e)) return false;
    bool r = b1 && b2;
    *out = sv_bool(h->not_ ? !r : r);
    return true;
  }
  case RHS_LIKE: {
    sel_value arg = *out;
    return ev_like(c, h, &arg, out, e);
  }
  case RHS_IN: {
    sel_value lhs = *out;
    return ev_in(c, h, &lhs, out, e);
  }
  }
  return fail(e, "invalid AST Node");
}

static bool ev_and(ctx *c, sel_and *x, sel_value *out, sel_err *e) {
  if (x->n == 1) return ev_cond(c, x->conds[0], out, e);
  for (size_t i = 0; i < x->n; i++) {
    sel_value v;
    if (!ev_cond(c, x->conds[i], &v, e)) return false;
    if (v.t != SV_BOOL) return fail(e, "expected bool");
    if (!v.b) return *out = sv_bool(false), true;
  }
  *out = sv_bool(true);
  return true;
}

static bool ev_expr(ctx *c, sel_expr *x, sel_value *out, sel_err *e) {
  if (x->n == 1) return ev_and(c, x->ands[0], out, e);
  for (size_t i = 0; i < x->n; i++) {
    sel_value v;
    if (!ev_and(c, x->ands[i], &v, e)) return false;
    if (v.t != SV_BOOL) return fail(e, "expected bool");
    if (v.b) return *out = sv_bool(true), true;
  }
  *out = sv_bool(false);
  return true;
}

/* ---- functions ---- */

static bool is_agg(const sel_func *f) {
  return f->kind == FN_COUNT ||
         (f->kind == FN_SIMPLE && (!strcmp(f->name, "AVG") || !strcmp(f->name, "MAX") || !strcmp(f->name, "MIN") ||
                                   !strcmp(f->name, "SUM")));
}

static bool get_aggregate(const sel_func *f, sel_value *out, sel_err *e) {
  sel_agg *g = f->agg;
  if (f->kind == FN_COUNT) return *out = sv_int(g->count), true;
  if (!strcmp(f->name, "AVG")) {
    if (g->count == 0) return *out = sv_null(), true;
    sel_value s = sv_float(g->sum), n = sv_int(g->count);
    if (!arith(&s, '/', &n, e)) return false;
    *out = s;
    return true;
  }
  if (!strcmp(f->name, "MIN") || !strcmp(f->name, "MAX")) {
    *out = g->seen ? g->running : sv_null();
    return true;
  }
  if (!strcmp(f->name, "SUM")) return *out = sv_float(g->sum), true;
  return fail(e, "Invalid aggregation seen");
}

static const char *incorrect_type = "Incorrect type of arguments in function call.";

static bool str_arg(sel_value *v) {
  sv_infer_string(v);
  return v->t == SV_STR;
}

static void time_parse_error(sel_err *e, const sel_value *v) {
  fail(e, "parsing time \"%.*s\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"%.*s\" as \"2006\"", (int)v->s.n,
       v->s.p, (int)v->s.n, v->s.p);
}

static bool to_timestamp(sel_value *v, sel_err *e) {
  if (v->t == SV_STR || v->t == SV_BYTES) {
    sel_time t;
    if (!sel_time_parse(v->s.p, v->s.n, &t)) {
      time_parse_error(e, v);
      return false;
    }
    *v = sv_time(t);
  }
  return true;
}

/* Go's strconv.ParseInt, then ParseFloat truncated. */
static bool str_to_int(const char *s, size_t n, int64_t *out) {
  sel_value b = sv_bytes(s, n);
  if (sv_bytes_to_int(&b, out)) return true;
  double f;
  if (sv_bytes_to_float(&b, &f)) {
    *out = f >= 9223372036854775808.0 || f < -9223372036854775808.0 || isnan(f) ? INT64_MIN : (int64_t)f;
    return true;
  }
  return false;
}

static bool ev_cast(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value v;
  if (!ev_expr(c, f->cast_expr, &v, e)) return false;
  const char *t = f->cast_type;
  if (!strcmp(t, "INT") || !strcmp(t, "INTEGER")) {
    int64_t i;
    switch (v.t) {
    case SV_FLOAT: i = v.f >= 9223372036854775808.0 || v.f < -9223372036854775808.0 || isnan(v.f) ? INT64_MIN : (int64_t)v.f; break;
    case SV_INT: i = v.i; break;
    case SV_STR:
    case SV_BYTES:
      if (!str_to_int(v.s.p, v.s.n, &i)) return fail(e, "Error casting: could not parse as int");
      break;
    default: return fail(e, "Cannot cast from %s to INT", sv_type_name(&v));
    }
    *out = sv_int(i);
    return true;
  }
  if (!strcmp(t, "FLOAT")) {
    double d;
    switch (v.t) {
    case SV_FLOAT: d = v.f; break;
    case SV_INT: d = (double)v.i; break;
    case SV_STR:
    case SV_BYTES:
      if (!sv_bytes_to_float(&(sel_value){.t = SV_BYTES, .s = v.s}, &d)) return fail(e, "Error casting: could not parse as float");
      break;
    default: return fail(e, "Cannot cast from %s to FLOAT", sv_type_name(&v));
    }
    *out = sv_float(d);
    return true;
  }
  if (!strcmp(t, "STRING")) {
    buckets_buf b = BUCKETS_BUF_INIT;
    switch (v.t) {
    case SV_FLOAT: sel_fmt_float_g(&b, v.f); break;
    case SV_INT: buckets_buf_appendf(&b, "%" PRId64, v.i); break;
    case SV_STR:
    case SV_BYTES: buckets_buf_append(&b, v.s.p, v.s.n); break;
    case SV_BOOL: buckets_buf_append_c(&b, v.b ? "true" : "false"); break;
    case SV_NULL: buckets_buf_append_c(&b, "NULL"); break;
    case SV_TIME: sel_time_format(&b, v.ts); break; /* MinIO cannot; AWS gives the timestamp text */
    default:
      buckets_buf_free(&b);
      return fail(e, "Error casting: cannot cast %s to string type", sv_type_name(&v));
    }
    *out = sv_str(sel_strndup(c->a, b.data ? b.data : "", b.len), b.len);
    buckets_buf_free(&b);
    return true;
  }
  if (!strcmp(t, "TIMESTAMP")) {
    if (v.t == SV_STR || v.t == SV_BYTES) {
      if (!to_timestamp(&v, e)) return false;
    } else if (v.t != SV_TIME) {
      return fail(e, "Error casting: cannot cast %s to Timestamp type", sv_type_name(&v));
    }
    *out = v;
    return true;
  }
  if (!strcmp(t, "BOOL")) {
    if (v.t == SV_BOOL) return *out = v, true;
    if (v.t == SV_STR || v.t == SV_BYTES) {
      if (v.s.n == 4 && !strncasecmp(v.s.p, "true", 4)) return *out = sv_bool(true), true;
      if (v.s.n == 5 && !strncasecmp(v.s.p, "false", 5)) return *out = sv_bool(false), true;
      return fail(e, "Error casting: cannot cast to Bool");
    }
    return fail(e, "Error casting: cannot cast %%v to Bool");
  }
  return fail(e, "This cast not yet implemented");
}

static bool ev_substring(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value s;
  if (!ev_primary(c, f->sub_expr, &s, e)) return false;
  if (!str_arg(&s)) return fail(e, "%s", incorrect_type);
  sel_operand *a2 = f->from ? f->from : f->arg2, *a3 = f->from ? f->for_ : f->arg3;
  sel_value v2;
  sel_err ignore = {0};
  if (!ev_operand(c, a2, &v2, e)) return false;
  sv_infer_arith(&v2, &ignore);
  if (v2.t != SV_INT) return fail(e, "%s", incorrect_type);
  int64_t start = v2.i, length = -1;
  if (a3) {
    sel_value v3;
    if (!ev_operand(c, a3, &v3, e)) return false;
    sv_infer_arith(&v3, &ignore);
    if (v3.t != SV_INT) return fail(e, "%s", incorrect_type);
    length = v3.i;
    if (length < 0) return fail(e, "%s", incorrect_type);
  }
  size_t rn;
  uint32_t *r = runes(c, s.s.p, s.s.n, &rn);
  (void)r;
  /* rune offsets to byte offsets */
  if (start < 1) start = 1;
  if ((size_t)start > rn) start = (int64_t)rn + 1;
  start--;
  int64_t end = (int64_t)rn;
  if (length != -1) {
    if (length > end - start) length = end - start;
    end = start + length;
  }
  size_t bi = 0, ri = 0, bs = 0, be = s.s.n;
  while (bi < s.s.n) {
    if (ri == (size_t)start) bs = bi;
    if (ri == (size_t)end) {
      be = bi;
      break;
    }
    uint32_t cp;
    bi += rune_at(s.s.p + bi, s.s.n - bi, &cp);
    ri++;
  }
  if (ri == (size_t)start && bi == s.s.n) bs = bi;
  *out = sv_str(s.s.p + bs, be > bs ? be - bs : 0);
  return true;
}

static bool in_cutset(uint32_t cp, const uint32_t *set, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (set[i] == cp) return true;
  return false;
}

static bool ev_trim(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value chars = sv_str(" ", 1), from;
  if (f->trim_chars) {
    if (!ev_primary(c, f->trim_chars, &chars, e)) return false;
    if (!str_arg(&chars)) return fail(e, "TRIM() received a non-string argument");
    if (!chars.s.n) chars = sv_str(" ", 1);
  }
  if (!ev_primary(c, f->trim_from, &from, e)) return false;
  if (!str_arg(&from)) return fail(e, "TRIM() received a non-string argument");
  bool lead = true, trail = true;
  if (f->trim_where) {
    if (!strcasecmp(f->trim_where, "LEADING")) trail = false;
    else if (!strcasecmp(f->trim_where, "TRAILING")) lead = false;
  }
  size_t cn;
  uint32_t *cs = runes(c, chars.s.p, chars.s.n, &cn);
  const char *p = from.s.p;
  size_t n = from.s.n;
  if (lead) {
    while (n) {
      uint32_t cp;
      size_t k = rune_at(p, n, &cp);
      if (!in_cutset(cp, cs, cn)) break;
      p += k, n -= k;
    }
  }
  if (trail) {
    while (n) {
      size_t k = 1;
      while (k < n && k < 4 && (((unsigned char)p[n - k]) & 0xc0) == 0x80) k++;
      uint32_t cp;
      rune_at(p + n - k, k, &cp);
      if (!in_cutset(cp, cs, cn)) break;
      n -= k;
    }
  }
  *out = sv_str(p, n);
  return true;
}

static bool ev_timestamp_arg(ctx *c, sel_primary *p, sel_value *out, const char *errmsg, sel_err *e) {
  if (!ev_primary(c, p, out, e) || !to_timestamp(out, e)) return false;
  if (out->t != SV_TIME) return fail(e, "%s", errmsg);
  return true;
}

static bool ev_extract(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value v;
  if (!ev_timestamp_arg(c, f->ext_from, &v, "Expected a timestamp argument", e)) return false;
  sel_civil cv;
  sel_time_civil(v.ts, &cv);
  const char *w = f->timeword;
  int64_t x;
  if (!strcmp(w, "YEAR")) x = cv.year;
  else if (!strcmp(w, "MONTH")) x = cv.month;
  else if (!strcmp(w, "DAY")) x = cv.day;
  else if (!strcmp(w, "HOUR")) x = cv.hour;
  else if (!strcmp(w, "MINUTE")) x = cv.min;
  else if (!strcmp(w, "SECOND")) x = cv.sec;
  else if (!strcmp(w, "TIMEZONE_HOUR")) x = v.ts.off / 3600;
  else x = (v.ts.off % 3600) / 60;
  *out = sv_int(x);
  return true;
}

static bool ev_date_add(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value q, t;
  sel_err ignore = {0};
  if (!ev_operand(c, f->qty, &q, e)) return false;
  sv_infer_arith(&q, &ignore);
  double qty;
  if (!sv_to_float(&q, &qty)) return fail(e, "QUANTITY must be a numeric argument to DATE_ADD()");
  if (!ev_timestamp_arg(c, f->ts1, &t, "DATE_ADD() expects a timestamp argument", e)) return false;
  int64_t n = isnan(qty) || fabs(qty) >= 9.2e18 ? 0 : (int64_t)qty;
  sel_civil cv;
  sel_time_civil(t.ts, &cv);
  const char *w = f->timeword;
  sel_time r = t.ts;
  if (!strcmp(w, "YEAR")) r = sel_time_from_civil(cv.year + n, cv.month, cv.day, cv.hour, cv.min, cv.sec, t.ts.nsec, t.ts.off);
  else if (!strcmp(w, "MONTH"))
    r = sel_time_from_civil(cv.year, cv.month + n, cv.day, cv.hour, cv.min, cv.sec, t.ts.nsec, t.ts.off);
  else if (!strcmp(w, "DAY"))
    r = sel_time_from_civil(cv.year, cv.month, cv.day + n, cv.hour, cv.min, cv.sec, t.ts.nsec, t.ts.off);
  else {
    int64_t unit = !strcmp(w, "HOUR") ? 3600 : !strcmp(w, "MINUTE") ? 60 : 1;
    r.sec += n * unit;
  }
  *out = sv_time(r);
  return true;
}

static bool ev_date_diff(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value a, b;
  if (!ev_timestamp_arg(c, f->ts1, &a, "DATE_DIFF() expects two timestamp arguments", e) ||
      !ev_timestamp_arg(c, f->ts2, &b, "DATE_DIFF() expects two timestamp arguments", e))
    return false;
  sel_time t1 = a.ts, t2 = b.ts;
  bool neg = sel_time_cmp(t2, t1) < 0;
  if (neg) {
    sel_time x = t1;
    t1 = t2;
    t2 = x;
  }
  int64_t dns = (t2.sec - t1.sec) * 1000000000LL + (t2.nsec - t1.nsec);
  sel_civil c1, c2;
  sel_time_civil(t1, &c1);
  sel_time_civil(t2, &c2);
  const char *w = f->timeword;
  int64_t x;
  if (!strcmp(w, "YEAR")) {
    x = c2.year - c1.year;
    if (!(c2.month > c1.month || (c2.month == c1.month && c2.day >= c1.day))) x--;
  } else if (!strcmp(w, "MONTH")) {
    x = (c2.month + 12 * c2.year) - (c1.month + 12 * c1.year);
  } else if (!strcmp(w, "DAY")) {
    x = dns / (86400LL * 1000000000LL);
  } else if (!strcmp(w, "HOUR")) {
    x = dns / (3600LL * 1000000000LL);
  } else if (!strcmp(w, "MINUTE")) {
    x = dns / (60LL * 1000000000LL);
  } else {
    x = dns / 1000000000LL;
  }
  *out = sv_int(neg ? -x : x);
  return true;
}

/* ToLower/ToUpper for ASCII and the common alphabets (Latin-1, Latin
 * Extended-A, Greek, Cyrillic). */
static uint32_t case_map(uint32_t cp, bool upper) {
  if (upper) {
    if (cp >= 'a' && cp <= 'z') return cp - 32;
    if (cp >= 0xe0 && cp <= 0xfe && cp != 0xf7) return cp - 32;
    if (cp == 0xff) return 0x178;
    if (cp >= 0x100 && cp <= 0x17f && cp != 0x131 && cp != 0x138 && cp != 0x149) {
      bool odd_upper = (cp >= 0x139 && cp <= 0x148) || (cp >= 0x179 && cp <= 0x17e);
      if (odd_upper ? cp % 2 == 0 : cp % 2 == 1) return cp - 1;
    }
    if (cp >= 0x3b1 && cp <= 0x3c9 && cp != 0x3c2) return cp - 32;
    if (cp >= 0x430 && cp <= 0x44f) return cp - 32;
    if (cp >= 0x450 && cp <= 0x45f) return cp - 80;
  } else {
    if (cp >= 'A' && cp <= 'Z') return cp + 32;
    if (cp >= 0xc0 && cp <= 0xde && cp != 0xd7) return cp + 32;
    if (cp == 0x178) return 0xff;
    if (cp >= 0x100 && cp <= 0x17f && cp != 0x130 && cp != 0x138 && cp != 0x149) {
      bool odd_upper = (cp >= 0x139 && cp <= 0x148) || (cp >= 0x179 && cp <= 0x17e);
      if (odd_upper ? cp % 2 == 1 : cp % 2 == 0) return cp + 1;
    }
    if (cp >= 0x391 && cp <= 0x3a9 && cp != 0x3a2) return cp + 32;
    if (cp >= 0x410 && cp <= 0x42f) return cp + 32;
    if (cp >= 0x400 && cp <= 0x40f) return cp + 80;
  }
  return cp;
}

static void put_rune(buckets_buf *b, uint32_t cp) {
  char u[4];
  size_t n;
  if (cp < 0x80) u[0] = (char)cp, n = 1;
  else if (cp < 0x800) u[0] = (char)(0xc0 | cp >> 6), u[1] = (char)(0x80 | (cp & 0x3f)), n = 2;
  else if (cp < 0x10000)
    u[0] = (char)(0xe0 | cp >> 12), u[1] = (char)(0x80 | (cp >> 6 & 0x3f)), u[2] = (char)(0x80 | (cp & 0x3f)), n = 3;
  else
    u[0] = (char)(0xf0 | cp >> 18), u[1] = (char)(0x80 | (cp >> 12 & 0x3f)), u[2] = (char)(0x80 | (cp >> 6 & 0x3f)),
    u[3] = (char)(0x80 | (cp & 0x3f)), n = 4;
  buckets_buf_append(b, u, n);
}

static sel_value change_case(ctx *c, const sel_value *v, bool upper) {
  buckets_buf b = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < v->s.n;) {
    uint32_t cp;
    size_t k = rune_at(v->s.p + i, v->s.n - i, &cp);
    put_rune(&b, case_map(cp, upper));
    i += k;
  }
  sel_value r = sv_str(sel_strndup(c->a, b.data ? b.data : "", b.len), b.len);
  buckets_buf_free(&b);
  return r;
}

/* TO_STRING's format patterns (AWS S3 Select's). */
static void format_time(buckets_buf *out, sel_time t, const char *f, size_t n) {
  static const char *const months[] = {"January", "February", "March",     "April",   "May",      "June",
                                       "July",    "August",   "September", "October", "November", "December"};
  sel_civil c;
  sel_time_civil(t, &c);
  for (size_t i = 0; i < n;) {
    char ch = f[i];
    size_t k = 1;
    while (i + k < n && f[i + k] == ch) k++;
    switch (ch) {
    case 'y':
      if (k == 2) buckets_buf_appendf(out, "%02d", (int)(c.year % 100));
      else buckets_buf_appendf(out, "%0*" PRId64, (int)k, c.year);
      break;
    case 'M':
      if (k <= 2) buckets_buf_appendf(out, "%0*d", (int)k, c.month);
      else if (k == 3) buckets_buf_append(out, months[c.month - 1], 3);
      else if (k == 4) buckets_buf_append_c(out, months[c.month - 1]);
      else buckets_buf_append_char(out, months[c.month - 1][0]);
      break;
    case 'd': buckets_buf_appendf(out, "%0*d", (int)k, c.day); break;
    case 'a': buckets_buf_append_c(out, c.hour < 12 ? "AM" : "PM"); break;
    case 'h': buckets_buf_appendf(out, "%0*d", (int)k, c.hour % 12 ? c.hour % 12 : 12); break;
    case 'H': buckets_buf_appendf(out, "%0*d", (int)k, c.hour); break;
    case 'm': buckets_buf_appendf(out, "%0*d", (int)k, c.min); break;
    case 's': buckets_buf_appendf(out, "%0*d", (int)k, c.sec); break;
    case 'S': {
      char frac[16];
      snprintf(frac, sizeof(frac), "%09d", (int)t.nsec);
      for (size_t j = 0; j < k; j++) buckets_buf_append_char(out, j < 9 ? frac[j] : '0');
      break;
    }
    case 'n': buckets_buf_appendf(out, "%d", (int)t.nsec); break;
    case 'X':
    case 'x': {
      int32_t off = t.off, a = off < 0 ? -off : off;
      if (ch == 'X' && off == 0) {
        buckets_buf_append_char(out, 'Z');
        break;
      }
      char sign = off < 0 ? '-' : '+';
      int hh = a / 3600, mm = a % 3600 / 60, ss = a % 60;
      if (k == 1) {
        buckets_buf_appendf(out, "%c%02d", sign, hh);
        if (mm) buckets_buf_appendf(out, "%02d", mm);
      } else if (k == 2) buckets_buf_appendf(out, "%c%02d%02d", sign, hh, mm);
      else if (k == 3) buckets_buf_appendf(out, "%c%02d:%02d", sign, hh, mm);
      else if (k == 4) {
        buckets_buf_appendf(out, "%c%02d%02d", sign, hh, mm);
        if (ss) buckets_buf_appendf(out, "%02d", ss);
      } else {
        buckets_buf_appendf(out, "%c%02d:%02d", sign, hh, mm);
        if (ss) buckets_buf_appendf(out, ":%02d", ss);
      }
      break;
    }
    case '\'': {
      /* quoted literal text; '' is a quote */
      size_t j = i + 1;
      if (k >= 2 && k % 2 == 0) {
        for (size_t q = 0; q < k / 2; q++) buckets_buf_append_char(out, '\'');
        break;
      }
      k = 1;
      while (j < n) {
        if (f[j] == '\'') {
          if (j + 1 < n && f[j + 1] == '\'') {
            buckets_buf_append_char(out, '\'');
            j += 2;
            continue;
          }
          break;
        }
        buckets_buf_append_char(out, f[j++]);
      }
      k = j - i + 1;
      if (i + k > n) k = n - i;
      break;
    }
    default:
      for (size_t j = 0; j < k; j++) buckets_buf_append_char(out, ch);
    }
    i += k;
  }
}

static bool ev_simple(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  sel_value *args = sel_alloc(c->a, (f->nargs ? f->nargs : 1) * sizeof(sel_value));
  for (size_t i = 0; i < f->nargs; i++)
    if (!ev_expr(c, f->args[i], &args[i], e)) return false;
  const char *n = f->name;
  if (!strcmp(n, "COALESCE")) {
    for (size_t i = 0; i < f->nargs; i++)
      if (args[i].t != SV_NULL) return *out = args[i], true;
    return *out = sv_null(), true;
  }
  if (!strcmp(n, "NULLIF")) {
    sel_value a = args[0], b = args[1];
    if (a.t == SV_NULL || b.t == SV_NULL) return *out = a, true;
    sel_value ca = a, cb = b;
    bool eq = false;
    sel_err ignore = {0};
    if (sv_compare(&ca, "=", &cb, &eq, &ignore) && eq) return *out = sv_null(), true;
    return *out = a, true;
  }
  if (!strcmp(n, "CHAR_LENGTH") || !strcmp(n, "CHARACTER_LENGTH")) {
    if (!str_arg(&args[0])) return fail(e, "%s", incorrect_type);
    return *out = sv_int((int64_t)sel_utf8_count(args[0].s.p, args[0].s.n)), true;
  }
  if (!strcmp(n, "LOWER") || !strcmp(n, "UPPER")) {
    if (!str_arg(&args[0])) return fail(e, "%s", incorrect_type);
    return *out = change_case(c, &args[0], n[0] == 'U'), true;
  }
  if (!strcmp(n, "UTCNOW")) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return *out = sv_time((sel_time){ts.tv_sec, (int32_t)ts.tv_nsec, 0}), true;
  }
  if (!strcmp(n, "TO_TIMESTAMP")) {
    sel_value v = args[0];
    if (v.t != SV_STR && v.t != SV_BYTES && v.t != SV_TIME) return fail(e, "%s", incorrect_type);
    if (!to_timestamp(&v, e)) return false;
    return *out = v, true;
  }
  if (!strcmp(n, "TO_STRING")) {
    sel_value v = args[0], fmt = args[1];
    if (!to_timestamp(&v, e)) return false;
    if (v.t != SV_TIME || !str_arg(&fmt)) return fail(e, "%s", incorrect_type);
    buckets_buf b = BUCKETS_BUF_INIT;
    format_time(&b, v.ts, fmt.s.p, fmt.s.n);
    *out = sv_str(sel_strndup(c->a, b.data ? b.data : "", b.len), b.len);
    buckets_buf_free(&b);
    return true;
  }
  return fail(e, "not implemented");
}

static bool ev_func(ctx *c, sel_func *f, sel_value *out, sel_err *e) {
  if (is_agg(f)) return get_aggregate(f, out, e);
  switch (f->kind) {
  case FN_CAST: return ev_cast(c, f, out, e);
  case FN_SUBSTRING: return ev_substring(c, f, out, e);
  case FN_EXTRACT: return ev_extract(c, f, out, e);
  case FN_TRIM: return ev_trim(c, f, out, e);
  case FN_DATE_ADD: return ev_date_add(c, f, out, e);
  case FN_DATE_DIFF: return ev_date_diff(c, f, out, e);
  default: return ev_simple(c, f, out, e);
  }
}

static bool ev_primary(ctx *c, sel_primary *p, sel_value *out, sel_err *e) {
  switch (p->kind) {
  case PT_VALUE: return *out = ev_lit(p->lit), true;
  case PT_PATH: return ev_path(c, p->path, out, e);
  case PT_LIST: return ev_list(c, p->list, out, e);
  case PT_SUB: return ev_expr(c, p->sub, out, e);
  case PT_FUNC: return ev_func(c, p->fn, out, e);
  }
  return fail(e, "invalid AST Node");
}

/* ---- aggregation ---- */

static bool agg_expr(ctx *c, sel_expr *x, sel_err *e);
static bool agg_operand(ctx *c, sel_operand *o, sel_err *e);
static bool agg_primary(ctx *c, sel_primary *p, sel_err *e);

static bool agg_update(ctx *c, sel_func *f, sel_err *e) {
  sel_agg *g = f->agg;
  if (f->kind == FN_COUNT && f->star) {
    g->count++;
    return true;
  }
  sel_value v;
  if (!ev_expr(c, f->kind == FN_COUNT ? f->count_arg : f->args[0], &v, e)) return false;
  if (v.t == SV_NULL) return true;
  if (f->kind != FN_COUNT && !sv_is_numeric(&v)) {
    int64_t i;
    double d;
    if (v.t == SV_BYTES && sv_bytes_to_int(&v, &i)) v = sv_int(i);
    else if (v.t == SV_BYTES && sv_bytes_to_float(&v, &d)) v = sv_float(d);
    else return fail(e, "%s() requires a numeric argument", f->name);
  }
  bool first = !g->seen;
  g->seen = true;
  if (f->kind == FN_COUNT) {
    g->count++;
    return true;
  }
  if (!strcmp(f->name, "AVG") || !strcmp(f->name, "SUM")) {
    g->count++;
    double d;
    sv_to_float(&v, &d);
    g->sum += d;
    return true;
  }
  if (!sv_minmax(&g->running, &v, !strcmp(f->name, "MAX"), first, e)) {
    e->code = "InternalError";
    return false;
  }
  return true;
}

static bool agg_func(ctx *c, sel_func *f, sel_err *e) {
  if (is_agg(f)) return agg_update(c, f, e);
  /* descend into the arguments (MinIO leaves aggregations under other functions unfed) */
  switch (f->kind) {
  case FN_SIMPLE:
    for (size_t i = 0; i < f->nargs; i++)
      if (!agg_expr(c, f->args[i], e)) return false;
    return true;
  case FN_CAST: return agg_expr(c, f->cast_expr, e);
  case FN_SUBSTRING:
    return agg_primary(c, f->sub_expr, e) && (!f->from || agg_operand(c, f->from, e)) &&
           (!f->for_ || agg_operand(c, f->for_, e)) && (!f->arg2 || agg_operand(c, f->arg2, e)) &&
           (!f->arg3 || agg_operand(c, f->arg3, e));
  case FN_EXTRACT: return agg_primary(c, f->ext_from, e);
  case FN_TRIM: return (!f->trim_chars || agg_primary(c, f->trim_chars, e)) && agg_primary(c, f->trim_from, e);
  case FN_DATE_ADD: return agg_operand(c, f->qty, e) && agg_primary(c, f->ts1, e);
  case FN_DATE_DIFF: return agg_primary(c, f->ts1, e) && agg_primary(c, f->ts2, e);
  default: return true;
  }
}

static bool agg_primary(ctx *c, sel_primary *p, sel_err *e) {
  switch (p->kind) {
  case PT_LIST:
    for (size_t i = 0; i < p->list->n; i++)
      if (!agg_expr(c, p->list->el[i], e)) return false;
    return true;
  case PT_SUB: return agg_expr(c, p->sub, e);
  case PT_FUNC: return agg_func(c, p->fn, e);
  default: return true;
  }
}

static bool agg_multop(ctx *c, sel_multop *m, sel_err *e) {
  if (!agg_primary(c, m->left->p, e)) return false;
  for (size_t i = 0; i < m->n; i++)
    if (!agg_primary(c, m->right[i]->p, e)) return false;
  return true;
}

static bool agg_operand(ctx *c, sel_operand *o, sel_err *e) {
  if (!agg_multop(c, o->left, e)) return false;
  for (size_t i = 0; i < o->n; i++)
    if (!agg_multop(c, o->right[i], e)) return false;
  return true;
}

static bool agg_cond(ctx *c, sel_cond *x, sel_err *e) {
  if (!x->operand) return agg_cond(c, x->not_, e);
  if (!agg_operand(c, x->operand->operand, e)) return false;
  sel_rhs *h = x->operand->rhs;
  if (!h) return true;
  switch (h->kind) {
  case RHS_CMP: return agg_operand(c, h->operand, e);
  case RHS_BETWEEN: return agg_operand(c, h->start, e) && agg_operand(c, h->end, e);
  case RHS_IN:
    if (h->in_list)
      for (size_t i = 0; i < h->in_list->n; i++)
        if (!agg_expr(c, h->in_list->el[i], e)) return false;
    return true;
  case RHS_LIKE: return agg_operand(c, h->pattern, e) && (!h->escape || agg_operand(c, h->escape, e));
  }
  return true;
}

static bool agg_expr(ctx *c, sel_expr *x, sel_err *e) {
  for (size_t i = 0; i < x->n; i++)
    for (size_t j = 0; j < x->ands[i]->n; j++)
      if (!agg_cond(c, x->ands[i]->conds[j], e)) return false;
  return true;
}

/* ---- statements ---- */

static bool passes_where(ctx *c, bool *ok, sel_err *e) {
  sel_select *s = c->st->ast;
  if (!s->where) return *ok = true, true;
  sel_value v;
  if (!ev_expr(c, s->where, &v, e)) return false;
  if (v.t != SV_BOOL) return fail(e, "WHERE expression did not return bool");
  *ok = v.b;
  return true;
}

bool sel_aggregate_row(sel_stmt *st, sel_arena *a, const sel_record *in, sel_err *e) {
  ctx c = {st, a, in};
  bool ok;
  if (!passes_where(&c, &ok, e)) return false;
  if (!ok) return true;
  for (size_t i = 0; i < st->ast->n; i++)
    if (!agg_expr(&c, st->ast->exprs[i]->expr, e)) return false;
  return true;
}

static void column_name(sel_arena *a, size_t i, const char **name, size_t *n) {
  char buf[24];
  int k = snprintf(buf, sizeof(buf), "_%zu", i + 1);
  *name = sel_strndup(a, buf, (size_t)k);
  *n = (size_t)k;
}

bool sel_aggregate_result(sel_stmt *st, sel_arena *a, sel_orec *out, sel_err *e) {
  ctx c = {st, a, NULL};
  for (size_t i = 0; i < st->ast->n; i++) {
    sel_aliased *x = st->ast->exprs[i];
    sel_value v;
    if (!ev_expr(&c, x->expr, &v, e)) return false;
    const char *name = x->as;
    size_t n = x->as_n;
    if (!name) column_name(a, i, &name, &n);
    if (!sel_orec_set(out, a, name, n, &v, e)) return false;
  }
  return true;
}

/* getLastKeypathComponent */
static bool last_component(sel_arena *a, sel_expr *x, const char **name, size_t *n) {
  if (x->n != 1 || x->ands[0]->n != 1) return false;
  sel_cond *cd = x->ands[0]->conds[0];
  if (!cd->operand || cd->operand->rhs) return false;
  sel_operand *o = cd->operand->operand;
  if (o->n || o->left->n || o->left->left->neg || o->left->left->p->kind != PT_PATH) return false;
  sel_jpath *j = o->left->left->p->path;
  if (j->n > 0 && j->el[j->n - 1].kind != PE_KEY) return false;
  /* the path's text, then what follows its last '.' */
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append(&b, j->base.s, j->base.n);
  for (size_t i = 0; i < j->n; i++) {
    const sel_pelem *el = &j->el[i];
    switch (el->kind) {
    case PE_KEY:
      if (el->lit_key) {
        buckets_buf_append_c(&b, "['");
        buckets_buf_append(&b, el->key.s, el->key.n);
        buckets_buf_append_c(&b, "']");
      } else {
        buckets_buf_append_char(&b, '.');
        buckets_buf_append(&b, el->key.s, el->key.n);
      }
      break;
    case PE_INDEX: buckets_buf_appendf(&b, "[%" PRId64 "]", el->index); break;
    case PE_OBJWILD: buckets_buf_append_c(&b, ".*"); break;
    case PE_ARRWILD: buckets_buf_append_c(&b, "[*]"); break;
    }
  }
  const char *s = b.data;
  size_t len = b.len;
  for (size_t i = len; i > 0; i--) {
    if (s[i - 1] == '.') {
      s += i;
      len -= i;
      break;
    }
  }
  *name = sel_strndup(a, s, len);
  *n = len;
  buckets_buf_free(&b);
  return true;
}

bool sel_eval(sel_stmt *st, sel_arena *a, const sel_record *in, sel_orec *out, bool *emit, sel_err *e) {
  ctx c = {st, a, in};
  *emit = false;
  bool ok;
  if (!passes_where(&c, &ok, e)) return false;
  if (!ok) return true;
  if (st->ast->all) {
    st->output_count++;
    sel_orec_clone(out, a, in);
    *emit = true;
    return true;
  }
  for (size_t i = 0; i < st->ast->n; i++) {
    sel_aliased *x = st->ast->exprs[i];
    sel_value v;
    if (!ev_expr(&c, x->expr, &v, e)) return false;
    const char *name = x->as;
    size_t n = x->as_n;
    if (!name && !last_component(a, x->expr, &name, &n)) column_name(a, i, &name, &n);
    if (!sel_orec_set(out, a, name, n, &v, e)) return false;
  }
  st->output_count++;
  *emit = true;
  return true;
}

bool sel_eval_from(sel_stmt *st, sel_arena *a, const sel_record *in, sel_record **out, size_t *n, sel_err *e) {
  sel_jpath *t = st->ast->table;
  if (t->n <= 1) {
    *out = (sel_record *)in;
    *n = 1;
    return true;
  }
  if (in->fmt != SEL_FMT_JSON) return fail(e, "Data source: path not supported");
  ctx c = {st, a, in};
  jres r;
  bool flat;
  if (!jpath_eval(&c, t->el + 1, t->n - 1, (jres){.k = JR_JV, .v = &in->obj}, &r, &flat, e)) return false;
  if (r.k == JR_ARR || (r.k == JR_JV && r.v->t == JV_ARR)) {
    size_t cnt = r.k == JR_ARR ? r.n : r.v->a.n;
    sel_record *recs = sel_alloc(a, (cnt ? cnt : 1) * sizeof(sel_record));
    for (size_t i = 0; i < cnt; i++) {
      const jv *v = r.k == JR_ARR ? (r.items[i].k == JR_JV ? r.items[i].v : NULL) : &r.v->a.v[i];
      if (!v || v->t != JV_OBJ) return fail(e, "cannot replace internal data in json record with type %s", "non-object");
      recs[i] = *in;
      recs[i].obj = *v;
    }
    *out = recs;
    *n = cnt;
    return true;
  }
  sel_record *rec = sel_alloc(a, sizeof(sel_record));
  *rec = *in;
  if (r.k == JR_JV && r.v->t == JV_OBJ) {
    rec->obj = *r.v;
  } else {
    /* anything else becomes the single column _1 */
    jv_kv *kv = sel_alloc(a, sizeof(jv_kv));
    kv->k = "_1";
    kv->kn = 2;
    if (r.k == JR_JV) kv->v = *r.v;
    else if (r.k == JR_MISSING) kv->v = (jv){.t = JV_OBJ}; /* Missing{} marshals as {} */
    else kv->v = (jv){.t = JV_NULL};
    rec->obj = (jv){.t = JV_OBJ, .o = {kv, 1}};
  }
  *out = rec;
  *n = 1;
  return true;
}
