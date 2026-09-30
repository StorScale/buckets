/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* S3 Select SQL: MinIO's lexer and participle grammar (sql/parser.go) as a
 * backtracking recursive-descent parser taking the grammar's alternatives in
 * the same order, and the query analysis of sql/analysis.go and
 * sql/statement.go. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "core/common.h"
#include "select/ast.h"

/* ---- lexer ---- */

typedef enum { T_EOF, T_TIMEWORD, T_KEYWORD, T_IDENT, T_QUOTIDENT, T_FLOAT, T_INT, T_LITSTRING, T_OP } tkind;
typedef struct {
  tkind k;
  const char *p;
  size_t n;
  int line, col;
} tok;

static const char *const k_timewords[] = {"YEAR",   "MONTH",         "DAY",           "HOUR", "MINUTE",
                                          "SECOND", "TIMEZONE_HOUR", "TIMEZONE_MINUTE", NULL};
static const char *const k_keywords[] = {
    "SELECT",   "FROM",      "TOP",      "DISTINCT", "ALL",     "WHERE",    "GROUP",        "BY",
    "HAVING",   "UNION",     "MINUS",    "EXCEPT",   "INTERSECT", "ORDER",  "LIMIT",        "OFFSET",
    "TRUE",     "FALSE",     "NULL",     "IS",       "NOT",     "ANY",      "SOME",         "BETWEEN",
    "AND",      "OR",        "LIKE",     "ESCAPE",   "AS",      "IN",       "BOOL",         "INT",
    "INTEGER",  "STRING",    "FLOAT",    "DECIMAL",  "NUMERIC", "TIMESTAMP", "AVG",         "COUNT",
    "MAX",      "MIN",       "SUM",      "COALESCE", "NULLIF",  "CAST",     "DATE_ADD",     "DATE_DIFF",
    "EXTRACT",  "TO_STRING", "TO_TIMESTAMP", "UTCNOW", "CHAR_LENGTH", "CHARACTER_LENGTH", "LOWER", "SUBSTRING",
    "TRIM",     "UPPER",     "LEADING",  "TRAILING", "BOTH",    "FOR",      "MISSING",      NULL};

static bool word_char(int c) { return isalnum(c) || c == '_'; }

/* A word from the list at s ending at a word boundary (the lexer matches
 * the rest of the input, so \b always holds before a token). */
static size_t match_word(const char *s, const char *end, const char *const *words) {
  size_t best = 0;
  for (const char *const *w = words; *w; w++) {
    size_t n = strlen(*w);
    if ((size_t)(end - s) >= n && strncasecmp(s, *w, n) == 0 && (s + n == end || !word_char((unsigned char)s[n])) &&
        n > best)
      best = n;
  }
  return best;
}

/* '...' or "..." with the quote doubled inside. */
static size_t match_quoted(const char *s, const char *end, char q) {
  if (s == end || *s != q) return 0;
  const char *p = s + 1;
  while (p < end) {
    if (*p == q) {
      if (p + 1 < end && p[1] == q) {
        p += 2;
        continue;
      }
      return (size_t)(p + 1 - s);
    }
    p++;
  }
  /* unterminated: the regexp backtracks to the first closing quote */
  const char *c = memchr(s + 1, q, (size_t)(end - s - 1));
  return c ? (size_t)(c + 1 - s) : 0;
}

static bool lex(const char *src, size_t n, tok **out, size_t *nt, sel_err *e) {
  const char *s = src, *end = src + n;
  size_t cap = 32, k = 0;
  tok *t = buckets_xmalloc(cap * sizeof(tok));
  int line = 1;
  const char *line_start = s;
  while (s < end) {
    if (isspace((unsigned char)*s)) {
      if (*s == '\n') line++, line_start = s + 1;
      s++;
      continue;
    }
    if (k + 1 >= cap) t = buckets_xrealloc(t, (cap *= 2) * sizeof(tok));
    tok x = {.p = s, .line = line, .col = (int)(s - line_start) + 1};
    size_t m;
    if ((m = match_word(s, end, k_timewords))) {
      x.k = T_TIMEWORD;
    } else if ((m = match_word(s, end, k_keywords))) {
      x.k = T_KEYWORD;
    } else if (isalpha((unsigned char)*s) || *s == '_') {
      m = 1;
      while (s + m < end && word_char((unsigned char)s[m])) m++;
      x.k = T_IDENT;
    } else if ((m = match_quoted(s, end, '"'))) {
      x.k = T_QUOTIDENT;
    } else {
      /* Float: \d*\.\d+([eE][-+]?\d+)? */
      const char *p = s;
      while (p < end && isdigit((unsigned char)*p)) p++;
      if (p < end && *p == '.' && p + 1 < end && isdigit((unsigned char)p[1])) {
        p++;
        while (p < end && isdigit((unsigned char)*p)) p++;
        if (p < end && (*p == 'e' || *p == 'E')) {
          const char *q = p + 1;
          if (q < end && (*q == '-' || *q == '+')) q++;
          if (q < end && isdigit((unsigned char)*q)) {
            while (q < end && isdigit((unsigned char)*q)) q++;
            p = q;
          }
        }
        m = (size_t)(p - s);
        x.k = T_FLOAT;
      } else if (isdigit((unsigned char)*s)) {
        m = 1;
        while (s + m < end && isdigit((unsigned char)s[m])) m++;
        x.k = T_INT;
      } else if ((m = match_quoted(s, end, '\''))) {
        x.k = T_LITSTRING;
      } else {
        static const char *const ops2[] = {"<>", "!=", "<=", ">=", ".*", NULL};
        m = 0;
        for (const char *const *o = ops2; *o; o++)
          if (end - s >= 2 && s[0] == (*o)[0] && s[1] == (*o)[1]) m = 2;
        if (!m && end - s >= 3 && !memcmp(s, "[*]", 3)) m = 3;
        if (!m && strchr("-+*/%,.()=<>[]", *s)) m = 1;
        if (!m) {
          free(t);
          unsigned char ch = (unsigned char)*s;
          if (ch >= 0x20 && ch < 0x7f && ch != '\'' && ch != '\\')
            return sel_fail(e, "ParseSelectFailure", "%d:%d: invalid token '%c'", x.line, x.col, ch);
          return sel_fail(e, "ParseSelectFailure", "%d:%d: invalid token '\\x%02x'", x.line, x.col, ch);
        }
        x.k = T_OP;
      }
    }
    x.n = m;
    t[k++] = x;
    s += m;
  }
  t[k] = (tok){.k = T_EOF, .p = end, .line = line, .col = (int)(end - line_start) + 1};
  *out = t;
  *nt = k;
  return true;
}

/* ---- parser ---- */

/* A rule's result at a token position, once parsed (packrat): nested
 * parentheses try several alternatives each, which without it is exponential
 * in the depth. Results depend on the position only, and a failed
 * alternative's nodes never reach the tree, so sharing them is safe. */
typedef struct {
  uint8_t st; /* 0: not tried, 1: failed, 2: parsed */
  size_t end;
  void *v;
} memo;

typedef struct {
  tok *t;
  size_t i, far;
  sel_arena *a;
  memo *m_expr, *m_primary, *m_operand; /* one per token */
  int depth; /* expression nesting, bounded: the parser recurses per level */
  bool too_deep; /* the bound was hit: the whole parse fails (no memo is trusted) */
} P;

/* Deeper nesting fails to parse rather than overflow a worker's stack
 * (MinIO's goroutine stacks grow instead). */
#define MAX_NESTING 128

#define MEMOIZED(type, name, field)                     \
  static type *name##_raw(P *p);                        \
  static type *name(P *p) {                             \
    size_t at = p->i;                                   \
    memo *m = &p->field[at];                            \
    if (p->too_deep) return NULL;                       \
    if (!m->st) {                                       \
      m->v = name##_raw(p);                             \
      m->end = p->i;                                    \
      m->st = m->v ? 2 : 1;                             \
    }                                                   \
    p->i = m->st == 2 ? m->end : at;                    \
    return m->v;                                        \
  }

static tok *cur(P *p) { return &p->t[p->i]; }
static void adv(P *p) {
  p->i++;
  if (p->i > p->far) p->far = p->i;
}

static bool is_kw(P *p, const char *w) {
  tok *t = cur(p);
  return (t->k == T_KEYWORD || t->k == T_TIMEWORD) && t->n == strlen(w) && strncasecmp(t->p, w, t->n) == 0;
}
static bool kw(P *p, const char *w) {
  if (!is_kw(p, w)) return false;
  adv(p);
  return true;
}
static bool is_op(P *p, const char *o) {
  tok *t = cur(p);
  return t->k == T_OP && t->n == strlen(o) && !memcmp(t->p, o, t->n);
}
static bool op(P *p, const char *o) {
  if (!is_op(p, o)) return false;
  adv(p);
  return true;
}

#define NEW(T) ((T *)sel_alloc(p->a, sizeof(T)))

/* A growable array of pointers in the arena. */
typedef struct {
  void **v;
  size_t n, cap;
} vec;
static void vpush(P *p, vec *v, void *x) {
  if (v->n == v->cap) {
    size_t cap = v->cap ? v->cap * 2 : 4;
    void **nv = sel_alloc(p->a, cap * sizeof(void *));
    if (v->n) memcpy(nv, v->v, v->n * sizeof(void *));
    v->v = nv;
    v->cap = cap;
  }
  v->v[v->n++] = x;
}

static sel_expr *p_expr(P *p);
static sel_operand *p_operand(P *p);
static sel_primary *p_primary(P *p);

/* 'it''s' -> it's */
static void unquote(P *p, const tok *t, const char **s, size_t *n) {
  char q = t->p[0];
  char *o = sel_alloc(p->a, t->n);
  size_t k = 0;
  for (size_t i = 1; i + 1 < t->n; i++) {
    o[k++] = t->p[i];
    if (t->p[i] == q && i + 2 < t->n && t->p[i + 1] == q) i++;
  }
  *s = o;
  *n = k;
}

static bool p_ident(P *p, sel_ident *id) {
  tok *t = cur(p);
  if (t->k == T_IDENT) {
    id->s = t->p;
    id->n = t->n;
  } else if (t->k == T_QUOTIDENT) {
    unquote(p, t, &id->s, &id->n);
  } else {
    return false;
  }
  adv(p);
  return true;
}

static bool p_pelem(P *p, sel_pelem *el) {
  size_t save = p->i;
  memset(el, 0, sizeof(*el));
  /* ObjectKey: "[" LitString "]" | "." Identifier */
  if (op(p, "[") && cur(p)->k == T_LITSTRING) {
    tok *t = cur(p);
    adv(p);
    if (op(p, "]")) {
      el->kind = PE_KEY;
      el->lit_key = true;
      unquote(p, t, &el->key.s, &el->key.n);
      return true;
    }
  }
  p->i = save;
  if (op(p, ".") && p_ident(p, &el->key)) {
    el->kind = PE_KEY;
    return true;
  }
  p->i = save;
  /* "[" Int "]" */
  if (op(p, "[") && cur(p)->k == T_INT) {
    tok *t = cur(p);
    adv(p);
    if (op(p, "]") && sel_parse_int(t->p, t->n, &el->index)) {
      el->kind = PE_INDEX;
      return true;
    }
  }
  p->i = save;
  if (op(p, ".*")) {
    el->kind = PE_OBJWILD;
    return true;
  }
  if (op(p, "[*]")) {
    el->kind = PE_ARRWILD;
    return true;
  }
  p->i = save;
  return false;
}

static sel_jpath *p_jpath(P *p) {
  size_t save = p->i;
  sel_jpath *j = NEW(sel_jpath);
  if (!p_ident(p, &j->base)) {
    p->i = save;
    return NULL;
  }
  size_t cap = 0;
  for (;;) {
    sel_pelem el;
    size_t at = p->i;
    if (!p_pelem(p, &el)) {
      p->i = at;
      break;
    }
    if (j->n == cap) {
      cap = cap ? cap * 2 : 4;
      sel_pelem *ne = sel_alloc(p->a, cap * sizeof(sel_pelem));
      if (j->n) memcpy(ne, j->el, j->n * sizeof(sel_pelem));
      j->el = ne;
    }
    j->el[j->n++] = el;
  }
  return j;
}

static sel_lit *p_lit(P *p) {
  tok *t = cur(p);
  sel_lit *l = NEW(sel_lit);
  char buf[64];
  switch (t->k) {
  case T_FLOAT:
  case T_INT:
    l->kind = t->k == T_FLOAT ? LIT_FLOAT : LIT_INT;
    snprintf(buf, sizeof(buf), "%.*s", (int)t->n, t->p);
    l->num = strtod(buf, NULL);
    break;
  case T_LITSTRING:
    l->kind = LIT_STR;
    unquote(p, t, &l->s, &l->sn);
    break;
  default:
    if (is_kw(p, "TRUE") || is_kw(p, "FALSE")) {
      l->kind = LIT_BOOL;
      l->b = is_kw(p, "TRUE");
    } else if (is_kw(p, "NULL")) {
      l->kind = LIT_NULL;
    } else if (is_kw(p, "MISSING")) {
      l->kind = LIT_MISSING;
    } else {
      return NULL;
    }
  }
  adv(p);
  return l;
}

/* "(" Expr ("," Expr)* ")" | "[" Expr ("," Expr)* "]" */
static sel_list *p_list(P *p) {
  size_t save = p->i;
  const char *close = NULL;
  if (op(p, "(")) close = ")";
  else if (op(p, "[")) close = "]";
  else return NULL;
  vec v = {0};
  for (;;) {
    sel_expr *x = p_expr(p);
    if (!x) {
      p->i = save;
      return NULL;
    }
    vpush(p, &v, x);
    if (op(p, ",")) continue;
    if (op(p, close)) break;
    p->i = save;
    return NULL;
  }
  sel_list *l = NEW(sel_list);
  l->el = (sel_expr **)v.v;
  l->n = v.n;
  return l;
}

static bool upper_into(char *dst, size_t cap, const tok *t) {
  if (t->n >= cap) return false;
  for (size_t i = 0; i < t->n; i++) dst[i] = (char)toupper((unsigned char)t->p[i]);
  dst[t->n] = 0;
  return true;
}

static bool p_timeword(P *p, char *dst, size_t cap, bool with_tz) {
  tok *t = cur(p);
  if (t->k != T_TIMEWORD) return false;
  upper_into(dst, cap, t);
  if (!with_tz && !strncmp(dst, "TIMEZONE", 8)) return false;
  adv(p);
  return true;
}

static sel_func *p_func(P *p) {
  size_t save = p->i;
  sel_func *f = NEW(sel_func);
  static const char *const simple[] = {"AVG",          "MAX",    "MIN",         "SUM",
                                       "COALESCE",     "NULLIF", "TO_STRING",   "TO_TIMESTAMP",
                                       "UTCNOW",       "CHAR_LENGTH", "CHARACTER_LENGTH", "LOWER",
                                       "UPPER",        NULL};
  for (const char *const *w = simple; *w; w++) {
    if (!is_kw(p, *w)) continue;
    upper_into(f->name, sizeof(f->name), cur(p));
    adv(p);
    f->kind = FN_SIMPLE;
    if (!op(p, "(")) goto fail;
    vec v = {0};
    if (!op(p, ")")) {
      for (;;) {
        sel_expr *x = p_expr(p);
        if (!x) goto fail;
        vpush(p, &v, x);
        if (op(p, ",")) continue;
        if (op(p, ")")) break;
        goto fail;
      }
    }
    f->args = (sel_expr **)v.v;
    f->nargs = v.n;
    return f;
  }
  if (kw(p, "COUNT")) {
    f->kind = FN_COUNT;
    strcpy(f->name, "COUNT");
    if (!op(p, "(")) goto fail;
    f->star = op(p, "*");
    size_t at = p->i;
    f->count_arg = p_expr(p);
    if (!f->count_arg) p->i = at;
    if ((!f->star && !f->count_arg) || !op(p, ")")) goto fail;
    return f;
  }
  if (kw(p, "CAST")) {
    f->kind = FN_CAST;
    strcpy(f->name, "CAST");
    static const char *const types[] = {"BOOL", "INT", "INTEGER", "STRING", "FLOAT", "DECIMAL", "NUMERIC", "TIMESTAMP", NULL};
    if (!op(p, "(") || !(f->cast_expr = p_expr(p)) || !kw(p, "AS")) goto fail;
    bool ok = false;
    for (const char *const *w = types; *w && !ok; w++) {
      if (is_kw(p, *w)) {
        upper_into(f->cast_type, sizeof(f->cast_type), cur(p));
        adv(p);
        ok = true;
      }
    }
    if (!ok || !op(p, ")")) goto fail;
    return f;
  }
  if (kw(p, "SUBSTRING")) {
    f->kind = FN_SUBSTRING;
    strcpy(f->name, "SUBSTRING");
    if (!op(p, "(") || !(f->sub_expr = p_primary(p))) goto fail;
    size_t at = p->i;
    if (kw(p, "FROM") && (f->from = p_operand(p))) {
      size_t at2 = p->i;
      if (!(kw(p, "FOR") && (f->for_ = p_operand(p)))) {
        p->i = at2;
        f->for_ = NULL;
      }
      if (op(p, ")")) return f;
    }
    p->i = at;
    f->from = f->for_ = NULL;
    if (op(p, ",") && (f->arg2 = p_operand(p))) {
      size_t at2 = p->i;
      if (!(op(p, ",") && (f->arg3 = p_operand(p)))) {
        p->i = at2;
        f->arg3 = NULL;
      }
      if (op(p, ")")) return f;
    }
    goto fail;
  }
  if (kw(p, "EXTRACT")) {
    f->kind = FN_EXTRACT;
    strcpy(f->name, "EXTRACT");
    if (!op(p, "(") || !p_timeword(p, f->timeword, sizeof(f->timeword), true) || !kw(p, "FROM") ||
        !(f->ext_from = p_primary(p)) || !op(p, ")"))
      goto fail;
    return f;
  }
  if (kw(p, "TRIM")) {
    f->kind = FN_TRIM;
    strcpy(f->name, "TRIM");
    if (!op(p, "(")) goto fail;
    size_t at = p->i;
    static const char *const where[] = {"LEADING", "TRAILING", "BOTH", NULL};
    bool grp = false;
    for (const char *const *w = where; *w && !grp; w++) {
      if (!is_kw(p, *w)) continue;
      tok *t = cur(p);
      adv(p);
      size_t at2 = p->i;
      f->trim_chars = p_primary(p);
      if (!f->trim_chars) p->i = at2;
      if (kw(p, "FROM")) {
        f->trim_where = sel_strndup(p->a, t->p, t->n);
        grp = true;
      } else {
        f->trim_chars = NULL;
      }
    }
    if (!grp) p->i = at;
    if (!(f->trim_from = p_primary(p)) || !op(p, ")")) goto fail;
    return f;
  }
  if (kw(p, "DATE_ADD")) {
    f->kind = FN_DATE_ADD;
    strcpy(f->name, "DATE_ADD");
    if (!op(p, "(") || !p_timeword(p, f->timeword, sizeof(f->timeword), false) || !op(p, ",") ||
        !(f->qty = p_operand(p)) || !op(p, ",") || !(f->ts1 = p_primary(p)) || !op(p, ")"))
      goto fail;
    return f;
  }
  if (kw(p, "DATE_DIFF")) {
    f->kind = FN_DATE_DIFF;
    strcpy(f->name, "DATE_DIFF");
    if (!op(p, "(") || !p_timeword(p, f->timeword, sizeof(f->timeword), false) || !op(p, ",") ||
        !(f->ts1 = p_primary(p)) || !op(p, ",") || !(f->ts2 = p_primary(p)) || !op(p, ")"))
      goto fail;
    return f;
  }
fail:
  p->i = save;
  return NULL;
}

MEMOIZED(sel_primary, p_primary, m_primary)
static sel_primary *p_primary_raw(P *p) {
  size_t save = p->i;
  sel_primary *x = NEW(sel_primary);
  if ((x->lit = p_lit(p))) return x->kind = PT_VALUE, x;
  if ((x->path = p_jpath(p))) return x->kind = PT_PATH, x;
  if ((x->list = p_list(p))) return x->kind = PT_LIST, x;
  if (op(p, "(")) {
    if ((x->sub = p_expr(p)) && op(p, ")")) return x->kind = PT_SUB, x;
    p->i = save;
    x->sub = NULL;
  }
  if ((x->fn = p_func(p))) return x->kind = PT_FUNC, x;
  p->i = save;
  return NULL;
}

static sel_unary *p_unary(P *p) {
  size_t save = p->i;
  sel_unary *u = NEW(sel_unary);
  if (op(p, "-")) {
    if ((u->p = p_primary(p))) return u->neg = true, u;
    p->i = save;
  }
  if ((u->p = p_primary(p))) return u;
  p->i = save;
  return NULL;
}

static sel_multop *p_multop(P *p) {
  sel_multop *m = NEW(sel_multop);
  if (!(m->left = p_unary(p))) return NULL;
  vec r = {0};
  char ops[256];
  size_t n = 0;
  for (;;) {
    size_t at = p->i;
    char o = is_op(p, "*") ? '*' : is_op(p, "/") ? '/' : is_op(p, "%") ? '%' : 0;
    if (!o) break;
    adv(p);
    sel_unary *u = p_unary(p);
    if (!u || n == sizeof(ops)) {
      p->i = at;
      break;
    }
    ops[n++] = o;
    vpush(p, &r, u);
  }
  m->n = n;
  m->right = (sel_unary **)r.v;
  m->ops = sel_strndup(p->a, ops, n);
  return m;
}

MEMOIZED(sel_operand, p_operand, m_operand)
static sel_operand *p_operand_raw(P *p) {
  sel_operand *o = NEW(sel_operand);
  if (!(o->left = p_multop(p))) return NULL;
  vec r = {0};
  char ops[256];
  size_t n = 0;
  for (;;) {
    size_t at = p->i;
    char c = is_op(p, "+") ? '+' : is_op(p, "-") ? '-' : 0;
    if (!c) break;
    adv(p);
    sel_multop *m = p_multop(p);
    if (!m || n == sizeof(ops)) {
      p->i = at;
      break;
    }
    ops[n++] = c;
    vpush(p, &r, m);
  }
  o->n = n;
  o->right = (sel_multop **)r.v;
  o->ops = sel_strndup(p->a, ops, n);
  return o;
}

static sel_rhs *p_rhs(P *p) {
  size_t save = p->i;
  sel_rhs *r = NEW(sel_rhs);
  /* Compare */
  static const char *const cmps[] = {"<>", "<=", ">=", "=", "<", ">", "!=", NULL};
  for (const char *const *c = cmps; *c; c++) {
    if (op(p, *c)) {
      strcpy(r->op, *c);
      goto operand;
    }
  }
  if (kw(p, "IS")) {
    size_t at = p->i;
    if (kw(p, "NOT")) strcpy(r->op, "ISNOT");
    else {
      p->i = at;
      strcpy(r->op, "IS");
    }
    goto operand;
  }
  goto between;
operand:
  r->kind = RHS_CMP;
  if ((r->operand = p_operand(p))) return r;
  /* IS NOT failing: try IS alone is the grammar's next alternative */
  if (!strcmp(r->op, "ISNOT")) {
    p->i = save;
    kw(p, "IS");
    strcpy(r->op, "IS");
    if ((r->operand = p_operand(p))) return r;
  }
  p->i = save;
between:
  memset(r, 0, sizeof(*r));
  r->kind = RHS_BETWEEN;
  r->not_ = kw(p, "NOT");
  if (kw(p, "BETWEEN") && (r->start = p_operand(p)) && kw(p, "AND") && (r->end = p_operand(p))) return r;
  p->i = save;
  memset(r, 0, sizeof(*r));
  r->kind = RHS_IN;
  if (kw(p, "IN")) {
    if ((r->in_path = p_jpath(p))) return r;
    if ((r->in_list = p_list(p))) return r;
  }
  p->i = save;
  memset(r, 0, sizeof(*r));
  r->kind = RHS_LIKE;
  r->not_ = kw(p, "NOT");
  if (kw(p, "LIKE") && (r->pattern = p_operand(p))) {
    size_t at = p->i;
    if (!(kw(p, "ESCAPE") && (r->escape = p_operand(p)))) {
      p->i = at;
      r->escape = NULL;
    }
    return r;
  }
  p->i = save;
  return NULL;
}

static sel_cond *p_cond(P *p) {
  size_t save = p->i;
  sel_cond *c = NEW(sel_cond);
  sel_operand *o = p_operand(p);
  if (o) {
    c->operand = NEW(sel_condop);
    c->operand->operand = o;
    size_t at = p->i;
    c->operand->rhs = p_rhs(p);
    if (!c->operand->rhs) p->i = at;
    return c;
  }
  p->i = save;
  if (kw(p, "NOT") && (c->not_ = p_cond(p))) return c;
  p->i = save;
  return NULL;
}

static sel_and *p_and(P *p) {
  vec v = {0};
  sel_cond *c = p_cond(p);
  if (!c) return NULL;
  vpush(p, &v, c);
  for (;;) {
    size_t at = p->i;
    if (!kw(p, "AND") || !(c = p_cond(p))) {
      p->i = at;
      break;
    }
    vpush(p, &v, c);
  }
  sel_and *a = NEW(sel_and);
  a->conds = (sel_cond **)v.v;
  a->n = v.n;
  return a;
}

MEMOIZED(sel_expr, p_expr, m_expr)
static sel_expr *p_expr_nested(P *p);
static sel_expr *p_expr_raw(P *p) {
  if (p->too_deep || p->depth >= MAX_NESTING) {
    p->too_deep = true;
    return NULL;
  }
  p->depth++;
  sel_expr *x = p_expr_nested(p);
  p->depth--;
  return x;
}

static sel_expr *p_expr_nested(P *p) {
  vec v = {0};
  sel_and *a = p_and(p);
  if (!a) return NULL;
  vpush(p, &v, a);
  for (;;) {
    size_t at = p->i;
    if (!kw(p, "OR") || !(a = p_and(p))) {
      p->i = at;
      break;
    }
    vpush(p, &v, a);
  }
  sel_expr *x = NEW(sel_expr);
  x->ands = (sel_and **)v.v;
  x->n = v.n;
  return x;
}

static sel_aliased *p_aliased(P *p) {
  sel_aliased *x = NEW(sel_aliased);
  if (!(x->expr = p_expr(p))) return NULL;
  size_t at = p->i;
  if (kw(p, "AS")) {
    tok *t = cur(p);
    if (t->k == T_IDENT || t->k == T_LITSTRING) {
      x->as = t->p; /* the token as written, quotes and all */
      x->as_n = t->n;
      adv(p);
      return x;
    }
  }
  p->i = at;
  return x;
}

static sel_select *p_select(P *p) {
  sel_select *s = NEW(sel_select);
  if (!kw(p, "SELECT")) return NULL;
  if (op(p, "*")) {
    s->all = true;
  } else {
    vec v = {0};
    sel_aliased *a = p_aliased(p);
    if (!a) return NULL;
    vpush(p, &v, a);
    for (;;) {
      size_t at = p->i;
      if (!op(p, ",") || !(a = p_aliased(p))) {
        p->i = at;
        break;
      }
      vpush(p, &v, a);
    }
    s->exprs = (sel_aliased **)v.v;
    s->n = v.n;
  }
  if (!kw(p, "FROM") || !(s->table = p_jpath(p))) return NULL;
  size_t at = p->i;
  kw(p, "AS");
  if (cur(p)->k == T_IDENT) {
    s->table_as = cur(p)->p;
    s->table_as_n = cur(p)->n;
    adv(p);
  } else {
    p->i = at;
  }
  if (is_kw(p, "WHERE")) {
    adv(p);
    if (!(s->where = p_expr(p))) return NULL;
  }
  if (is_kw(p, "LIMIT")) {
    adv(p);
    if (!(s->limit = p_lit(p))) return NULL;
  }
  if (cur(p)->k != T_EOF) return NULL;
  return s;
}

/* ---- analysis ---- */

typedef struct {
  bool agg, row;
  char err[96]; /* "": none */
} qprop;

static void combine(qprop *p, qprop q) {
  if (p->err[0]) return;
  if (q.err[0]) {
    *p = q;
    return;
  }
  p->agg |= q.agg;
  p->row |= q.row;
  if (p->agg && p->row) snprintf(p->err, sizeof(p->err), "Cannot nest aggregations");
}

static qprop q_err(const char *m) {
  qprop q = {0};
  snprintf(q.err, sizeof(q.err), "%s", m);
  return q;
}

static qprop a_expr(sel_select *s, sel_expr *e, sel_arena *a);
static qprop a_operand(sel_select *s, sel_operand *o, sel_arena *a);
static qprop a_primary(sel_select *s, sel_primary *x, sel_arena *a);

static bool ident_eq(sel_ident id, const char *s, size_t n) { return id.n == n && (!n || !memcmp(id.s, s, n)); }
static bool ident_ieq(sel_ident id, const char *s) { return id.n == strlen(s) && !strncasecmp(id.s, s, id.n); }

static qprop a_path(sel_select *s, sel_jpath *j) {
  if (j->n > 0 && !ident_eq(j->base, s->table_as ? s->table_as : "", s->table_as ? s->table_as_n : 0) &&
      !ident_ieq(j->base, "s3object"))
    return q_err("A provided keypath is invalid");
  return (qprop){.row = true};
}

static qprop a_list(sel_select *s, sel_list *l, sel_arena *a) {
  qprop r = {0};
  for (size_t i = 0; i < l->n; i++) combine(&r, a_expr(s, l->el[i], a));
  return r;
}

static qprop a_func(sel_select *s, sel_func *f, sel_arena *a) {
  qprop r = {0};
  const char *n = f->name;
  switch (f->kind) {
  case FN_CAST: return a_expr(s, f->cast_expr, a);
  case FN_EXTRACT: return a_primary(s, f->ext_from, a);
  case FN_DATE_ADD:
    combine(&r, a_operand(s, f->qty, a));
    combine(&r, a_primary(s, f->ts1, a));
    return r;
  case FN_DATE_DIFF:
    combine(&r, a_primary(s, f->ts1, a));
    combine(&r, a_primary(s, f->ts2, a));
    return r;
  case FN_COUNT: {
    f->agg = sel_alloc(a, sizeof(sel_agg));
    if (f->star) return (qprop){.agg = true};
    qprop q = a_expr(s, f->count_arg, a);
    if (q.err[0]) return q;
    if (q.agg) return q_err("Cannot nest aggregations");
    return (qprop){.agg = true};
  }
  case FN_TRIM:
    if (f->trim_chars) combine(&r, a_primary(s, f->trim_chars, a));
    if (f->trim_from) combine(&r, a_primary(s, f->trim_from, a));
    return r;
  case FN_SUBSTRING:
    combine(&r, a_primary(s, f->sub_expr, a));
    if (f->from) {
      combine(&r, a_operand(s, f->from, a));
      if (f->for_) combine(&r, a_primary(s, f->sub_expr, a));
    } else if (f->arg2) {
      combine(&r, a_operand(s, f->arg2, a));
      if (f->arg3) combine(&r, a_operand(s, f->arg3, a));
    } else {
      snprintf(r.err, sizeof(r.err), "Invalid argument(s) to SUBSTRING");
    }
    return r;
  case FN_SIMPLE: break;
  }
  if (!strcmp(n, "AVG") || !strcmp(n, "MAX") || !strcmp(n, "MIN") || !strcmp(n, "SUM")) {
    f->agg = sel_alloc(a, sizeof(sel_agg));
    if (f->nargs != 1) {
      snprintf(r.err, sizeof(r.err), "%s takes exactly one argument", n);
      return r;
    }
    qprop q = a_expr(s, f->args[0], a);
    if (q.err[0]) return q;
    if (q.agg) return q_err("Cannot nest aggregations");
    return (qprop){.agg = true};
  }
  int want = -1; /* exact argument count, -1: any */
  const char *need = NULL;
  if (!strcmp(n, "COALESCE")) {
    if (f->nargs == 0) need = "needs at least one argument";
  } else if (!strcmp(n, "NULLIF")) {
    want = 2, need = "needs exactly 2 arguments";
  } else if (!strcmp(n, "CHAR_LENGTH") || !strcmp(n, "CHARACTER_LENGTH") || !strcmp(n, "LOWER") ||
             !strcmp(n, "UPPER")) {
    want = 1, need = "needs exactly 2 arguments"; /* sic */
  } else if (!strcmp(n, "TO_TIMESTAMP")) {
    want = 1, need = "needs exactly 1 argument";
  } else if (!strcmp(n, "TO_STRING")) {
    want = 2, need = "needs exactly 2 arguments";
  } else if (!strcmp(n, "UTCNOW")) {
    if (f->nargs) {
      snprintf(r.err, sizeof(r.err), "%s() takes no arguments", n);
    }
    return r;
  } else {
    return q_err("Function is not yet implemented");
  }
  if (need && (want < 0 ? f->nargs == 0 : (int)f->nargs != want)) {
    snprintf(r.err, sizeof(r.err), "%s %s", n, need);
    return r;
  }
  for (size_t i = 0; i < f->nargs; i++) combine(&r, a_expr(s, f->args[i], a));
  return r;
}

static qprop a_primary(sel_select *s, sel_primary *x, sel_arena *a) {
  switch (x->kind) {
  case PT_VALUE: return (qprop){0};
  case PT_PATH: return a_path(s, x->path);
  case PT_LIST: return a_list(s, x->list, a);
  case PT_SUB: return a_expr(s, x->sub, a);
  case PT_FUNC: return a_func(s, x->fn, a);
  }
  return q_err("Unexpected node value");
}

static qprop a_multop(sel_select *s, sel_multop *m, sel_arena *a) {
  qprop r = {0};
  combine(&r, a_primary(s, m->left->p, a));
  for (size_t i = 0; i < m->n; i++) combine(&r, a_primary(s, m->right[i]->p, a));
  return r;
}

static qprop a_operand(sel_select *s, sel_operand *o, sel_arena *a) {
  qprop r = {0};
  combine(&r, a_multop(s, o->left, a));
  for (size_t i = 0; i < o->n; i++) combine(&r, a_multop(s, o->right[i], a));
  return r;
}

static qprop a_cond(sel_select *s, sel_cond *c, sel_arena *a) {
  if (!c->operand) return a_cond(s, c->not_, a);
  qprop r = {0};
  combine(&r, a_operand(s, c->operand->operand, a));
  sel_rhs *h = c->operand->rhs;
  if (!h) return r;
  switch (h->kind) {
  case RHS_CMP: combine(&r, a_operand(s, h->operand, a)); break;
  case RHS_BETWEEN:
    combine(&r, a_operand(s, h->start, a));
    combine(&r, a_operand(s, h->end, a));
    break;
  case RHS_IN: combine(&r, h->in_path ? a_path(s, h->in_path) : a_list(s, h->in_list, a)); break;
  case RHS_LIKE:
    combine(&r, a_operand(s, h->pattern, a));
    if (h->escape) combine(&r, a_operand(s, h->escape, a));
    break;
  }
  return r;
}

static qprop a_expr(sel_select *s, sel_expr *e, sel_arena *a) {
  qprop r = {0};
  for (size_t i = 0; i < e->n; i++)
    for (size_t j = 0; j < e->ands[i]->n; j++) combine(&r, a_cond(s, e->ands[i]->conds[j], a));
  return r;
}

/* ---- ParseSelectStatement ---- */

/* The path of a lone key path expression: "SELECT s.* FROM S3Object s". */
static sel_jpath *lone_path(sel_expr *e) {
  if (e->n != 1 || e->ands[0]->n != 1) return NULL;
  sel_cond *c = e->ands[0]->conds[0];
  if (!c->operand || c->operand->rhs) return NULL;
  sel_operand *o = c->operand->operand;
  if (o->n || o->left->n || o->left->left->neg || o->left->left->p->kind != PT_PATH) return NULL;
  return o->left->left->p->path;
}

sel_stmt *sel_parse(const char *src, size_t n, sel_err *e) {
  tok *toks;
  size_t nt;
  sel_stmt *st = buckets_xcalloc(1, sizeof(*st));
  /* the tree points into the text: the statement keeps its own copy */
  const char *sql = sel_strndup(&st->arena, src, n);
  if (!lex(sql, n, &toks, &nt, e)) {
    sel_stmt_free(st);
    return NULL;
  }
  P p = {.t = toks, .a = &st->arena, .m_expr = buckets_xcalloc(nt + 1, sizeof(memo)),
         .m_primary = buckets_xcalloc(nt + 1, sizeof(memo)), .m_operand = buckets_xcalloc(nt + 1, sizeof(memo))};
  sel_select *s = p_select(&p);
  if (p.too_deep) s = NULL;
  free(p.m_expr);
  free(p.m_primary);
  free(p.m_operand);
  if (!s) {
    tok *t = &toks[p.far < nt ? p.far : nt];
    if (t->k == T_EOF) sel_fail(e, "ParseSelectFailure", "%d:%d: unexpected token \"<EOF>\"", t->line, t->col);
    else sel_fail(e, "ParseSelectFailure", "%d:%d: unexpected token \"%.*s\"", t->line, t->col, (int)t->n, t->p);
    free(toks);
    sel_stmt_free(st);
    return NULL;
  }
  free(toks);
  st->ast = s;
  /* SELECT s.* FROM S3Object s */
  if (!s->all && s->n == 1) {
    sel_jpath *j = lone_path(s->exprs[0]->expr);
    if (j && j->n == 1 && j->el[0].kind == PE_OBJWILD && ident_eq(j->base, s->table_as ? s->table_as : "", s->table_as_n))
      s->all = true;
  }
  st->limit = -1;
  if (s->limit) {
    if (s->limit->kind != LIT_INT) {
      sel_fail(e, "InvalidQuery", "Limit value must be a positive integer");
      sel_stmt_free(st);
      return NULL;
    }
    st->limit = (int64_t)s->limit->num;
  }
  if (s->where) {
    qprop q = a_expr(s, s->where, &st->arena);
    if (q.err[0]) {
      sel_fail(e, "InvalidQuery", "Where clause error: %s", q.err);
      sel_stmt_free(st);
      return NULL;
    }
    if (q.agg) {
      sel_fail(e, "InvalidQuery", "WHERE clause cannot have an aggregation");
      sel_stmt_free(st);
      return NULL;
    }
  }
  if (!ident_ieq(s->table->base, "s3object")) {
    sel_fail(e, "BadTableName", "The table name is not supported: table name must be `s3object`");
    sel_stmt_free(st);
    return NULL;
  }
  if (s->table->n > 0 && s->table->el[0].kind != PE_ARRWILD) {
    sel_fail(e, "BadTableName",
             "The table name is not supported: keypath table name is invalid - please check the service documentation");
    sel_stmt_free(st);
    return NULL;
  }
  qprop q = {0};
  if (s->all) q.row = true;
  else
    for (size_t i = 0; i < s->n; i++) combine(&q, a_expr(s, s->exprs[i]->expr, &st->arena));
  if (q.err[0]) {
    sel_fail(e, "InvalidQuery", "%s", q.err);
    sel_stmt_free(st);
    return NULL;
  }
  st->aggregated = q.agg;
  st->table_alias = s->table_as ? s->table_as : "";
  st->table_alias_n = s->table_as ? s->table_as_n : 0;
  /* quotes come off column aliases */
  for (size_t i = 0; i < s->n; i++) {
    sel_aliased *x = s->exprs[i];
    if (x->as && x->as_n >= 2 && x->as[0] == '\'' && x->as[x->as_n - 1] == '\'') x->as++, x->as_n -= 2;
  }
  return st;
}

void sel_stmt_free(sel_stmt *s) {
  if (!s) return;
  sel_arena_free(&s->arena);
  free(s);
}

bool sel_stmt_aggregated(const sel_stmt *s) { return s->aggregated; }
bool sel_stmt_limit_reached(const sel_stmt *s) { return s->limit >= 0 && s->output_count >= s->limit; }
