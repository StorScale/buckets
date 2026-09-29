/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SELECT_AST_H
#define BUCKETS_SELECT_AST_H

/* The S3 Select syntax tree, node for node as MinIO's participle grammar
 * (internal/s3select/sql/parser.go) builds it. */

#include "select/sel.h"

typedef struct sel_expr sel_expr;
typedef struct sel_operand sel_operand;
typedef struct sel_primary sel_primary;

typedef struct {
  const char *s;
  size_t n;
} sel_ident; /* quoted identifiers are stored unquoted */

typedef enum { PE_KEY, PE_INDEX, PE_OBJWILD, PE_ARRWILD } pe_kind;
typedef struct {
  pe_kind kind;
  bool lit_key; /* ['name'] rather than .name */
  sel_ident key;
  int64_t index;
} sel_pelem;

typedef struct {
  sel_ident base;
  sel_pelem *el;
  size_t n;
  /* StripTableAlias cache */
  const char *strip_alias;
  sel_pelem *stripped;
  size_t nstripped;
} sel_jpath;

typedef enum { LIT_FLOAT, LIT_INT, LIT_STR, LIT_BOOL, LIT_NULL, LIT_MISSING } lit_kind;
typedef struct {
  lit_kind kind;
  double num; /* LIT_FLOAT and LIT_INT (a float64, as MinIO keeps it) */
  const char *s;
  size_t sn;
  bool b;
} sel_lit;

typedef struct {
  sel_expr **el;
  size_t n;
} sel_list;

typedef enum {
  FN_SIMPLE,
  FN_COUNT,
  FN_CAST,
  FN_SUBSTRING,
  FN_EXTRACT,
  FN_TRIM,
  FN_DATE_ADD,
  FN_DATE_DIFF,
} fn_kind;

typedef struct {
  double sum;
  bool sum_set;
  sel_value running; /* MIN/MAX */
  int64_t count;
  bool seen;
} sel_agg;

typedef struct {
  fn_kind kind;
  char name[20]; /* upper case: AVG ... UPPER, COUNT, CAST, ... */
  /* FN_SIMPLE */
  sel_expr **args;
  size_t nargs;
  /* FN_COUNT */
  bool star;
  sel_expr *count_arg;
  /* FN_CAST */
  sel_expr *cast_expr;
  char cast_type[12];
  /* FN_SUBSTRING */
  sel_primary *sub_expr;
  sel_operand *from, *for_, *arg2, *arg3;
  /* FN_EXTRACT, FN_DATE_ADD, FN_DATE_DIFF */
  char timeword[20];
  sel_primary *ext_from;
  sel_operand *qty;
  sel_primary *ts1, *ts2;
  /* FN_TRIM */
  const char *trim_where; /* LEADING, TRAILING, BOTH (as written) or NULL */
  sel_primary *trim_chars, *trim_from;
  /* aggregation state */
  sel_agg *agg;
} sel_func;

typedef enum { PT_VALUE, PT_PATH, PT_LIST, PT_SUB, PT_FUNC } pt_kind;
struct sel_primary {
  pt_kind kind;
  sel_lit *lit;
  sel_jpath *path;
  sel_list *list;
  sel_expr *sub;
  sel_func *fn;
};

typedef struct {
  bool neg;
  sel_primary *p;
} sel_unary;

typedef struct {
  sel_unary *left;
  char *ops;
  sel_unary **right;
  size_t n;
} sel_multop;

struct sel_operand {
  sel_multop *left;
  char *ops;
  sel_multop **right;
  size_t n;
};

typedef enum { RHS_CMP, RHS_BETWEEN, RHS_IN, RHS_LIKE } rhs_kind;
typedef struct {
  rhs_kind kind;
  char op[8]; /* RHS_CMP: <> <= >= = < > != ISNOT IS */
  sel_operand *operand;
  bool not_;
  sel_operand *start, *end;      /* BETWEEN */
  sel_jpath *in_path;            /* IN */
  sel_list *in_list;
  sel_operand *pattern, *escape; /* LIKE */
} sel_rhs;

typedef struct {
  sel_operand *operand;
  sel_rhs *rhs;
} sel_condop;

typedef struct sel_cond sel_cond;
struct sel_cond {
  sel_condop *operand;
  sel_cond *not_;
};

typedef struct {
  sel_cond **conds;
  size_t n;
} sel_and;

struct sel_expr {
  sel_and **ands;
  size_t n;
};

typedef struct {
  sel_expr *expr;
  const char *as; /* NULL: none */
  size_t as_n;
} sel_aliased;

typedef struct {
  bool all;
  sel_aliased **exprs;
  size_t n;
  sel_jpath *table;
  const char *table_as;
  size_t table_as_n;
  sel_expr *where;
  sel_lit *limit;
} sel_select;

struct sel_stmt {
  sel_arena arena;
  sel_select *ast;
  bool aggregated;
  int64_t limit; /* -1: none */
  int64_t output_count;
  const char *table_alias; /* "" when none */
  size_t table_alias_n;
};

#endif
