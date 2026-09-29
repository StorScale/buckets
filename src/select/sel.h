/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SELECT_SEL_H
#define BUCKETS_SELECT_SEL_H

/* S3 Select internals (MinIO's internal/s3select): values, JSON, records,
 * the SQL syntax tree, and the readers. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* ---- arena: records and their values live until the next record ---- */

typedef struct sel_chunk sel_chunk;
typedef struct {
  sel_chunk *head;
} sel_arena;

void *sel_alloc(sel_arena *a, size_t n); /* zeroed, 16-byte aligned */
char *sel_strndup(sel_arena *a, const char *s, size_t n);
void sel_arena_reset(sel_arena *a); /* frees all but the first chunk */
void sel_arena_free(sel_arena *a);

/* ---- errors: an S3 error code and message (code NULL: none) ---- */

typedef struct {
  const char *code;
  char msg[512];
  int status; /* 400 unless set */
} sel_err;

bool sel_fail(sel_err *e, const char *code, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* ---- time: an instant and the zone it was written in ---- */

typedef struct {
  int64_t sec; /* Unix seconds */
  int32_t nsec;
  int32_t off; /* the zone's offset east of UTC, in seconds */
} sel_time;

/* Go's time.Parse with S3 Select's layouts (2006T ... 2006-01-02T15:04:05.999999999Z07:00). */
bool sel_time_parse(const char *s, size_t n, sel_time *t);
/* FormatSQLTimestamp: the shortest of those layouts that keeps the value. */
void sel_time_format(buckets_buf *out, sel_time t);
/* The civil fields in the time's own zone. */
typedef struct {
  int64_t year;
  int month, day, hour, min, sec;
} sel_civil;
void sel_time_civil(sel_time t, sel_civil *c);
/* time.Date(...) normalizing overflowing fields, in the zone off. */
sel_time sel_time_from_civil(int64_t year, int64_t month, int64_t day, int64_t hour, int64_t min, int64_t sec, int32_t nsec,
                             int32_t off);
int sel_time_cmp(sel_time a, sel_time b);

/* ---- JSON values (jstream's KVS model: objects keep their key order) ---- */

typedef enum { JV_NULL, JV_BOOL, JV_FLOAT, JV_INT, JV_STR, JV_ARR, JV_OBJ } jv_type;
typedef struct jv jv;
typedef struct jv_kv jv_kv;
struct jv {
  jv_type t;
  union {
    bool b;
    double f;
    int64_t i;
    struct {
      const char *p;
      size_t n;
    } s;
    struct {
      jv *v;
      size_t n;
    } a;
    struct {
      jv_kv *kv;
      size_t n;
    } o;
  };
};
struct jv_kv {
  const char *k;
  size_t kn;
  jv v;
};

/* Go's encoding/json for a value (strings HTML-escaped, floats as ES6). */
void jv_marshal(buckets_buf *out, const jv *v);

/* Streaming reader of a sequence of JSON values (jstream with MaxDepth 100). */
typedef long (*sel_read_fn)(void *ud, void *buf, size_t n);
typedef struct jv_reader jv_reader;
jv_reader *jv_reader_new(sel_read_fn rd, void *ud, int64_t limit /* -1: none */);
void jv_reader_free(jv_reader *r);
/* 1: a value, 0: the end, -1: an error (e set). */
int jv_reader_next(jv_reader *r, sel_arena *a, jv *out, sel_err *e);
/* jstream's own message for the last error ("invalid character ...: 'x' [line,col]"). */
const char *jv_reader_detail(const jv_reader *r);

/* ---- SQL values ---- */

typedef enum { SV_NULL, SV_MISSING, SV_BOOL, SV_INT, SV_FLOAT, SV_STR, SV_BYTES, SV_TIME, SV_ARR } sv_type;
typedef struct sel_value sel_value;
struct sel_value {
  sv_type t;
  union {
    bool b;
    int64_t i;
    double f;
    struct {
      const char *p;
      size_t n;
    } s; /* SV_STR, SV_BYTES */
    sel_time ts;
    struct {
      sel_value *v;
      size_t n;
    } a;
  };
};

static inline sel_value sv_null(void) { return (sel_value){.t = SV_NULL}; }
static inline sel_value sv_missing(void) { return (sel_value){.t = SV_MISSING}; }
static inline sel_value sv_bool(bool b) { return (sel_value){.t = SV_BOOL, .b = b}; }
static inline sel_value sv_int(int64_t i) { return (sel_value){.t = SV_INT, .i = i}; }
static inline sel_value sv_float(double f) { return (sel_value){.t = SV_FLOAT, .f = f}; }
static inline sel_value sv_str(const char *p, size_t n) { return (sel_value){.t = SV_STR, .s = {p, n}}; }
static inline sel_value sv_bytes(const char *p, size_t n) { return (sel_value){.t = SV_BYTES, .s = {p, n}}; }
static inline sel_value sv_time(sel_time t) { return (sel_value){.t = SV_TIME, .ts = t}; }

const char *sv_type_name(const sel_value *v);
bool sv_is_numeric(const sel_value *v);
bool sv_to_float(const sel_value *v, double *f);
/* Go strconv on untyped bytes (trimmed): ParseInt, ParseFloat, the
 * bool words t/true/1 f/false/0. */
bool sv_bytes_to_int(const sel_value *v, int64_t *i);
bool sv_bytes_to_float(const sel_value *v, double *f);
bool sv_bytes_to_bool(const sel_value *v, bool *b);
/* The inference and operations of MinIO's sql.Value, in place. */
bool sv_infer_arith(sel_value *v, sel_err *e);
bool sv_infer_cmp(sel_value *a, sel_value *b, sel_err *e);
void sv_infer_string(sel_value *v);
bool sv_infer_timestamp(sel_value *v, sel_err *e);
bool sv_arith(sel_value *v, char op, sel_value *a, sel_err *e);
/* op: < <= > >= = != IS ISNOT */
bool sv_compare(sel_value *v, const char *op, sel_value *a, bool *res, sel_err *e);
bool sv_equals(const sel_value *a, const sel_value *b); /* same type and value */
bool sv_minmax(sel_value *v, sel_value *a, bool is_max, bool first, sel_err *e);
/* Value.CSVString */
void sv_csv_string(buckets_buf *out, const sel_value *v);
/* Value.MarshalJSON */
void sv_marshal_json(buckets_buf *out, const sel_value *v);
/* A JSON value as a SQL value (objects become their JSON bytes). */
sel_value sv_from_jv(sel_arena *a, const jv *v);

/* Go number formatting and parsing */
void sel_fmt_float_g(buckets_buf *out, double f);    /* strconv 'g', -1 (and %v) */
void sel_fmt_float_json(buckets_buf *out, double f); /* encoding/json */
bool sel_parse_int(const char *s, size_t n, int64_t *out);   /* strconv.ParseInt(s, 10, 64) */
bool sel_parse_float(const char *s, size_t n, double *out);  /* strconv.ParseFloat(s, 64) */
bool sel_utf8_valid(const char *s, size_t n);
size_t sel_utf8_count(const char *s, size_t n);

/* ---- records ---- */

typedef enum { SEL_FMT_CSV = 1, SEL_FMT_JSON, SEL_FMT_PARQUET } sel_fmt;

/* CSV column names shared by a reader's records. */
typedef struct sel_csv_names sel_csv_names;
bool sel_csv_names_find(const sel_csv_names *n, const char *name, size_t len, size_t *idx);

typedef struct {
  sel_fmt fmt;
  /* CSV */
  const sel_csv_names *names;
  const char **fields;
  size_t *flen;
  size_t nf;
  /* JSON and Parquet: an object */
  jv obj;
} sel_record;

/* An output column's value (json.Record's KV values, or csv.Record's strings). */
typedef enum { OV_NULL, OV_BOOL, OV_INT, OV_FLOAT, OV_STR, OV_RAW, OV_JV, OV_VARR } ov_type;
typedef struct {
  ov_type t;
  union {
    bool b;
    int64_t i;
    double f;
    struct {
      const char *p;
      size_t n;
    } s; /* OV_STR, OV_RAW */
    const jv *j;
    sel_value arr; /* OV_VARR: an SV_ARR */
  };
} sel_oval;

typedef struct {
  const char *name;
  size_t nlen;
  sel_oval v;
} sel_okv;

/* csv.Record (every value a string) or json.Record (KVS). */
typedef struct {
  bool csv;
  sel_okv *kv;
  size_t n, cap;
} sel_orec;

void sel_orec_add(sel_orec *r, sel_arena *a, const char *name, size_t nlen, sel_oval v);
/* Record.Set for the output format (csv: CSVString; json: the typed value;
 * a MISSING value is left out of JSON). */
bool sel_orec_set(sel_orec *r, sel_arena *a, const char *name, size_t nlen, const sel_value *v, sel_err *e);
/* Record.Clone of an input record (SELECT *). */
void sel_orec_clone(sel_orec *r, sel_arena *a, const sel_record *in);

typedef struct {
  uint32_t field_delim, quote, quote_escape; /* code points */
  bool always_quote;
} sel_csv_wopts;
void sel_orec_write_csv(buckets_buf *out, const sel_orec *r, const sel_csv_wopts *o);
void sel_orec_write_json(buckets_buf *out, const sel_orec *r);

/* ---- SQL ---- */

typedef struct sel_stmt sel_stmt;
/* ParseSelectStatement: syntax, then analysis. */
sel_stmt *sel_parse(const char *sql, size_t n, sel_err *e);
void sel_stmt_free(sel_stmt *s);
bool sel_stmt_aggregated(const sel_stmt *s);
bool sel_stmt_limit_reached(const sel_stmt *s);
/* EvalFrom: the records a FROM key path makes of one input record. */
bool sel_eval_from(sel_stmt *s, sel_arena *a, const sel_record *in, sel_record **out, size_t *n, sel_err *e);
/* Eval: false on error; *emit when the row passes WHERE (out filled). */
bool sel_eval(sel_stmt *s, sel_arena *a, const sel_record *in, sel_orec *out, bool *emit, sel_err *e);
bool sel_aggregate_row(sel_stmt *s, sel_arena *a, const sel_record *in, sel_err *e);
bool sel_aggregate_result(sel_stmt *s, sel_arena *a, sel_orec *out, sel_err *e);

#endif
