/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Parquet input for S3 Select, as MinIO reads it (internal/s3select/parquet
 * over fraugster/parquet-go): each row is its leaf columns in schema order,
 * keyed by their dotted names. Only top-level columns have values (nested
 * ones are null, since the row map is looked up by the dotted name);
 * repeated top-level primitives are arrays. Values are converted by their
 * annotations: DATE and UTC TIMESTAMP as S3 Select timestamps, byte arrays
 * (and INT96) as strings. */
#include "select/parquet.h"

#include <lz4.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

#include "compress/s2.h"
#include "core/common.h"

#define MAX_META (64 << 20)
#define MAX_CHUNK ((int64_t)1 << 31)

static bool perr(sel_err *e) {
  return sel_fail(e, "ParquetParsingError", "Error parsing Parquet file. Please check the file and try again.");
}

/* ---- Thrift compact protocol ---- */

typedef struct {
  const uint8_t *p, *end;
  bool bad;
} tr;

enum { T_STOP = 0, T_TRUE = 1, T_FALSE = 2, T_BYTE = 3, T_I16 = 4, T_I32 = 5, T_I64 = 6, T_DOUBLE = 7, T_BIN = 8, T_LIST = 9, T_SET = 10, T_MAP = 11, T_STRUCT = 12 };

static uint64_t t_varint(tr *t) {
  uint64_t v = 0;
  for (int s = 0; s < 64; s += 7) {
    if (t->p >= t->end) return t->bad = true, 0;
    uint8_t b = *t->p++;
    v |= (uint64_t)(b & 0x7f) << s;
    if (!(b & 0x80)) return v;
  }
  t->bad = true;
  return 0;
}
static int64_t t_zz(tr *t) {
  uint64_t v = t_varint(t);
  return (int64_t)(v >> 1) ^ -(int64_t)(v & 1);
}
static void t_bin(tr *t, const uint8_t **p, size_t *n) {
  uint64_t len = t_varint(t);
  if (t->bad || len > (uint64_t)(t->end - t->p)) {
    t->bad = true;
    *p = NULL, *n = 0;
    return;
  }
  *p = t->p;
  *n = (size_t)len;
  t->p += len;
}

static void t_skip(tr *t, int type, int depth);

/* The next field of a struct: its id and type (T_STOP at the end). */
static int t_field(tr *t, int *id) {
  if (t->p >= t->end) return t->bad = true, T_STOP;
  uint8_t b = *t->p++;
  int type = b & 0x0f;
  if (type == T_STOP) return T_STOP;
  int delta = b >> 4;
  *id = delta ? *id + delta : (int)t_zz(t);
  return type;
}

static void t_list(tr *t, int *etype, size_t *n) {
  if (t->p >= t->end) {
    t->bad = true;
    *n = 0;
    return;
  }
  uint8_t b = *t->p++;
  *etype = b & 0x0f;
  size_t k = b >> 4;
  if (k == 15) k = (size_t)t_varint(t);
  if (k > (size_t)(t->end - t->p)) { /* every element takes a byte at least */
    t->bad = true;
    k = 0;
  }
  *n = k;
}

static void t_skip(tr *t, int type, int depth) {
  if (depth > 32) {
    t->bad = true;
    return;
  }
  switch (type) {
  case T_TRUE:
  case T_FALSE: break; /* in a field header */
  case T_BYTE:
    if (t->p < t->end) t->p++;
    else t->bad = true;
    break;
  case T_I16:
  case T_I32:
  case T_I64: t_varint(t); break;
  case T_DOUBLE:
    if (t->end - t->p < 8) t->bad = true;
    else t->p += 8;
    break;
  case T_BIN: {
    const uint8_t *p;
    size_t n;
    t_bin(t, &p, &n);
    break;
  }
  case T_LIST:
  case T_SET: {
    int et;
    size_t n;
    t_list(t, &et, &n);
    for (size_t i = 0; i < n && !t->bad; i++) {
      if (et == T_TRUE || et == T_FALSE) {
        if (t->p < t->end) t->p++; /* booleans in lists take a byte */
      } else {
        t_skip(t, et, depth + 1);
      }
    }
    break;
  }
  case T_MAP: {
    uint64_t n = t_varint(t);
    if (!n) break;
    if (t->p >= t->end) {
      t->bad = true;
      break;
    }
    uint8_t kv = *t->p++;
    for (uint64_t i = 0; i < n && !t->bad; i++) {
      t_skip(t, kv >> 4, depth + 1);
      t_skip(t, kv & 0x0f, depth + 1);
    }
    break;
  }
  case T_STRUCT: {
    int id = 0;
    for (int ft; !t->bad && (ft = t_field(t, &id)) != T_STOP;) t_skip(t, ft, depth + 1);
    break;
  }
  default: t->bad = true;
  }
}

/* ---- metadata ---- */

enum { PT_BOOLEAN, PT_INT32, PT_INT64, PT_INT96, PT_FLOAT, PT_DOUBLE, PT_BYTE_ARRAY, PT_FIXED };
enum { REP_REQUIRED, REP_OPTIONAL, REP_REPEATED };
enum { CT_DATE = 6, CT_TS_MILLIS = 9, CT_TS_MICROS = 10 };

typedef struct {
  int type; /* -1: a group */
  int type_length;
  int rep;
  char *name;
  int nchildren;
  int converted; /* -1: none */
  bool has_logical, logical_date, logical_ts, ts_utc;
  int ts_unit; /* 1 millis, 2 micros, 3 nanos */
} schema_el;

typedef struct {
  int type, codec;
  int64_t num_values, data_off, dict_off, size;
} chunk_meta;

typedef struct {
  int64_t rows;
  chunk_meta *cols;
  size_t ncols;
} row_group;

/* A leaf column: its schema element, levels and dotted name. */
typedef struct {
  const schema_el *el;
  char *flat;
  size_t flat_n;
  int max_def, max_rep;
  bool top; /* a top-level column: the only ones with values */
  /* the decoded chunk of the current row group */
  int16_t *def, *repl;
  jv *vals;
  size_t nlevels, nvals, li, vi;
} leaf;

struct sel_parquet {
  const buckets_select_source *src;
  schema_el *schema;
  size_t nschema;
  leaf *leaves;
  size_t nleaves;
  row_group *groups;
  size_t ngroups, gi;
  int64_t row_in_group;
  sel_arena group_arena; /* the current row group's values */
  buckets_buf dict_scratch;
};

static void parse_logical(tr *t, schema_el *s) {
  int id = 0;
  s->has_logical = true;
  for (int ft; !t->bad && (ft = t_field(t, &id)) != T_STOP;) {
    if (id == 6 && ft == T_STRUCT) {
      s->logical_date = true;
      t_skip(t, ft, 0);
    } else if (id == 8 && ft == T_STRUCT) {
      s->logical_ts = true;
      int fid = 0;
      for (int f2; !t->bad && (f2 = t_field(t, &fid)) != T_STOP;) {
        if (fid == 1 && (f2 == T_TRUE || f2 == T_FALSE)) s->ts_utc = f2 == T_TRUE;
        else if (fid == 2 && f2 == T_STRUCT) {
          int uid = 0;
          for (int f3; !t->bad && (f3 = t_field(t, &uid)) != T_STOP;) {
            s->ts_unit = uid;
            t_skip(t, f3, 0);
          }
        } else t_skip(t, f2, 0);
      }
    } else {
      t_skip(t, ft, 0);
    }
  }
}

static void parse_schema_el(tr *t, schema_el *s) {
  memset(s, 0, sizeof(*s));
  s->type = -1;
  s->converted = -1;
  int id = 0;
  for (int ft; !t->bad && (ft = t_field(t, &id)) != T_STOP;) {
    switch (id) {
    case 1: s->type = (int)t_zz(t); break;
    case 2: s->type_length = (int)t_zz(t); break;
    case 3: s->rep = (int)t_zz(t); break;
    case 4: {
      const uint8_t *p;
      size_t n;
      t_bin(t, &p, &n);
      free(s->name); /* a repeated field: the last one wins */
      s->name = buckets_xmalloc(n + 1);
      if (n) memcpy(s->name, p, n);
      s->name[n] = 0;
      break;
    }
    case 5: s->nchildren = (int)t_zz(t); break;
    case 6: s->converted = (int)t_zz(t); break;
    case 10:
      if (ft == T_STRUCT) parse_logical(t, s);
      else t_skip(t, ft, 0);
      break;
    default: t_skip(t, ft, 0);
    }
  }
  if (!s->name) s->name = buckets_xstrdup("");
}

static void parse_column_meta(tr *t, chunk_meta *c) {
  int id = 0;
  for (int ft; !t->bad && (ft = t_field(t, &id)) != T_STOP;) {
    switch (id) {
    case 1: c->type = (int)t_zz(t); break;
    case 4: c->codec = (int)t_zz(t); break;
    case 5: c->num_values = t_zz(t); break;
    case 7: c->size = t_zz(t); break;
    case 9: c->data_off = t_zz(t); break;
    case 11: c->dict_off = t_zz(t); break;
    default: t_skip(t, ft, 0);
    }
  }
}

static void parse_row_group(tr *t, row_group *g) {
  int id = 0;
  for (int ft; !t->bad && (ft = t_field(t, &id)) != T_STOP;) {
    if (id == 1 && ft == T_LIST) {
      int et;
      size_t n;
      t_list(t, &et, &n);
      if (n > 100000 || g->cols) { /* a repeated field too */
        t->bad = true;
        return;
      }
      g->cols = buckets_xcalloc(n ? n : 1, sizeof(chunk_meta));
      g->ncols = n;
      for (size_t i = 0; i < n && !t->bad; i++) {
        int cid = 0;
        for (int f2; !t->bad && (f2 = t_field(t, &cid)) != T_STOP;) {
          if (cid == 3 && f2 == T_STRUCT) parse_column_meta(t, &g->cols[i]);
          else t_skip(t, f2, 0);
        }
      }
    } else if (id == 3) {
      g->rows = t_zz(t);
    } else {
      t_skip(t, ft, 0);
    }
  }
}

static bool parse_meta(sel_parquet *q, const uint8_t *m, size_t n) {
  tr t = {m, m + n, false};
  int id = 0;
  for (int ft; !t.bad && (ft = t_field(&t, &id)) != T_STOP;) {
    if (id == 2 && ft == T_LIST) {
      int et;
      size_t k;
      t_list(&t, &et, &k);
      if (k > 100000 || q->schema) return false;
      q->schema = buckets_xcalloc(k ? k : 1, sizeof(schema_el));
      q->nschema = k;
      for (size_t i = 0; i < k && !t.bad; i++) parse_schema_el(&t, &q->schema[i]);
    } else if (id == 4 && ft == T_LIST) {
      int et;
      size_t k;
      t_list(&t, &et, &k);
      if (k > 1000000 || q->groups) return false;
      q->groups = buckets_xcalloc(k ? k : 1, sizeof(row_group));
      q->ngroups = k;
      for (size_t i = 0; i < k && !t.bad; i++) parse_row_group(&t, &q->groups[i]);
    } else {
      t_skip(&t, ft, 0);
    }
  }
  return !t.bad && q->nschema > 0;
}

/* The leaves under schema[*i], depth-first. */
static bool walk_schema(sel_parquet *q, size_t *i, const char *prefix, int def, int rep, int depth, size_t *nleaf) {
  if (*i >= q->nschema || depth > 64) return false;
  schema_el *s = &q->schema[*i];
  (*i)++;
  if (depth > 0) {
    if (s->rep == REP_OPTIONAL) def++;
    if (s->rep == REP_REPEATED) def++, rep++;
  }
  char *name = NULL;
  if (depth > 0) {
    size_t pl = strlen(prefix), nl = strlen(s->name);
    name = buckets_xmalloc(pl + nl + 2);
    if (pl) {
      memcpy(name, prefix, pl);
      name[pl] = '.';
      memcpy(name + pl + 1, s->name, nl + 1);
    } else {
      memcpy(name, s->name, nl + 1);
    }
  }
  if (depth > 0 && s->nchildren == 0) {
    q->leaves = buckets_xrealloc(q->leaves, (*nleaf + 1) * sizeof(leaf));
    leaf *l = &q->leaves[(*nleaf)++];
    memset(l, 0, sizeof(*l));
    l->el = s;
    l->flat = name;
    l->flat_n = strlen(name);
    l->max_def = def;
    l->max_rep = rep;
    l->top = depth == 1;
    return s->type >= 0;
  }
  for (int c = 0; c < s->nchildren; c++) {
    if (!walk_schema(q, i, name ? name : "", def, rep, depth + 1, nleaf)) {
      free(name);
      return false;
    }
  }
  free(name);
  return true;
}

void sel_parquet_free(sel_parquet *q) {
  if (!q) return;
  for (size_t i = 0; i < q->nschema; i++) free(q->schema[i].name);
  free(q->schema);
  for (size_t i = 0; i < q->nleaves; i++) free(q->leaves[i].flat);
  free(q->leaves);
  for (size_t i = 0; i < q->ngroups; i++) free(q->groups[i].cols);
  free(q->groups);
  sel_arena_free(&q->group_arena);
  buckets_buf_free(&q->dict_scratch);
  free(q);
}

sel_parquet *sel_parquet_open(const buckets_select_source *src, sel_err *e) {
  uint8_t tail[8];
  if (src->size < 12 || !src->read_at(src->ud, src->size - 8, tail, 8) || memcmp(tail + 4, "PAR1", 4)) {
    perr(e);
    return NULL;
  }
  uint32_t mlen = (uint32_t)tail[0] | (uint32_t)tail[1] << 8 | (uint32_t)tail[2] << 16 | (uint32_t)tail[3] << 24;
  if (mlen > MAX_META || (int64_t)mlen > src->size - 12) {
    perr(e);
    return NULL;
  }
  uint8_t *m = buckets_xmalloc(mlen ? mlen : 1);
  if (!src->read_at(src->ud, src->size - 8 - mlen, m, mlen)) {
    free(m);
    perr(e);
    return NULL;
  }
  sel_parquet *q = buckets_xcalloc(1, sizeof(*q));
  q->src = src;
  bool ok = parse_meta(q, m, mlen);
  free(m);
  size_t i = 0;
  if (ok) ok = walk_schema(q, &i, "", 0, 0, 0, &q->nleaves);
  for (size_t g = 0; ok && g < q->ngroups; g++) ok = q->groups[g].ncols == q->nleaves;
  if (!ok) {
    sel_parquet_free(q);
    perr(e);
    return NULL;
  }
  q->gi = (size_t)-1;
  return q;
}

/* ---- pages ---- */

typedef struct {
  const uint8_t *p, *end;
} rd;

static bool rd_take(rd *r, size_t n, const uint8_t **out) {
  if ((size_t)(r->end - r->p) < n) return false;
  *out = r->p;
  r->p += n;
  return true;
}

static uint64_t uvarint(rd *r, bool *ok) {
  uint64_t v = 0;
  for (int s = 0; s < 64; s += 7) {
    if (r->p >= r->end) return *ok = false, 0;
    uint8_t b = *r->p++;
    v |= (uint64_t)(b & 0x7f) << s;
    if (!(b & 0x80)) return v;
  }
  *ok = false;
  return 0;
}

/* The RLE / bit-packed hybrid: n values of bit width w into out. */
static bool hybrid(rd *r, int w, size_t n, uint32_t *out) {
  if (w < 0 || w > 32) return false;
  size_t k = 0;
  bool ok = true;
  while (k < n) {
    uint64_t h = uvarint(r, &ok);
    if (!ok) return false;
    if (h & 1) {
      size_t groups = (size_t)(h >> 1), count = groups * 8;
      size_t bytes = groups * (size_t)w;
      const uint8_t *p;
      if (!rd_take(r, bytes, &p)) return false;
      uint64_t acc = 0;
      int bits = 0;
      size_t bi = 0;
      for (size_t j = 0; j < count; j++) {
        while (bits < w) {
          acc |= (uint64_t)p[bi++] << bits;
          bits += 8;
        }
        uint32_t v = w ? (uint32_t)(acc & ((w == 32) ? 0xffffffffu : ((1u << w) - 1))) : 0;
        acc >>= w;
        bits -= w;
        if (k < n) out[k++] = v;
      }
    } else {
      size_t count = (size_t)(h >> 1);
      int nb = (w + 7) / 8;
      const uint8_t *p;
      if (!rd_take(r, (size_t)nb, &p)) return false;
      uint32_t v = 0;
      for (int b = 0; b < nb; b++) v |= (uint32_t)p[b] << (8 * b);
      for (size_t j = 0; j < count && k < n; j++) out[k++] = v;
      if (count == 0) return false;
    }
  }
  return true;
}

static int bit_width(int max) {
  int w = 0;
  while ((1 << w) <= max) w++;
  return max ? w : 0;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

/* w bits (at most 64) at bit position pos, least significant first. */
static uint64_t bits_at(const uint8_t *p, size_t nbytes, size_t pos, int w) {
  uint64_t v = 0;
  for (int i = 0; i < w;) {
    size_t byte = (pos + (size_t)i) / 8;
    int off = (int)((pos + (size_t)i) % 8);
    if (byte >= nbytes) break;
    int take = 8 - off < w - i ? 8 - off : w - i;
    v |= (uint64_t)((p[byte] >> off) & ((1u << take) - 1)) << i;
    i += take;
  }
  return v;
}

/* DELTA_BINARY_PACKED: n values (int64) into out. */
static bool delta_bp(rd *r, size_t n, int64_t *out, size_t *got) {
  bool ok = true;
  uint64_t block = uvarint(r, &ok), minis = uvarint(r, &ok), total = uvarint(r, &ok);
  uint64_t z = uvarint(r, &ok);
  if (!ok || !minis || block % minis || block > 1 << 20 || (block / minis) % 32) return false;
  int64_t v = (int64_t)(z >> 1) ^ -(int64_t)(z & 1);
  size_t k = 0;
  if (total > 0 && k < n) out[k++] = v;
  size_t per = (size_t)(block / minis);
  while (k < total && k < n) {
    uint64_t mz = uvarint(r, &ok);
    if (!ok) return false;
    int64_t min_delta = (int64_t)(mz >> 1) ^ -(int64_t)(mz & 1);
    const uint8_t *widths;
    if (!rd_take(r, (size_t)minis, &widths)) return false;
    for (uint64_t m = 0; m < minis && k < total; m++) {
      int w = widths[m];
      if (w > 64) return false;
      const uint8_t *p;
      size_t bytes = per * (size_t)w / 8;
      if (!rd_take(r, bytes, &p)) {
        /* the last miniblock may be cut short */
        p = r->p;
        bytes = (size_t)(r->end - r->p);
        r->p = r->end;
      }
      for (size_t j = 0; j < per && k < total; j++) {
        uint64_t d = bits_at(p, bytes, j * (size_t)w, w);
        v = (int64_t)((uint64_t)v + (uint64_t)min_delta + d);
        if (k < n) out[k++] = v;
      }
    }
  }
  *got = k;
  return true;
}

/* ---- values ---- */

static void time_value(sel_parquet *q, jv *out, int64_t sec, int32_t nsec) {
  buckets_buf b = BUCKETS_BUF_INIT;
  sel_time_format(&b, (sel_time){sec, nsec, 0});
  out->t = JV_STR;
  out->s.n = b.len;
  out->s.p = sel_strndup(&q->group_arena, b.data, b.len);
  buckets_buf_free(&b);
}

static int64_t fdiv(int64_t a, int64_t b) { return a / b - (a % b != 0 && (a < 0) != (b < 0)); }

/* convertFromAnnotation */
static void convert_int32(sel_parquet *q, const schema_el *s, int32_t v, jv *out) {
  bool date = s->has_logical ? s->logical_date : s->converted == CT_DATE;
  if (date) time_value(q, out, (int64_t)v * 86400, 0);
  else *out = (jv){.t = JV_INT, .i = v};
}

static void convert_int64(sel_parquet *q, const schema_el *s, int64_t v, jv *out) {
  *out = (jv){.t = JV_INT, .i = v};
  if (!s->has_logical) return; /* MinIO converts only under a logical type */
  if (s->logical_ts) {
    if (!s->ts_utc) return;
    int64_t unit = s->ts_unit == 1 ? 1000 : s->ts_unit == 2 ? 1000000 : s->ts_unit == 3 ? 1000000000 : 0;
    if (!unit) return;
    int64_t sec = fdiv(v, unit), frac = v - sec * unit;
    time_value(q, out, sec, (int32_t)(frac * (1000000000 / unit)));
  } else if (s->converted == CT_TS_MILLIS || s->converted == CT_TS_MICROS) {
    int64_t unit = s->converted == CT_TS_MILLIS ? 1000 : 1000000;
    int64_t sec = fdiv(v, unit), frac = v - sec * unit;
    time_value(q, out, sec, (int32_t)(frac * (1000000000 / unit)));
  }
}

static void bytes_value(sel_parquet *q, const uint8_t *p, size_t n, jv *out) {
  out->t = JV_STR;
  out->s.n = n;
  out->s.p = sel_strndup(&q->group_arena, (const char *)p, n);
}

/* PLAIN values into out (n of them). */
static bool plain(sel_parquet *q, const schema_el *s, rd *r, size_t n, jv *out) {
  const uint8_t *p;
  switch (s->type) {
  case PT_BOOLEAN:
    if (!rd_take(r, (n + 7) / 8, &p)) return false;
    for (size_t i = 0; i < n; i++) out[i] = (jv){.t = JV_BOOL, .b = (p[i / 8] >> (i % 8)) & 1};
    return true;
  case PT_INT32:
    for (size_t i = 0; i < n; i++) {
      if (!rd_take(r, 4, &p)) return false;
      convert_int32(q, s, (int32_t)le32(p), &out[i]);
    }
    return true;
  case PT_INT64:
    for (size_t i = 0; i < n; i++) {
      if (!rd_take(r, 8, &p)) return false;
      convert_int64(q, s, (int64_t)le64(p), &out[i]);
    }
    return true;
  case PT_INT96:
    for (size_t i = 0; i < n; i++) {
      if (!rd_take(r, 12, &p)) return false;
      bytes_value(q, p, 12, &out[i]);
    }
    return true;
  case PT_FLOAT:
    for (size_t i = 0; i < n; i++) {
      if (!rd_take(r, 4, &p)) return false;
      uint32_t u = le32(p);
      float f;
      memcpy(&f, &u, 4);
      out[i] = (jv){.t = JV_FLOAT, .f = f};
    }
    return true;
  case PT_DOUBLE:
    for (size_t i = 0; i < n; i++) {
      if (!rd_take(r, 8, &p)) return false;
      uint64_t u = le64(p);
      double d;
      memcpy(&d, &u, 8);
      out[i] = (jv){.t = JV_FLOAT, .f = d};
    }
    return true;
  case PT_BYTE_ARRAY:
    for (size_t i = 0; i < n; i++) {
      const uint8_t *lp;
      if (!rd_take(r, 4, &lp)) return false;
      uint32_t len = le32(lp);
      if (!rd_take(r, len, &p)) return false;
      bytes_value(q, p, len, &out[i]);
    }
    return true;
  case PT_FIXED:
    if (s->type_length < 0) return false;
    for (size_t i = 0; i < n; i++) {
      if (!rd_take(r, (size_t)s->type_length, &p)) return false;
      bytes_value(q, p, (size_t)s->type_length, &out[i]);
    }
    return true;
  }
  return false;
}

/* The values of a page in the given encoding. */
static bool decode_values(sel_parquet *q, const schema_el *s, int enc, rd *r, size_t n, jv *out, const jv *dict,
                          size_t ndict) {
  switch (enc) {
  case 0: return plain(q, s, r, n, out); /* PLAIN */
  case 2:                                /* PLAIN_DICTIONARY */
  case 8: {                              /* RLE_DICTIONARY */
    const uint8_t *w;
    if (!dict || !rd_take(r, 1, &w)) return false;
    uint32_t *idx = buckets_xmalloc((n ? n : 1) * sizeof(uint32_t));
    bool ok = hybrid(r, w[0], n, idx);
    for (size_t i = 0; ok && i < n; i++) {
      if (idx[i] >= ndict) ok = false;
      else out[i] = dict[idx[i]];
    }
    free(idx);
    return ok;
  }
  case 3: { /* RLE (booleans), with a length prefix */
    if (s->type != PT_BOOLEAN) return false;
    const uint8_t *lp;
    if (!rd_take(r, 4, &lp)) return false;
    uint32_t len = le32(lp);
    if (len > (size_t)(r->end - r->p)) return false;
    rd sub = {r->p, r->p + len};
    uint32_t *v = buckets_xmalloc((n ? n : 1) * sizeof(uint32_t));
    bool ok = hybrid(&sub, 1, n, v);
    for (size_t i = 0; ok && i < n; i++) out[i] = (jv){.t = JV_BOOL, .b = v[i] != 0};
    free(v);
    r->p += len;
    return ok;
  }
  case 5: { /* DELTA_BINARY_PACKED */
    if (s->type != PT_INT32 && s->type != PT_INT64) return false;
    int64_t *v = buckets_xmalloc((n ? n : 1) * sizeof(int64_t));
    size_t got = 0;
    bool ok = delta_bp(r, n, v, &got) && got == n;
    for (size_t i = 0; ok && i < n; i++) {
      if (s->type == PT_INT32) convert_int32(q, s, (int32_t)v[i], &out[i]);
      else convert_int64(q, s, v[i], &out[i]);
    }
    free(v);
    return ok;
  }
  case 6:   /* DELTA_LENGTH_BYTE_ARRAY */
  case 7: { /* DELTA_BYTE_ARRAY */
    if (s->type != PT_BYTE_ARRAY && s->type != PT_FIXED) return false;
    int64_t *pre = NULL, *len = buckets_xmalloc((n ? n : 1) * sizeof(int64_t));
    size_t got = 0;
    bool ok = true;
    if (enc == 7) {
      pre = buckets_xmalloc((n ? n : 1) * sizeof(int64_t));
      ok = delta_bp(r, n, pre, &got) && got == n;
    }
    ok = ok && delta_bp(r, n, len, &got) && got == n;
    buckets_buf prev = BUCKETS_BUF_INIT, cur = BUCKETS_BUF_INIT;
    for (size_t i = 0; ok && i < n; i++) {
      const uint8_t *p;
      if (len[i] < 0 || !rd_take(r, (size_t)len[i], &p)) {
        ok = false;
        break;
      }
      buckets_buf_reset(&cur);
      if (pre) {
        if (pre[i] < 0 || (size_t)pre[i] > prev.len) {
          ok = false;
          break;
        }
        buckets_buf_append(&cur, prev.data, (size_t)pre[i]);
      }
      buckets_buf_append(&cur, p, (size_t)len[i]);
      bytes_value(q, (const uint8_t *)(cur.data ? cur.data : ""), cur.len, &out[i]);
      buckets_buf_reset(&prev);
      buckets_buf_append(&prev, cur.data, cur.len);
    }
    buckets_buf_free(&prev);
    buckets_buf_free(&cur);
    free(pre);
    free(len);
    return ok;
  }
  case 9: { /* BYTE_STREAM_SPLIT */
    int w = s->type == PT_FLOAT || s->type == PT_INT32 ? 4 : s->type == PT_DOUBLE || s->type == PT_INT64 ? 8 : 0;
    if (!w) return false;
    const uint8_t *p;
    if (!rd_take(r, n * (size_t)w, &p)) return false;
    for (size_t i = 0; i < n; i++) {
      uint8_t b[8];
      for (int k = 0; k < w; k++) b[k] = p[(size_t)k * n + i];
      rd one = {b, b + w};
      if (!plain(q, s, &one, 1, &out[i])) return false;
    }
    return true;
  }
  }
  return false;
}

/* Page payloads by codec. */
static bool decompress(int codec, const uint8_t *in, size_t n, size_t want, uint8_t **out) {
  *out = buckets_xmalloc(want ? want : 1);
  switch (codec) {
  case 0:
    if (n != want) return false;
    memcpy(*out, in, n);
    return true;
  case 1: /* SNAPPY: an S2 block reader decodes Snappy blocks */
    return buckets_s2_decode(*out, want, in, n) == (long)want;
  case 2: { /* GZIP */
    z_stream z;
    memset(&z, 0, sizeof(z));
    if (inflateInit2(&z, 32 + MAX_WBITS) != Z_OK) return false;
    z.next_in = (Bytef *)in;
    z.avail_in = (uInt)n;
    z.next_out = *out;
    z.avail_out = (uInt)want;
    int rc = inflate(&z, Z_FINISH);
    bool ok = (rc == Z_STREAM_END || rc == Z_OK) && z.total_out == want;
    inflateEnd(&z);
    return ok;
  }
  case 5: { /* LZ4: Hadoop's framing, else a raw block */
    size_t o = 0;
    const uint8_t *p = in, *end = in + n;
    bool framed = true;
    while (p + 8 <= end && o < want) {
      uint32_t ul = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
      uint32_t cl = (uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 | (uint32_t)p[6] << 8 | p[7];
      if (cl > (size_t)(end - p - 8) || ul > want - o) {
        framed = false;
        break;
      }
      int k = LZ4_decompress_safe((const char *)p + 8, (char *)*out + o, (int)cl, (int)(want - o));
      if (k < 0 || (uint32_t)k != ul) {
        framed = false;
        break;
      }
      o += (size_t)k;
      p += 8 + cl;
    }
    if (framed && o == want && p == end) return true;
    return LZ4_decompress_safe((const char *)in, (char *)*out, (int)n, (int)want) == (int)want;
  }
  case 6: /* ZSTD */
    return ZSTD_decompress(*out, want, in, n) == want;
  case 7: /* LZ4_RAW */
    return LZ4_decompress_safe((const char *)in, (char *)*out, (int)n, (int)want) == (int)want;
  }
  return false; /* LZO, BROTLI */
}

typedef struct {
  int type;
  int32_t usize, csize;
  /* data page (v1 and v2) */
  int32_t nvalues, encoding, def_enc, rep_enc;
  int32_t def_len, rep_len;
  bool v2_compressed;
  /* dictionary page */
  int32_t dict_n, dict_enc;
} page_header;

static bool parse_page_header(tr *t, page_header *h) {
  memset(h, 0, sizeof(*h));
  h->v2_compressed = true;
  h->def_enc = h->rep_enc = 3;
  int id = 0;
  for (int ft; !t->bad && (ft = t_field(t, &id)) != T_STOP;) {
    switch (id) {
    case 1: h->type = (int)t_zz(t); break;
    case 2: h->usize = (int32_t)t_zz(t); break;
    case 3: h->csize = (int32_t)t_zz(t); break;
    case 5:
    case 8: {
      int fid = 0;
      for (int f2; !t->bad && (f2 = t_field(t, &fid)) != T_STOP;) {
        if (fid == 1) h->nvalues = (int32_t)t_zz(t);
        else if (id == 5 && fid == 2) h->encoding = (int32_t)t_zz(t);
        else if (id == 5 && fid == 3) h->def_enc = (int32_t)t_zz(t);
        else if (id == 5 && fid == 4) h->rep_enc = (int32_t)t_zz(t);
        else if (id == 8 && fid == 4) h->encoding = (int32_t)t_zz(t);
        else if (id == 8 && fid == 5) h->def_len = (int32_t)t_zz(t);
        else if (id == 8 && fid == 6) h->rep_len = (int32_t)t_zz(t);
        else if (id == 8 && fid == 7 && (f2 == T_TRUE || f2 == T_FALSE)) h->v2_compressed = f2 == T_TRUE;
        else t_skip(t, f2, 0);
      }
      break;
    }
    case 7: {
      int fid = 0;
      for (int f2; !t->bad && (f2 = t_field(t, &fid)) != T_STOP;) {
        if (fid == 1) h->dict_n = (int32_t)t_zz(t);
        else if (fid == 2) h->dict_enc = (int32_t)t_zz(t);
        else t_skip(t, f2, 0);
      }
      break;
    }
    default: t_skip(t, ft, 0);
    }
  }
  return !t->bad && h->csize >= 0 && h->usize >= 0;
}

/* Levels of a v1 page: a length-prefixed RLE run (or BIT_PACKED). */
static bool levels_v1(rd *r, int enc, int max, size_t n, int16_t *out) {
  if (max == 0) {
    for (size_t i = 0; i < n; i++) out[i] = 0;
    return true;
  }
  int w = bit_width(max);
  uint32_t *v = buckets_xmalloc((n ? n : 1) * sizeof(uint32_t));
  bool ok;
  if (enc == 4) { /* BIT_PACKED, most significant bit first */
    size_t bytes = (n * (size_t)w + 7) / 8;
    const uint8_t *p;
    ok = rd_take(r, bytes, &p);
    for (size_t i = 0; ok && i < n; i++) {
      uint32_t x = 0;
      for (int b = 0; b < w; b++) {
        size_t bit = i * (size_t)w + (size_t)b;
        x = x << 1 | ((p[bit / 8] >> (7 - bit % 8)) & 1);
      }
      v[i] = x;
    }
  } else {
    const uint8_t *lp;
    ok = rd_take(r, 4, &lp);
    uint32_t len = ok ? le32(lp) : 0;
    ok = ok && len <= (size_t)(r->end - r->p);
    if (ok) {
      rd sub = {r->p, r->p + len};
      ok = hybrid(&sub, w, n, v);
      r->p += len;
    }
  }
  for (size_t i = 0; ok && i < n; i++) out[i] = (int16_t)v[i];
  free(v);
  return ok;
}

static bool levels_raw(const uint8_t *p, size_t len, int max, size_t n, int16_t *out) {
  if (max == 0) {
    for (size_t i = 0; i < n; i++) out[i] = 0;
    return true;
  }
  uint32_t *v = buckets_xmalloc((n ? n : 1) * sizeof(uint32_t));
  rd r = {p, p + len};
  bool ok = hybrid(&r, bit_width(max), n, v);
  for (size_t i = 0; ok && i < n; i++) out[i] = (int16_t)v[i];
  free(v);
  return ok;
}

/* Decodes one column chunk of the current row group into its leaf. */
static bool load_chunk(sel_parquet *q, leaf *l, const chunk_meta *c, sel_err *e) {
  int64_t start = c->dict_off > 0 && c->dict_off < c->data_off ? c->dict_off : c->data_off;
  if (start < 4 || c->size <= 0 || c->size > MAX_CHUNK || start + c->size > q->src->size - 8 || c->num_values < 0 ||
      c->num_values > (int64_t)1 << 31)
    return perr(e);
  uint8_t *buf = buckets_xmalloc((size_t)c->size);
  if (!q->src->read_at(q->src->ud, start, buf, (size_t)c->size)) {
    free(buf);
    return perr(e);
  }
  size_t total = (size_t)c->num_values;
  l->def = sel_alloc(&q->group_arena, (total ? total : 1) * sizeof(int16_t));
  l->repl = sel_alloc(&q->group_arena, (total ? total : 1) * sizeof(int16_t));
  l->vals = sel_alloc(&q->group_arena, (total ? total : 1) * sizeof(jv));
  l->nlevels = l->nvals = l->li = l->vi = 0;
  jv *dict = NULL;
  size_t ndict = 0;
  const uint8_t *p = buf, *end = buf + c->size;
  bool ok = true;
  while (ok && p < end && l->nlevels < total) {
    tr t = {p, end, false};
    page_header h;
    if (!parse_page_header(&t, &h) || (size_t)h.csize > (size_t)(end - t.p)) {
      ok = false;
      break;
    }
    const uint8_t *body = t.p;
    p = t.p + h.csize;
    if (h.type == 2) { /* dictionary */
      uint8_t *u = NULL;
      if (h.dict_n < 0 || !decompress(c->codec, body, (size_t)h.csize, (size_t)h.usize, &u)) {
        free(u);
        ok = false;
        break;
      }
      dict = sel_alloc(&q->group_arena, ((size_t)h.dict_n ? (size_t)h.dict_n : 1) * sizeof(jv));
      ndict = (size_t)h.dict_n;
      rd r = {u, u + h.usize};
      ok = plain(q, l->el, &r, ndict, dict);
      free(u);
      continue;
    }
    if (h.type != 0 && h.type != 3) continue; /* index pages */
    size_t n = (size_t)h.nvalues;
    if (n > total - l->nlevels) {
      ok = false;
      break;
    }
    int16_t *repl = l->repl + l->nlevels, *def = l->def + l->nlevels;
    uint8_t *u = NULL;
    rd vr;
    if (h.type == 0) {
      if (!decompress(c->codec, body, (size_t)h.csize, (size_t)h.usize, &u)) {
        free(u);
        ok = false;
        break;
      }
      rd r = {u, u + h.usize};
      ok = (l->max_rep == 0 || levels_v1(&r, h.rep_enc, l->max_rep, n, repl)) &&
           levels_v1(&r, h.def_enc, l->max_def, n, def);
      if (l->max_rep == 0)
        for (size_t i = 0; i < n; i++) repl[i] = 0;
      vr = r;
    } else {
      if (h.rep_len < 0 || h.def_len < 0 || (size_t)h.rep_len + (size_t)h.def_len > (size_t)h.csize) {
        ok = false;
        break;
      }
      ok = levels_raw(body, (size_t)h.rep_len, l->max_rep, n, repl) &&
           levels_raw(body + h.rep_len, (size_t)h.def_len, l->max_def, n, def);
      size_t lv = (size_t)h.rep_len + (size_t)h.def_len;
      if (ok && h.v2_compressed && c->codec != 0) {
        ok = decompress(c->codec, body + lv, (size_t)h.csize - lv, (size_t)h.usize - lv, &u);
        vr = (rd){u, u + (h.usize - (int32_t)lv)};
      } else {
        vr = (rd){body + lv, body + h.csize};
      }
    }
    size_t nv = 0;
    for (size_t i = 0; ok && i < n; i++) nv += def[i] == l->max_def;
    if (ok) ok = decode_values(q, l->el, h.encoding, &vr, nv, l->vals + l->nvals, dict, ndict);
    free(u);
    l->nlevels += n;
    l->nvals += nv;
  }
  free(buf);
  if (!ok) return perr(e);
  return true;
}

static bool next_group(sel_parquet *q, sel_err *e) {
  for (;;) {
    q->gi = q->gi == (size_t)-1 ? 0 : q->gi + 1;
    if (q->gi >= q->ngroups) return true;
    sel_arena_reset(&q->group_arena);
    row_group *g = &q->groups[q->gi];
    q->row_in_group = 0;
    if (g->rows <= 0) continue;
    for (size_t i = 0; i < q->nleaves; i++)
      if (!load_chunk(q, &q->leaves[i], &g->cols[i], e)) return false;
    return true;
  }
}

int sel_parquet_next(sel_parquet *q, sel_arena *a, sel_record *out, sel_err *e) {
  if (q->gi == (size_t)-1 || (q->gi < q->ngroups && q->row_in_group >= q->groups[q->gi].rows)) {
    if (!next_group(q, e)) return -1;
  }
  if (q->gi >= q->ngroups) return 0;
  jv_kv *kv = sel_alloc(a, (q->nleaves ? q->nleaves : 1) * sizeof(jv_kv));
  for (size_t c = 0; c < q->nleaves; c++) {
    leaf *l = &q->leaves[c];
    kv[c].k = l->flat;
    kv[c].kn = l->flat_n;
    kv[c].v = (jv){.t = JV_NULL};
    if (l->li >= l->nlevels) {
      perr(e);
      e->code = "InternalError";
      return -1;
    }
    /* this row's entries: up to the next repetition level 0 */
    size_t first = l->li, n = 1;
    while (first + n < l->nlevels && l->repl[first + n] != 0) n++;
    size_t vals = 0;
    for (size_t i = 0; i < n; i++) vals += l->def[first + i] == l->max_def;
    if (l->vi + vals > l->nvals) {
      perr(e);
      e->code = "InternalError";
      return -1;
    }
    if (l->top) {
      if (l->max_rep == 0) {
        if (vals) kv[c].v = l->vals[l->vi];
      } else if (l->def[first] > 0) {
        /* a repeated primitive: its values as an array */
        jv arr = {.t = JV_ARR};
        arr.a.n = vals;
        arr.a.v = sel_alloc(a, (vals ? vals : 1) * sizeof(jv));
        memcpy(arr.a.v, l->vals + l->vi, vals * sizeof(jv));
        kv[c].v = arr;
      }
    }
    l->li += n;
    l->vi += vals;
  }
  q->row_in_group++;
  out->fmt = SEL_FMT_PARQUET;
  out->obj = (jv){.t = JV_OBJ, .o = {kv, q->nleaves}};
  return 1;
}
