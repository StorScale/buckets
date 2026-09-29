/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* CSV input and output for S3 Select: MinIO's csv package (reader, record,
 * record delimiter transform) and its csvparser fork of encoding/csv with
 * LazyQuotes, a configurable quote and quote escape. Records are read as one
 * stream, so quoted fields may span any number of lines. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "select/csv.h"
#include "select/sel.h"

#define RAW_CAP (128 * 1024)
#define FIRST_BLOCK (128 * 1024)

struct sel_csv_names {
  const char **name;
  size_t *len;
  size_t n;
};

bool sel_csv_names_find(const sel_csv_names *n, const char *name, size_t len, size_t *idx) {
  /* later duplicates win, as in MinIO's name map */
  for (size_t i = n->n; i > 0; i--) {
    if (n->len[i - 1] == len && (!len || !memcmp(n->name[i - 1], name, len))) {
      *idx = i - 1;
      return true;
    }
  }
  return false;
}

struct sel_csv_reader {
  sel_read_fn rd;
  void *ud;
  sel_csv_ropts o;
  /* delimiter transform */
  const char *delim;
  size_t dlen;
  unsigned char *raw;
  size_t carry; /* raw bytes kept back: a possible delimiter prefix */
  bool raw_eof, failed;
  /* transformed bytes */
  unsigned char *buf;
  size_t pos, len, cap;
  /* the current line */
  buckets_buf line;
  /* the record being built */
  buckets_buf rec;
  size_t *idx;
  size_t nidx, idxcap;
  sel_csv_names names;
  bool have_names;
  bool bad_delim;
  sel_arena names_arena;
};

/* Moves raw input into buf, replacing the record delimiter with \n. */
static bool fill(sel_csv_reader *r) {
  if (r->raw_eof && !r->carry) return false;
  if (r->pos > 0) {
    memmove(r->buf, r->buf + r->pos, r->len - r->pos);
    r->len -= r->pos;
    r->pos = 0;
  }
  if (r->len + RAW_CAP + 8 > r->cap) {
    r->cap = (r->len + RAW_CAP + 8) * 2;
    r->buf = buckets_xrealloc(r->buf, r->cap);
  }
  size_t have = r->carry;
  if (!r->raw_eof) {
    long k = r->rd(r->ud, r->raw + have, RAW_CAP - have);
    if (k < 0) {
      r->failed = true;
      return false;
    }
    if (k == 0) r->raw_eof = true;
    have += (size_t)k;
  }
  r->carry = 0;
  size_t i = 0;
  while (i < have) {
    if (r->dlen == 1 && r->raw[i] == (unsigned char)r->delim[0]) {
      r->buf[r->len++] = '\n';
      i++;
      continue;
    }
    if (r->dlen > 1 && r->raw[i] == (unsigned char)r->delim[0]) {
      size_t avail = have - i;
      if (avail >= r->dlen && !memcmp(r->raw + i, r->delim, r->dlen)) {
        r->buf[r->len++] = '\n';
        i += r->dlen;
        continue;
      }
      if (avail < r->dlen && !r->raw_eof && !memcmp(r->raw + i, r->delim, avail)) {
        /* may be completed by the next read */
        memmove(r->raw, r->raw + i, avail);
        r->carry = avail;
        break;
      }
    }
    r->buf[r->len++] = r->raw[i++];
  }
  return true;
}

/* The next physical line, "\r\n" normalized to "\n" (a trailing \r dropped at
 * the end); false at the end of input. */
static bool read_line(sel_csv_reader *r) {
  buckets_buf_reset(&r->line);
  for (;;) {
    unsigned char *nl = r->pos < r->len ? memchr(r->buf + r->pos, '\n', r->len - r->pos) : NULL;
    if (nl) {
      size_t n = (size_t)(nl - (r->buf + r->pos)) + 1;
      buckets_buf_append(&r->line, r->buf + r->pos, n);
      r->pos += n;
      break;
    }
    buckets_buf_append(&r->line, r->buf + r->pos, r->len - r->pos);
    r->pos = r->len;
    if (!fill(r)) {
      if (r->line.len == 0) return false;
      if (r->line.data[r->line.len - 1] == '\r') r->line.len--;
      return true;
    }
  }
  size_t n = r->line.len;
  if (n >= 2 && r->line.data[n - 2] == '\r' && r->line.data[n - 1] == '\n') {
    r->line.data[n - 2] = '\n';
    r->line.len--;
  }
  return true;
}

static size_t enc(uint32_t cp, char *u) {
  if (cp < 0x80) return u[0] = (char)cp, 1;
  if (cp < 0x800) return u[0] = (char)(0xc0 | cp >> 6), u[1] = (char)(0x80 | (cp & 0x3f)), 2;
  if (cp < 0x10000)
    return u[0] = (char)(0xe0 | cp >> 12), u[1] = (char)(0x80 | (cp >> 6 & 0x3f)), u[2] = (char)(0x80 | (cp & 0x3f)), 3;
  u[0] = (char)(0xf0 | cp >> 18), u[1] = (char)(0x80 | (cp >> 12 & 0x3f)), u[2] = (char)(0x80 | (cp >> 6 & 0x3f)),
  u[3] = (char)(0x80 | (cp & 0x3f));
  return 4;
}

static size_t dec(const char *s, size_t n, uint32_t *cp) {
  const unsigned char *p = (const unsigned char *)s;
  if (!n) return *cp = 0, 0;
  if (p[0] < 0x80) return *cp = p[0], 1;
  size_t len = (p[0] & 0xe0) == 0xc0 ? 2 : (p[0] & 0xf0) == 0xe0 ? 3 : (p[0] & 0xf8) == 0xf0 ? 4 : 0;
  if (!len || len > n) return *cp = 0xfffd, 1;
  uint32_t v = len == 2 ? p[0] & 0x1f : len == 3 ? p[0] & 0x0f : p[0] & 0x07;
  for (size_t i = 1; i < len; i++) {
    if ((p[i] & 0xc0) != 0x80) return *cp = 0xfffd, 1;
    v = v << 6 | (p[i] & 0x3f);
  }
  *cp = v;
  return len;
}

static bool valid_delim(uint32_t r) {
  return r != 0 && r != '"' && r != '\r' && r != '\n' && r <= 0x10ffff && !(r >= 0xd800 && r <= 0xdfff) && r != 0xfffd;
}

static size_t len_nl(const char *s, size_t n) { return n > 0 && s[n - 1] == '\n' ? 1 : 0; }

static const char *find_rune(const char *s, size_t n, uint32_t r) {
  char u[4];
  size_t k = enc(r, u);
  if (k == 1) return memchr(s, u[0], n);
  for (size_t i = 0; i + k <= n; i++)
    if (!memcmp(s + i, u, k)) return s + i;
  return NULL;
}

static void field_end(sel_csv_reader *r) {
  if (r->nidx == r->idxcap) r->idx = buckets_xrealloc(r->idx, (r->idxcap = r->idxcap ? r->idxcap * 2 : 16) * sizeof(size_t));
  r->idx[r->nidx++] = r->rec.len;
}

/* csvparser's readRecord with LazyQuotes: 1 a record, 0 the end. */
static int read_record(sel_csv_reader *r) {
  uint32_t q = r->o.quote, qe = r->o.quote_escape, comma = r->o.field_delim, comment = r->o.comment;
  char qb[4], qeb[4], cb[4];
  size_t qn = q ? enc(q, qb) : 0, qen = enc(qe, qeb), cn = enc(comma, cb);
  for (;;) {
    if (!read_line(r)) return 0;
    uint32_t first;
    dec(r->line.data, r->line.len, &first);
    if (comment && first == comment) continue;
    if (r->line.len == len_nl(r->line.data, r->line.len) && r->line.len) continue;
    break;
  }
  buckets_buf_reset(&r->rec);
  r->nidx = 0;
  const char *line = r->line.data;
  size_t n = r->line.len;
  bool more = true; /* input may continue after this line */
  for (;;) {
    uint32_t c0;
    dec(line, n, &c0);
    if (n == 0 || !qn || c0 != q) {
      /* unquoted field */
      const char *i = find_rune(line, n, comma);
      size_t fl = i ? (size_t)(i - line) : n - len_nl(line, n);
      buckets_buf_append(&r->rec, line, fl);
      field_end(r);
      if (i) {
        size_t adv = (size_t)(i - line) + cn;
        line += adv, n -= adv;
        continue;
      }
      return 1;
    }
    /* quoted field */
    line += qn, n -= qn;
    for (;;) {
      /* the next quote or quote escape */
      const char *hit = NULL;
      for (size_t k = 0; k < n && !hit; k++) {
        if ((n - k >= qn && !memcmp(line + k, qb, qn)) || (n - k >= qen && !memcmp(line + k, qeb, qen))) hit = line + k;
      }
      if (hit) {
        buckets_buf_append(&r->rec, line, (size_t)(hit - line));
        size_t off = (size_t)(hit - line);
        bool escape = n - off >= qen && !memcmp(hit, qeb, qen);
        size_t adv = off + (escape ? qen : qn);
        line += adv, n -= adv;
        uint32_t rn;
        size_t rl = dec(line, n, &rn);
        if (escape && qe != q) {
          buckets_buf_append(&r->rec, line, rl);
          line += rl, n -= rl;
        } else if (n && rn == q) {
          buckets_buf_append(&r->rec, qb, qn);
          line += qn, n -= qn;
        } else if (n && rn == comma) {
          line += cn, n -= cn;
          field_end(r);
          goto next_field;
        } else if (len_nl(line, n) == n) {
          field_end(r);
          return 1;
        } else {
          buckets_buf_append(&r->rec, qb, qn); /* a bare quote */
        }
      } else if (n > 0) {
        buckets_buf_append(&r->rec, line, n);
        if (!more || !read_line(r)) {
          more = false;
          field_end(r);
          return 1;
        }
        line = r->line.data;
        n = r->line.len;
      } else {
        field_end(r);
        return 1;
      }
    }
  next_field:;
  }
}

sel_csv_reader *sel_csv_reader_new(sel_read_fn rd, void *ud, const sel_csv_ropts *o, sel_err *e) {
  sel_csv_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->rd = rd;
  r->ud = ud;
  r->o = *o;
  r->delim = o->record_delim && *o->record_delim ? o->record_delim : "\n";
  r->dlen = strlen(r->delim);
  if (r->dlen == 1 && r->delim[0] == '\n') r->dlen = 0; /* nothing to replace */
  r->raw = buckets_xmalloc(RAW_CAP);
  r->cap = RAW_CAP * 2;
  r->buf = buckets_xmalloc(r->cap);
  bool bad_delim = o->field_delim == o->comment || !valid_delim(o->field_delim) || (o->comment && !valid_delim(o->comment));
  if (o->header != SEL_CSV_HEADER_NONE) {
    /* the header is the first line, parsed on its own */
    if (!read_line(r)) {
      if (r->failed) sel_fail(e, "InternalError", "reading the object failed");
      else r->have_names = o->header != SEL_CSV_HEADER_USE; /* no header, no records */
      if (r->failed) {
        sel_csv_reader_free(r);
        return NULL;
      }
    } else {
      if (!sel_utf8_valid(r->line.data, r->line.len)) {
        sel_fail(e, "InvalidTextEncoding", "UTF-8 encoding is required.");
        sel_csv_reader_free(r);
        return NULL;
      }
      if (bad_delim) {
        sel_fail(e, "CSVParsingError", "Encountered an error parsing the CSV file. Check the file and try again.");
        sel_csv_reader_free(r);
        return NULL;
      }
      /* parse just this line: park the rest of the input */
      unsigned char *sbuf = r->buf;
      size_t spos = r->pos, slen = r->len, scap = r->cap, scarry = r->carry;
      bool seof = r->raw_eof;
      unsigned char *hb = buckets_xmalloc(r->line.len + 1);
      memcpy(hb, r->line.data, r->line.len);
      r->buf = hb;
      r->pos = 0;
      r->len = r->line.len;
      r->cap = r->line.len + 1;
      r->raw_eof = true;
      r->carry = 0;
      int got = read_record(r);
      free(r->buf);
      r->buf = sbuf, r->pos = spos, r->len = slen, r->cap = scap, r->carry = scarry, r->raw_eof = seof;
      if (got == 1 && o->header == SEL_CSV_HEADER_USE) {
        r->names.n = r->nidx;
        r->names.name = sel_alloc(&r->names_arena, (r->nidx ? r->nidx : 1) * sizeof(char *));
        r->names.len = sel_alloc(&r->names_arena, (r->nidx ? r->nidx : 1) * sizeof(size_t));
        size_t prev = 0;
        for (size_t i = 0; i < r->nidx; i++) {
          r->names.name[i] = sel_strndup(&r->names_arena, r->rec.data + prev, r->idx[i] - prev);
          r->names.len[i] = r->idx[i] - prev;
          prev = r->idx[i];
        }
        r->have_names = true;
      }
    }
  }
  /* the first block must be UTF-8 */
  while (r->len - r->pos < FIRST_BLOCK && fill(r)) {
  }
  if (r->failed && o->header != SEL_CSV_HEADER_NONE) {
    /* reading the header failed: MinIO answers at once; without a header
     * the failure reaches the first record */
    sel_fail(e, "InternalError", "reading the object failed");
    sel_csv_reader_free(r);
    return NULL;
  }
  size_t n = r->len - r->pos;
  if (n > FIRST_BLOCK) {
    const unsigned char *nl = memchr(r->buf + r->pos + FIRST_BLOCK, '\n', n - FIRST_BLOCK);
    if (nl) n = (size_t)(nl - (r->buf + r->pos)) + 1;
  }
  size_t k = n;
  /* a sequence cut by the block's end is not an error */
  for (size_t back = 0; back < 3 && k > 0 && (r->buf[r->pos + k - 1] & 0xc0) == 0x80; back++) k--;
  if (k > 0 && r->buf[r->pos + k - 1] >= 0xc0 && k != r->len - r->pos) k--;
  if (!sel_utf8_valid((const char *)r->buf + r->pos, k)) {
    sel_fail(e, "InvalidTextEncoding", "UTF-8 encoding is required.");
    sel_csv_reader_free(r);
    return NULL;
  }
  if (bad_delim) r->bad_delim = true; /* the first record read fails */
  return r;
}

void sel_csv_reader_free(sel_csv_reader *r) {
  if (!r) return;
  free(r->raw);
  free(r->buf);
  free(r->idx);
  buckets_buf_free(&r->line);
  buckets_buf_free(&r->rec);
  sel_arena_free(&r->names_arena);
  free(r);
}

int sel_csv_reader_next(sel_csv_reader *r, sel_arena *a, sel_record *out, sel_err *e) {
  if (r->bad_delim) {
    sel_fail(e, "InternalError", "Encountered an error parsing the CSV file. Check the file and try again.");
    return -1;
  }
  int got = r->failed ? 0 : read_record(r);
  if (r->failed) {
    sel_fail(e, "InternalError", "reading the object failed");
    return -1;
  }
  if (got == 0) return 0;
  if (!r->have_names) {
    /* _1 ... _n from the first record */
    r->names.n = r->nidx;
    r->names.name = sel_alloc(&r->names_arena, (r->nidx ? r->nidx : 1) * sizeof(char *));
    r->names.len = sel_alloc(&r->names_arena, (r->nidx ? r->nidx : 1) * sizeof(size_t));
    for (size_t i = 0; i < r->nidx; i++) {
      char b[24];
      int k = snprintf(b, sizeof(b), "_%zu", i + 1);
      r->names.name[i] = sel_strndup(&r->names_arena, b, (size_t)k);
      r->names.len[i] = (size_t)k;
    }
    r->have_names = true;
  }
  out->fmt = SEL_FMT_CSV;
  out->names = &r->names;
  out->nf = r->nidx;
  out->fields = sel_alloc(a, (r->nidx ? r->nidx : 1) * sizeof(char *));
  out->flen = sel_alloc(a, (r->nidx ? r->nidx : 1) * sizeof(size_t));
  char *all = sel_strndup(a, r->rec.data ? r->rec.data : "", r->rec.len);
  size_t prev = 0;
  for (size_t i = 0; i < r->nidx; i++) {
    out->fields[i] = all + prev;
    out->flen[i] = r->idx[i] - prev;
    prev = r->idx[i];
  }
  return 1;
}

/* ---- csv.Record ---- */

bool sel_csv_get(const sel_record *r, const char *name, size_t n, sel_value *out, sel_err *e);
bool sel_csv_get(const sel_record *r, const char *name, size_t n, sel_value *out, sel_err *e) {
  size_t idx;
  if (!sel_csv_names_find(r->names, name, n, &idx)) {
    int64_t i;
    if (n > 0 && name[0] == '_' && sel_parse_int(name + 1, n - 1, &i)) {
      if (i < 1 || (uint64_t)(i - 1) >= r->nf) return *out = sv_null(), true;
      *out = sv_bytes(r->fields[i - 1], r->flen[i - 1]);
      return true;
    }
    return sel_fail(e, "InternalError", "column %.*s not found", (int)n, name);
  }
  if (idx >= r->nf) return *out = sv_null(), true;
  *out = sv_bytes(r->fields[idx], r->flen[idx]);
  return true;
}

void sel_csv_clone(sel_orec *o, sel_arena *a, const sel_record *in);
void sel_csv_clone(sel_orec *o, sel_arena *a, const sel_record *in) {
  o->csv = true;
  o->n = 0;
  size_t names = in->names ? in->names->n : 0;
  /* the record's names and fields (WriteJSON pairs them; WriteCSV takes every field) */
  for (size_t i = 0; i < in->nf; i++) {
    const char *nm = i < names ? in->names->name[i] : NULL;
    size_t nl = i < names ? in->names->len[i] : 0;
    sel_orec_add(o, a, nm, nl, (sel_oval){.t = OV_STR, .s = {in->fields[i], in->flen[i]}});
  }
}

/* ---- output ---- */

static bool is_space_rune(uint32_t c) {
  switch (c) {
  case '\t': case '\n': case '\v': case '\f': case '\r': case ' ': case 0x85: case 0xa0: case 0x1680:
  case 0x2028: case 0x2029: case 0x202f: case 0x205f: case 0x3000: return true;
  }
  return c >= 0x2000 && c <= 0x200a;
}

static bool needs_quotes(const char *f, size_t n, const sel_csv_wopts *o) {
  if (n == 0) return false;
  if (n == 2 && f[0] == '\\' && f[1] == '.') return true;
  for (size_t i = 0; i < n;) {
    uint32_t cp;
    size_t k = dec(f + i, n - i, &cp);
    if (cp == '\r' || cp == '\n' || cp == o->quote || cp == o->field_delim) return true;
    i += k;
  }
  uint32_t first;
  dec(f, n, &first);
  return is_space_rune(first);
}

static void put(buckets_buf *out, uint32_t cp) {
  char u[4];
  buckets_buf_append(out, u, enc(cp, u));
}

static void write_field(buckets_buf *out, const char *f, size_t n, const sel_csv_wopts *o) {
  if (!o->always_quote && !needs_quotes(f, n, o)) {
    buckets_buf_append(out, f, n);
    return;
  }
  put(out, o->quote);
  for (size_t i = 0; i < n;) {
    uint32_t cp;
    size_t k = dec(f + i, n - i, &cp);
    if (cp == o->quote) {
      put(out, o->quote_escape);
      put(out, o->quote);
      i += 1; /* csvparser advances one byte here */
      if (k > 1) buckets_buf_append(out, f + i, k - 1), i += k - 1;
      continue;
    }
    buckets_buf_append(out, f + i, k);
    i += k;
  }
  put(out, o->quote);
}

void sel_oval_csv_text(buckets_buf *out, const sel_oval *v);

void sel_orec_write_csv(buckets_buf *out, const sel_orec *r, const sel_csv_wopts *o) {
  buckets_buf t = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < r->n; i++) {
    if (i) put(out, o->field_delim);
    const sel_oval *v = &r->kv[i].v;
    if (r->csv || v->t == OV_STR) {
      write_field(out, v->s.p, v->s.n, o);
    } else {
      buckets_buf_reset(&t);
      sel_oval_csv_text(&t, v);
      write_field(out, t.data ? t.data : "", t.len, o);
    }
  }
  buckets_buf_free(&t);
}
