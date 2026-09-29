/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* A streaming reader of JSON values, as MinIO's jstream decodes them for
 * S3 Select: a sequence of top-level values separated by whitespace,
 * objects keeping their key order, numbers as float64, depth at most 100. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "select/sel.h"

#define BUF_CAP (256 * 1024)
#define MAX_DEPTH 100

struct jv_reader {
  sel_read_fn rd;
  void *ud;
  int64_t limit; /* bytes still allowed (-1: no limit) */
  unsigned char *buf;
  size_t pos, len;
  bool eof, failed;
  buckets_buf scratch;
  /* jstream's error position: the last byte taken, its line and column */
  int64_t consumed, line_start;
  int line;
  int last;
  char detail[160]; /* the decoder's own message for the last error */
};

jv_reader *jv_reader_new(sel_read_fn rd, void *ud, int64_t limit) {
  jv_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->rd = rd;
  r->ud = ud;
  r->limit = limit;
  r->buf = buckets_xmalloc(BUF_CAP);
  return r;
}

void jv_reader_free(jv_reader *r) {
  if (!r) return;
  free(r->buf);
  buckets_buf_free(&r->scratch);
  free(r);
}

static bool refill(jv_reader *r) {
  if (r->pos < r->len) return true;
  if (r->eof || r->failed) return false;
  size_t want = BUF_CAP;
  if (r->limit >= 0 && (int64_t)want > r->limit) want = (size_t)r->limit;
  if (want == 0) {
    r->eof = true;
    return false;
  }
  long k = r->rd(r->ud, r->buf, want);
  if (k < 0) {
    r->failed = true;
    return false;
  }
  if (k == 0) {
    r->eof = true;
    return false;
  }
  if (r->limit >= 0) r->limit -= k;
  r->pos = 0;
  r->len = (size_t)k;
  return true;
}

/* The current byte, or -1 at the end. */
static int peek(jv_reader *r) { return refill(r) ? r->buf[r->pos] : -1; }
static int next(jv_reader *r) {
  int c = peek(r);
  if (c >= 0) {
    r->pos++;
    r->consumed++;
    r->last = c;
  }
  return c;
}

static void skip_spaces(jv_reader *r) {
  for (int c; (c = peek(r)) == ' ' || c == '\t' || c == '\n' || c == '\r';) {
    next(r);
    if (c == '\n') {
      r->line++;
      r->line_start = r->consumed;
    }
  }
}

/* jstream's quoteChar */
static void quote_char(char *out, size_t cap, int c) {
  if (c == '\'') snprintf(out, cap, "'\\''");
  else if (c == '"') snprintf(out, cap, "'\"'");
  else if (c == '\n') snprintf(out, cap, "'\\n'");
  else if (c == '\r') snprintf(out, cap, "'\\r'");
  else if (c == '\t') snprintf(out, cap, "'\\t'");
  else if (c < 0x20 || c >= 0x7f) snprintf(out, cap, "'\\x%02x'", c & 0xff);
  else snprintf(out, cap, "'%c'", c);
}

static bool jerr(jv_reader *r, sel_err *e, const char *msg, const char *ctx) {
  char q[16];
  quote_char(q, sizeof(q), r->last);
  snprintf(r->detail, sizeof(r->detail), "%s %s: %s [%d,%lld]", msg, ctx, q, r->line + 1,
           (long long)(r->consumed - r->line_start));
  return sel_fail(e, "JSONParsingError", "Encountered an error parsing the JSON file. Check the file and try again.");
}

/* A syntax error at the next byte (taken, as jstream has it), or the end. */
static bool syntax_ctx(jv_reader *r, sel_err *e, const char *ctx) {
  if (peek(r) < 0) return jerr(r, e, "unexpected end of JSON input", "");
  next(r);
  return jerr(r, e, "invalid character", ctx);
}


static void add_rune(buckets_buf *b, uint32_t cp) {
  if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
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

static bool hex4(jv_reader *r, uint32_t *v) {
  *v = 0;
  for (int i = 0; i < 4; i++) {
    int c = next(r);
    int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0) return false;
    *v = *v << 4 | (uint32_t)d;
  }
  return true;
}

/* A string after its opening quote, into scratch. */
static bool read_string(jv_reader *r, sel_err *e) {
  buckets_buf_reset(&r->scratch);
  for (;;) {
    if (!refill(r)) return jerr(r, e, "invalid character", "in string literal");
    /* copy a run of plain bytes */
    size_t i = r->pos;
    while (i < r->len && r->buf[i] != '"' && r->buf[i] != '\\' && r->buf[i] >= 0x20) i++;
    buckets_buf_append(&r->scratch, r->buf + r->pos, i - r->pos);
    if (i > r->pos) {
      r->consumed += (int64_t)(i - r->pos);
      r->last = r->buf[i - 1];
    }
    r->pos = i;
    if (i == r->len) continue;
    int c = next(r);
    if (c == '"') return true;
    if (c < 0x20) return jerr(r, e, "invalid character", "in string literal");
    c = next(r); /* after a backslash */
    switch (c) {
    case '"':
    case '\\':
    case '/':
    case '\'': buckets_buf_append_char(&r->scratch, (char)c); break;
    case 'b': buckets_buf_append_char(&r->scratch, '\b'); break;
    case 'f': buckets_buf_append_char(&r->scratch, '\f'); break;
    case 'n': buckets_buf_append_char(&r->scratch, '\n'); break;
    case 'r': buckets_buf_append_char(&r->scratch, '\r'); break;
    case 't': buckets_buf_append_char(&r->scratch, '\t'); break;
    case 'u': {
      uint32_t cp;
      if (!hex4(r, &cp)) return jerr(r, e, "invalid character", "in unicode escape sequence");
      if (cp >= 0xd800 && cp < 0xdc00 && peek(r) == '\\') {
        next(r);
        uint32_t lo;
        if (next(r) != 'u' || !hex4(r, &lo)) return jerr(r, e, "invalid character", "in unicode escape sequence");
        if (lo >= 0xdc00 && lo <= 0xdfff) cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        else {
          add_rune(&r->scratch, 0xfffd);
          cp = lo;
        }
      }
      add_rune(&r->scratch, cp);
      break;
    }
    default: return jerr(r, e, "invalid character", "in string escape code");
    }
  }
}

static bool is_digit(int c) { return c >= '0' && c <= '9'; }

static bool read_number(jv_reader *r, jv *out, sel_err *e) {
  buckets_buf_reset(&r->scratch);
  int c = peek(r);
  if (c == '-') {
    buckets_buf_append_char(&r->scratch, '-');
    next(r);
    c = peek(r);
    if (!is_digit(c)) return syntax_ctx(r, e, "in negative numeric literal");
  }
  if (c == '0') {
    buckets_buf_append_char(&r->scratch, '0');
    next(r);
  } else {
    while (is_digit(c = peek(r))) buckets_buf_append_char(&r->scratch, (char)next(r));
  }
  if (peek(r) == '.') {
    buckets_buf_append_char(&r->scratch, (char)next(r));
    if (!is_digit(peek(r))) return syntax_ctx(r, e, "after decimal point in numeric literal");
    while (is_digit(peek(r))) buckets_buf_append_char(&r->scratch, (char)next(r));
    if (peek(r) < 0) return jerr(r, e, "unexpected end of JSON input", ""); /* jstream: a fraction needs more */
  }
  c = peek(r);
  if (c == 'e' || c == 'E') {
    buckets_buf_append_char(&r->scratch, (char)next(r));
    c = peek(r);
    if (c == '+' || c == '-') {
      buckets_buf_append_char(&r->scratch, (char)next(r));
      if (!is_digit(peek(r))) return syntax_ctx(r, e, "in exponent of numeric literal");
    }
    while (is_digit(peek(r))) buckets_buf_append_char(&r->scratch, (char)next(r));
  }
  buckets_buf_append_char(&r->scratch, 0);
  out->t = JV_FLOAT;
  out->f = strtod(r->scratch.data, NULL);
  return true;
}

static bool literal(jv_reader *r, const char *rest) {
  for (; *rest; rest++)
    if (next(r) != *rest) return false;
  return true;
}

static bool read_value(jv_reader *r, sel_arena *a, jv *out, int depth, sel_err *e);

static bool read_array(jv_reader *r, sel_arena *a, jv *out, int depth, sel_err *e) {
  size_t n = 0, cap = 8;
  jv *items = buckets_xmalloc(cap * sizeof(jv));
  skip_spaces(r);
  if (peek(r) == ']') {
    next(r);
  } else {
    for (;;) {
      if (n == cap) items = buckets_xrealloc(items, (cap *= 2) * sizeof(jv));
      if (!read_value(r, a, &items[n], depth, e)) {
        free(items);
        return false;
      }
      n++;
      skip_spaces(r);
      int c = peek(r);
      if (c == ']' || c == ',') next(r);
      if (c == ']') break;
      if (c != ',') {
        free(items);
        return syntax_ctx(r, e, "after array element");
      }
      skip_spaces(r);
    }
  }
  out->t = JV_ARR;
  out->a.n = n;
  out->a.v = sel_alloc(a, (n ? n : 1) * sizeof(jv));
  if (n) memcpy(out->a.v, items, n * sizeof(jv));
  free(items);
  return true;
}

static bool read_object(jv_reader *r, sel_arena *a, jv *out, int depth, sel_err *e) {
  size_t n = 0, cap = 8;
  jv_kv *kv = buckets_xmalloc(cap * sizeof(jv_kv));
  skip_spaces(r);
  if (peek(r) == '}') {
    next(r);
  } else {
    for (;;) {
      if (peek(r) != '"') {
        free(kv);
        return syntax_ctx(r, e, "looking for beginning of object key string");
      }
      next(r);
      if (!read_string(r, e)) {
        free(kv);
        return false;
      }
      if (n == cap) kv = buckets_xrealloc(kv, (cap *= 2) * sizeof(jv_kv));
      kv[n].kn = r->scratch.len;
      kv[n].k = sel_strndup(a, r->scratch.data ? r->scratch.data : "", r->scratch.len);
      skip_spaces(r);
      if (peek(r) != ':') {
        free(kv);
        return syntax_ctx(r, e, "after object key");
      }
      next(r);
      skip_spaces(r);
      if (!read_value(r, a, &kv[n].v, depth, e)) {
        free(kv);
        return false;
      }
      n++;
      skip_spaces(r);
      int c = peek(r);
      if (c == '}' || c == ',') next(r);
      if (c == '}') break;
      if (c != ',') {
        free(kv);
        return syntax_ctx(r, e, "after object key:value pair");
      }
      skip_spaces(r);
    }
  }
  out->t = JV_OBJ;
  out->o.n = n;
  out->o.kv = sel_alloc(a, (n ? n : 1) * sizeof(jv_kv));
  if (n) memcpy(out->o.kv, kv, n * sizeof(jv_kv));
  free(kv);
  return true;
}

static bool read_value(jv_reader *r, sel_arena *a, jv *out, int depth, sel_err *e) {
  memset(out, 0, sizeof(*out));
  int c = peek(r);
  switch (c) {
  case '"':
    next(r);
    if (!read_string(r, e)) return false;
    out->t = JV_STR;
    out->s.n = r->scratch.len;
    out->s.p = sel_strndup(a, r->scratch.data ? r->scratch.data : "", r->scratch.len);
    return true;
  case '-':
  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9': return read_number(r, out, e);
  case 't':
    next(r);
    if (!literal(r, "rue")) return jerr(r, e, r->last < 0 ? "unexpected end of JSON input" : "invalid character", "in literal true");
    out->t = JV_BOOL, out->b = true;
    return true;
  case 'f':
    next(r);
    if (!literal(r, "alse")) return jerr(r, e, "invalid character", "in literal false");
    out->t = JV_BOOL, out->b = false;
    return true;
  case 'n':
    next(r);
    if (!literal(r, "ull")) return jerr(r, e, "invalid character", "in literal null");
    out->t = JV_NULL;
    return true;
  case '[':
  case '{':
    next(r);
    if (depth + 1 > MAX_DEPTH) return jerr(r, e, "maximum recursion depth exceeded", "");
    return c == '[' ? read_array(r, a, out, depth + 1, e) : read_object(r, a, out, depth + 1, e);
  default: return syntax_ctx(r, e, "looking for beginning of value");
  }
}

int jv_reader_next(jv_reader *r, sel_arena *a, jv *out, sel_err *e) {
  skip_spaces(r);
  if (peek(r) < 0) {
    if (r->failed) return sel_fail(e, "InternalError", "reading the object failed"), -1;
    return 0;
  }
  if (!read_value(r, a, out, 0, e)) return -1;
  return 1;
}

const char *jv_reader_detail(const jv_reader *r) { return r->detail; }
