/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SelectObjectContent: the request (MinIO's s3select/select.go), the input
 * readers and decompression (progress.go), and the event stream
 * (message.go), produced on demand for a pulling HTTP response. */
#include "select/select.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <zlib.h>

#include "compress/stream.h"
#include "core/buf.h"
#include "core/common.h"
#include "core/str.h"
#include "s3/xml.h"
#include "select/csv.h"
#include "select/parquet.h"
#include "select/sel.h"

#define MAX_RECORD_SIZE (1 << 20)
#define MAX_MESSAGE ((128 << 10) - 256)
#define MAX_DOCUMENT (10 << 20)
#define QUEUE_MAX 100

typedef enum { IN_CSV, IN_JSON, IN_PARQUET } in_fmt;

struct buckets_select {
  sel_stmt *stmt;
  /* request */
  in_fmt in;
  buckets_decomp_type comp;
  sel_csv_ropts csv_in;
  char csv_rdelim[64];
  bool json_lines;
  bool out_csv;
  sel_csv_wopts csv_out;
  char out_rdelim[64];
  bool progress;
  bool parquet_on; /* MINIO_API_SELECT_PARQUET */
  bool have_start, have_end;
  uint64_t start, end;
  /* input */
  const buckets_select_source *src;
  buckets_decomp *dc;
  int64_t processed;
  sel_csv_reader *csv;
  jv_reader *json;
  sel_parquet *pq;
  bool empty;   /* nothing to read (an empty object or range) */
  int64_t left; /* bytes of the range still to read (-1: to the end) */
  unsigned char pb; /* a byte read ahead at open */
  bool have_pb;
  /* evaluation */
  sel_arena rec_arena;
  buckets_buf queue; /* marshaled records not yet handed to the writer */
  size_t queued;
  buckets_buf payload; /* the Records message being filled */
  buckets_buf out;     /* framed messages ready to send */
  size_t out_pos;
  int64_t returned;
  double last_write, last_flush, last_progress;
  bool finished, done;
};

static bool efail(buckets_select_err *e, int status, const char *code, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static bool efail(buckets_select_err *e, int status, const char *code, const char *fmt, ...) {
  e->code = code;
  e->status = status;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
  va_end(ap);
  return false;
}

static const char *const k_malformed =
    "The XML provided was not well-formed or did not validate against our published schema. Check the service "
    "documentation and try again: ";

static bool malformed(buckets_select_err *e, const char *why) {
  return efail(e, 400, "MalformedXML", "%s%s", k_malformed, why);
}

static double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- the request document ---- */

typedef struct {
  const buckets_xml_doc *doc;
  buckets_buf tmp;
} xr;

static const buckets_xml_node *node(const xr *x, size_t i) { return &x->doc->nodes[i]; }

/* A child's unescaped text (NUL-terminated in x->tmp). */
static const char *text_of(xr *x, size_t i) {
  buckets_buf_reset(&x->tmp);
  buckets_xml_unescape(node(x, i)->text, &x->tmp);
  buckets_buf_append_char(&x->tmp, 0);
  x->tmp.len--;
  return x->tmp.data;
}

static bool parse_bool(const char *s, bool *b) {
  buckets_str t = buckets_str_trim(buckets_str_c(s));
  static const char *const yes[] = {"1", "t", "T", "TRUE", "true", "True", NULL};
  static const char *const no[] = {"0", "f", "F", "FALSE", "false", "False", NULL};
  for (const char *const *w = yes; *w; w++)
    if (buckets_str_eq_c(t, *w)) return *b = true, true;
  for (const char *const *w = no; *w; w++)
    if (buckets_str_eq_c(t, *w)) return *b = false, true;
  return false;
}

static bool parse_u64(const char *s, uint64_t *v) {
  buckets_str t = buckets_str_trim(buckets_str_c(s));
  if (!t.n || t.n > 20) return false;
  uint64_t x = 0;
  for (size_t i = 0; i < t.n; i++) {
    if (t.p[i] < '0' || t.p[i] > '9') return false;
    uint64_t d = (uint64_t)(t.p[i] - '0');
    if (x > (UINT64_MAX - d) / 10) return false;
    x = x * 10 + d;
  }
  *v = x;
  return true;
}

static size_t runes_in(const char *s) { return sel_utf8_count(s, strlen(s)); }

static uint32_t first_rune(const char *s) {
  const unsigned char *p = (const unsigned char *)s;
  if (!*p) return 0;
  if (p[0] < 0x80) return p[0];
  size_t len = (p[0] & 0xe0) == 0xc0 ? 2 : (p[0] & 0xf0) == 0xe0 ? 3 : 4;
  uint32_t v = len == 2 ? p[0] & 0x1f : len == 3 ? p[0] & 0x0f : p[0] & 0x07;
  for (size_t i = 1; i < len && p[i]; i++) v = v << 6 | (p[i] & 0x3f);
  return v;
}

static bool parse_csv_in(buckets_select *s, xr *x, size_t el, buckets_select_err *e) {
  sel_csv_ropts *o = &s->csv_in;
  *o = (sel_csv_ropts){SEL_CSV_HEADER_NONE, NULL, ',', '"', '"', '#'};
  snprintf(s->csv_rdelim, sizeof(s->csv_rdelim), "\n");
  for (size_t c = node(x, el)->first_child; c; c = node(x, c)->next_sibling) {
    buckets_str name = node(x, c)->name;
    const char *v = text_of(x, c);
    if (buckets_str_eq_c(name, "AllowQuotedRecordDelimiter")) {
      bool b;
      if (!parse_bool(v, &b)) {
        char m[200];
        snprintf(m, sizeof(m), "strconv.ParseBool: parsing \"%s\": invalid syntax", v);
        return malformed(e, m);
      }
    } else if (buckets_str_eq_c(name, "FileHeaderInfo")) {
      if (*v) {
        if (!strcasecmp(v, "none")) o->header = SEL_CSV_HEADER_NONE;
        else if (!strcasecmp(v, "use")) o->header = SEL_CSV_HEADER_USE;
        else if (!strcasecmp(v, "ignore")) o->header = SEL_CSV_HEADER_IGNORE;
        else return malformed(e, "unsupported FileHeaderInfo");
      }
    } else if (buckets_str_eq_c(name, "RecordDelimiter")) {
      if (*v) snprintf(s->csv_rdelim, sizeof(s->csv_rdelim), "%s", v);
    } else if (buckets_str_eq_c(name, "FieldDelimiter")) {
      if (*v) o->field_delim = first_rune(v);
    } else if (buckets_str_eq_c(name, "QuoteCharacter")) {
      if (runes_in(v) > 1) {
        char m[160];
        snprintf(m, sizeof(m), "unsupported QuoteCharacter '%s'", v);
        return malformed(e, m);
      }
      o->quote = first_rune(v);
    } else if (buckets_str_eq_c(name, "QuoteEscapeCharacter")) {
      size_t n = runes_in(v);
      if (n > 1) {
        char m[160];
        snprintf(m, sizeof(m), "unsupported QuoteEscapeCharacter '%s'", v);
        return malformed(e, m);
      }
      o->quote_escape = n ? first_rune(v) : '"';
    } else if (buckets_str_eq_c(name, "Comments")) {
      if (*v) o->comment = first_rune(v);
    } else {
      return malformed(e, "unrecognized option");
    }
  }
  o->record_delim = s->csv_rdelim;
  return true;
}

static bool parse_csv_out(buckets_select *s, xr *x, size_t el, buckets_select_err *e) {
  sel_csv_wopts *o = &s->csv_out;
  *o = (sel_csv_wopts){',', '"', '"', false};
  snprintf(s->out_rdelim, sizeof(s->out_rdelim), "\n");
  for (size_t c = node(x, el)->first_child; c; c = node(x, c)->next_sibling) {
    buckets_str name = node(x, c)->name;
    const char *v = text_of(x, c);
    if (buckets_str_eq_c(name, "QuoteFields")) {
      o->always_quote = !strcasecmp(v, "always");
    } else if (buckets_str_eq_c(name, "RecordDelimiter")) {
      snprintf(s->out_rdelim, sizeof(s->out_rdelim), "%s", v);
    } else if (buckets_str_eq_c(name, "FieldDelimiter")) {
      o->field_delim = *v ? first_rune(v) : ','; /* MinIO fails on an empty one */
    } else if (buckets_str_eq_c(name, "QuoteCharacter")) {
      size_t n = runes_in(v);
      if (n > 1) {
        char m[160];
        snprintf(m, sizeof(m), "unsupported QuoteCharacter '%s'", v);
        return malformed(e, m);
      }
      o->quote = n ? first_rune(v) : 0;
    } else if (buckets_str_eq_c(name, "QuoteEscapeCharacter")) {
      size_t n = runes_in(v);
      if (n > 1) {
        char m[160];
        snprintf(m, sizeof(m), "unsupported QuoteCharacter '%s'", v);
        return malformed(e, m);
      }
      o->quote_escape = n ? first_rune(v) : '"';
    } else {
      return malformed(e, "unrecognized option");
    }
  }
  return true;
}

static bool parse_input(buckets_select *s, xr *x, size_t el, buckets_select_err *e) {
  int found = 0;
  bool have_comp = false;
  s->comp = BUCKETS_DECOMP_NONE;
  for (size_t c = node(x, el)->first_child; c; c = node(x, c)->next_sibling) {
    buckets_str name = node(x, c)->name;
    if (buckets_str_eq_c(name, "CompressionType")) {
      const char *v = text_of(x, c);
      static const struct {
        const char *n;
        buckets_decomp_type t;
      } types[] = {{"NONE", BUCKETS_DECOMP_NONE},   {"GZIP", BUCKETS_DECOMP_GZIP}, {"BZIP2", BUCKETS_DECOMP_BZIP2},
                   {"SNAPPY", BUCKETS_DECOMP_SNAPPY}, {"S2", BUCKETS_DECOMP_S2},   {"ZSTD", BUCKETS_DECOMP_ZSTD},
                   {"LZ4", BUCKETS_DECOMP_LZ4}};
      bool ok = !*v;
      for (size_t i = 0; i < sizeof(types) / sizeof(types[0]) && !ok; i++)
        if (!strcasecmp(v, types[i].n)) s->comp = types[i].t, ok = true;
      if (!ok)
        return malformed(e, "The file is not in a supported compression format. GZIP, BZIP2, ZSTD, LZ4, S2 and SNAPPY are "
                            "supported.");
      have_comp = s->comp != BUCKETS_DECOMP_NONE;
    } else if (buckets_str_eq_c(name, "CSV")) {
      if (!parse_csv_in(s, x, c, e)) return false;
      s->in = IN_CSV;
      found++;
    } else if (buckets_str_eq_c(name, "JSON")) {
      const char *type = "";
      size_t t = buckets_xml_child(x->doc, c, "Type");
      if (t) type = text_of(x, t);
      if (strcasecmp(type, "document") && strcasecmp(type, "lines"))
        return malformed(e, "The JsonType is invalid. Only DOCUMENT and LINES are supported.");
      s->json_lines = !strcasecmp(type, "lines");
      s->in = IN_JSON;
      found++;
    } else if (buckets_str_eq_c(name, "Parquet")) {
      if (have_comp)
        return efail(e, 400, "InvalidRequestParameter",
                     "The value of a parameter in SelectRequest element is invalid. Check the service API documentation "
                     "and try again.");
      s->in = IN_PARQUET;
      found++;
    }
  }
  if (s->in == IN_PARQUET && have_comp)
    return efail(e, 400, "InvalidRequestParameter",
                 "The value of a parameter in SelectRequest element is invalid. Check the service API documentation and "
                 "try again.");
  if (found != 1)
    return efail(e, 400, "InvalidDataSource", "Invalid data source type. Only CSV, JSON, and Parquet are supported.");
  return true;
}

static bool parse_output(buckets_select *s, xr *x, size_t el, buckets_select_err *e) {
  int found = 0;
  for (size_t c = node(x, el)->first_child; c; c = node(x, c)->next_sibling) {
    buckets_str name = node(x, c)->name;
    if (buckets_str_eq_c(name, "CSV")) {
      if (!parse_csv_out(s, x, c, e)) return false;
      s->out_csv = true;
      found++;
    } else if (buckets_str_eq_c(name, "JSON")) {
      snprintf(s->out_rdelim, sizeof(s->out_rdelim), "\n");
      size_t d = buckets_xml_child(x->doc, c, "RecordDelimiter");
      if (d) {
        const char *v = text_of(x, d);
        size_t n = strlen(v);
        if (n > 2) {
          char m[160];
          snprintf(m, sizeof(m), "invalid RecordDelimiter '%s'", v);
          return malformed(e, m);
        }
        if (n) snprintf(s->out_rdelim, sizeof(s->out_rdelim), "%s", v);
      }
      s->out_csv = false;
      found++;
    }
  }
  if (found != 1)
    return efail(e, 400, "ObjectSerializationConflict",
                 "InputSerialization specifies more than one format (CSV, JSON, or Parquet), or OutputSerialization "
                 "specifies more than one format (CSV or JSON). InputSerialization and OutputSerialization can only "
                 "specify one format each.");
  return true;
}

/* The request under doc node root (SelectRequest, or a restore's
 * SelectParameters). */
static buckets_select *parse_node(const buckets_xml_doc *doc, size_t root_i, bool parquet, buckets_select_err *e) {
  buckets_select *s = buckets_xcalloc(1, sizeof(*s));
  xr x = {doc, BUCKETS_BUF_INIT};
  char *expr = NULL, *etype = NULL;
  bool have_in = false, have_out = false, ok = true;
  for (size_t c = doc->nodes[root_i].first_child; ok && c; c = doc->nodes[c].next_sibling) {
    buckets_str name = doc->nodes[c].name;
    if (buckets_str_eq_c(name, "Expression")) {
      free(expr);
      expr = buckets_xstrdup(text_of(&x, c));
    } else if (buckets_str_eq_c(name, "ExpressionType")) {
      free(etype);
      etype = buckets_xstrdup(text_of(&x, c));
    } else if (buckets_str_eq_c(name, "InputSerialization")) {
      ok = parse_input(s, &x, c, e);
      have_in = true;
    } else if (buckets_str_eq_c(name, "OutputSerialization")) {
      ok = parse_output(s, &x, c, e);
      have_out = true;
    } else if (buckets_str_eq_c(name, "RequestProgress")) {
      size_t en = buckets_xml_child(doc, c, "Enabled");
      if (en && !parse_bool(text_of(&x, en), &s->progress)) {
        char m[200];
        snprintf(m, sizeof(m), "strconv.ParseBool: parsing \"%s\": invalid syntax", x.tmp.data);
        ok = malformed(e, m);
      }
    } else if (buckets_str_eq_c(name, "ScanRange")) {
      size_t st = buckets_xml_child(doc, c, "Start"), en = buckets_xml_child(doc, c, "End");
      char m[200];
      if (st && !(s->have_start = parse_u64(text_of(&x, st), &s->start))) {
        snprintf(m, sizeof(m), "strconv.ParseUint: parsing \"%s\": invalid syntax", x.tmp.data);
        ok = malformed(e, m);
      }
      if (ok && en && !(s->have_end = parse_u64(text_of(&x, en), &s->end))) {
        snprintf(m, sizeof(m), "strconv.ParseUint: parsing \"%s\": invalid syntax", x.tmp.data);
        ok = malformed(e, m);
      }
      if (ok && ((!s->have_start && !s->have_end) || (s->have_start && s->have_end && s->start > s->end)))
        ok = efail(e, 400, "InvalidRequestParameter",
                   "The value of a parameter in ScanRange element is invalid. Check the service API documentation and "
                   "try again.");
    }
  }
  if (ok && (!etype || strcasecmp(etype, "sql")))
    ok = efail(e, 400, "InvalidExpressionType", "The ExpressionType is invalid. Only SQL expressions are supported.");
  if (ok && (!have_in || !have_out))
    ok = efail(e, 400, "MissingRequiredParameter",
               "The SelectRequest entity is missing a required parameter. Check the service documentation and try again.");
  if (ok) {
    sel_err se = {0};
    s->stmt = sel_parse(expr ? expr : "", expr ? strlen(expr) : 0, &se);
    if (!s->stmt) ok = efail(e, se.status ? se.status : 400, se.code, "%s", se.msg);
  }
  free(expr);
  free(etype);
  buckets_buf_free(&x.tmp);
  if (!ok) {
    buckets_select_free(s);
    return NULL;
  }
  s->parquet_on = parquet;
  return s;
}

buckets_select *buckets_select_parse_node(const buckets_xml_doc *doc, size_t node, bool parquet, buckets_select_err *e) {
  memset(e, 0, sizeof(*e));
  return parse_node(doc, node, parquet, e);
}

buckets_select *buckets_select_parse(const char *body, size_t n, bool parquet, buckets_select_err *e) {
  memset(e, 0, sizeof(*e));
  buckets_xml_doc doc = {0};
  if (!buckets_xml_parse((buckets_str){body, n}, &doc) || doc.count == 0) {
    buckets_xml_doc_free(&doc);
    malformed(e, "XML syntax error");
    return NULL;
  }
  buckets_str root = doc.nodes[0].name;
  buckets_select *s = NULL;
  if (!buckets_str_eq_c(root, "SelectRequest") && !buckets_str_eq_c(root, "SelectObjectContentRequest")) {
    char m[160];
    snprintf(m, sizeof(m), "expected element type <SelectRequest> but have <%.*s>", (int)root.n, root.p);
    malformed(e, m);
  } else {
    s = parse_node(&doc, 0, parquet, e);
  }
  buckets_xml_doc_free(&doc);
  return s;
}

void buckets_select_free(buckets_select *s) {
  if (!s) return;
  sel_stmt_free(s->stmt);
  sel_csv_reader_free(s->csv);
  jv_reader_free(s->json);
  sel_parquet_free(s->pq);
  buckets_decomp_free(s->dc);
  sel_arena_free(&s->rec_arena);
  buckets_buf_free(&s->queue);
  buckets_buf_free(&s->payload);
  buckets_buf_free(&s->out);
  free(s);
}

/* ---- input ---- */

/* The object's plaintext within the scan range. */
static long range_read(void *ud, void *buf, size_t n) {
  buckets_select *s = ud;
  if (s->empty || s->left == 0) return 0;
  if (s->left > 0 && (int64_t)n > s->left) n = (size_t)s->left;
  long k = s->src->read(s->src->ud, buf, n);
  if (k > 0 && s->left > 0) s->left -= k;
  return k;
}

/* The decompressed input, counted. */
static long processed_read(void *ud, void *buf, size_t n) {
  buckets_select *s = ud;
  if (n == 0) return 0;
  if (s->have_pb) {
    s->have_pb = false;
    ((unsigned char *)buf)[0] = s->pb;
    return 1;
  }
  long k = buckets_decomp_read(s->dc, buf, n);
  if (k > 0) s->processed += k;
  return k;
}

static const char *const k_comp_names[] = {"NONE", "GZIP", "BZIP2", "ZSTD", "LZ4", "S2", "SNAPPY"};

static bool decomp_error(buckets_select *s, buckets_select_err *e) {
  buckets_decomp_err de = buckets_decomp_error(s->dc);
  if (de == BUCKETS_DECOMP_ERR_FORMAT)
    return efail(e, 400, "InvalidCompressionFormat",
                 "%s is not applicable to the queried object. Please correct the request and try again.",
                 k_comp_names[s->comp]);
  if (de == BUCKETS_DECOMP_ERR_TRUNCATED || s->comp != BUCKETS_DECOMP_NONE)
    return efail(e, 400, "TruncatedInput",
                 "Object decompression failed. Check that the object is properly compressed using the format specified "
                 "in the request.");
  return efail(e, 500, "InternalError", "We encountered an internal error, please try again.");
}

static bool internal(buckets_select_err *e) {
  return efail(e, 500, "InternalError", "We encountered an internal error, please try again.");
}

static bool internal_cause(buckets_select_err *e, const char *cause) {
  return efail(e, 500, "InternalError", "We encountered an internal error, please try again.: cause(%s)", cause);
}

bool buckets_select_open(buckets_select *s, const buckets_select_source *src, buckets_select_err *e) {
  memset(e, 0, sizeof(*e));
  s->src = src;
  double t = now();
  s->last_write = s->last_flush = s->last_progress = t;
  if (s->in == IN_PARQUET) {
    if (!s->parquet_on) return internal_cause(e, "parquet format parsing not enabled on server");
    if (s->have_start || s->have_end) return internal_cause(e, "parquet format does not support offsets");
    sel_err se = {0};
    s->pq = sel_parquet_open(src, &se);
    if (!s->pq) return efail(e, se.status ? se.status : 400, se.code, "%s", se.msg);
    return true;
  }
  /* ScanRange: bytes [start, end], [start, EOF) or the last `end` bytes */
  int64_t off = 0, size = src->size;
  s->left = -1;
  if (s->have_start && s->have_end) off = (int64_t)s->start, s->left = (int64_t)(s->end - s->start + 1);
  else if (s->have_start) off = (int64_t)s->start;
  else if (s->have_end) off = size - (int64_t)s->end;
  if (size == 0 && off == 0) s->empty = true; /* MinIO cannot seek into an empty object; it has no records */
  else if (off < 0) return internal_cause(e, "seek to invalid negative offset");
  else if (off >= size) return internal_cause(e, "seek past end of object");
  if (!s->empty && !src->open(src->ud, off)) return internal(e);
  s->dc = buckets_decomp_new(s->comp, range_read, s);
  if (s->comp == BUCKETS_DECOMP_GZIP && !s->empty) {
    /* gzip.NewReader reads the header at once */
    long k = buckets_decomp_read(s->dc, &s->pb, 1);
    if (k < 0) return decomp_error(s, e);
    if (k == 0)
      return efail(e, 400, "TruncatedInput",
                   "Object decompression failed. Check that the object is properly compressed using the format "
                   "specified in the request.");
    s->processed++;
    s->have_pb = true;
  }
  if (s->in == IN_CSV) {
    sel_err se = {0};
    s->csv = sel_csv_reader_new(processed_read, s, &s->csv_in, &se);
    if (!s->csv) {
      if (buckets_decomp_error(s->dc)) return decomp_error(s, e);
      if (!se.code || !strcmp(se.code, "InternalError")) return internal(e);
      return efail(e, se.status ? se.status : 400, se.code, "%s", se.msg);
    }
  } else {
    s->json = jv_reader_new(processed_read, s, s->json_lines ? -1 : MAX_DOCUMENT);
  }
  return true;
}

/* ---- the event stream ---- */

static void put_u32(buckets_buf *b, uint32_t v) {
  unsigned char x[4] = {(unsigned char)(v >> 24), (unsigned char)(v >> 16), (unsigned char)(v >> 8), (unsigned char)v};
  buckets_buf_append(b, x, 4);
}

static void header(buckets_buf *h, const char *name, const char *value, size_t vn) {
  size_t nn = strlen(name);
  unsigned char x[3] = {(unsigned char)nn};
  buckets_buf_append(h, x, 1);
  buckets_buf_append(h, name, nn);
  x[0] = 7;
  x[1] = (unsigned char)(vn >> 8);
  x[2] = (unsigned char)vn;
  buckets_buf_append(h, x, 3);
  buckets_buf_append(h, value, vn);
}

static void message(buckets_select *s, const buckets_buf *hdr, const void *payload, size_t pn) {
  buckets_buf *b = &s->out;
  size_t start = b->len;
  put_u32(b, (uint32_t)(4 + 4 + 4 + hdr->len + pn + 4));
  put_u32(b, (uint32_t)hdr->len);
  put_u32(b, (uint32_t)crc32(0, (const unsigned char *)b->data + start, 8));
  buckets_buf_append(b, hdr->data, hdr->len);
  if (pn) buckets_buf_append(b, payload, pn);
  put_u32(b, (uint32_t)crc32(0, (const unsigned char *)b->data + start, (uInt)(b->len - start)));
  s->last_write = now();
}

static void event(buckets_select *s, const char *type, const char *ctype, const void *payload, size_t pn) {
  buckets_buf h = BUCKETS_BUF_INIT;
  header(&h, ":message-type", "event", 5);
  if (ctype) header(&h, ":content-type", ctype, strlen(ctype));
  header(&h, ":event-type", type, strlen(type));
  message(s, &h, payload, pn);
  buckets_buf_free(&h);
}

static size_t max_payload(void) {
  /* the Records headers are 85 bytes */
  return MAX_MESSAGE - 4 - 4 - 4 - 85 - 4;
}

static void flush_records(buckets_select *s) {
  if (!s->payload.len) return;
  event(s, "Records", "application/octet-stream", s->payload.data, s->payload.len);
  s->returned += (int64_t)s->payload.len;
  buckets_buf_reset(&s->payload);
  s->last_flush = now();
}

/* The writer takes the queued records: whole messages go out as the
 * payload fills. */
static void send_queue(buckets_select *s) {
  size_t cap = max_payload();
  const char *p = s->queue.data;
  size_t n = s->queue.len;
  while (n) {
    size_t room = cap - s->payload.len, k = n < room ? n : room;
    buckets_buf_append(&s->payload, p, k);
    p += k, n -= k;
    if (s->payload.len == cap) flush_records(s);
  }
  buckets_buf_reset(&s->queue);
  s->queued = 0;
}

static void stats_payload(buckets_select *s, buckets_buf *b, const char *tag, bool final) {
  int64_t scanned = -1, processed = -1;
  if (!s->pq) {
    scanned = s->dc ? buckets_decomp_consumed(s->dc) : 0;
    processed = s->processed;
  }
  (void)final;
  buckets_buf_appendf(b,
                      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><%s><BytesScanned>%lld</BytesScanned><BytesProcessed>%lld"
                      "</BytesProcessed><BytesReturned>%lld</BytesReturned></%s>",
                      tag, (long long)scanned, (long long)processed, (long long)s->returned, tag);
}

static void finish(buckets_select *s) {
  flush_records(s);
  buckets_buf b = BUCKETS_BUF_INIT;
  stats_payload(s, &b, "Stats", true);
  event(s, "Stats", "text/xml", b.data, b.len);
  buckets_buf_free(&b);
  event(s, "End", NULL, NULL, 0);
  s->finished = true;
}

static void finish_error(buckets_select *s, const char *code, const char *msg) {
  /* records still queued are dropped, as MinIO drops them */
  buckets_buf_reset(&s->queue);
  flush_records(s);
  buckets_buf h = BUCKETS_BUF_INIT;
  header(&h, ":message-type", "error", 5);
  header(&h, ":error-message", msg, strlen(msg));
  header(&h, ":error-code", code, strlen(code));
  message(s, &h, NULL, 0);
  buckets_buf_free(&h);
  s->finished = true;
}

static void ticks(buckets_select *s) {
  double t = now();
  if (t - s->last_flush >= 0.5 && s->payload.len) flush_records(s);
  if (t - s->last_write >= 1.0) event(s, "Cont", NULL, NULL, 0);
  if (s->progress && t - s->last_progress >= 60.0) {
    buckets_buf b = BUCKETS_BUF_INIT;
    stats_payload(s, &b, "Progress", false);
    event(s, "Progress", "text/xml", b.data, b.len);
    buckets_buf_free(&b);
    s->last_progress = t;
  }
}

/* Marshals an output record onto the queue; false with e when it fails. */
static bool enqueue(buckets_select *s, const sel_orec *r, sel_err *e) {
  size_t before = s->queue.len;
  if (s->out_csv) {
    if (!(s->csv_out.field_delim && s->csv_out.field_delim != '"' && s->csv_out.field_delim != '\r' &&
          s->csv_out.field_delim != '\n'))
      return sel_fail(e, "InternalError", "csv: invalid field or comment delimiter");
    sel_orec_write_csv(&s->queue, r, &s->csv_out);
  } else {
    sel_orec_write_json(&s->queue, r);
  }
  buckets_buf_append_c(&s->queue, s->out_rdelim);
  if (s->queue.len - before > MAX_RECORD_SIZE) {
    s->queue.len = before;
    e->code = "OverMaxRecordSize";
    snprintf(e->msg, sizeof(e->msg), "The length of a record in the input or result is greater than maxCharsPerRecord of 1 MB.");
    return false;
  }
  s->queued++;
  return true;
}

/* 1: a record, 0: the end, -1: an error. */
static int next_record(buckets_select *s, sel_record *rec, sel_err *e) {
  if (s->csv) return sel_csv_reader_next(s->csv, &s->rec_arena, rec, e);
  if (s->pq) return sel_parquet_next(s->pq, &s->rec_arena, rec, e);
  jv v;
  int k = jv_reader_next(s->json, &s->rec_arena, &v, e);
  if (k <= 0) {
    /* LINES errors carry the decoder's message, DOCUMENT ones MinIO's JSONParsingError */
    if (k < 0 && s->json_lines && *jv_reader_detail(s->json)) snprintf(e->msg, sizeof(e->msg), "%s", jv_reader_detail(s->json));
    return k;
  }
  rec->fmt = SEL_FMT_JSON;
  if (v.t == JV_OBJ) {
    rec->obj = v;
  } else {
    /* a non-object is the single column _1 */
    jv_kv *kv = sel_alloc(&s->rec_arena, sizeof(jv_kv));
    kv->k = "_1";
    kv->kn = 2;
    kv->v = v;
    rec->obj = (jv){.t = JV_OBJ, .o = {kv, 1}};
  }
  return 1;
}

/* Evaluates records until messages are ready to send, or the end. */
static void step(buckets_select *s) {
  sel_err e = {0};
  bool agg = sel_stmt_aggregated(s->stmt);
  for (int i = 0; !s->finished && s->out.len == s->out_pos; i++) {
    if ((i & 63) == 63) {
      ticks(s);
      if (s->out.len > s->out_pos) return;
    }
    if (sel_stmt_limit_reached(s->stmt)) {
      send_queue(s);
      finish(s);
      return;
    }
    sel_arena_reset(&s->rec_arena);
    sel_record rec = {0};
    int k = s->empty ? 0 : next_record(s, &rec, &e);
    if (k < 0 && s->dc && buckets_decomp_error(s->dc)) snprintf(e.msg, sizeof(e.msg), "%s", buckets_decomp_message(s->dc));
    if (k < 0) {
      if (e.code && !strcmp(e.code, "OverMaxRecordSize")) finish_error(s, e.code, e.msg);
      else finish_error(s, "InternalError", e.msg);
      return;
    }
    if (k == 0) {
      if (agg) {
        sel_orec out = {.csv = s->out_csv};
        if (!sel_aggregate_result(s->stmt, &s->rec_arena, &out, &e)) {
          finish_error(s, "InternalError", e.msg);
          return;
        }
        if (!enqueue(s, &out, &e)) {
          finish_error(s, e.code ? e.code : "InternalError", e.msg);
          return;
        }
      }
      send_queue(s);
      finish(s);
      return;
    }
    sel_record *recs;
    size_t nr;
    if (!sel_eval_from(s->stmt, &s->rec_arena, &rec, &recs, &nr, &e)) {
      finish_error(s, "InternalError", e.msg);
      return;
    }
    for (size_t j = 0; j < nr; j++) {
      if (agg) {
        if (!sel_aggregate_row(s->stmt, &s->rec_arena, &recs[j], &e)) {
          finish_error(s, "InternalError", e.msg);
          return;
        }
        continue;
      }
      sel_orec out = {.csv = s->out_csv};
      bool emit;
      if (!sel_eval(s->stmt, &s->rec_arena, &recs[j], &out, &emit, &e)) {
        finish_error(s, "InternalError", e.msg);
        return;
      }
      if (!emit) continue;
      if (!enqueue(s, &out, &e)) {
        finish_error(s, e.code ? e.code : "InternalError", e.msg);
        return;
      }
      if (sel_stmt_limit_reached(s->stmt)) {
        send_queue(s);
        finish(s);
        return;
      }
      if (s->queued >= QUEUE_MAX) send_queue(s);
    }
  }
}

long buckets_select_read(void *ud, void *buf, size_t n) {
  buckets_select *s = ud;
  while (s->out.len == s->out_pos) {
    if (s->finished) return 0;
    buckets_buf_reset(&s->out);
    s->out_pos = 0;
    step(s);
  }
  size_t k = s->out.len - s->out_pos;
  if (k > n) k = n;
  memcpy(buf, s->out.data + s->out_pos, k);
  s->out_pos += k;
  return (long)k;
}
