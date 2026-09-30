/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* S3 Select: a SQL expression and input from the fuzzer, run to the end of
 * the event stream. Input: byte 0 picks the format, then the SQL up to a NUL,
 * then the object. */
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "select/select.h"

typedef struct {
  const uint8_t *p;
  size_t n, pos;
} mem;

static bool m_open(void *ud, int64_t off) {
  mem *m = ud;
  if (off < 0 || (size_t)off > m->n) return false;
  m->pos = (size_t)off;
  return true;
}

static long m_read(void *ud, void *buf, size_t n) {
  mem *m = ud;
  size_t k = m->n - m->pos < n ? m->n - m->pos : n;
  if (k > 509) k = 509; /* short reads */
  memcpy(buf, m->p + m->pos, k);
  m->pos += k;
  return (long)k;
}

static bool m_read_at(void *ud, int64_t off, void *buf, size_t n) {
  mem *m = ud;
  if (off < 0 || (size_t)off > m->n || n > m->n - (size_t)off) return false;
  memcpy(buf, m->p + off, n);
  return true;
}

static const char *const k_inputs[] = {
    "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
    "<CSV><FileHeaderInfo>NONE</FileHeaderInfo><AllowQuotedRecordDelimiter>TRUE</AllowQuotedRecordDelimiter></CSV>",
    "<CSV><FileHeaderInfo>IGNORE</FileHeaderInfo><FieldDelimiter>;</FieldDelimiter><Comments>#</Comments></CSV>",
    "<JSON><Type>LINES</Type></JSON>",
    "<JSON><Type>DOCUMENT</Type></JSON>",
    "<Parquet/>",
    "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV></InputSerialization><CompressionType>GZIP</CompressionType><X>",
};

static const char *const k_outputs[] = {"<CSV/>", "<JSON/>"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  size_t in = data[0] % (sizeof(k_inputs) / sizeof(*k_inputs)), out = (data[0] >> 4) & 1;
  const uint8_t *sql = data + 1, *end = memchr(sql, 0, size - 1);
  if (!end) return 0;
  buckets_buf req = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&req, "<SelectObjectContentRequest><Expression>");
  for (const uint8_t *p = sql; p < end; p++) {
    switch (*p) {
    case '<': buckets_buf_append_c(&req, "&lt;"); break;
    case '>': buckets_buf_append_c(&req, "&gt;"); break;
    case '&': buckets_buf_append_c(&req, "&amp;"); break;
    default: buckets_buf_append(&req, p, 1);
    }
  }
  buckets_buf_append_c(&req, "</Expression><ExpressionType>SQL</ExpressionType><InputSerialization>");
  buckets_buf_append_c(&req, k_inputs[in]);
  buckets_buf_append_c(&req, "</InputSerialization><OutputSerialization>");
  buckets_buf_append_c(&req, k_outputs[out]);
  buckets_buf_append_c(&req, "</OutputSerialization></SelectObjectContentRequest>");
  buckets_select_err e;
  buckets_select *s = buckets_select_parse(req.data, req.len, true, &e);
  if (s) {
    mem m = {end + 1, size - (size_t)(end + 1 - data), 0};
    buckets_select_source src = {&m, m_open, m_read, m_read_at, (int64_t)m.n};
    if (buckets_select_open(s, &src, &e)) {
      char buf[4096];
      size_t total = 0;
      long k;
      while ((k = buckets_select_read(s, buf, sizeof(buf))) > 0 && total < (64u << 20)) total += (size_t)k;
    }
    buckets_select_free(s);
  }
  buckets_buf_free(&req);
  return 0;
}
