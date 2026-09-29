/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* S3 Select: MinIO's exact event streams for its CSV and JSON input tests,
 * and Go's number and time formatting. The full query corpus runs against
 * MinIO in tests/integration/select.sh. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "core/buf.h"
#include "select/sel.h"
#include "select/select.h"

#include "select_vectors.inc"

typedef struct {
  const char *data;
  size_t n, pos;
} mem;

static bool m_open(void *ud, int64_t off) {
  mem *m = ud;
  m->pos = (size_t)off;
  return true;
}
static long m_read(void *ud, void *buf, size_t n) {
  mem *m = ud;
  size_t k = m->n - m->pos < n ? m->n - m->pos : n;
  memcpy(buf, m->data + m->pos, k);
  m->pos += k;
  return (long)k;
}
static bool m_read_at(void *ud, int64_t off, void *buf, size_t n) {
  mem *m = ud;
  if ((size_t)off + n > m->n) return false;
  memcpy(buf, m->data + off, n);
  return true;
}

static void run(const char *data, const char *req, const unsigned char *want, size_t want_n) {
  buckets_select_err e;
  buckets_select *s = buckets_select_parse(req, strlen(req), false, &e);
  assert_non_null(s);
  mem m = {data, strlen(data), 0};
  buckets_select_source src = {&m, m_open, m_read, m_read_at, (int64_t)m.n};
  assert_true(buckets_select_open(s, &src, &e));
  buckets_buf out = BUCKETS_BUF_INIT;
  char buf[4096];
  long k;
  while ((k = buckets_select_read(s, buf, sizeof(buf))) > 0) buckets_buf_append(&out, buf, (size_t)k);
  assert_int_equal(out.len, want_n);
  assert_memory_equal(out.data, want, want_n);
  buckets_buf_free(&out);
  buckets_select_free(s);
}

#define RUN(fmt, i) run(k_##fmt##_data, k_##fmt##_req##i, k_##fmt##_want##i, sizeof(k_##fmt##_want##i))

static void test_csv_streams(void **state) {
  (void)state;
  RUN(csv, 0);
  RUN(csv, 1);
  RUN(csv, 2);
  RUN(csv, 3);
}

static void test_json_streams(void **state) {
  (void)state;
  RUN(json, 4);
  RUN(json, 5);
  RUN(json, 6);
}

static void check_g(double f, const char *want) {
  buckets_buf b = BUCKETS_BUF_INIT;
  sel_fmt_float_g(&b, f);
  buckets_buf_append_char(&b, 0);
  assert_string_equal(b.data, want);
  buckets_buf_free(&b);
}

static void check_json(double f, const char *want) {
  buckets_buf b = BUCKETS_BUF_INIT;
  sel_fmt_float_json(&b, f);
  buckets_buf_append_char(&b, 0);
  assert_string_equal(b.data, want);
  buckets_buf_free(&b);
}

static void test_floats(void **state) {
  (void)state;
  /* strconv.FormatFloat(f, 'g', -1, 64) */
  check_g(0, "0");
  check_g(1, "1");
  check_g(0.1, "0.1");
  check_g(123456, "123456");
  check_g(1234567, "1.234567e+06");
  check_g(100000000, "1e+08");
  check_g(0.0001, "0.0001");
  check_g(0.00001, "1e-05");
  check_g(-2.5, "-2.5");
  check_g(1e21, "1e+21");
  check_g(3.0 / 2 * 0.3, "0.44999999999999996");
  /* encoding/json */
  check_json(1, "1");
  check_json(100000000, "100000000");
  check_json(1e20, "100000000000000000000");
  check_json(1e21, "1e+21");
  check_json(1e-7, "1e-7");
  check_json(0.000001, "0.000001");
  check_json(1.5e-9, "1.5e-9");
  check_json(-0.0, "-0");
}

static void check_time(const char *in, const char *want) {
  sel_time t;
  assert_true(sel_time_parse(in, strlen(in), &t));
  buckets_buf b = BUCKETS_BUF_INIT;
  sel_time_format(&b, t);
  buckets_buf_append_char(&b, 0);
  assert_string_equal(b.data, want);
  buckets_buf_free(&b);
}

static void test_times(void **state) {
  (void)state;
  check_time("2010T", "2010T");
  check_time("2010-05T", "2010-05T");
  check_time("2010-05-06T", "2010-05-06T");
  check_time("2010-01-01T", "2010T");
  check_time("2010-05-06T7:08Z", "2010-05-06T07:08Z");
  check_time("2017-01-02T03:04:05.1234Z", "2017-01-02T03:04:05.1234Z");
  check_time("2017-01-02T03:04:05+05:30", "2017-01-02T03:04:05+05:30");
  check_time("2017-01-02T00:00+01:00", "2017-01-02T00:00+01:00");
  sel_time t;
  assert_false(sel_time_parse("2010-02-30T", 11, &t));
  assert_false(sel_time_parse("2010-13T", 8, &t));
  assert_false(sel_time_parse("2010", 4, &t));
  assert_false(sel_time_parse("2010-05-06T07:08", 16, &t));
}

static void test_parse_numbers(void **state) {
  (void)state;
  int64_t i;
  double f;
  assert_true(sel_parse_int("-9223372036854775808", 20, &i) && i == INT64_MIN);
  assert_false(sel_parse_int("9223372036854775808", 19, &i));
  assert_false(sel_parse_int("1_000", 5, &i));
  assert_true(sel_parse_float("1e3", 3, &f) && f == 1000);
  assert_true(sel_parse_float(".5", 2, &f) && f == 0.5);
  assert_true(sel_parse_float("Inf", 3, &f) && f > 1e308);
  assert_false(sel_parse_float("1e", 2, &f));
  assert_false(sel_parse_float("0x10", 4, &f)); /* hex needs a p exponent */
  assert_true(sel_parse_float("0x1p4", 5, &f) && f == 16);
  assert_false(sel_parse_float("1e400", 5, &f));
}

static void test_errors(void **state) {
  (void)state;
  buckets_select_err e;
  static const char bad[] = "<SelectRequest><Expression>SELECT * FROM x</Expression><ExpressionType>SQL</ExpressionType>"
                            "<InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/>"
                            "</OutputSerialization></SelectRequest>";
  assert_null(buckets_select_parse(bad, strlen(bad), false, &e));
  assert_string_equal(e.code, "BadTableName");
  static const char noout[] = "<SelectRequest><Expression>SELECT * FROM s3object</Expression>"
                              "<ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization>"
                              "</SelectRequest>";
  assert_null(buckets_select_parse(noout, strlen(noout), false, &e));
  assert_string_equal(e.code, "MissingRequiredParameter");
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_csv_streams), cmocka_unit_test(test_json_streams), cmocka_unit_test(test_floats),
      cmocka_unit_test(test_times),       cmocka_unit_test(test_parse_numbers), cmocka_unit_test(test_errors),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
