/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>

#include "core/buf.h"
#include "core/query.h"
#include "core/str.h"
#include "core/timefmt.h"
#include "s3/bucketname.h"

static void test_buf(void **state) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "hello");
  buckets_buf_appendf(&b, " %d", 42);
  assert_string_equal(b.data, "hello 42");
  buckets_buf_consume(&b, 6);
  assert_string_equal(b.data, "42");
  for (int i = 0; i < 1000; i++) buckets_buf_append_char(&b, 'x');
  assert_int_equal(b.len, 1002);
  buckets_buf_free(&b);
}

static void test_str(void **state) {
  buckets_str h, t;
  assert_true(buckets_str_cut(buckets_str_c("a=b=c"), '=', &h, &t));
  assert_true(buckets_str_eq_c(h, "a"));
  assert_true(buckets_str_eq_c(t, "b=c"));
  assert_false(buckets_str_cut(buckets_str_c("abc"), '=', &h, &t));
  assert_true(buckets_str_eq_c(h, "abc"));
  assert_int_equal(t.n, 0);
  assert_true(buckets_str_ieq_c(buckets_str_c("Content-Type"), "content-type"));
  assert_true(buckets_str_eq_c(buckets_str_trim(buckets_str_c("  x y \t")), "x y"));

  char out[32];
  long n = buckets_url_decode(buckets_str_c("a%20b+c%2Fd"), out, true);
  assert_int_equal(n, 7);
  assert_memory_equal(out, "a b c/d", 7);
  assert_int_equal(buckets_url_decode(buckets_str_c("bad%2"), out, false), -1);
  assert_int_equal(buckets_url_decode(buckets_str_c("bad%zz"), out, false), -1);
}

static void test_time(void **state) {
  time_t t;
  assert_true(buckets_time_parse_amz(buckets_str_c("20150830T123600Z"), &t));
  assert_int_equal((long long)t, 1440938160LL);
  char buf[64];
  buckets_time_amz(t, buf);
  assert_string_equal(buf, "20150830T123600Z");
  buckets_time_iso8601(t, buf);
  assert_string_equal(buf, "2015-08-30T12:36:00.000Z");
  buckets_time_http(t, buf);
  assert_string_equal(buf, "Sun, 30 Aug 2015 12:36:00 GMT");
  time_t t2;
  assert_true(buckets_time_parse_http(buckets_str_c(buf), &t2));
  assert_int_equal((long long)t2, (long long)t);
  assert_false(buckets_time_parse_amz(buckets_str_c("20151330T123600Z"), &t));
  assert_false(buckets_time_parse_amz(buckets_str_c("2015-08-30T12:36:00Z"), &t));
}

static void test_query(void **state) {
  buckets_query q;
  assert_true(buckets_query_parse(buckets_str_c("location&prefix=a%2Fb&x=1+2&x=3"), &q));
  assert_int_equal(q.n, 4);
  assert_string_equal(buckets_query_get(&q, "location"), "");
  assert_string_equal(buckets_query_get(&q, "prefix"), "a/b");
  assert_string_equal(buckets_query_get(&q, "x"), "1 2");
  assert_null(buckets_query_get(&q, "missing"));
  buckets_query_free(&q);

  assert_false(buckets_query_parse(buckets_str_c("a=%zz&b=1;c=2&d=4"), &q));
  assert_int_equal(q.n, 1); /* only d survives */
  assert_string_equal(buckets_query_get(&q, "d"), "4");
  buckets_query_free(&q);
}

static void test_bucket_names(void **state) {
  assert_true(buckets_bucket_name_valid_strict("my-bucket.1"));
  assert_false(buckets_bucket_name_valid_strict("ab"));
  assert_false(buckets_bucket_name_valid_strict("MyBucket"));
  assert_false(buckets_bucket_name_valid_strict("my..bucket"));
  assert_false(buckets_bucket_name_valid_strict("my-.bucket"));
  assert_false(buckets_bucket_name_valid_strict("-bucket"));
  assert_false(buckets_bucket_name_valid_strict("192.168.1.1"));
  assert_false(buckets_bucket_name_valid_strict("a/b/c"));
  assert_true(buckets_bucket_name_valid("My_Bucket"));
  assert_false(buckets_bucket_name_valid("../etc"));
  assert_true(buckets_bucket_name_reserved(".minio.sys"));
  assert_true(buckets_bucket_name_reserved("minio"));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_buf),   cmocka_unit_test(test_str),          cmocka_unit_test(test_time),
      cmocka_unit_test(test_query), cmocka_unit_test(test_bucket_names),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
