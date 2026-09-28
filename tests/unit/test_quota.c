/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>

#include "bucket/quota.h"

static void test_parse(void **state) {
  buckets_quota q;
  char err[256];
  const char *j = "{\"QUOTA\":5,\"size\":100,\"quotatype\":\"hard\",\"other\":[1]}";
  assert_true(buckets_quota_parse(j, strlen(j), &q, err, sizeof(err)));
  assert_int_equal(q.quota, 5);
  assert_int_equal(buckets_quota_hard_limit(&q), 100);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_quota_json(&q, &b);
  assert_string_equal(b.data, "{\"quota\":5,\"size\":100,\"rate\":0,\"requests\":0,\"quotatype\":\"hard\"}");
  buckets_buf_free(&b);
  assert_true(buckets_quota_parse("null", 4, &q, err, sizeof(err)));
  assert_int_equal(buckets_quota_hard_limit(&q), 0);
  assert_false(buckets_quota_parse("{\"quota\":1}", 11, &q, err, sizeof(err))); /* quota needs a type */
  assert_false(buckets_quota_parse("{\"size\":\"1\"}", 12, &q, err, sizeof(err)));
  assert_string_equal(err, "json: cannot unmarshal string into Go struct field BucketQuota.size of type uint64");
  assert_false(buckets_quota_parse("{", 1, &q, err, sizeof(err)));
  assert_string_equal(err, "unexpected end of JSON input");
}

static void test_exceeded(void **state) {
  buckets_quota q = {.size = 100};
  strcpy(q.type, "hard");
  assert_false(buckets_quota_exceeded(&q, 99, 0));
  assert_true(buckets_quota_exceeded(&q, 100, 0)); /* >= */
  assert_false(buckets_quota_exceeded(&q, 49, 50));
  assert_true(buckets_quota_exceeded(&q, 50, 50));
  assert_false(buckets_quota_exceeded(&q, -1, 1000)); /* unknown size */
  strcpy(q.type, "");
  assert_false(buckets_quota_exceeded(&q, 1000, 0)); /* not a hard quota */
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_parse), cmocka_unit_test(test_exceeded)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
