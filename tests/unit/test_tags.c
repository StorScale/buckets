/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "bucket/tags.h"

static char *str_of(const buckets_tags *t) {
  static char s[1024];
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_tags_string(t, &b);
  snprintf(s, sizeof(s), "%s", b.data ? b.data : "");
  buckets_buf_free(&b);
  return s;
}

static void test_query_roundtrip(void **state) {
  buckets_tags t;
  buckets_tags_error e;
  assert_true(buckets_tags_parse_query("z=1&a+b=x%2Fy&&empty=&k", true, &t, &e));
  assert_int_equal(t.n, 4);
  assert_string_equal(buckets_tags_get(&t, "a b"), "x/y");
  assert_string_equal(buckets_tags_get(&t, "k"), "");
  assert_string_equal(str_of(&t), "a+b=x%2Fy&empty=&k=&z=1");
  buckets_tags_free(&t);
}

static void test_query_errors(void **state) {
  buckets_tags t;
  buckets_tags_error e;
  char msg[256];
  assert_false(buckets_tags_parse_query("a=1&a=2", true, &t, &e));
  assert_string_equal(buckets_tags_err_code(&e), "InvalidTag");
  buckets_tags_err_message(&e, msg, sizeof(msg));
  assert_string_equal(msg, "Cannot provide multiple Tags with the same key");
  assert_false(buckets_tags_parse_query("a=%zz", true, &t, &e));
  assert_string_equal(buckets_tags_err_code(&e), "XMinioInvalidObjectName");
  buckets_tags_err_message(&e, msg, sizeof(msg));
  assert_string_equal(msg, "Object name contains unsupported characters. (invalid URL escape \"%zz\")");
  /* minio-go forgets the escape error once a later tag parses */
  assert_true(buckets_tags_parse_query("a=%zz&b=1", true, &t, &e));
  assert_int_equal(t.n, 1);
  buckets_tags_free(&t);
  assert_false(buckets_tags_parse_query("k=a%2Ab", true, &t, &e)); /* '*' is not allowed */
  assert_int_equal(e.code, BUCKETS_TAGS_INVALID_VALUE);
  assert_false(buckets_tags_parse_query("1&2&3&4&5&6&7&8&9&10&11", true, &t, &e));
  assert_int_equal(e.code, BUCKETS_TAGS_TOO_MANY_OBJECT);
  assert_true(buckets_tags_parse_query("1&2&3&4&5&6&7&8&9&10&11", false, &t, &e));
  buckets_tags_free(&t);
}

static void test_xml(void **state) {
  const char *doc = "<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>"
                    "<Tag><Key>b</Key><Value>2 &amp; 3</Value></Tag><Tag><Key>a</Key><Value></Value></Tag>"
                    "</TagSet></Tagging>";
  buckets_tags t;
  buckets_tags_error e;
  assert_false(buckets_tags_parse_xml(doc, strlen(doc), true, &t, &e)); /* '&' is not a valid tag character */
  assert_int_equal(e.code, BUCKETS_TAGS_INVALID_VALUE);
  doc = "<Tagging><TagSet><Tag><Key>b</Key><Value>2=3</Value></Tag><Tag><Key>a</Key></Tag></TagSet></Tagging>";
  assert_true(buckets_tags_parse_xml(doc, strlen(doc), true, &t, &e));
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_tags_xml(&t, &b);
  assert_string_equal(b.data, "<Tagging><TagSet><Tag><Key>a</Key><Value></Value></Tag>"
                              "<Tag><Key>b</Key><Value>2=3</Value></Tag></TagSet></Tagging>");
  assert_string_equal(str_of(&t), "a=&b=2%3D3");
  buckets_buf_free(&b);
  buckets_tags_free(&t);
  doc = "<Tagging><TagSet><Tag><Key>a</Key></Tag><Tag><Key>a</Key></Tag></TagSet></Tagging>";
  assert_false(buckets_tags_parse_xml(doc, strlen(doc), true, &t, &e));
  assert_int_equal(e.code, BUCKETS_TAGS_DUPLICATE_KEY);
  doc = "<Tags/>";
  assert_false(buckets_tags_parse_xml(doc, strlen(doc), true, &t, &e));
  assert_int_equal(e.code, BUCKETS_TAGS_MALFORMED_XML);
  doc = "<Tagging><TagSet></TagSet></Tagging>";
  assert_true(buckets_tags_parse_xml(doc, strlen(doc), false, &t, &e));
  assert_int_equal(t.n, 0);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_query_roundtrip),
      cmocka_unit_test(test_query_errors),
      cmocka_unit_test(test_xml),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
