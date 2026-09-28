/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>

#include "s3/errors.h"
#include "s3/xml.h"

static void test_writer_escapes(void **state) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_xml_elem(&b, "Key", "a<b>&\"c'\n");
  assert_string_equal(b.data, "<Key>a&lt;b&gt;&amp;&#34;c&#39;&#xA;</Key>");
  buckets_buf_free(&b);
}

static void test_error_document(void **state) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_s3_error_xml(&b, BUCKETS_ERR_NO_SUCH_BUCKET, "/nope", "nope", NULL, "REQ", "HOST");
  assert_string_equal(b.data,
                      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                      "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>"
                      "<BucketName>nope</BucketName><Resource>/nope</Resource><RequestId>REQ</RequestId>"
                      "<HostId>HOST</HostId></Error>");
  assert_int_equal(buckets_s3_error_get(BUCKETS_ERR_NO_SUCH_BUCKET)->status, 404);
  assert_int_equal(buckets_s3_error_get(BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH)->status, 403);
  buckets_buf_free(&b);
}

static void test_parse_create_bucket(void **state) {
  const char *in =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      "<!-- comment -->\n"
      "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
      "  <LocationConstraint>eu-west-1</LocationConstraint>\n"
      "</CreateBucketConfiguration>\n";
  buckets_xml_doc doc;
  assert_true(buckets_xml_parse(buckets_str_c(in), &doc));
  assert_true(buckets_str_eq_c(doc.nodes[0].name, "CreateBucketConfiguration"));
  size_t lc = buckets_xml_child(&doc, 0, "LocationConstraint");
  assert_int_not_equal(lc, 0);
  assert_true(buckets_str_eq_c(doc.nodes[lc].text, "eu-west-1"));
  assert_int_equal(buckets_xml_child(&doc, 0, "Missing"), 0);
  buckets_xml_doc_free(&doc);
}

static void test_parse_siblings_and_prefixes(void **state) {
  const char *in = "<s3:Delete><s3:Object><Key>a&amp;b</Key></s3:Object><s3:Object><Key>c</Key></s3:Object>"
                   "<Quiet>true</Quiet><Empty/></s3:Delete>";
  buckets_xml_doc doc;
  assert_true(buckets_xml_parse(buckets_str_c(in), &doc));
  int objects = 0;
  for (size_t i = doc.nodes[0].first_child; i; i = doc.nodes[i].next_sibling) {
    if (buckets_str_eq_c(doc.nodes[i].name, "Object")) objects++;
  }
  assert_int_equal(objects, 2);
  size_t obj = buckets_xml_child(&doc, 0, "Object");
  size_t key = buckets_xml_child(&doc, obj, "Key");
  buckets_buf out = BUCKETS_BUF_INIT;
  assert_true(buckets_xml_unescape(doc.nodes[key].text, &out));
  assert_string_equal(out.data, "a&b");
  buckets_buf_free(&out);
  assert_int_not_equal(buckets_xml_child(&doc, 0, "Empty"), 0);
  buckets_xml_doc_free(&doc);
}

static void test_parse_rejects(void **state) {
  static const char *const bad[] = {
      "",
      "<a>",
      "<a></b>",
      "<a></a><b></b>",
      "text<a/>",
      "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
      "<a><![CDATA[x]]></a>",
      "<a attr=unquoted></a>",
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    buckets_xml_doc doc;
    assert_false(buckets_xml_parse(buckets_str_c(bad[i]), &doc));
  }
  /* Nesting beyond the depth limit is refused rather than recursing. */
  buckets_buf deep = BUCKETS_BUF_INIT;
  for (int i = 0; i < 64; i++) buckets_buf_append_c(&deep, "<a>");
  for (int i = 0; i < 64; i++) buckets_buf_append_c(&deep, "</a>");
  buckets_xml_doc doc;
  assert_false(buckets_xml_parse(buckets_buf_str(&deep), &doc));
  buckets_buf_free(&deep);
}

static void test_unescape(void **state) {
  buckets_buf out = BUCKETS_BUF_INIT;
  assert_true(buckets_xml_unescape(buckets_str_c("&lt;&#65;&#x42;&#x20AC;&gt;"), &out));
  assert_string_equal(out.data, "<AB\xE2\x82\xAC>");
  buckets_buf_reset(&out);
  assert_false(buckets_xml_unescape(buckets_str_c("&bogus;"), &out));
  assert_false(buckets_xml_unescape(buckets_str_c("&#0;"), &out));
  assert_false(buckets_xml_unescape(buckets_str_c("&amp"), &out));
  buckets_buf_free(&out);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_writer_escapes),     cmocka_unit_test(test_error_document),
      cmocka_unit_test(test_parse_create_bucket), cmocka_unit_test(test_parse_siblings_and_prefixes),
      cmocka_unit_test(test_parse_rejects),       cmocka_unit_test(test_unescape),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
