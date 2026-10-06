/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bucketspec.h"

static yyjson_doc *doc(const char *json) {
  yyjson_doc *d = yyjson_read(json, strlen(json), 0);
  assert_non_null(d);
  return d;
}

static void check(const char *json, bool ok, const char *want) {
  yyjson_doc *d = doc(json);
  char err[256] = "";
  bool got = bspec_check(yyjson_doc_get_root(d), err, sizeof(err));
  if (got != ok) fail_msg("%s: %s", json, err);
  if (want) assert_non_null(strstr(err, want));
  yyjson_doc_free(d);
}

static void test_check(void **state) {
  (void)state;
  check("{\"cluster\":\"store\"}", true, NULL);
  check(
      "{\"versioning\":true,\"objectLock\":true,\"quota\":\"100Gi\",\"encryption\":{\"sse\":\"S3\"},"
      "\"lifecycle\":[]}",
      true, NULL);
  check("{\"objectLock\":{\"mode\":\"GOVERNANCE\",\"days\":30}}", true, NULL);
  check("{\"objectLock\":{\"mode\":\"COMPLIANCE\",\"years\":1}}", true, NULL);
  check("{\"versioning\":\"yes\"}", false, "versioning");
  check("{\"versioning\":false,\"objectLock\":true}", false, "cannot be false");
  check("{\"objectLock\":{\"mode\":\"STRICT\",\"days\":1}}", false, "GOVERNANCE or COMPLIANCE");
  check("{\"objectLock\":{\"mode\":\"GOVERNANCE\"}}", false, "days or years");
  check("{\"objectLock\":{\"mode\":\"GOVERNANCE\",\"days\":1,\"years\":1}}", false, "days or years");
  check("{\"objectLock\":{\"mode\":\"GOVERNANCE\",\"days\":0}}", false, "positive");
  check("{\"quota\":\"lots\"}", false, "quota");
  check("{\"quota\":5}", false, "quota");
  check("{\"quota\":\"\"}", true, NULL);
  check("{\"encryption\":{}}", false, "kmsKey");
  check("{\"encryption\":{\"kmsKey\":\"k\",\"sse\":\"S3\"}}", false, "kmsKey");
  check("{\"encryption\":{\"sse\":\"C\"}}", false, "S3");
  check("{\"encryption\":null}", true, NULL);
  check("{\"lifecycle\":{}}", false, "list");
  check("{\"lifecycle\":[{\"expireDays\":1}]}", false, "needs an id");
  check("{\"lifecycle\":[{\"id\":\"a\",\"expireDays\":1},{\"id\":\"a\",\"expireDays\":2}]}", false,
        "used twice");
  check("{\"lifecycle\":[{\"id\":\"a\",\"prefix\":\"x/\"}]}", false, "does nothing");
  check("{\"lifecycle\":[{\"id\":\"a\",\"expireDays\":-1}]}", false, "positive");
  check("{\"lifecycle\":[{\"id\":\"a\",\"expireDays\":1,\"expireDeleteMarkers\":true}]}", false, "use two");
  check("{\"lifecycle\":[{\"id\":\"a\",\"noncurrentExpireDays\":3,\"expireDeleteMarkers\":true}]}", true,
        NULL);
}

static void test_size(void **state) {
  (void)state;
  uint64_t b;
  assert_true(bspec_size("100Gi", &b));
  assert_int_equal(b, 100ULL << 30);
  assert_true(bspec_size("1T", &b));
  assert_int_equal(b, 1000000000000ULL);
  assert_true(bspec_size("1.5Ki", &b));
  assert_int_equal(b, 1536);
  assert_true(bspec_size("500000", &b));
  assert_int_equal(b, 500000);
  assert_true(bspec_size("2GiB", &b));
  assert_int_equal(b, 2ULL << 30);
  assert_true(bspec_size("", &b));
  assert_int_equal(b, 0);
  assert_true(bspec_size(NULL, &b));
  assert_int_equal(b, 0);
  assert_false(bspec_size("10 parsecs", &b));
  assert_false(bspec_size("Gi", &b));
  assert_false(bspec_size("-1Gi", &b));
}

static void test_hash(void **state) {
  (void)state;
  yyjson_doc *a =
      doc("{\"cluster\":\"store\",\"versioning\":true,\"encryption\":{\"sse\":\"S3\"},\"quota\":\"1Gi\"}");
  yyjson_doc *b =
      doc("{\"quota\":\"1Gi\",\"encryption\":{\"sse\":\"S3\"},\"versioning\":true,\"cluster\":\"store\"}");
  yyjson_doc *c =
      doc("{\"cluster\":\"store\",\"versioning\":false,\"encryption\":{\"sse\":\"S3\"},\"quota\":\"1Gi\"}");
  yyjson_doc *e =
      doc("{\"cluster\":\"store\",\"versioning\":true,\"encryption\":{\"sse\":\"S3\"},\"quota\":\"1Gi\","
          "\"lifecycle\":[]}");
  char ha[17], hb[17], hc[17], he[17];
  bspec_hash(yyjson_doc_get_root(a), ha);
  bspec_hash(yyjson_doc_get_root(b), hb);
  bspec_hash(yyjson_doc_get_root(c), hc);
  bspec_hash(yyjson_doc_get_root(e), he);
  assert_int_equal(strlen(ha), 16);
  assert_string_equal(ha, hb); /* key order does not matter */
  assert_string_not_equal(ha, hc);
  assert_string_not_equal(ha, he); /* lifecycle: [] is a setting, not a missing one */
  yyjson_doc_free(a), yyjson_doc_free(b), yyjson_doc_free(c), yyjson_doc_free(e);
}

static void test_documents(void **state) {
  (void)state;
  buckets_buf b = BUCKETS_BUF_INIT;
  bspec_versioning_xml(true, &b);
  assert_non_null(strstr(b.data, "<Status>Enabled</Status>"));
  b.len = 0;
  bspec_versioning_xml(false, &b);
  buckets_buf_append_char(&b, '\0');
  assert_non_null(strstr(b.data, "<Status>Suspended</Status>"));

  yyjson_doc *d = doc("{\"mode\":\"GOVERNANCE\",\"days\":30}");
  b.len = 0;
  assert_true(bspec_object_lock_xml(yyjson_doc_get_root(d), &b));
  buckets_buf_append_char(&b, '\0');
  assert_string_equal(
      b.data,
      "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
      "<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode>"
      "<Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>");
  yyjson_doc_free(d);
  d = doc("true");
  b.len = 0;
  assert_false(bspec_object_lock_xml(yyjson_doc_get_root(d), &b));
  buckets_buf_append_char(&b, '\0');
  assert_null(strstr(b.data, "<Rule>"));
  yyjson_doc_free(d);

  b.len = 0;
  bspec_quota_json(1024, &b);
  buckets_buf_append_char(&b, '\0');
  assert_string_equal(b.data, "{\"quota\":1024,\"size\":1024,\"quotatype\":\"hard\"}");

  d = doc("{\"kmsKey\":\"a&b\"}");
  b.len = 0;
  assert_true(bspec_encryption_xml(yyjson_doc_get_root(d), &b));
  buckets_buf_append_char(&b, '\0');
  assert_non_null(
      strstr(b.data, "<SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>a&amp;b</KMSMasterKeyID>"));
  yyjson_doc_free(d);
  d = doc("{\"sse\":\"S3\"}");
  b.len = 0;
  assert_true(bspec_encryption_xml(yyjson_doc_get_root(d), &b));
  buckets_buf_append_char(&b, '\0');
  assert_non_null(strstr(b.data, "<SSEAlgorithm>AES256</SSEAlgorithm></Apply"));
  yyjson_doc_free(d);
  d = doc("null");
  b.len = 0;
  assert_false(bspec_encryption_xml(yyjson_doc_get_root(d), &b));
  yyjson_doc_free(d);

  d =
      doc("[{\"id\":\"tmp\",\"prefix\":\"tmp/"
          "\",\"expireDays\":7,\"noncurrentExpireDays\":30,\"abortIncompleteUploadDays\":2},"
          "{\"id\":\"markers\",\"expireDeleteMarkers\":true}]");
  b.len = 0;
  assert_true(bspec_lifecycle_xml(yyjson_doc_get_root(d), &b));
  buckets_buf_append_char(&b, '\0');
  assert_string_equal(
      b.data,
      "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
      "<Rule><ID>tmp</ID><Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter>"
      "<Expiration><Days>7</Days></Expiration>"
      "<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>"
      "<AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation>"
      "</AbortIncompleteMultipartUpload></Rule>"
      "<Rule><ID>markers</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>"
      "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>"
      "</LifecycleConfiguration>");
  yyjson_doc_free(d);
  d = doc("[]");
  b.len = 0;
  assert_false(bspec_lifecycle_xml(yyjson_doc_get_root(d), &b));
  yyjson_doc_free(d);
  buckets_buf_free(&b);
}

static void sig(const char *xml, const char *const *tags, const char *want) {
  buckets_buf b = BUCKETS_BUF_INIT;
  bspec_xml_sig(xml, strlen(xml), tags, &b);
  buckets_buf_append_char(&b, '\0');
  assert_string_equal(b.data, want);
  buckets_buf_free(&b);
}

static void test_signature(void **state) {
  (void)state;
  /* what was sent and what a server sends back, formatted differently */
  sig("<VersioningConfiguration xmlns=\"x\"><Status>Enabled</Status></VersioningConfiguration>",
      bspec_versioning_tags, "Status=Enabled;");
  sig("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration>\n  <Status> Enabled </Status>\n"
      "  <MFADelete>Disabled</MFADelete>\n</VersioningConfiguration>",
      bspec_versioning_tags, "Status=Enabled;");
  sig("<VersioningConfiguration/>", bspec_versioning_tags, "");
  sig("<LifecycleConfiguration><Rule><ID>a</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>"
      "<Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>",
      bspec_lifecycle_tags, "ID=a;Prefix=;Status=Enabled;Days=3;");
  sig("<A><Prefix/><Days>1</Days></A>", bspec_lifecycle_tags, "Days=1;");
  sig("<Rule><Days><X>1</X></Days></Rule>", bspec_lifecycle_tags, ""); /* not a text element */
  sig("<Days>1", bspec_lifecycle_tags, "");                            /* cut short */
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_check),     cmocka_unit_test(test_size),      cmocka_unit_test(test_hash),
      cmocka_unit_test(test_documents), cmocka_unit_test(test_signature),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
