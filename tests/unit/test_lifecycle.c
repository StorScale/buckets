/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "bucket/lifecycle.h"

#define DAY (86400LL * 1000000000LL)
#define T(y, m, d, h) ((int64_t)days_from_civil(y, m, d) * DAY + (int64_t)(h) * 3600LL * 1000000000LL)

static long days_from_civil(int y, int m, int d) {
  y -= m <= 2;
  long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (long)doe - 719468;
}

static void parse_ok(const char *xml, buckets_lifecycle *lc) {
  buckets_lc_error e;
  assert_true(buckets_lifecycle_parse(xml, strlen(xml), true, lc, &e));
  assert_true(buckets_lifecycle_validate(lc, false, NULL, NULL, &e));
}

static void test_expected_expiry(void **state) {
  /* ExpectedExpiryTime: days+1 later, down to midnight UTC */
  assert_int_equal(buckets_lc_expected_expiry(T(2024, 1, 1, 10), 1), T(2024, 1, 3, 0));
  assert_int_equal(buckets_lc_expected_expiry(T(2024, 1, 1, 0), 30), T(2024, 2, 1, 0));
  assert_int_equal(buckets_lc_expected_expiry(T(2024, 1, 1, 10), 0), T(2024, 1, 1, 10));
}

static void test_days_rule(void **state) {
  buckets_lifecycle lc;
  parse_ok("<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter>"
           "<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
           &lc);
  buckets_lc_obj o = {.name = "logs/a", .mod_time_ns = T(2024, 1, 1, 10), .size = 5, .version_id = "", .is_latest = true, .num_versions = 1};
  assert_int_equal(buckets_lifecycle_eval(&lc, &o, T(2024, 1, 2, 23), 0).action, BUCKETS_LC_NONE);
  buckets_lc_event e = buckets_lifecycle_eval(&lc, &o, T(2024, 1, 3, 1), 0);
  assert_int_equal(e.action, BUCKETS_LC_DELETE);
  assert_string_equal(e.rule_id, "r");
  o.name = "other/a";
  assert_int_equal(buckets_lifecycle_eval(&lc, &o, T(2025, 1, 1, 0), 0).action, BUCKETS_LC_NONE);
  o.name = "logs/a";
  char v[256];
  const char *h = buckets_lifecycle_prediction(&lc, &o, v, sizeof(v));
  assert_string_equal(h, "x-amz-expiration");
  assert_string_equal(v, "expiry-date=\"Wed, 03 Jan 2024 00:00:00 GMT\", rule-id=\"r\"");
  buckets_lifecycle_free(&lc);
}

static void test_all_versions_and_noncurrent(void **state) {
  buckets_lifecycle lc;
  parse_ok("<LifecycleConfiguration><Rule><ID>all</ID><Status>Enabled</Status><Filter><Prefix>a/</Prefix></Filter>"
           "<Expiration><Days>2</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration></Rule>"
           "<Rule><ID>nc</ID><Status>Enabled</Status><Filter><Prefix>n/</Prefix></Filter>"
           "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions>"
           "</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
           &lc);
  int64_t now = T(2024, 6, 1, 0);
  buckets_lc_obj v[5];
  buckets_lc_event ev[5];
  for (int i = 0; i < 5; i++) {
    v[i] = (buckets_lc_obj){.name = "a/x", .mod_time_ns = T(2024, 1, 5 - i, 0), .size = 1, .version_id = "v",
                            .is_latest = i == 0, .num_versions = 5, .successor_mod_time_ns = i ? T(2024, 1, 6 - i, 0) : 0};
  }
  buckets_lifecycle_eval_versions(&lc, false, v, 5, now, ev);
  assert_int_equal(ev[0].action, BUCKETS_LC_DELETE_ALL_VERSIONS);
  assert_int_equal(ev[1].action, BUCKETS_LC_NONE); /* the loop stops */
  buckets_lifecycle_eval_versions(&lc, true, v, 5, now, ev); /* object lock: never all versions */
  assert_int_equal(ev[0].action, BUCKETS_LC_NONE);
  for (int i = 0; i < 5; i++) v[i].name = "n/x";
  buckets_lifecycle_eval_versions(&lc, false, v, 5, now, ev);
  assert_int_equal(ev[0].action, BUCKETS_LC_NONE);
  assert_int_equal(ev[1].action, BUCKETS_LC_NONE); /* two newer noncurrent versions are kept */
  assert_int_equal(ev[2].action, BUCKETS_LC_NONE);
  assert_int_equal(ev[3].action, BUCKETS_LC_DELETE_VERSION);
  assert_int_equal(ev[4].action, BUCKETS_LC_DELETE_VERSION);
  v[4].locked = true;
  buckets_lifecycle_eval_versions(&lc, true, v, 5, now, ev);
  assert_int_equal(ev[4].action, BUCKETS_LC_NONE); /* retention holds it */
  buckets_lifecycle_free(&lc);
}

static void test_delete_markers(void **state) {
  buckets_lifecycle lc;
  parse_ok("<LifecycleConfiguration><Rule><ID>dm</ID><Status>Enabled</Status><Filter></Filter>"
           "<DelMarkerExpiration><Days>3</Days></DelMarkerExpiration></Rule>"
           "<Rule><ID>lone</ID><Status>Enabled</Status><Filter><Prefix>l/</Prefix></Filter>"
           "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>",
           &lc);
  buckets_lc_obj m = {.name = "x", .mod_time_ns = T(2024, 1, 1, 0), .version_id = "v", .is_latest = true,
                      .delete_marker = true, .num_versions = 2};
  assert_int_equal(buckets_lifecycle_eval(&lc, &m, T(2024, 1, 4, 1), 0).action, BUCKETS_LC_NONE);
  assert_int_equal(buckets_lifecycle_eval(&lc, &m, T(2024, 1, 5, 1), 0).action, BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS);
  m.name = "l/x";
  m.num_versions = 1;
  assert_int_equal(buckets_lifecycle_eval(&lc, &m, T(2024, 1, 1, 1), 0).action, BUCKETS_LC_DELETE_VERSION);
  buckets_lifecycle_free(&lc);
}

static void test_tag_and_size_filters(void **state) {
  buckets_lifecycle lc;
  parse_ok("<LifecycleConfiguration><Rule><ID>t</ID><Status>Enabled</Status><Filter><And><Tag><Key>env</Key><Value>dev</Value></Tag>"
           "<ObjectSizeGreaterThan>100</ObjectSizeGreaterThan></And></Filter><Expiration><Days>1</Days></Expiration></Rule>"
           "</LifecycleConfiguration>",
           &lc);
  buckets_lc_obj o = {.name = "k", .user_tags = "env=dev&x=1", .mod_time_ns = T(2024, 1, 1, 0), .size = 500,
                      .version_id = "", .is_latest = true, .num_versions = 1};
  int64_t now = T(2024, 2, 1, 0);
  assert_int_equal(buckets_lifecycle_eval(&lc, &o, now, 0).action, BUCKETS_LC_DELETE);
  o.size = 100;
  assert_int_equal(buckets_lifecycle_eval(&lc, &o, now, 0).action, BUCKETS_LC_NONE);
  o.size = 500;
  o.user_tags = "env=prod";
  assert_int_equal(buckets_lifecycle_eval(&lc, &o, now, 0).action, BUCKETS_LC_NONE);
  buckets_lifecycle_free(&lc);
}

static void test_marshal_roundtrip(void **state) {
  const char *xml = "<LifecycleConfiguration><Rule><ID>a</ID><Status>Enabled</Status><Filter><And><ObjectSizeGreaterThan>5</ObjectSizeGreaterThan>"
                    "<Prefix>p/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter><Expiration><Days>3</Days></Expiration>"
                    "<NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays><NewerNoncurrentVersions>4</NewerNoncurrentVersions>"
                    "</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>";
  buckets_lifecycle lc;
  parse_ok(xml, &lc);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_lifecycle_xml(&lc, false, &b);
  assert_string_equal(b.data, xml);
  buckets_buf_free(&b);
  buckets_lifecycle_free(&lc);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_expected_expiry),     cmocka_unit_test(test_days_rule),
      cmocka_unit_test(test_all_versions_and_noncurrent), cmocka_unit_test(test_delete_markers),
      cmocka_unit_test(test_tag_and_size_filters), cmocka_unit_test(test_marshal_roundtrip),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
