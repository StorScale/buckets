/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* What the compliance reports count per version (src/scanner/compliance.h). */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "s3/sse.h"
#include "scanner/compliance.h"

#define NOW 1800000000LL /* 2027-01-15 */

static buckets_xl_kv kv(const char *k, const char *v) {
  return (buckets_xl_kv){(char *)k, (uint8_t *)v, strlen(v)};
}

/* a version: its user metadata and system metadata, as key/value pairs */
static buckets_object_info version(buckets_xl_kv *meta, size_t nmeta, buckets_xl_kv *sys, size_t nsys) {
  buckets_object_info v;
  memset(&v, 0, sizeof(v));
  v.name = "o";
  v.meta = meta;
  v.nmeta = nmeta;
  v.meta_sys = sys;
  v.nmeta_sys = nsys;
  return v;
}

static void test_encryption(void **state) {
  (void)state;
  buckets_compliance_counts c = {0};
  buckets_xl_kv s3[] = {kv(BUCKETS_SSE_META_SEALED_S3, "sealed")},
                kms[] = {kv(BUCKETS_SSE_META_SEALED_KMS, "sealed")},
                ssec[] = {kv(BUCKETS_SSE_META_SEALED_SSEC, "sealed")};
  buckets_object_info a = version(NULL, 0, s3, 1), b = version(NULL, 0, kms, 1),
                      d = version(NULL, 0, ssec, 1), p = version(NULL, 0, NULL, 0);
  buckets_compliance_add(&c, &a, 100, NOW);
  buckets_compliance_add(&c, &b, 200, NOW);
  buckets_compliance_add(&c, &b, 300, NOW);
  buckets_compliance_add(&c, &d, 50, NOW);
  buckets_compliance_add(&c, &p, 7, NOW);
  assert_int_equal(c.sse_s3.versions, 1);
  assert_int_equal(c.sse_s3.bytes, 100);
  assert_int_equal(c.sse_kms.versions, 2);
  assert_int_equal(c.sse_kms.bytes, 500);
  assert_int_equal(c.sse_c.bytes, 50);
  assert_int_equal(c.plain.versions, 1);
  assert_int_equal(c.plain.bytes, 7);
  /* delete markers hold no data: counted nowhere */
  buckets_object_info dm = version(NULL, 0, NULL, 0);
  dm.delete_marker = true;
  buckets_compliance_add(&c, &dm, 0, NOW);
  assert_int_equal(c.plain.versions, 1);
}

static void test_retention(void **state) {
  (void)state;
  buckets_compliance_counts c = {0};
  /* as MinIO writes them (canonical case), and as lower case */
  buckets_xl_kv gov[] = {kv("X-Amz-Object-Lock-Mode", "GOVERNANCE"),
                         kv("X-Amz-Object-Lock-Retain-Until-Date", "2027-03-01T00:00:00Z")};
  buckets_xl_kv comp[] = {kv("x-amz-object-lock-mode", "COMPLIANCE"),
                          kv("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")};
  buckets_xl_kv over[] = {kv("X-Amz-Object-Lock-Mode", "COMPLIANCE"),
                          kv("X-Amz-Object-Lock-Retain-Until-Date", "2020-01-01T00:00:00Z")}; /* past */
  buckets_xl_kv hold[] = {kv("X-Amz-Object-Lock-Legal-Hold", "ON")};
  buckets_xl_kv off[] = {kv("X-Amz-Object-Lock-Legal-Hold", "OFF")};
  buckets_object_info g = version(gov, 2, NULL, 0), k = version(comp, 2, NULL, 0),
                      o = version(over, 2, NULL, 0), h = version(hold, 1, NULL, 0),
                      f = version(off, 1, NULL, 0);
  buckets_compliance_add(&c, &g, 10, NOW);
  buckets_compliance_add(&c, &k, 20, NOW);
  buckets_compliance_add(&c, &o, 40, NOW);
  buckets_compliance_add(&c, &h, 80, NOW);
  buckets_compliance_add(&c, &f, 160, NOW);
  assert_int_equal(c.governance.versions, 1);
  assert_int_equal(c.governance.bytes, 10);
  assert_int_equal(c.compliance.versions, 1);
  assert_int_equal(c.compliance.bytes, 20); /* an expired retention is no retention */
  assert_int_equal(c.legal_hold.versions, 1);
  assert_int_equal(c.legal_hold.bytes, 80);
  assert_int_equal(c.latest_until, 1893456000); /* 2030-01-01 */
  assert_int_equal(c.plain.versions, 5);        /* and all unencrypted */
}

static void test_json(void **state) {
  (void)state;
  buckets_compliance_bucket b[2] = {{"locked", {0}}, {"plain", {0}}};
  b[0].c.compliance = (buckets_compliance_count){3, 300};
  b[0].c.latest_until = 1893456000;
  b[1].c.plain = (buckets_compliance_count){5, 500};
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_compliance_json(b, 2, NOW, &j);
  buckets_compliance_counts c;
  int64_t at;
  assert_true(buckets_compliance_lookup(j.data, j.len, "locked", &c, &at));
  assert_int_equal(at, NOW);
  assert_int_equal(c.compliance.bytes, 300);
  assert_int_equal(c.latest_until, 1893456000);
  assert_true(buckets_compliance_lookup(j.data, j.len, "plain", &c, &at));
  assert_int_equal(c.plain.versions, 5);
  assert_false(buckets_compliance_lookup(j.data, j.len, "newer", &c, &at)); /* made after the cycle */
  assert_false(buckets_compliance_lookup(NULL, 0, "plain", &c, &at));       /* no cycle yet */
  assert_int_equal(at, 0);
  buckets_buf_free(&j);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_encryption),
      cmocka_unit_test(test_retention),
      cmocka_unit_test(test_json),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
