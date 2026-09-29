/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include "metrics/expo.h"

static void check(double v, const char *want) {
  char got[40];
  buckets_go_float(v, got);
  assert_string_equal(got, want);
}

/* strconv.FormatFloat(v, 'g', -1, 64), as expfmt writes values */
static void test_go_float(void **state) {
  (void)state;
  check(0, "0");
  check(1, "1");
  check(-1, "-1");
  check(100, "100");
  check(999999, "999999");
  check(1000000, "1e+06");
  check(1234567, "1.234567e+06");
  check(494384795648, "4.94384795648e+11");
  check(0.05, "0.05");
  check(0.0001, "0.0001");
  check(0.00001, "1e-05");
  check(123.456, "123.456");
  check(-2.5, "-2.5");
  check(1e21, "1e+21");
  check(1.7275e9, "1.7275e+09");
  check(0.1 + 0.2, "0.30000000000000004");
  check(1.0 / 0.0, "+Inf");
}

static void test_write(void **state) {
  (void)state;
  buckets_expo *e = buckets_expo_new(BUCKETS_CATALOG_V2);
  buckets_expo_addl(e, "minio_s3_requests_total", 3, "server", "s", "api", "putobject", NULL);
  buckets_expo_addl(e, "minio_s3_requests_total", 1, "api", "getobject", "server", "s", NULL);
  buckets_expo_addl(e, "minio_cluster_drive_total", 4, "server", "s", NULL);
  buckets_expo_addl(e, "minio_not_a_metric", 1, NULL);
  buckets_expo_addl(e, "minio_s3_requests_ttfb_seconds_distribution", 2, "api", "a", "le", "0.050", NULL);
  buckets_expo_addl(e, "minio_s3_requests_ttfb_seconds_distribution", 2, "api", "a", "le", "+Inf", NULL);
  assert_int_equal(buckets_expo_dropped(e), 1);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_expo_write(e, &b);
  const char *want =
      "# HELP minio_cluster_drive_total Total drives in this cluster\n"
      "# TYPE minio_cluster_drive_total gauge\n"
      "minio_cluster_drive_total{server=\"s\"} 4\n"
      "# HELP minio_s3_requests_total Total number of S3 requests\n"
      "# TYPE minio_s3_requests_total counter\n"
      "minio_s3_requests_total{api=\"getobject\",server=\"s\"} 1\n"
      "minio_s3_requests_total{api=\"putobject\",server=\"s\"} 3\n"
      "# HELP minio_s3_requests_ttfb_seconds_distribution Distribution of time to first byte across API calls\n"
      "# TYPE minio_s3_requests_ttfb_seconds_distribution gauge\n"
      "minio_s3_requests_ttfb_seconds_distribution{api=\"a\",le=\"+Inf\"} 2\n"
      "minio_s3_requests_ttfb_seconds_distribution{api=\"a\",le=\"0.050\"} 2\n";
  assert_string_equal(b.data, want);
  buckets_buf_free(&b);
  buckets_expo_free(e);
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_go_float), cmocka_unit_test(test_write)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
