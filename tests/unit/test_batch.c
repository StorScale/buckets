/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "batch/job.h"
#include "core/yaml.h"

/* Job definitions and what MinIO RELEASE.2025-10-15 prints for them
 * (mc batch describe after mc batch start). */
static const char k_repl_yaml[] =
    "replicate:\n"
    "  apiVersion: v1\n"
    "  source:\n"
    "    type: minio\n"
    "    bucket: srcbkt\n"
    "    prefix: [docs/, img]\n"
    "  target:\n"
    "    type: minio\n"
    "    bucket: dstbkt\n"
    "    prefix: copy\n"
    "    endpoint: \"http://127.0.0.1:19950\"\n"
    "    credentials:\n"
    "      accessKey: rootadmin\n"
    "      secretKey: rootsecret123\n"
    "  flags:\n"
    "    filter:\n"
    "      newerThan: \"7d\"\n"
    "      olderThan: 1h30m\n"
    "      createdAfter: \"2020-01-01T00:00:00Z\"\n"
    "      tags:\n"
    "        - key: \"env\"\n"
    "          value: \"prod*\"\n"
    "      metadata:\n"
    "        - key: \"content-type\"\n"
    "          value: \"image/*\"\n"
    "    notify:\n"
    "      endpoint: \"https://notify.example.net\"\n"
    "      token: \"Bearer xyz\"\n"
    "    retry:\n"
    "      attempts: 5\n"
    "      delay: 500ms\n";
static const char k_repl_describe[] =
    "replicate:\n"
    "    apiVersion: v1\n"
    "    flags:\n"
    "        filter:\n"
    "            newerThan: 168h0m0s\n"
    "            olderThan: 1h30m0s\n"
    "            createdAfter: 2020-01-01T00:00:00Z\n"
    "            tags:\n"
    "                - key: env\n"
    "                  value: prod*\n"
    "            metadata:\n"
    "                - key: content-type\n"
    "                  value: image/*\n"
    "        notify:\n"
    "            endpoint: https://notify.example.net\n"
    "            token: Bearer xyz\n"
    "        retry:\n"
    "            attempts: 5\n"
    "            delay: 500ms\n"
    "    target:\n"
    "        type: minio\n"
    "        bucket: dstbkt\n"
    "        prefix: copy\n"
    "        endpoint: http://127.0.0.1:19950\n"
    "        path: \"\"\n"
    "        credentials:\n"
    "            accessKey: rootadmin\n"
    "            secretKey: '**REDACTED**'\n"
    "            sessionToken: \"\"\n"
    "    source:\n"
    "        type: minio\n"
    "        bucket: srcbkt\n"
    "        prefix:\n"
    "            - docs/\n"
    "            - img\n"
    "        endpoint: \"\"\n"
    "        path: \"\"\n"
    "        credentials:\n"
    "            accessKey: \"\"\n"
    "            secretKey: \"\"\n"
    "            sessionToken: \"\"\n"
    "        snowball:\n"
    "            disable: false\n"
    "            batch: 100\n"
    "            inmemory: true\n"
    "            compress: false\n"
    "            smallerThan: 5MiB\n"
    "            skipErrs: true\n"
    "keyrotate: null\n"
    "expire: null\n";

static const char k_rot_yaml[] =
    "keyrotate:\n"
    "  apiVersion: v1\n"
    "  bucket: srcbkt\n"
    "  prefix: docs/\n"
    "  encryption:\n"
    "    type: sse-s3\n"
    "  flags:\n"
    "    filter:\n"
    "      newerThan: 24h\n"
    "      createdBefore: 2030-01-01T00:00:00Z\n"
    "      kmskeyid: my-minio-key\n"
    "    retry:\n"
    "      attempts: 2\n"
    "      delay: 1s\n";
static const char k_rot_describe[] =
    "replicate: null\n"
    "keyrotate:\n"
    "    apiVersion: v1\n"
    "    flags:\n"
    "        filter:\n"
    "            newerThan: 24h0m0s\n"
    "            createdBefore: 2030-01-01T00:00:00Z\n"
    "            kmskeyid: my-minio-key\n"
    "        notify:\n"
    "            endpoint: \"\"\n"
    "            token: \"\"\n"
    "        retry:\n"
    "            attempts: 2\n"
    "            delay: 1s\n"
    "    bucket: srcbkt\n"
    "    prefix: docs/\n"
    "    encryption:\n"
    "        type: sse-s3\n"
    "        key: \"\"\n"
    "        context: \"\"\n"
    "expire: null\n";

static const char k_exp_yaml[] =
    "expire:\n"
    "  apiVersion: v1\n"
    "  bucket: srcbkt\n"
    "  prefix: img/\n"
    "  rules:\n"
    "    - type: object\n"
    "      name: \"*.jpg\"\n"
    "      olderThan: 70h\n"
    "      createdBefore: \"2025-01-01T00:00:00Z\"\n"
    "      tags:\n"
    "        - key: name\n"
    "          value: pick*\n"
    "      size:\n"
    "        lessThan: \"10MiB\"\n"
    "        greaterThan: 1KiB\n"
    "      purge:\n"
    "        retainVersions: 2\n"
    "    - type: deleted\n"
    "      name: \"x\"\n"
    "  notify:\n"
    "    endpoint: \"https://notify.example.net\"\n"
    "    token: \"Bearer xyz\"\n"
    "  retry:\n"
    "    attempts: 10\n"
    "    delay: 500ms\n";
static const char k_exp_describe[] =
    "replicate: null\n"
    "keyrotate: null\n"
    "expire:\n"
    "    apiVersion: v1\n"
    "    bucket: srcbkt\n"
    "    prefix:\n"
    "        - img/\n"
    "    notify:\n"
    "        endpoint: https://notify.example.net\n"
    "        token: '**REDACTED**'\n"
    "    retry:\n"
    "        attempts: 10\n"
    "        delay: 500ms\n"
    "    rules:\n"
    "        - olderThan: 70h0m0s\n"
    "          createdBefore: 2025-01-01T00:00:00Z\n"
    "          tags:\n"
    "            - key: name\n"
    "              value: pick*\n"
    "          size:\n"
    "            lessThan: 10485760\n"
    "            greaterThan: 1024\n"
    "          type: object\n"
    "          name: '*.jpg'\n"
    "          purge:\n"
    "            retainVersions: 2\n"
    "        - size:\n"
    "            lessThan: 0\n"
    "            greaterThan: 0\n"
    "          type: deleted\n"
    "          name: x\n"
    "          purge:\n"
    "            retainVersions: 0\n";

/* start: parse, defaults; describe: from job.bin, redacted */
static void roundtrip(const char *yaml, const char *want) {
  buckets_batch_job j;
  char *err = NULL;
  assert_true(buckets_batch_job_parse(yaml, strlen(yaml), &j, &err));
  assert_null(err);
  buckets_batch_job_defaults(&j);
  buckets_buf bin = BUCKETS_BUF_INIT;
  buckets_batch_job_msgp(&j, &bin);
  buckets_batch_job_free(&j);
  assert_true(buckets_batch_job_from_msgp(bin.data, bin.len, &j));
  buckets_batch_job_redact(&j);
  buckets_buf y = BUCKETS_BUF_INIT;
  buckets_batch_job_yaml(&j, &y);
  assert_string_equal(y.data, want);
  /* msgp is stable across a decode */
  buckets_batch_job j2;
  assert_true(buckets_batch_job_from_msgp(bin.data, bin.len, &j2));
  buckets_buf bin2 = BUCKETS_BUF_INIT;
  buckets_batch_job_msgp(&j2, &bin2);
  assert_int_equal(bin.len, bin2.len);
  assert_memory_equal(bin.data, bin2.data, bin.len);
  buckets_batch_job_free(&j2);
  buckets_buf_free(&bin2);
  buckets_buf_free(&y);
  buckets_buf_free(&bin);
  buckets_batch_job_free(&j);
}

static void test_describe(void **state) {
  (void)state;
  roundtrip(k_repl_yaml, k_repl_describe);
  roundtrip(k_rot_yaml, k_rot_describe);
  roundtrip(k_exp_yaml, k_exp_describe);
}

static void parse_fails(const char *yaml, const char *want) {
  buckets_batch_job j;
  char *err = NULL;
  assert_false(buckets_batch_job_parse(yaml, strlen(yaml), &j, &err));
  assert_non_null(err);
  assert_string_equal(err, want);
  free(err);
}

static void test_errors(void **state) {
  (void)state;
  parse_fails("expire:\n  apiVersion: v1\n  bucket: srcbkt\n  retry:\n    attempts: abc\n",
              "yaml: unmarshal errors:\n  line 5: cannot unmarshal !!str `abc` into int");
  parse_fails("foo: [\n", "yaml: line 1: did not find expected node content");
  parse_fails("expire:\n  rules:\n    - olderThan: 3x\n", "unknown unit \"x\" in duration \"3x\"");
  parse_fails("expire:\n  rules:\n    - size:\n        lessThan: 10QB\n", "unhandled size name: qb");
  parse_fails("replicate: [1]\n", "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!seq into cmd.BatchJobReplicateV1");
  /* the expire rule type is checked by Validate */
  buckets_batch_job j;
  char *err = NULL;
  const char *y = "expire:\n  apiVersion: v1\n  bucket: srcbkt\n  rules:\n    - type: foo\n";
  assert_true(buckets_batch_job_parse(y, strlen(y), &j, &err));
  buckets_batch_err e = {0};
  assert_false(buckets_batch_expire_rule_validate(&j.expire->rules[0], 0, &e));
  assert_string_equal(e.desc, "invalid batch-expire type\n Hint: error near line: 5, col: 7");
  buckets_batch_job_free(&j);
  /* an empty document is no job */
  assert_true(buckets_batch_job_parse("{}\n", 3, &j, &err));
  assert_string_equal(buckets_batch_job_type(&j), "unknown");
  buckets_batch_job_free(&j);
}

static void test_units(void **state) {
  (void)state;
  char err[128], b[64];
  uint64_t v;
  assert_true(buckets_humanize_parse_bytes("10MiB", &v, err, sizeof(err)));
  assert_int_equal(v, 10485760);
  assert_true(buckets_humanize_parse_bytes("1.5 kb", &v, err, sizeof(err)));
  assert_int_equal(v, 1500);
  assert_true(buckets_humanize_parse_bytes("1,000", &v, err, sizeof(err)));
  assert_int_equal(v, 1000);
  int64_t ns;
  assert_true(buckets_xtime_parse_duration("7d", &ns, err, sizeof(err)));
  assert_int_equal(ns, 7 * 86400000000000LL);
  assert_true(buckets_xtime_parse_duration("1w2d3h", &ns, err, sizeof(err)));
  assert_int_equal(ns, 9 * 86400000000000LL + 3 * 3600000000000LL);
  assert_false(buckets_xtime_parse_duration("abc", &ns, err, sizeof(err)));
  assert_string_equal(err, "invalid duration \"abc\"");
  buckets_go_duration_string(5400000000000LL, b, sizeof(b));
  assert_string_equal(b, "1h30m0s");
  buckets_go_duration_string(500000000LL, b, sizeof(b));
  assert_string_equal(b, "500ms");
  buckets_go_duration_string(1500, b, sizeof(b));
  assert_string_equal(b, "1.5\xC2\xB5s");
  buckets_go_duration_string(0, b, sizeof(b));
  assert_string_equal(b, "0s");
  buckets_go_duration_string(-61000000000LL, b, sizeof(b));
  assert_string_equal(b, "-1m1s");
}

static void test_scalars(void **state) {
  (void)state;
  static const char *const cases[][2] = {
      {"", "\"\""}, {"abc", "abc"}, {"*.jpg", "'*.jpg'"}, {"**REDACTED**", "'**REDACTED**'"},
      {"true", "\"true\""}, {"yes", "\"yes\""}, {"123", "\"123\""}, {"1.5", "\"1.5\""},
      {"null", "\"null\""}, {"https://x.y:9000/p", "https://x.y:9000/p"}, {"a: b", "'a: b'"},
      {"a #b", "'a #b'"}, {" lead", "' lead'"}, {"it's", "it's"}, {"- x", "'- x'"},
      {"2020-01-01", "\"2020-01-01\""}, {"Bearer xyz", "Bearer xyz"}, {"image/*", "image/*"},
      {"line\nbreak", "\"line\\nbreak\""}, {"0x1F", "\"0x1F\""}, {"~", "\"~\""},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_yaml_scalar(&b, cases[i][0]);
    assert_string_equal(b.data, cases[i][1]);
    buckets_buf_free(&b);
  }
}

static void test_report(void **state) {
  (void)state;
  buckets_batch_info ri = {.version = 1, .job_id = "expire-abc:0", .job_type = "expire",
                           .start = {1759170034, 636146000, true}, .complete = true,
                           .bucket = "srcbkt", .object = "a3", .objects = 3};
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_batch_info_encode(&ri, &b);
  buckets_batch_info out;
  char err[128];
  assert_true(buckets_batch_info_decode("batch-expire.bin", b.data, b.len, &out, err, sizeof(err)));
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_batch_info_metric_json(&out, &j);
  assert_string_equal(j.data,
                      "{\"jobID\":\"expire-abc:0\",\"jobType\":\"expire\",\"startTime\":\"2025-09-29T18:20:34.636146Z\","
                      "\"lastUpdate\":\"0001-01-01T00:00:00Z\",\"retryAttempts\":0,\"complete\":true,\"failed\":false,"
                      "\"expired\":{\"lastBucket\":\"srcbkt\",\"lastObject\":\"a3\",\"objects\":3,\"objectsFailed\":0,"
                      "\"deleteMarkers\":0,\"deleteMarkersFailed\":0}}");
  assert_false(buckets_batch_info_decode("batch-expire.bin", "\x02\x00\x01\x00\x80", 5, &out, err, sizeof(err)) &&
               false);
  assert_string_equal(err, "expire: unknown format: 2");
  buckets_batch_info_free(&out);
  buckets_buf_free(&j);
  buckets_buf_free(&b);
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_describe), cmocka_unit_test(test_errors),
                                     cmocka_unit_test(test_units), cmocka_unit_test(test_scalars),
                                     cmocka_unit_test(test_report)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
