/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "config/config.h"

static void test_set_get(void **state) {
  (void)state;
  buckets_config *c = buckets_config_new();
  char err[512];
  bool dyn;
  assert_true(buckets_config_set_text(c, "scanner speed=slow\n# comment\n\napi requests_max=10", &dyn, err, sizeof(err)));
  assert_true(dyn);
  char *v = buckets_config_get(c, "scanner", NULL, "speed");
  assert_string_equal(v, "slow");
  free(v);
  /* Values with spaces, and quotes stripped. */
  assert_true(buckets_config_set_text(c, "notify_webhook:a endpoint=\"http://x/\" comment=two words here", NULL, err,
                                      sizeof(err)));
  buckets_buf out = BUCKETS_BUF_INIT;
  assert_true(buckets_config_get_text(c, "notify_webhook", "a", true, &out, err, sizeof(err)));
  assert_non_null(strstr(out.data, "notify_webhook:a endpoint=http://x/ "));
  assert_non_null(strstr(out.data, "comment=\"two words here\""));
  buckets_buf_free(&out);
  assert_false(buckets_config_set_text(c, "nosuch key=1", NULL, err, sizeof(err)));
  assert_string_equal(err, "unknown sub-system nosuch key=1");
  assert_false(buckets_config_set_text(c, "identity_ldap enable=on", NULL, err, sizeof(err)));
  assert_non_null(strstr(err, "'server_addr' is not optional"));
  /* Reset: one key back to its default, or the whole target. */
  assert_true(buckets_config_del_text(c, "scanner speed", err, sizeof(err)));
  v = buckets_config_get(c, "scanner", NULL, "speed");
  assert_string_equal(v, "default");
  free(v);
  assert_true(buckets_config_del_text(c, "notify_webhook:a", err, sizeof(err)));
  assert_false(buckets_config_del_text(c, "notify_webhook:a", err, sizeof(err)));
  buckets_config_free(c);
}

static void test_env(void **state) {
  (void)state;
  buckets_config *c = buckets_config_new();
  setenv("MINIO_SCANNER_SPEED", "fastest", 1);
  setenv("BUCKETS_NOTIFY_WEBHOOK_ENDPOINT_PRIMARY", "http://p/", 1);
  char *v = buckets_config_get(c, "scanner", NULL, "speed");
  assert_string_equal(v, "fastest");
  free(v);
  char **t;
  size_t n = buckets_config_targets(c, "notify_webhook", &t);
  assert_int_equal(n, 2);
  assert_string_equal(t[0], "_");
  assert_string_equal(t[1], "PRIMARY");
  for (size_t i = 0; i < n; i++) free(t[i]);
  free(t);
  v = buckets_config_get(c, "notify_webhook", "PRIMARY", "endpoint");
  assert_string_equal(v, "http://p/");
  free(v);
  char err[512];
  setenv("MINIO_SCANNER_NOPE", "1", 1);
  assert_false(buckets_config_check_valid_keys(c, "scanner", err, sizeof(err)));
  assert_non_null(strstr(err, "MINIO_SCANNER_NOPE"));
  unsetenv("MINIO_SCANNER_NOPE");
  unsetenv("MINIO_SCANNER_SPEED");
  unsetenv("BUCKETS_NOTIFY_WEBHOOK_ENDPOINT_PRIMARY");
  buckets_config_free(c);
}

static void test_json(void **state) {
  (void)state;
  /* MinIO's layout; crawler became scanner; unknown sub-systems are dropped. */
  const char *json = "{\"crawler\":{\"_\":[{\"key\":\"speed\",\"value\":\"slow\"}]},"
                     "\"notify_webhook\":{\"t1\":[{\"key\":\"enable\",\"value\":\"on\"},"
                     "{\"key\":\"endpoint\",\"value\":\"http://h/\"}]},\"bogus\":{\"_\":[]}}";
  char err[256];
  buckets_config *c = buckets_config_from_json(json, strlen(json), err, sizeof(err));
  assert_non_null(c);
  char *v = buckets_config_get(c, "scanner", NULL, "speed");
  assert_string_equal(v, "slow");
  free(v);
  v = buckets_config_get(c, "notify_webhook", "t1", "queue_limit"); /* filled from defaults */
  assert_string_equal(v, "0");
  free(v);
  char *out = buckets_config_to_json(c);
  buckets_config *c2 = buckets_config_from_json(out, strlen(out), err, sizeof(err));
  char *out2 = buckets_config_to_json(c2);
  assert_string_equal(out, out2);
  free(out);
  free(out2);
  buckets_config_free(c);
  buckets_config_free(c2);
}


/* MINIO_CONFIG_ENV_FILE lines, as MinIO's parsEnvEntry reads them. */
static void test_env_file(void **state) {
  (void)state;
  struct {
    const char *line, *key, *value;
    bool ok, skip;
  } cases[] = {
      {"export MINIO_ROOT_USER=minio", "MINIO_ROOT_USER", "minio", true, false},
      {"  export MINIO_ROOT_PASSWORD=\"s3cr3t=x\"  \n", "MINIO_ROOT_PASSWORD", "s3cr3t=x", true, false},
      {"MINIO_REGION='eu-west-1'", "MINIO_REGION", "eu-west-1", true, false},
      {"K=\"unbalanced'", "K", "\"unbalanced'", true, false},
      {"K=", "K", "", true, false},
      {"exportK=v", "K", "v", true, false}, /* TrimPrefix needs no space */
      {"", NULL, NULL, true, true},
      {"   ", NULL, NULL, true, true},
      {"# export K=v", NULL, NULL, true, true},
      {"export K", NULL, NULL, false, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *k, *v;
    bool skip;
    bool ok = buckets_config_env_line(cases[i].line, &k, &v, &skip);
    assert_int_equal(ok, cases[i].ok);
    assert_int_equal(skip, cases[i].skip);
    if (cases[i].key) {
      assert_string_equal(k, cases[i].key);
      assert_string_equal(v, cases[i].value);
    }
    free(k);
    free(v);
  }
  char path[] = "/tmp/buckets-envfile-XXXXXX";
  int fd = mkstemp(path);
  assert_true(fd >= 0);
  const char *body = "# MinIO Operator\nexport BUCKETS_TEST_ENVFILE_A=one\n\nexport BUCKETS_TEST_ENVFILE_B=\"two\"\n";
  assert_int_equal(write(fd, body, strlen(body)), (ssize_t)strlen(body));
  close(fd);
  setenv("BUCKETS_TEST_ENVFILE_A", "before", 1);
  char err[256];
  assert_true(buckets_config_load_env_file(path, err, sizeof(err)));
  assert_string_equal(getenv("BUCKETS_TEST_ENVFILE_A"), "one"); /* the file overrides */
  assert_string_equal(getenv("BUCKETS_TEST_ENVFILE_B"), "two");
  unlink(path);
  assert_true(buckets_config_load_env_file(path, err, sizeof(err))); /* missing: ignored */
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_set_get),
      cmocka_unit_test(test_env),
      cmocka_unit_test(test_json),
      cmocka_unit_test(test_env_file),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
