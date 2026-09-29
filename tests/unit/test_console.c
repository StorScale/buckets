/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>
#include <time.h>

#include "console/console.h"

static buckets_console *make(const char *pass) {
  buckets_console_config cfg = {.upstream_host = "127.0.0.1", .upstream_port = 9, .passphrase = pass, .salt = "s"};
  return buckets_console_new(&cfg);
}

static void test_cookie(void **state) {
  (void)state;
  buckets_console *a = make("secret"), *b = make("secret"), *other = make("different");
  buckets_console_session s = {.expires = (int64_t)time(NULL) + 60};
  strcpy(s.access_key, "AK");
  strcpy(s.secret_key, "SK/+=");
  strcpy(s.session_token, "token");
  strcpy(s.user, "alice");
  buckets_buf ck = BUCKETS_BUF_INIT;
  assert_true(buckets_console_seal(a, &s, &ck));
  assert_null(strpbrk(ck.data, "+/=; ")); /* cookie-safe */
  buckets_console_session got;
  /* any replica with the same passphrase opens it */
  assert_true(buckets_console_open(b, ck.data, ck.len, &got));
  assert_string_equal(got.secret_key, "SK/+=");
  assert_string_equal(got.user, "alice");
  assert_false(buckets_console_open(other, ck.data, ck.len, &got));
  /* tampering */
  ck.data[ck.len / 2] = ck.data[ck.len / 2] == 'A' ? 'B' : 'A';
  assert_false(buckets_console_open(a, ck.data, ck.len, &got));
  assert_false(buckets_console_open(a, "", 0, &got));
  /* expiry */
  buckets_buf old = BUCKETS_BUF_INIT;
  s.expires = (int64_t)time(NULL) - 1;
  assert_true(buckets_console_seal(a, &s, &old));
  assert_false(buckets_console_open(a, old.data, old.len, &got));
  buckets_buf_free(&ck);
  buckets_buf_free(&old);
  buckets_console_free(a);
  buckets_console_free(b);
  buckets_console_free(other);
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_cookie)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
