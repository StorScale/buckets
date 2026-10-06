/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Local drive health (src/storage/health.h): a drive that cannot be written,
 * whose format.json is gone or names another drive, or whose check hangs is
 * offline; faulty and hung drives refuse calls at once; all come back. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#include "storage/drive.h"
#include "storage/health.h"
#include "storage/remote.h"

static char g_dir[256];

static int setup(void **state) {
  (void)state;
  snprintf(g_dir, sizeof(g_dir), "%s/buckets-health-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
  assert_non_null(mkdtemp(g_dir));
  return 0;
}

static int teardown(void **state) {
  (void)state;
  char cmd[600];
  snprintf(cmd, sizeof(cmd), "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
  return system(cmd) == 0 ? 0 : 0;
}

static buckets_drive *open_drive(const char *name) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", g_dir, name);
  mkdir(path, 0755);
  buckets_drive *d = NULL;
  assert_int_equal(buckets_drive_open(path, &d), BUCKETS_DRIVE_OK);
  assert_true(*d->drive_id);
  return d;
}

static void format_path(buckets_drive *d, char *out, size_t cap) {
  snprintf(out, cap, "%s/" BUCKETS_META_BUCKET "/format.json", d->root);
}

static void test_healthy(void **state) {
  (void)state;
  buckets_drive *d = open_drive("ok");
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_OK);
  assert_true(buckets_drive_is_online(d));
  assert_false(buckets_drive_health_refuses(d));
  char why[256];
  buckets_drive_health_describe(d, why, sizeof(why));
  assert_string_equal(why, "ok");
  /* the probe leaves nothing behind */
  buckets_dir_list l = {0};
  assert_int_equal(buckets_drive_list_dir(d, BUCKETS_META_BUCKET, "tmp", &l), BUCKETS_DRIVE_OK);
  for (size_t i = 0; i < l.n; i++) assert_null(strstr(l.names[i], ".drive-check-"));
  buckets_dir_list_free(&l);
  buckets_drive_close(d);
}

static void test_faulty(void **state) {
  (void)state;
  if (geteuid() == 0) skip(); /* root reads and writes through permissions */
  buckets_drive *d = open_drive("faulty");
  chmod(d->root, 0);
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_FAULTY);
  assert_false(buckets_drive_is_online(d));
  assert_true(buckets_drive_health_refuses(d));
  char why[256];
  buckets_drive_health_describe(d, why, sizeof(why));
  assert_string_equal(why, "faulty: Permission denied");
  /* calls are refused at once, not attempted */
  assert_int_equal(buckets_drive_make_vol(d, "bkt"), BUCKETS_DRIVE_ERR_OFFLINE);
  uint64_t total, free_b;
  assert_int_equal(buckets_drive_disk_info(d, &total, &free_b), BUCKETS_DRIVE_ERR_OFFLINE);
  chmod(d->root, 0755);
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_OK);
  assert_true(buckets_drive_is_online(d));
  assert_int_equal(buckets_drive_make_vol(d, "bkt"), BUCKETS_DRIVE_OK);
  buckets_drive_close(d);
}

static void test_read_only(void **state) {
  (void)state;
  if (geteuid() == 0) skip();
  buckets_drive *d = open_drive("ro");
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s/" BUCKETS_META_BUCKET "/tmp", d->root);
  chmod(tmp, 0555); /* format.json reads fine; nothing can be written */
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_FAULTY);
  chmod(tmp, 0755);
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_OK);
  buckets_drive_close(d);
}

static void test_changed(void **state) {
  (void)state;
  buckets_drive *d = open_drive("changed");
  char fp[512], keep[600];
  format_path(d, fp, sizeof(fp));
  snprintf(keep, sizeof(keep), "%s.keep", fp);
  /* gone: an empty or replaced drive under the mount point */
  assert_int_equal(rename(fp, keep), 0);
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_CHANGED);
  assert_false(buckets_drive_is_online(d));
  assert_false(buckets_drive_health_refuses(d)); /* healing may format it */
  assert_int_equal(buckets_drive_make_vol(d, "bkt2"), BUCKETS_DRIVE_OK);
  uint64_t total, free_b;
  assert_int_equal(buckets_drive_disk_info(d, &total, &free_b), BUCKETS_DRIVE_ERR_OFFLINE); /* peers see it offline */
  char why[256];
  buckets_drive_health_describe(d, why, sizeof(why));
  assert_non_null(strstr(why, "format.json is gone"));
  assert_int_equal(rename(keep, fp), 0);
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_OK);
  /* another drive's format.json */
  FILE *f = fopen(fp, "r");
  char buf[16384];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';
  char *self = strstr(buf, d->drive_id);
  assert_non_null(self);
  memcpy(self, "00000000-0000-0000-0000-000000000000", 36);
  f = fopen(fp, "w");
  fwrite(buf, 1, n, f);
  fclose(f);
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_CHANGED);
  buckets_drive_health_describe(d, why, sizeof(why));
  assert_string_equal(why, "changed: format.json names another drive");
  buckets_drive_close(d);
}

static long long now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void test_hung(void **state) {
  (void)state;
  buckets_drive *d = open_drive("hung");
  assert_int_equal(buckets_drive_health_check(d), BUCKETS_DRIVE_HEALTH_OK);
  /* a check that started 31 seconds ago and has not finished */
  atomic_store(&d->check_started_ms, now_ms() - 31000);
  assert_int_equal(buckets_drive_health_state(d), BUCKETS_DRIVE_HEALTH_HUNG);
  assert_false(buckets_drive_is_online(d));
  assert_true(buckets_drive_health_refuses(d));
  assert_int_equal(buckets_drive_make_vol(d, "bkt"), BUCKETS_DRIVE_ERR_OFFLINE);
  /* one running for less than the timeout is fine */
  atomic_store(&d->check_started_ms, now_ms() - 5000);
  assert_int_equal(buckets_drive_health_state(d), BUCKETS_DRIVE_HEALTH_OK);
  /* the timeout is tunable */
  setenv("BUCKETS_DRIVE_CHECK_TIMEOUT", "2", 1);
  assert_int_equal(buckets_drive_health_state(d), BUCKETS_DRIVE_HEALTH_HUNG);
  unsetenv("BUCKETS_DRIVE_CHECK_TIMEOUT");
  atomic_store(&d->check_started_ms, 0);
  assert_int_equal(buckets_drive_health_state(d), BUCKETS_DRIVE_HEALTH_OK);
  buckets_drive_close(d);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_healthy), cmocka_unit_test(test_faulty), cmocka_unit_test(test_read_only),
      cmocka_unit_test(test_changed), cmocka_unit_test(test_hung),
  };
  return cmocka_run_group_tests(tests, setup, teardown);
}
