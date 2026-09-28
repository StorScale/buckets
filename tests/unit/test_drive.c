/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "storage/drive.h"

static char *make_tmpdir(void) {
  const char *base = getenv("TMPDIR");
  char tmpl[1024];
  snprintf(tmpl, sizeof(tmpl), "%s/buckets-test-XXXXXX", base && *base ? base : "/tmp");
  char *d = mkdtemp(tmpl);
  assert_non_null(d);
  return strdup(d);
}

static void rm_rf(const char *path) {
  char cmd[2048];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
  assert_int_equal(system(cmd), 0);
}

static void test_format_roundtrip(void **state) {
  char *dir = make_tmpdir();
  buckets_drive *d = NULL;
  assert_int_equal(buckets_drive_open(dir, &d), BUCKETS_DRIVE_OK);
  assert_true(d->freshly_formatted);
  char dep[64], id[64];
  strcpy(dep, d->deployment_id);
  strcpy(id, d->drive_id);
  buckets_drive_close(d);

  assert_int_equal(buckets_drive_open(dir, &d), BUCKETS_DRIVE_OK);
  assert_false(d->freshly_formatted);
  assert_string_equal(d->deployment_id, dep);
  assert_string_equal(d->drive_id, id);
  buckets_drive_close(d);

  /* The on-disk document matches MinIO's xl-single format.json shape. */
  char path[2048];
  snprintf(path, sizeof(path), "%s/.minio.sys/format.json", dir);
  FILE *f = fopen(path, "r");
  assert_non_null(f);
  char json[1024] = {0};
  fread(json, 1, sizeof(json) - 1, f);
  fclose(f);
  char want[1024];
  snprintf(want, sizeof(want),
           "{\"version\":\"1\",\"format\":\"xl-single\",\"id\":\"%s\",\"xl\":{\"version\":\"3\",\"this\":\"%s\","
           "\"sets\":[[\"%s\"]],\"distributionAlgo\":\"SIPMOD+PARITY\"}}",
           dep, id, id);
  assert_string_equal(json, want);

  /* A corrupt format.json is refused, never silently reformatted. */
  f = fopen(path, "w");
  fputs("{not json", f);
  fclose(f);
  assert_int_equal(buckets_drive_open(dir, &d), BUCKETS_DRIVE_ERR_CORRUPT);
  rm_rf(dir);
  free(dir);
}

static void test_volumes(void **state) {
  char *dir = make_tmpdir();
  buckets_drive *d = NULL;
  assert_int_equal(buckets_drive_open(dir, &d), BUCKETS_DRIVE_OK);

  assert_int_equal(buckets_drive_make_vol(d, "beta"), BUCKETS_DRIVE_OK);
  assert_int_equal(buckets_drive_make_vol(d, "alpha"), BUCKETS_DRIVE_OK);
  assert_int_equal(buckets_drive_make_vol(d, "alpha"), BUCKETS_DRIVE_ERR_EXISTS);
  time_t created = 0;
  assert_int_equal(buckets_drive_stat_vol(d, "alpha", &created), BUCKETS_DRIVE_OK);
  assert_true(created > 0);
  assert_int_equal(buckets_drive_stat_vol(d, "gamma", NULL), BUCKETS_DRIVE_ERR_NOT_FOUND);

  buckets_vol_info *vols;
  size_t n;
  assert_int_equal(buckets_drive_list_vols(d, &vols, &n), BUCKETS_DRIVE_OK);
  assert_int_equal(n, 2); /* .minio.sys is hidden */
  assert_string_equal(vols[0].name, "alpha");
  assert_string_equal(vols[1].name, "beta");
  buckets_vol_info_free(vols, n);

  char p[2048];
  snprintf(p, sizeof(p), "%s/beta/child", dir);
  assert_int_equal(mkdir(p, 0755), 0);
  assert_int_equal(buckets_drive_delete_vol(d, "beta"), BUCKETS_DRIVE_ERR_NOT_EMPTY);
  rmdir(p);
  assert_int_equal(buckets_drive_delete_vol(d, "beta"), BUCKETS_DRIVE_OK);
  assert_int_equal(buckets_drive_delete_vol(d, "beta"), BUCKETS_DRIVE_ERR_NOT_FOUND);

  buckets_drive_close(d);
  rm_rf(dir);
  free(dir);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_format_roundtrip),
      cmocka_unit_test(test_volumes),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
