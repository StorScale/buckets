/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <cmocka.h>

#include "object/object.h"
#include "storage/format.h"

typedef struct {
  char root[256];
  buckets_objlayer *layer;
} fixture;

static int setup(void **state) {
  fixture *f = calloc(1, sizeof(*f));
  snprintf(f->root, sizeof(f->root), "/tmp/buckets-object-XXXXXX");
  assert_non_null(mkdtemp(f->root));
  buckets_drive *drives[4];
  for (int i = 0; i < 4; i++) {
    char p[300];
    snprintf(p, sizeof(p), "%s/d%d", f->root, i);
    mkdir(p, 0755);
    assert_int_equal(buckets_drive_open_raw(p, &drives[i]), BUCKETS_DRIVE_OK);
  }
  buckets_format_result fr;
  char err[256];
  if (!buckets_format_negotiate(drives, 4, 4, NULL, NULL, &fr, err, sizeof(err))) fail_msg("format: %s", err);
  f->layer = buckets_objlayer_new(&fr, 1, -1);
  buckets_format_result_free(&fr);
  assert_int_equal(buckets_obj_make_bucket(f->layer, "b"), BUCKETS_OBJ_OK);
  *state = f;
  return 0;
}

static int teardown(void **state) {
  fixture *f = *state;
  buckets_objlayer_free(f->layer);
  char cmd[300];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->root);
  if (system(cmd) != 0) return 1;
  free(f);
  return 0;
}

typedef struct {
  const char *p;
  size_t n;
} mem;

static long mem_read(void *ud, void *buf, size_t n) {
  mem *m = ud;
  if (n > m->n) n = m->n;
  memcpy(buf, m->p, n);
  m->p += n, m->n -= n;
  return (long)n;
}

static buckets_obj_err put(fixture *f, const char *data, const buckets_put_opts *opts, buckets_object_info *oi) {
  mem m = {data, strlen(data)};
  buckets_put_opts none = {0};
  return buckets_obj_put(f->layer, "b", "o", mem_read, &m, (int64_t)m.n, opts ? opts : &none, oi);
}

static void expect_data(fixture *f, const char *want) {
  buckets_object_info oi;
  assert_int_equal(buckets_obj_stat(f->layer, "b", "o", NULL, &oi), BUCKETS_OBJ_OK);
  assert_int_equal(oi.size, (int64_t)strlen(want));
  buckets_object_info_free(&oi);
}

/* A rewrite in place commits only over the version it read (expect_mod_time_ns,
 * expect_etag), checked under the namespace lock. */
static void test_put_expect_unchanged(void **state) {
  fixture *f = *state;
  buckets_object_info v1;
  assert_int_equal(put(f, "first", NULL, &v1), BUCKETS_OBJ_OK);
  buckets_put_opts o = {.version_id = v1.version_id, .mod_time_ns = v1.mod_time_ns,
                        .expect_mod_time_ns = v1.mod_time_ns + 1, .expect_etag = v1.etag};
  buckets_object_info oi;
  assert_int_equal(put(f, "stale-time", &o, &oi), BUCKETS_OBJ_ERR_CHANGED);
  o.expect_mod_time_ns = v1.mod_time_ns, o.expect_etag = "0123456789abcdef0123456789abcdef";
  assert_int_equal(put(f, "stale-etag", &o, &oi), BUCKETS_OBJ_ERR_CHANGED);
  expect_data(f, "first");

  o.expect_etag = v1.etag;
  assert_int_equal(put(f, "rewritten", &o, &oi), BUCKETS_OBJ_OK);
  assert_int_equal(oi.mod_time_ns, v1.mod_time_ns);
  buckets_object_info_free(&oi);
  expect_data(f, "rewritten");

  /* replaced after it was read: the rewrite of the old one is refused */
  buckets_object_info v2;
  assert_int_equal(put(f, "replaced!!", NULL, &v2), BUCKETS_OBJ_OK);
  o.expect_etag = v1.etag;
  assert_int_equal(put(f, "late", &o, &oi), BUCKETS_OBJ_ERR_CHANGED);
  expect_data(f, "replaced!!");

  /* deleted after it was read */
  assert_int_equal(buckets_obj_delete(f->layer, "b", "o", NULL), BUCKETS_OBJ_OK);
  o.expect_mod_time_ns = v2.mod_time_ns, o.expect_etag = v2.etag, o.mod_time_ns = v2.mod_time_ns;
  assert_int_equal(put(f, "late", &o, &oi), BUCKETS_OBJ_ERR_CHANGED);
  assert_int_equal(buckets_obj_stat(f->layer, "b", "o", NULL, &oi), BUCKETS_OBJ_ERR_NO_SUCH_KEY);
  buckets_object_info_free(&v1);
  buckets_object_info_free(&v2);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_put_expect_unchanged, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
