/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h> /* mkdtemp, on macOS */

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

/* Reads a whole version back and checks its bytes: proves the batch left a
 * kept version's data in place (its data dir was not swept with a removed one). */
static void expect_version_data(fixture *f, const char *version_id, const char *want) {
  buckets_obj_reader *r = NULL;
  buckets_object_info oi;
  assert_int_equal(buckets_obj_open(f->layer, "b", "o", version_id, 0, INT64_MAX, &r, &oi), BUCKETS_OBJ_OK);
  char buf[64] = {0};
  long got = buckets_obj_read(r, buf, sizeof(buf));
  assert_int_equal(got, (long)strlen(want));
  assert_memory_equal(buf, want, strlen(want));
  buckets_obj_reader_free(r);
  buckets_object_info_free(&oi);
}

/* Batched version delete: several versions of one object removed in one call,
 * with the rest (and their data) untouched, matching single-version deletes. */
static void test_delete_versions(void **state) {
  fixture *f = *state;
  buckets_put_opts vo = {.versioned = true};
  char ids[5][37], data[5][8];
  for (int i = 0; i < 5; i++) {
    snprintf(data[i], sizeof(data[i]), "ver-%d", i);
    mem m = {data[i], strlen(data[i])};
    buckets_object_info oi;
    assert_int_equal(buckets_obj_put(f->layer, "b", "o", mem_read, &m, (int64_t)m.n, &vo, &oi), BUCKETS_OBJ_OK);
    snprintf(ids[i], sizeof(ids[i]), "%s", oi.version_id);
    buckets_object_info_free(&oi);
  }

  /* Remove versions 0 and 2 plus a version that does not exist; keep 1, 3, 4. */
  buckets_obj_vdel v[3] = {{.version_id = ids[0]},
                           {.version_id = "00000000-0000-0000-0000-000000000000"},
                           {.version_id = ids[2]}};
  assert_int_equal(buckets_obj_delete_versions(f->layer, "b", "o", v, 3), BUCKETS_OBJ_OK);
  assert_int_equal(v[0].err, BUCKETS_OBJ_OK);
  assert_int_equal(v[1].err, BUCKETS_OBJ_ERR_NO_SUCH_VERSION);
  assert_int_equal(v[2].err, BUCKETS_OBJ_OK);

  buckets_object_info oi;
  assert_int_equal(buckets_obj_stat(f->layer, "b", "o", ids[0], &oi), BUCKETS_OBJ_ERR_NO_SUCH_VERSION);
  assert_int_equal(buckets_obj_stat(f->layer, "b", "o", ids[2], &oi), BUCKETS_OBJ_ERR_NO_SUCH_VERSION);
  /* The kept versions still read back their own bytes. */
  expect_version_data(f, ids[1], "ver-1");
  expect_version_data(f, ids[3], "ver-3");
  expect_version_data(f, ids[4], "ver-4");

  /* Removing the remaining versions in one batch drops the object entirely. */
  buckets_obj_vdel rest[3] = {{.version_id = ids[1]}, {.version_id = ids[3]}, {.version_id = ids[4]}};
  assert_int_equal(buckets_obj_delete_versions(f->layer, "b", "o", rest, 3), BUCKETS_OBJ_OK);
  for (int i = 0; i < 3; i++) assert_int_equal(rest[i].err, BUCKETS_OBJ_OK);
  assert_int_equal(buckets_obj_stat(f->layer, "b", "o", NULL, &oi), BUCKETS_OBJ_ERR_NO_SUCH_KEY);
}

/* A warm tier that just drains the bytes and names a remote object/version. */
static buckets_obj_err mock_upload(void *ud, buckets_read_fn rd, void *rd_ud, int64_t size, char *remote, size_t rcap,
                                   char *rv, size_t rvcap) {
  (void)size;
  char buf[4096];
  while (rd(rd_ud, buf, sizeof(buf)) > 0) {}
  int seq = *(int *)ud;
  snprintf(remote, rcap, "remote-obj-%d", seq);
  snprintf(rv, rvcap, "remote-ver-%d", seq);
  return BUCKETS_OBJ_OK;
}

/* A transitioned version removed via the batch reports its remote tier copy,
 * so the caller can drop it without a separate per-version stat. */
static void test_delete_versions_tiered(void **state) {
  fixture *f = *state;
  char *big = malloc(200000);
  memset(big, 'z', 200000);
  mem m = {big, 200000};
  buckets_put_opts vo = {.versioned = true};
  buckets_object_info oi;
  assert_int_equal(buckets_obj_put(f->layer, "b", "o", mem_read, &m, 200000, &vo, &oi), BUCKETS_OBJ_OK);
  char vid[37], etag[128];
  snprintf(vid, sizeof(vid), "%s", oi.version_id);
  snprintf(etag, sizeof(etag), "%s", oi.etag);
  int64_t mt = oi.mod_time_ns;
  buckets_object_info_free(&oi);

  int seq = 7;
  buckets_object_info ti;
  assert_int_equal(buckets_obj_transition(f->layer, "b", "o", vid, mt, etag, "WARMTIER", mock_upload, &seq, &ti),
                   BUCKETS_OBJ_OK);
  buckets_object_info_free(&ti);

  buckets_obj_vdel v[1] = {{.version_id = vid}};
  assert_int_equal(buckets_obj_delete_versions(f->layer, "b", "o", v, 1), BUCKETS_OBJ_OK);
  assert_int_equal(v[0].err, BUCKETS_OBJ_OK);
  assert_non_null(v[0].tier);
  assert_string_equal(v[0].tier, "WARMTIER");
  assert_string_equal(v[0].remote, "remote-obj-7");
  assert_string_equal(v[0].tier_version, "remote-ver-7");
  free(v[0].tier);
  free(v[0].remote);
  free(v[0].tier_version);
  assert_int_equal(buckets_obj_stat(f->layer, "b", "o", NULL, &oi), BUCKETS_OBJ_ERR_NO_SUCH_KEY);
  free(big);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_put_expect_unchanged, setup, teardown),
      cmocka_unit_test_setup_teardown(test_delete_versions, setup, teardown),
      cmocka_unit_test_setup_teardown(test_delete_versions_tiered, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
