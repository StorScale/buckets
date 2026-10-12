/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dist/dsync.h"

/* A lock whose lock servers forget it (they restarted) is lost, and can be
 * taken again; one they still hold is not. */
static void test_lost_when_forgotten(void** state) {
  (void)state;
  buckets_lock_server* s = buckets_lock_server_new();
  buckets_http_client* none[1] = {NULL};
  buckets_dsync* d = buckets_dsync_new(none, 0, s);
  void* h = buckets_dsync_lock(d, ".minio.sys/leader.lock", true, 1000);
  assert_non_null(h);
  buckets_dsync_refresh(d);
  assert_false(buckets_dsync_lost(h));

  buckets_lock_server_force_unlock(s, ".minio.sys/leader.lock"); /* as a restart forgets it */
  buckets_dsync_refresh(d);
  assert_true(buckets_dsync_lost(h));
  buckets_dsync_refresh(d); /* no longer refreshed */
  assert_true(buckets_dsync_lost(h));

  buckets_dsync_unlock(d, h);
  h = buckets_dsync_lock(d, ".minio.sys/leader.lock", true, 1000);
  assert_non_null(h);
  assert_false(buckets_dsync_lost(h));
  assert_int_equal(buckets_lock_server_held(s), 1);
  buckets_dsync_unlock(d, h);
  assert_int_equal(buckets_lock_server_held(s), 0);
  assert_false(buckets_dsync_lost(NULL));
  buckets_dsync_free(d);
  buckets_lock_server_free(s);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_lost_when_forgotten),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
