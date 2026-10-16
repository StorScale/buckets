/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/log.h"
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

static atomic_int lost_warnings;
static void count_lost(void *ud, buckets_log_level level, const char *msg, size_t n) {
  (void)ud;
  (void)level;
  if (memmem(msg, n, " lost", 5)) atomic_fetch_add(&lost_warnings, 1);
}

typedef struct {
  buckets_dsync *d;
  int id;
  atomic_bool *stop;
} churn_arg;

static void *churn(void *p) {
  churn_arg *a = p;
  char res[32];
  snprintf(res, sizeof(res), "bucket/object-%d", a->id);
  while (!atomic_load(a->stop)) {
    void *h = buckets_dsync_lock(a->d, res, a->id % 2 == 0, 1000);
    assert_non_null(h);
    buckets_dsync_unlock(a->d, h);
  }
  return NULL;
}

/* A lock released while it is being refreshed is not lost: the lock servers
 * that already let it go are not forgetting it. */
static void test_released_while_refreshed(void **state) {
  (void)state;
  buckets_lock_server *s = buckets_lock_server_new();
  buckets_http_client *none[1] = {NULL};
  buckets_dsync *d = buckets_dsync_new(none, 0, s);
  atomic_store(&lost_warnings, 0);
  buckets_log_set_sink(count_lost, NULL);
  atomic_bool stop = false;
  pthread_t t[4];
  churn_arg a[4];
  for (int i = 0; i < 4; i++) {
    a[i] = (churn_arg){d, i, &stop};
    pthread_create(&t[i], NULL, churn, &a[i]);
  }
  for (int i = 0; i < 20000; i++) buckets_dsync_refresh(d);
  atomic_store(&stop, true);
  for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
  buckets_log_set_sink(NULL, NULL);
  assert_int_equal(atomic_load(&lost_warnings), 0);
  assert_int_equal(buckets_lock_server_held(s), 0);
  buckets_dsync_free(d);
  buckets_lock_server_free(s);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_lost_when_forgotten),
      cmocka_unit_test(test_released_while_refreshed),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
