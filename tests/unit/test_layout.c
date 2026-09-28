/* Drive layout and placement vs MinIO (endpoint-ellipses_test.go, erasure-sets.go).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erasure/layout.h"

#include "golden_vectors.inc"

/* TestGetSetIndexes cases: args, total sizes, expected set size (0 = failure). */
static const struct {
  const char *arg;
  size_t totals[3];
  size_t ntotals;
  size_t want;
} k_cases[] = {
    {"data{1...17}/export{1...52}", {14144}, 1, 0},
    {"data{1...3}", {3}, 1, 3},
    {"data/controller1/export{1...2}, data/controller2/export{1...4}, data/controller3/export{1...8}", {2, 4, 8}, 3, 2},
    {"data{1...27}", {27}, 1, 9},
    {"http://host{1...3}/data{1...180}", {540}, 1, 15},
    {"http://host{1...2}.rack{1...4}/data{1...180}", {1440}, 1, 16},
    {"http://host{1...2}/data{1...180}", {360}, 1, 12},
    {"data/controller1/export{1...4}, data/controller2/export{1...8}, data/controller3/export{1...12}", {4, 8, 12}, 3, 4},
    {"data{1...64}", {64}, 1, 16},
    {"data{1...24}", {24}, 1, 12},
    {"data/controller{1...11}/export{1...8}", {88}, 1, 11},
    {"data{1...4}", {4}, 1, 4},
    {"data{1...16}/export{1...52}", {832}, 1, 16},
};

static void test_set_indexes(void **state) {
  for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
    buckets_ell_arg a;
    assert_true(buckets_ell_parse(k_cases[i].arg, &a));
    char err[256];
    size_t got = buckets_layout_set_size(k_cases[i].totals, k_cases[i].ntotals, 0, &a, 1, err, sizeof(err));
    if (got != k_cases[i].want) fail_msg("%s: got %zu want %zu (%s)", k_cases[i].arg, got, k_cases[i].want, err);
    buckets_ell_arg_free(&a);
  }
}

static void test_expand_order(void **state) {
  buckets_ell_arg a;
  assert_true(buckets_ell_parse("http://host{1...2}/disk{1...3}", &a));
  size_t n;
  char **v = buckets_ell_expand(&a, &n);
  static const char *const want[] = {"http://host1/disk1", "http://host2/disk1", "http://host1/disk2",
                                     "http://host2/disk2", "http://host1/disk3", "http://host2/disk3"};
  assert_int_equal(n, 6);
  for (size_t i = 0; i < n; i++) {
    assert_string_equal(v[i], want[i]);
    free(v[i]);
  }
  free(v);
  buckets_ell_arg_free(&a);

  assert_true(buckets_ell_parse("/mnt/drive{01...12}", &a));
  v = buckets_ell_expand(&a, &n);
  assert_int_equal(n, 12);
  assert_string_equal(v[0], "/mnt/drive01");
  assert_string_equal(v[11], "/mnt/drive12");
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
  buckets_ell_arg_free(&a);

  assert_true(buckets_ell_parse("/x/{a...f}", &a)); /* hex */
  v = buckets_ell_expand(&a, &n);
  assert_int_equal(n, 6);
  assert_string_equal(v[5], "/x/f");
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
  buckets_ell_arg_free(&a);

  assert_false(buckets_ell_parse("/x/{5...1}", &a));
  assert_false(buckets_ell_parse("/x/{1..4}", &a));
}

static void test_pool_layout(void **state) {
  char err[256];
  buckets_pool_layout l;
  char *one[] = {"/data"};
  assert_true(buckets_layout_pool(one, 1, 0, &l, err, sizeof(err)));
  assert_int_equal(l.set_size, 1);
  buckets_layout_free(&l);
  char *four[] = {"/d{1...4}"};
  assert_true(buckets_layout_pool(four, 1, 0, &l, err, sizeof(err)));
  assert_int_equal(l.ndrives, 4);
  assert_int_equal(l.set_size, 4);
  buckets_layout_free(&l);
  char *list[] = {"/a", "/b", "/c", "/d", "/e", "/f"};
  assert_true(buckets_layout_pool(list, 6, 0, &l, err, sizeof(err)));
  assert_int_equal(l.set_size, 6);
  buckets_layout_free(&l);
  char *dup[] = {"/a", "/b", "/a", "/c"};
  assert_false(buckets_layout_pool(dup, 4, 0, &l, err, sizeof(err)));
  char *seventeen[] = {"/d{1...17}"};
  assert_false(buckets_layout_pool(seventeen, 1, 0, &l, err, sizeof(err)));
  assert_int_equal(buckets_default_parity(1), 0);
  assert_int_equal(buckets_default_parity(4), 2);
  assert_int_equal(buckets_default_parity(16), 4);
}

static void test_placement_golden(void **state) {
  static const uint8_t id[16] = {0xa8, 0x9a, 0xd6, 0xa1, 0xf0, 0x17, 0x4e, 0x24,
                                 0x9c, 0xf4, 0xe6, 0xfa, 0x82, 0x5e, 0xa2, 0x92};
  for (size_t i = 0; i < sizeof(golden_place) / sizeof(golden_place[0]); i++) {
    if (buckets_set_index(golden_place[i].key, golden_place[i].sets, id) != golden_place[i].set) {
      fail_msg("set index for '%s' / %u", golden_place[i].key, golden_place[i].sets);
    }
    int order[16];
    buckets_hash_order(golden_place[i].key, (int)golden_place[i].n, order);
    assert_memory_equal(order, golden_place[i].order, golden_place[i].n * sizeof(int));
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_set_indexes),
      cmocka_unit_test(test_expand_order),
      cmocka_unit_test(test_pool_layout),
      cmocka_unit_test(test_placement_golden),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
