/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Regression tests for the 2026-10 security-parity fixes (docs/roadmap.md):
 * the path-traversal guard on the storage REST layer and the link-local /
 * metadata-address guard on batch job endpoints. The CopyObject reserved-source
 * fix is exercised end to end in tests/integration/security-parity.sh. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>

#include "core/str.h"
#include "net/conn.h"

static void test_path_has_dotdot(void **state) {
  (void)state;
  /* traversal, in any component */
  assert_true(buckets_path_has_dotdot(".."));
  assert_true(buckets_path_has_dotdot("../etc/passwd"));
  assert_true(buckets_path_has_dotdot("a/../b"));
  assert_true(buckets_path_has_dotdot("a/b/.."));
  assert_true(buckets_path_has_dotdot("bucket/../../.minio.sys/config"));
  /* not traversal: a lone dot, or ".." only as a substring of a name */
  assert_false(buckets_path_has_dotdot(""));
  assert_false(buckets_path_has_dotdot("."));
  assert_false(buckets_path_has_dotdot("a/b/c"));
  assert_false(buckets_path_has_dotdot("..foo/bar"));
  assert_false(buckets_path_has_dotdot("foo/..bar/baz"));
  assert_false(buckets_path_has_dotdot("a..b"));
  assert_false(buckets_path_has_dotdot(".minio.sys/buckets"));
}

static void test_host_is_linklocal(void **state) {
  (void)state;
  /* the cloud metadata address and its 169.254.0.0/16 block */
  assert_true(buckets_net_host_is_linklocal("169.254.169.254"));
  assert_true(buckets_net_host_is_linklocal("169.254.169.254:80"));
  assert_true(buckets_net_host_is_linklocal("169.254.0.1"));
  /* IPv6 link-local, bracketed with and without a port */
  assert_true(buckets_net_host_is_linklocal("[fe80::1]"));
  assert_true(buckets_net_host_is_linklocal("[fe80::1]:9000"));
  /* ordinary and private addresses are allowed: on-prem replication to 10.x /
   * 192.168.x must keep working, so only link-local is refused */
  assert_false(buckets_net_host_is_linklocal("127.0.0.1"));
  assert_false(buckets_net_host_is_linklocal("127.0.0.1:9000"));
  assert_false(buckets_net_host_is_linklocal("10.0.0.5"));
  assert_false(buckets_net_host_is_linklocal("192.168.1.10:9000"));
  assert_false(buckets_net_host_is_linklocal("8.8.8.8"));
  assert_false(buckets_net_host_is_linklocal("[::1]:9000"));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_path_has_dotdot),
      cmocka_unit_test(test_host_is_linklocal),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
