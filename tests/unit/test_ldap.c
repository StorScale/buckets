/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "net/ldap.h"

/* Generated from go-ldap v3.4.11 by tools/ldapvec. */
#include "ldap_vectors.inc"

static void test_filters(void **state) {
  (void)state;
  buckets_buf out = BUCKETS_BUF_INIT, hex = BUCKETS_BUF_INIT;
  char err[256];
  for (size_t i = 0; i < sizeof(filter_vectors) / sizeof(filter_vectors[0]); i++) {
    if (!buckets_ldap_compile_filter(filter_vectors[i].in, &out, err, sizeof(err))) fail_msg("%s: %s", filter_vectors[i].in, err);
    buckets_buf_reset(&hex);
    for (size_t k = 0; k < out.len; k++) buckets_buf_appendf(&hex, "%02x", (unsigned char)out.data[k]);
    buckets_buf_append_char(&hex, '\0');
    if (strcmp(hex.data, filter_vectors[i].hex) != 0)
      fail_msg("%s:\n got  %s\n want %s", filter_vectors[i].in, hex.data, filter_vectors[i].hex);
  }
  for (size_t i = 0; i < sizeof(bad_filters) / sizeof(bad_filters[0]); i++)
    if (buckets_ldap_compile_filter(bad_filters[i], &out, err, sizeof(err))) fail_msg("accepted %s", bad_filters[i]);
  buckets_buf_free(&out);
  buckets_buf_free(&hex);
}

static void test_dns(void **state) {
  (void)state;
  for (size_t i = 0; i < sizeof(dn_vectors) / sizeof(dn_vectors[0]); i++) {
    char *n = buckets_ldap_normalize_dn(dn_vectors[i].in);
    if (!n) fail_msg("rejected %s", dn_vectors[i].in);
    if (strcmp(n, dn_vectors[i].out) != 0) fail_msg("%s:\n got  %s\n want %s", dn_vectors[i].in, n, dn_vectors[i].out);
    free(n);
  }
  for (size_t i = 0; i < sizeof(bad_dns) / sizeof(bad_dns[0]); i++) {
    char *n = buckets_ldap_normalize_dn(bad_dns[i]);
    if (n) fail_msg("accepted %s as %s", bad_dns[i], n);
  }
  assert_true(buckets_ldap_dn_ancestor_of("ou=widgets,o=acme.com", "ou=sprockets,OU=widgets,o=acme.com"));
  assert_false(buckets_ldap_dn_ancestor_of("ou=widgets,o=acme.com", "ou=sprockets,ou=widgets,o=foo.com"));
  assert_false(buckets_ldap_dn_ancestor_of("ou=widgets,o=acme.com", "ou=widgets,o=acme.com"));
  char *d = buckets_ldap_decode_dn("cn=Smith\\, John\\c3\\a9");
  assert_string_equal(d, "cn=Smith, John\xc3\xa9");
  free(d);
}

static void test_escape(void **state) {
  (void)state;
  char *e = buckets_ldap_escape_filter(escape_in);
  assert_string_equal(e, escape_out);
  free(e);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_filters),
      cmocka_unit_test(test_dns),
      cmocka_unit_test(test_escape),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
