/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* SCIM 2.0 Users (iam/scim.h): Entra ID's and Okta's requests as they send them, filters, the store, and what
 * identity sync makes of a person. */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iam/scim.h"

static yyjson_doc *doc(const char *s) {
  yyjson_doc *d = yyjson_read(s, strlen(s), 0);
  assert_non_null(d);
  return d;
}

static void make(buckets_scim_user *u, const char *body) {
  yyjson_doc *d = doc(body);
  int st = 0;
  char err[200];
  assert_true(buckets_scim_user_from_json(yyjson_doc_get_root(d), u, &st, err, sizeof(err)));
  yyjson_doc_free(d);
}

static bool patch(buckets_scim_user *u, const char *body) {
  yyjson_doc *d = doc(body);
  int st = 0;
  char err[200];
  bool ok = buckets_scim_patch(u, yyjson_doc_get_root(d), &st, err, sizeof(err));
  yyjson_doc_free(d);
  return ok;
}

/* Entra ID: create (externalId mapped from objectId), then its patch forms */
static void test_entra(void **state) {
  (void)state;
  buckets_scim_user u;
  make(&u,
       "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\","
       "\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"],\"externalId\":\"0b9e-oid\","
       "\"userName\":\"alice@contoso.com\",\"active\":true,\"displayName\":\"Alice\","
       "\"emails\":[{\"primary\":true,\"type\":\"work\",\"value\":\"alice@contoso.com\"}],"
       "\"meta\":{\"resourceType\":\"User\"},\"name\":{\"formatted\":\"Alice A\",\"familyName\":\"A\"}}");
  assert_string_equal(u.external_id, "0b9e-oid");
  assert_string_equal(u.user_name, "alice@contoso.com");
  assert_true(u.active);
  /* "Replace", capitalised, with the boolean as a string */
  assert_true(patch(&u,
                    "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":["
                    "{\"op\":\"Replace\",\"path\":\"active\",\"value\":\"False\"}]}"));
  assert_false(u.active);
  /* no path: a value object */
  assert_true(patch(&u,
                    "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":["
                    "{\"op\":\"replace\",\"value\":{\"active\":true,\"displayName\":\"Alice B\"}}]}"));
  assert_true(u.active);
  assert_string_equal(u.display_name, "Alice B");
  /* attributes it doesn't keep are fine */
  assert_true(patch(
      &u,
      "{\"Operations\":[{\"op\":\"Add\",\"path\":\"emails[type eq \\\"work\\\"].value\","
      "\"value\":\"a@contoso.com\"},{\"op\":\"Replace\",\"path\":\"name.familyName\",\"value\":\"B\"}]}"));
  /* bad ones are refused */
  assert_false(patch(&u, "{\"Operations\":[{\"op\":\"Move\",\"path\":\"active\",\"value\":true}]}"));
  assert_false(patch(&u, "{\"Operations\":[{\"op\":\"replace\",\"path\":\"active\",\"value\":\"maybe\"}]}"));
  assert_false(patch(&u, "{\"nothing\":1}"));
  buckets_scim_user_free(&u);
}

/* Okta: externalId is its user ID; turning someone off is a PUT with active false */
static void test_okta(void **state) {
  (void)state;
  buckets_scim_user u;
  make(&u,
       "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"bob@example.com\","
       "\"name\":{\"givenName\":\"Bob\",\"familyName\":\"B\"},\"emails\":[{\"primary\":true,\"value\":\"bob@"
       "example.com\","
       "\"type\":\"work\"}],\"displayName\":\"Bob "
       "B\",\"locale\":\"en-US\",\"externalId\":\"00u1abcd\",\"groups\":[],"
       "\"password\":\"x\",\"active\":true}");
  assert_string_equal(u.external_id, "00u1abcd");
  buckets_scim_user put;
  make(&put,
       "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"id\":\"ignored\",\"userName\":\"bob@"
       "example.com\","
       "\"externalId\":\"00u1abcd\",\"active\":false}");
  assert_false(put.active);
  buckets_scim_user_free(&put);
  /* active defaults to true; userName is required */
  buckets_scim_user d;
  make(&d, "{\"userName\":\"c\"}");
  assert_true(d.active);
  buckets_scim_user_free(&d);
  yyjson_doc *nd = doc("{\"externalId\":\"x\"}");
  int st = 0;
  char err[200];
  assert_false(buckets_scim_user_from_json(yyjson_doc_get_root(nd), &d, &st, err, sizeof(err)));
  assert_int_equal(st, 400);
  yyjson_doc_free(nd);
  buckets_scim_user_free(&u);
}

static void test_filters(void **state) {
  (void)state;
  buckets_scim_filter f;
  buckets_scim_user u = {.id = "1"};
  u.user_name = "Alice@Contoso.com";
  u.external_id = "Oid-1";
  assert_true(buckets_scim_filter_parse("userName eq \"alice@contoso.com\"", &f));
  assert_true(buckets_scim_filter_match(&f, &u)); /* userName isn't case-exact */
  assert_true(buckets_scim_filter_parse("externalId eq \"oid-1\"", &f));
  assert_false(buckets_scim_filter_match(&f, &u)); /* externalId is */
  assert_true(buckets_scim_filter_parse("  EXTERNALID   EQ \"Oid-1\" ", &f));
  assert_true(buckets_scim_filter_match(&f, &u));
  assert_true(buckets_scim_filter_parse("", &f));
  assert_true(buckets_scim_filter_match(&f, &u));
  assert_false(buckets_scim_filter_parse("userName sw \"a\"", &f));
  assert_false(buckets_scim_filter_parse("userName eq \"a\" and active eq true", &f));
  assert_false(buckets_scim_filter_parse("emails eq \"a\"", &f));
  u.deleted = true;
  assert_true(buckets_scim_filter_parse("", &f));
  assert_false(buckets_scim_filter_match(&f, &u)); /* the deleted aren't listed */
}

static void test_store_and_state(void **state) {
  (void)state;
  const char *j =
      "{\"rev\":7,\"users\":[{\"id\":\"a\",\"externalId\":\"p1\",\"userName\":\"one\",\"active\":true,"
      "\"created\":1,"
      "\"modified\":10},{\"id\":\"b\",\"externalId\":\"p2\",\"userName\":\"two\",\"active\":false,"
      "\"modified\":10},"
      "{\"id\":\"c\",\"externalId\":\"p3\",\"userName\":\"three\",\"active\":false,\"deleted\":true,"
      "\"modified\":10},"
      "{\"id\":\"d\",\"externalId\":\"p3\",\"userName\":\"three\",\"active\":true,\"modified\":20}]}";
  buckets_scim_store s;
  assert_true(buckets_scim_store_parse(j, strlen(j), &s));
  assert_int_equal(s.rev, 7);
  assert_int_equal(s.n, 4);
  assert_int_equal(buckets_scim_state_of(&s, "p1"), BUCKETS_IDSYNC_ACTIVE);
  assert_int_equal(buckets_scim_state_of(&s, "p2"), BUCKETS_IDSYNC_DISABLED);
  assert_int_equal(buckets_scim_state_of(&s, "p3"), BUCKETS_IDSYNC_ACTIVE); /* deleted, then assigned again */
  assert_int_equal(buckets_scim_state_of(&s, "nobody"), BUCKETS_IDSYNC_UNKNOWN);
  assert_non_null(buckets_scim_find_user_name(&s, "THREE"));
  assert_string_equal(buckets_scim_find_user_name(&s, "three")->id, "d");
  assert_null(buckets_scim_find_id(&s, "c")); /* deleted */
  s.u[3].deleted = true;
  s.u[3].modified = 20;
  assert_int_equal(buckets_scim_state_of(&s, "p3"), BUCKETS_IDSYNC_GONE);
  /* round trip, then the deleted pruned after the grace period */
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_scim_store_json(&s, &b);
  buckets_scim_store s2;
  assert_true(buckets_scim_store_parse(b.data, b.len, &s2));
  assert_int_equal(s2.n, 4);
  buckets_scim_store_prune(&s2, 100, 85); /* modified 10: gone; 20: kept */
  assert_int_equal(s2.n, 3);
  assert_string_equal(s2.u[2].id, "d");
  buckets_buf_free(&b);
  buckets_scim_store_free(&s2);
  buckets_scim_store_free(&s);
  assert_true(buckets_scim_store_parse("", 0, &s));
  assert_int_equal(s.n, 0);
  assert_false(buckets_scim_store_parse("[1]", 3, &s));
}

static void test_json_out(void **state) {
  (void)state;
  buckets_scim_user u = {.id = "u-1", .active = false, .created = 0, .modified = 86400};
  u.user_name = "a@b.c";
  u.external_id = "x";
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_scim_user_json(&u, "https://s3.example.com/minio/scim/v2", &b);
  assert_non_null(strstr(b.data, "\"active\":false"));
  assert_non_null(strstr(b.data, "\"location\":\"https://s3.example.com/minio/scim/v2/Users/u-1\""));
  assert_non_null(strstr(b.data, "\"lastModified\":\"1970-01-02T00:00:00"));
  buckets_buf_reset(&b);
  buckets_scim_error_json(409, "uniqueness", "taken", &b);
  assert_string_equal(b.data,
                      "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:Error\"],\"status\":\"409\","
                      "\"scimType\":\"uniqueness\",\"detail\":\"taken\"}");
  buckets_buf_free(&b);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_entra),           cmocka_unit_test(test_okta),     cmocka_unit_test(test_filters),
      cmocka_unit_test(test_store_and_state), cmocka_unit_test(test_json_out),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
