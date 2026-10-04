/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Teams (src/iam/teams.h): the policies each level gets, as the policy
 * evaluator enforces them; teams read back from their policies; checks. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "iam/policy.h"
#include "iam/teams.h"

#define FINANCE "{\"name\":\"finance\",\"buckets\":[\"finance-reports\",\"ledger\"],\"prefixes\":[\"finance-\"],"

static yyjson_doc *J(const char *s) {
  yyjson_doc *d = yyjson_read(s, strlen(s), 0);
  assert_non_null(d);
  return d;
}

static char *policy_json(const char *team, const char *level) {
  yyjson_doc *t = J(team);
  char err[256] = "";
  if (!buckets_team_check(yyjson_doc_get_root(t), err, sizeof(err))) fail_msg("check: %s", err);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_team_policy(yyjson_doc_get_root(t), level, &b);
  yyjson_doc_free(t);
  return b.data;
}

static buckets_policy *policy(const char *team, const char *level) {
  char *json = policy_json(team, level);
  buckets_policy *p = NULL;
  char err[256] = "";
  if (!buckets_policy_parse(json, strlen(json), &p, err, sizeof(err))) fail_msg("parse: %s\n%s", err, json);
  free(json);
  return p;
}

static bool may(const buckets_policy *p, const char *action, const char *bucket, const char *object) {
  buckets_policy_args a = {.action = action, .bucket = bucket, .object = object ? object : ""};
  return buckets_policy_allowed(p, &a);
}

static void test_levels(void **state) {
  (void)state;
  const char *t = FINANCE "\"levels\":[\"ro\",\"rw\",\"admin\"]}";
  buckets_policy *ro = policy(t, "ro"), *rw = policy(t, "rw"), *admin = policy(t, "admin");
  /* the team's buckets, named and by prefix, and nothing else */
  const char *mine[] = {"finance-reports", "ledger", "finance-q4"};
  for (int i = 0; i < 3; i++) {
    assert_true(may(ro, "s3:ListBucket", mine[i], NULL));
    assert_true(may(ro, "s3:GetObject", mine[i], "a/b.csv"));
    assert_false(may(ro, "s3:PutObject", mine[i], "a/b.csv"));
    assert_true(may(rw, "s3:PutObject", mine[i], "a/b.csv"));
    assert_true(may(rw, "s3:DeleteObject", mine[i], "a/b.csv"));
    assert_false(may(rw, "s3:PutLifecycleConfiguration", mine[i], NULL));
    assert_true(may(admin, "s3:PutLifecycleConfiguration", mine[i], NULL));
    assert_true(may(admin, "s3:PutBucketVersioning", mine[i], NULL));
    assert_true(may(admin, "s3:PutObjectRetention", mine[i], "a"));
    assert_false(may(admin, "s3:PutBucketPolicy", mine[i], NULL)); /* no sharing or making public */
    assert_false(may(admin, "s3:DeleteBucketPolicy", mine[i], NULL));
    assert_false(may(admin, "s3:BypassGovernanceRetention", mine[i], "a"));
  }
  const char *theirs[] = {"hr-payroll", "ledger2", "financereports"};
  for (int i = 0; i < 3; i++) {
    assert_false(may(admin, "s3:ListBucket", theirs[i], NULL));
    assert_false(may(admin, "s3:GetObject", theirs[i], "a"));
  }
  /* creating and deleting buckets: admin, under the prefix only */
  assert_true(may(admin, "s3:CreateBucket", "finance-q4", NULL));
  assert_true(may(admin, "s3:DeleteBucket", "finance-q4", NULL));
  assert_false(may(admin, "s3:CreateBucket", "hr-q4", NULL));
  assert_false(may(admin, "s3:DeleteBucket", "ledger", NULL)); /* named, not under the prefix */
  assert_false(may(rw, "s3:CreateBucket", "finance-q4", NULL));
  /* no admin API, and no listing of every bucket (ListBuckets filters to what the caller can reach) */
  assert_false(may(admin, "admin:CreateUser", "", NULL));
  assert_false(may(admin, "s3:ListAllMyBuckets", "", NULL));
  buckets_policy_free(ro);
  buckets_policy_free(rw);
  buckets_policy_free(admin);
}

static void test_no_prefix_no_create(void **state) {
  (void)state;
  char *json = policy_json("{\"name\":\"hr\",\"buckets\":[\"hr-payroll\"],\"levels\":[\"admin\"]}", "admin");
  assert_null(strstr(json, "CreateBucket"));
  assert_null(strstr(json, ":create"));
  assert_non_null(strstr(json, "\"Sid\":\"buckets-team:v1:hr:admin\""));
  free(json);
}

/* list-canned-policies' reply for a team's levels, plus whatever else */
static char *listing(const char *team, const char *const *levels, const char *extra) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "{");
  yyjson_doc *t = J(team);
  const char *name = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(t), "name"));
  for (int i = 0; levels[i]; i++) {
    char pn[128];
    buckets_team_policy_name(name, levels[i], pn, sizeof(pn));
    char *p = policy_json(team, levels[i]);
    buckets_buf_appendf(&b, "%s\"%s\":%s", i ? "," : "", pn, p);
    free(p);
  }
  yyjson_doc_free(t);
  if (extra) buckets_buf_appendf(&b, ",%s", extra);
  buckets_buf_append_c(&b, "}");
  return b.data;
}

static char *teams_of(const char *policies_json) {
  yyjson_doc *p = J(policies_json);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, buckets_teams_from_policies(d, yyjson_doc_get_root(p)));
  char *out = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  yyjson_doc_free(p);
  return out;
}

static void test_read_back(void **state) {
  (void)state;
  const char *t = FINANCE "\"levels\":[\"ro\",\"rw\"]}";
  const char *lv[] = {"ro", "rw", NULL};
  char *pol = listing(t, lv,
                      "\"readwrite\":{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],"
                      "\"Resource\":[\"arn:aws:s3:::*\"]}]},"
                      /* named like a team, but not marked as one */
                      "\"team-x-rw\":{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],"
                      "\"Resource\":[\"arn:aws:s3:::x\"]}]}");
  char *got = teams_of(pol);
  assert_string_equal(got, "[{\"name\":\"finance\",\"buckets\":[\"finance-reports\",\"ledger\"],\"prefixes\":[\"finance-\"],"
                           "\"levels\":[\"ro\",\"rw\"],\"edited\":[]}]");
  free(got);
  free(pol);
}

static void test_sorted_and_marker_must_match_name(void **state) {
  (void)state;
  const char *lv[] = {"rw", NULL};
  char *b = policy_json("{\"name\":\"zeta\",\"buckets\":[\"zeta-1\"],\"levels\":[\"rw\"]}", "rw");
  char extra[4096];
  /* zeta's policy stored under another name is not a team */
  snprintf(extra, sizeof(extra), "\"team-zeta-ro\":%s,\"team-zeta-rw\":%s", b, b);
  char *pol = listing("{\"name\":\"alpha\",\"buckets\":[\"alpha-1\"],\"levels\":[\"rw\"]}", lv, extra);
  char *got = teams_of(pol);
  assert_string_equal(got, "[{\"name\":\"alpha\",\"buckets\":[\"alpha-1\"],\"prefixes\":[],\"levels\":[\"rw\"],\"edited\":[]},"
                           "{\"name\":\"zeta\",\"buckets\":[\"zeta-1\"],\"prefixes\":[],\"levels\":[\"rw\"],\"edited\":[]}]");
  free(got);
  free(pol);
  free(b);
}

static void test_edited(void **state) {
  (void)state;
  const char *t = FINANCE "\"levels\":[\"ro\",\"rw\"]}";
  char *ro = policy_json(t, "ro"), *rw = policy_json(t, "rw");
  /* reordered actions and a single-string Resource are the same policy */
  yyjson_doc *d = J(rw);
  yyjson_mut_doc *m = yyjson_doc_mut_copy(d, NULL);
  yyjson_mut_val *s1 = yyjson_mut_arr_get(yyjson_mut_obj_get(yyjson_mut_doc_get_root(m), "Statement"), 1);
  yyjson_mut_val *acts = yyjson_mut_obj_get(s1, "Action");
  yyjson_mut_arr_append(acts, yyjson_mut_arr_remove_first(acts));
  char *reordered = yyjson_mut_write(m, 0, NULL);
  char pol[16384];
  snprintf(pol, sizeof(pol), "{\"team-finance-ro\":%s,\"team-finance-rw\":%s}", ro, reordered);
  char *got = teams_of(pol);
  assert_non_null(strstr(got, "\"edited\":[]"));
  free(got);
  /* an extra action on rw: edited; the buckets still come from ro */
  yyjson_mut_arr_add_str(m, acts, "s3:PutBucketPolicy");
  char *more = yyjson_mut_write(m, 0, NULL);
  snprintf(pol, sizeof(pol), "{\"team-finance-ro\":%s,\"team-finance-rw\":%s}", ro, more);
  got = teams_of(pol);
  assert_non_null(strstr(got, "\"levels\":[\"ro\",\"rw\"],\"edited\":[\"rw\"]"));
  assert_non_null(strstr(got, "\"buckets\":[\"finance-reports\",\"ledger\"]"));
  free(got);
  /* a Condition added: edited */
  yyjson_mut_obj_add_val(m, s1, "Condition", yyjson_mut_obj(m));
  char *cond = yyjson_mut_write(m, 0, NULL);
  snprintf(pol, sizeof(pol), "{\"team-finance-rw\":%s}", cond);
  got = teams_of(pol);
  assert_non_null(strstr(got, "\"edited\":[\"rw\"]"));
  free(got);
  free(cond);
  free(more);
  free(reordered);
  yyjson_mut_doc_free(m);
  yyjson_doc_free(d);
  free(ro);
  free(rw);
}

static void expect_error(const char *json, const char *words) {
  yyjson_doc *d = J(json);
  char err[256] = "";
  assert_false(buckets_team_check(yyjson_doc_get_root(d), err, sizeof(err)));
  if (!strstr(err, words)) fail_msg("error %s, expected it to mention %s", err, words);
  yyjson_doc_free(d);
}

static void test_checks(void **state) {
  (void)state;
  expect_error("{\"buckets\":[\"abc\"],\"levels\":[\"rw\"]}", "name");
  expect_error("{\"name\":\"Finance\",\"buckets\":[\"abc\"],\"levels\":[\"rw\"]}", "not a team name");
  expect_error("{\"name\":\"fin-\",\"buckets\":[\"abc\"],\"levels\":[\"rw\"]}", "not a team name");
  expect_error("{\"name\":\"a23456789012345678901234567890123456789012\",\"buckets\":[\"abc\"],\"levels\":[\"rw\"]}",
               "not a team name");
  expect_error("{\"name\":\"fin\",\"levels\":[\"rw\"]}", "at least one bucket or prefix");
  expect_error("{\"name\":\"fin\",\"buckets\":[\"AB\"],\"levels\":[\"rw\"]}", "not a bucket name");
  expect_error("{\"name\":\"fin\",\"buckets\":[\"abc\",\"abc\"],\"levels\":[\"rw\"]}", "listed twice");
  expect_error("{\"name\":\"fin\",\"prefixes\":[\"f*\"],\"levels\":[\"rw\"]}", "not a bucket-name prefix");
  expect_error("{\"name\":\"fin\",\"prefixes\":[\"f\"],\"levels\":[\"rw\"]}", "not a bucket-name prefix");
  expect_error("{\"name\":\"fin\",\"buckets\":[\"abc\"]}", "at least one access level");
  expect_error("{\"name\":\"fin\",\"buckets\":[\"abc\"],\"levels\":[\"owner\"]}", "not an access level");
  yyjson_doc *d = J("{\"name\":\"a2345678901234567890123456789012345678x\",\"buckets\":[\"abc\"],\"levels\":[\"admin\"]}");
  char err[256];
  assert_true(buckets_team_check(yyjson_doc_get_root(d), err, sizeof(err)));
  yyjson_doc_free(d);
}

static void test_overlaps(void **state) {
  (void)state;
  yyjson_doc *teams = J("[{\"name\":\"finance\",\"buckets\":[\"ledger\"],\"prefixes\":[\"finance-\"]},"
                        "{\"name\":\"hr\",\"buckets\":[],\"prefixes\":[\"hr-\"]}]");
  char err[256] = "";
  const char *cases[][2] = {
      {"{\"name\":\"fin2\",\"prefixes\":[\"fin\"]}", "overlaps team finance's prefix \"finance-\""},
      {"{\"name\":\"fin2\",\"prefixes\":[\"finance-q4-\"]}", "overlaps team finance"},
      {"{\"name\":\"fin2\",\"prefixes\":[\"fintech-\"]}", NULL},
      {"{\"name\":\"finance\",\"prefixes\":[\"finance-\",\"fin-\"]}", NULL}, /* itself */
      {"{\"name\":\"audit\",\"buckets\":[\"ledger\"]}", NULL},               /* named buckets may be shared */
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    yyjson_doc *t = J(cases[i][0]);
    bool o = buckets_team_overlaps(yyjson_doc_get_root(t), yyjson_doc_get_root(teams), err, sizeof(err));
    if (o != (cases[i][1] != NULL)) fail_msg("case %zu: overlap %d (%s)", i, o, err);
    if (o && !strstr(err, cases[i][1])) fail_msg("case %zu: %s", i, err);
    yyjson_doc_free(t);
  }
  yyjson_doc_free(teams);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_levels),        cmocka_unit_test(test_no_prefix_no_create),
      cmocka_unit_test(test_read_back),     cmocka_unit_test(test_sorted_and_marker_must_match_name),
      cmocka_unit_test(test_edited),        cmocka_unit_test(test_checks),
      cmocka_unit_test(test_overlaps),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
