/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The access review (src/iam/access.h): routes to a bucket through each kind
 * of principal, limits and conditions, bucket policies, access keys with a
 * policy of their own, and every check held to the policy evaluator. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "core/buf.h"
#include "iam/access.h"
#include "iam/policy.h"

#define V "\"Version\":\"2012-10-17\""
static const char *k_policies =
    "{\"readwrite\":{" V ",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],\"Resource\":[\"arn:aws:s3:::*\"]}]},"
    "\"team-finance-rw\":{" V ",\"Statement\":["
    "{\"Sid\":\"buckets-team:v1:finance:rw\",\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\",\"s3:GetBucketLocation\"],"
    "\"Resource\":[\"arn:aws:s3:::finance-reports\"]},"
    "{\"Sid\":\"buckets-team:v1:finance:rw:objects\",\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\","
    "\"s3:DeleteObject\"],\"Resource\":[\"arn:aws:s3:::finance-reports/*\"]}]},"
    "\"audit-ro\":{" V ",\"Statement\":["
    "{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::finance-reports\"]},"
    "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::finance-reports/reports/*\"]}]},"
    "\"deny-secret\":{" V ",\"Statement\":[{\"Sid\":\"NoSecrets\",\"Effect\":\"Deny\",\"Action\":[\"s3:GetObject\"],"
    "\"Resource\":[\"arn:aws:s3:::finance-reports/secret/*\"]}]},"
    "\"ip-only\":{" V ",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],"
    "\"Resource\":[\"arn:aws:s3:::finance-reports/*\"],\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":[\"10.0.0.0/8\"]}}}]},"
    "\"home\":{" V ",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],"
    "\"Resource\":[\"arn:aws:s3:::home/${aws:username}/*\"]}]}}";

static const char *k_principals =
    "[{\"kind\":\"root\",\"name\":\"rootadmin\"},"
    "{\"kind\":\"user\",\"name\":\"alice\",\"policies\":[\"team-finance-rw\"],\"status\":\"enabled\"},"
    "{\"kind\":\"user\",\"name\":\"bob\",\"policies\":[],\"groups\":[\"auditors\"],\"status\":\"enabled\"},"
    "{\"kind\":\"group\",\"name\":\"auditors\",\"policies\":[\"audit-ro\"],\"members\":[\"bob\"],\"status\":\"enabled\"},"
    "{\"kind\":\"user\",\"name\":\"carol\",\"policies\":[\"ip-only\"],\"status\":\"enabled\"},"
    "{\"kind\":\"user\",\"name\":\"dave\",\"policies\":[\"readwrite\",\"deny-secret\"],\"status\":\"enabled\"},"
    "{\"kind\":\"user\",\"name\":\"erin\",\"policies\":[\"readwrite\"],\"status\":\"disabled\"},"
    "{\"kind\":\"user\",\"name\":\"frank\",\"policies\":[\"home\"],\"status\":\"enabled\"},"
    "{\"kind\":\"ldap-group\",\"name\":\"cn=devs,ou=groups,dc=example,dc=com\",\"policies\":[\"team-finance-rw\"]},"
    "{\"kind\":\"openid-role\",\"name\":\"team-finance-rw\",\"policies\":[\"team-finance-rw\"],\"seen\":[\"kcteam\"]},"
    "{\"kind\":\"key\",\"name\":\"AKREADONLY\",\"owner\":\"alice\",\"policy\":{" V ",\"Statement\":[{\"Effect\":\"Allow\","
    "\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::finance-reports/*\"]}]}},"
    "{\"kind\":\"key\",\"name\":\"AKINHERITS\",\"owner\":\"alice\"}]";

static const char *k_bucket_policy =
    "{" V ",\"Statement\":[{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"*\"]},"
    "\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::finance-reports/public/*\"]}]}";

static yyjson_doc *facts(bool with_bucket_policy) {
  char buf[16384];
  snprintf(buf, sizeof(buf), "{\"policies\":%s,\"principals\":%s,\"bucketPolicy\":%s,\"missing\":[]}", k_policies,
           k_principals, with_bucket_policy ? k_bucket_policy : "null");
  yyjson_doc *d = yyjson_read(buf, strlen(buf), 0);
  assert_non_null(d);
  return d;
}

/* The review of finance-reports at level, as a JSON string. */
static char *review(const char *level) {
  yyjson_doc *f = facts(true);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *r = buckets_access_bucket(d, yyjson_doc_get_root(f), "finance-reports", level);
  assert_non_null(r);
  yyjson_mut_doc_set_root(d, r);
  char *out = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  yyjson_doc_free(f);
  return out;
}

/* The row of a principal in a review, as "kind name access", or NULL. */
static char *row_of(const char *json, const char *name, yyjson_doc **keep) {
  yyjson_doc *d = yyjson_read(json, strlen(json), 0);
  *keep = d;
  size_t i, max;
  yyjson_val *r;
  yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(d), "rows"), i, max, r) {
    if (strcmp(yyjson_get_str(yyjson_obj_get(r, "name")), name) != 0) continue;
    return yyjson_val_write(r, 0, NULL);
  }
  return NULL;
}

static void expect_row(const char *json, const char *name, const char *const *contains) {
  yyjson_doc *keep;
  char *r = row_of(json, name, &keep);
  if (!r) fail_msg("no row for %s in %s", name, json);
  for (; *contains; contains++)
    if (!strstr(r, *contains)) fail_msg("row %s lacks %s: %s", name, *contains, r);
  free(r);
  yyjson_doc_free(keep);
}

static void expect_no_row(const char *json, const char *name) {
  yyjson_doc *keep;
  char *r = row_of(json, name, &keep);
  if (r) fail_msg("unexpected row for %s: %s", name, r);
  yyjson_doc_free(keep);
}

static void test_read_review(void **state) {
  (void)state;
  char *j = review("read");
  expect_row(j, "rootadmin", (const char *[]){"\"access\":\"full\"", NULL});
  expect_row(j, "alice", (const char *[]){"\"access\":\"full\"", "\"policy\":\"team-finance-rw\"", "\"sid\":\"buckets-team:v1:finance:rw:objects\"", NULL});
  /* bob through his group: the listing, and only the reports (the public part is the "everyone" row's) */
  expect_row(j, "bob", (const char *[]){"\"access\":\"limited\"", "\"limits\":[\"reports/*\"]", "\"policy\":\"audit-ro\"", NULL});
  expect_row(j, "auditors", (const char *[]){"\"access\":\"limited\"", "\"members\":[\"bob\"]", NULL});
  expect_row(j, "carol", (const char *[]){"\"decision\":\"conditional\"", "\"conditions\":[\"SourceIp\"]", NULL});
  expect_row(j, "dave", (const char *[]){"\"access\":\"full\"", NULL});
  expect_row(j, "erin", (const char *[]){"\"status\":\"disabled\"", NULL});
  expect_no_row(j, "frank"); /* his home bucket, not this one */
  expect_row(j, "cn=devs,ou=groups,dc=example,dc=com", (const char *[]){"\"kind\":\"ldap-group\"", "\"access\":\"full\"", NULL});
  expect_row(j, "team-finance-rw", (const char *[]){"\"kind\":\"openid-role\"", "\"seen\":[\"kcteam\"]", NULL});
  /* a key with its own policy: reads, but its policy does not list; one without is its owner's row */
  expect_row(j, "AKREADONLY", (const char *[]){"\"owner\":\"alice\"", "\"access\":\"limited\"", "\"action\":\"s3:GetObject\",\"decision\":\"allowed\"", NULL});
  expect_no_row(j, "AKINHERITS");
  expect_row(j, "everyone, signed in or not", (const char *[]){"\"kind\":\"anyone\"", "\"limits\":[\"public/*\"]", "\"bucketPolicy\":true", NULL});
  free(j);
}

static void test_write_and_manage(void **state) {
  (void)state;
  char *j = review("write");
  expect_row(j, "alice", (const char *[]){"\"access\":\"full\"", NULL});
  expect_no_row(j, "bob");
  expect_no_row(j, "AKREADONLY");
  expect_no_row(j, "everyone, signed in or not");
  free(j);
  j = review("manage");
  expect_row(j, "dave", (const char *[]){"\"access\":\"full\"", NULL});
  expect_no_row(j, "alice");
  free(j);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_doc *f = facts(false);
  assert_null(buckets_access_bucket(d, yyjson_doc_get_root(f), "finance-reports", "owner"));
  yyjson_doc_free(f);
  yyjson_mut_doc_free(d);
}

/* buckets_access_check's decision and its first deciding statement's policy (or "bucketPolicy"). */
static void check(const char *who, const char *action, const char *bucket, const char *object, const char *conds,
                  const char *want, const char *by) {
  yyjson_doc *f = facts(true);
  yyjson_doc *w = yyjson_read(who, strlen(who), 0);
  yyjson_doc *c = conds ? yyjson_read(conds, strlen(conds), 0) : NULL;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *r = buckets_access_check(d, yyjson_doc_get_root(f), yyjson_doc_get_root(w), action, bucket, object,
                                           yyjson_doc_get_root(c));
  assert_non_null(r);
  const char *got = yyjson_mut_get_str(yyjson_mut_obj_get(r, "decision"));
  if (strcmp(got, want) != 0) {
    yyjson_mut_doc_set_root(d, r);
    fail_msg("%s %s %s/%s: %s, want %s: %s", who, action, bucket, object, got, want, yyjson_mut_write(d, 0, NULL));
  }
  if (by) {
    yyjson_mut_val *b = yyjson_mut_arr_get_first(yyjson_mut_obj_get(r, "by"));
    const char *p = yyjson_mut_get_str(yyjson_mut_obj_get(b, "policy"));
    if (!p && yyjson_mut_get_bool(yyjson_mut_obj_get(b, "bucketPolicy"))) p = "bucketPolicy";
    if (!p || strcmp(p, by) != 0) fail_msg("%s %s: decided by %s, want %s", who, action, p ? p : "(none)", by);
  }
  yyjson_mut_doc_free(d);
  yyjson_doc_free(c);
  yyjson_doc_free(w);
  yyjson_doc_free(f);
}

#define USER(n) "{\"kind\":\"user\",\"name\":\"" n "\"}"

static void test_checks(void **state) {
  (void)state;
  check(USER("alice"), "s3:PutObject", "finance-reports", "q3.csv", NULL, "allowed", "team-finance-rw");
  check(USER("alice"), "s3:PutObject", "hr-payroll", "q3.csv", NULL, "denied", NULL);
  check(USER("dave"), "s3:GetObject", "finance-reports", "secret/keys.txt", NULL, "denied", "deny-secret");
  check(USER("dave"), "s3:GetObject", "finance-reports", "q3.csv", NULL, "allowed", "readwrite");
  check(USER("bob"), "s3:GetObject", "finance-reports", "reports/q3.pdf", NULL, "allowed", "audit-ro");
  check(USER("bob"), "s3:GetObject", "finance-reports", "q3.csv", NULL, "denied", NULL);
  check(USER("bob"), "s3:GetObject", "finance-reports", "public/notice.txt", NULL, "allowed", "bucketPolicy");
  /* a condition: undecided without its value, decided with it */
  check(USER("carol"), "s3:GetObject", "finance-reports", "q3.csv", NULL, "conditional", "ip-only");
  check(USER("carol"), "s3:GetObject", "finance-reports", "q3.csv", "{\"aws:SourceIp\":\"10.1.2.3\"}", "allowed", "ip-only");
  check(USER("carol"), "s3:GetObject", "finance-reports", "q3.csv", "{\"SourceIp\":\"192.168.1.9\"}", "denied", NULL);
  /* ${aws:username} */
  check(USER("frank"), "s3:GetObject", "home", "frank/notes.txt", NULL, "allowed", "home");
  check(USER("frank"), "s3:GetObject", "home", "gina/notes.txt", NULL, "denied", NULL);
  check(USER("erin"), "s3:GetObject", "finance-reports", "q3.csv", NULL, "denied", NULL);
  /* keys: the owner's access, narrowed */
  check("{\"kind\":\"key\",\"name\":\"AKREADONLY\"}", "s3:GetObject", "finance-reports", "q3.csv", NULL, "allowed", NULL);
  check("{\"kind\":\"key\",\"name\":\"AKREADONLY\"}", "s3:PutObject", "finance-reports", "q3.csv", NULL, "denied", NULL);
  check("{\"kind\":\"key\",\"name\":\"AKINHERITS\"}", "s3:PutObject", "finance-reports", "q3.csv", NULL, "allowed", "team-finance-rw");
  /* OpenID roles, anonymous requests, root */
  check("{\"kind\":\"openid\",\"roles\":[\"team-finance-rw\",\"no-such-policy\"]}", "s3:DeleteObject", "finance-reports", "x",
        NULL, "allowed", "team-finance-rw");
  check("{\"kind\":\"anonymous\"}", "s3:GetObject", "finance-reports", "public/a.txt", NULL, "allowed", "bucketPolicy");
  check("{\"kind\":\"anonymous\"}", "s3:GetObject", "finance-reports", "q3.csv", NULL, "denied", NULL);
  check("{\"kind\":\"root\",\"name\":\"rootadmin\"}", "s3:DeleteBucket", "finance-reports", "", NULL, "allowed", NULL);
  /* someone not in the facts */
  yyjson_doc *f = facts(true);
  yyjson_doc *w = yyjson_read(USER("zed"), strlen(USER("zed")), 0);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  assert_null(buckets_access_check(d, yyjson_doc_get_root(f), yyjson_doc_get_root(w), "s3:GetObject", "b", "o", NULL));
  yyjson_mut_doc_free(d);
  yyjson_doc_free(w);
  yyjson_doc_free(f);
}

/* For users whose policies have no conditions, every check agrees with the evaluator over their merged
 * policies, across a grid of actions and objects. */
static void test_agrees_with_evaluator(void **state) {
  (void)state;
  struct {
    const char *user;
    const char *policies[3];
  } users[] = {{"alice", {"team-finance-rw", NULL}}, {"bob", {"audit-ro", NULL}}, {"dave", {"readwrite", "deny-secret", NULL}},
               {"frank", {"home", NULL}}};
  const char *actions[] = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:PutBucketPolicy", "s3:DeleteBucket"};
  const char *targets[][2] = {{"finance-reports", "q3.csv"}, {"finance-reports", "reports/a"}, {"finance-reports", "secret/k"},
                              {"finance-reports", ""},       {"hr-payroll", "x"},            {"home", "frank/a"},
                              {"home", "gina/a"},            {"home", ""}};
  yyjson_doc *pol = yyjson_read(k_policies, strlen(k_policies), 0);
  yyjson_doc *f = facts(false);
  for (size_t u = 0; u < sizeof(users) / sizeof(users[0]); u++) {
    buckets_policy *ps[3] = {0};
    size_t np = 0;
    for (; users[u].policies[np]; np++) {
      char *js = yyjson_val_write(yyjson_obj_get(yyjson_doc_get_root(pol), users[u].policies[np]), 0, NULL);
      char err[256];
      assert_true(buckets_policy_parse(js, strlen(js), &ps[np], err, sizeof(err)));
      free(js);
    }
    char who[64];
    snprintf(who, sizeof(who), "{\"kind\":\"user\",\"name\":\"%s\"}", users[u].user);
    yyjson_doc *w = yyjson_read(who, strlen(who), 0);
    for (size_t a = 0; a < sizeof(actions) / sizeof(actions[0]); a++) {
      for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
        const char *uv[] = {users[u].user};
        buckets_cond_value cv = {"username", uv, 1};
        buckets_policy_args args = {.action = actions[a], .bucket = targets[t][0], .object = targets[t][1], .conds = &cv, .nconds = 1};
        bool want = buckets_policies_allowed((const buckets_policy *const *)ps, np, &args);
        yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
        yyjson_mut_val *r = buckets_access_check(d, yyjson_doc_get_root(f), yyjson_doc_get_root(w), actions[a], targets[t][0],
                                                 targets[t][1], NULL);
        bool got = strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(r, "decision")), "allowed") == 0;
        if (got != want)
          fail_msg("%s %s %s/%s: review says %d, evaluator %d", users[u].user, actions[a], targets[t][0], targets[t][1], got, want);
        yyjson_mut_doc_free(d);
      }
    }
    yyjson_doc_free(w);
    for (size_t i = 0; i < np; i++) buckets_policy_free(ps[i]);
  }
  yyjson_doc_free(f);
  yyjson_doc_free(pol);
}

/* A bucket policy that denies everyone writes under locked/ and names a partner account. */
static void test_bucket_policy_deny_and_account(void **state) {
  (void)state;
  const char *bp = "{" V ",\"Statement\":["
                   "{\"Sid\":\"Locked\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":[\"s3:PutObject\"],"
                   "\"Resource\":[\"arn:aws:s3:::finance-reports/locked/*\"]},"
                   "{\"Sid\":\"Partner\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"partner\"]},"
                   "\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::finance-reports/*\"]}]}";
  char buf[16384];
  snprintf(buf, sizeof(buf), "{\"policies\":%s,\"principals\":%s,\"bucketPolicy\":%s}", k_policies, k_principals, bp);
  yyjson_doc *f = yyjson_read(buf, strlen(buf), 0);
  assert_non_null(f);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  /* the Deny cuts into alice's team access */
  const char *who = USER("alice");
  yyjson_doc *w = yyjson_read(who, strlen(who), 0);
  yyjson_mut_val *r = buckets_access_check(d, yyjson_doc_get_root(f), yyjson_doc_get_root(w), "s3:PutObject",
                                           "finance-reports", "locked/a", NULL);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(r, "decision")), "denied");
  assert_true(yyjson_mut_get_bool(yyjson_mut_obj_get(yyjson_mut_arr_get_first(yyjson_mut_obj_get(r, "by")), "bucketPolicy")));
  r = buckets_access_check(d, yyjson_doc_get_root(f), yyjson_doc_get_root(w), "s3:PutObject", "finance-reports", "open/a", NULL);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(r, "decision")), "allowed");
  /* the partner account: a row of its own, from the bucket policy only; no "everyone" row (nothing allowed to all) */
  yyjson_mut_val *rev = buckets_access_bucket(d, yyjson_doc_get_root(f), "finance-reports", "read");
  yyjson_mut_doc_set_root(d, rev);
  char *j = yyjson_mut_write(d, 0, NULL);
  expect_row(j, "partner", (const char *[]){"\"kind\":\"account\"", "\"access\":\"limited\"", "\"sid\":\"Partner\"", NULL});
  expect_no_row(j, "everyone, signed in or not");
  free(j);
  yyjson_mut_doc_free(d);
  yyjson_doc_free(w);
  yyjson_doc_free(f);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_read_review),
      cmocka_unit_test(test_write_and_manage),
      cmocka_unit_test(test_checks),
      cmocka_unit_test(test_agrees_with_evaluator),
      cmocka_unit_test(test_bucket_policy_deny_and_account),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
