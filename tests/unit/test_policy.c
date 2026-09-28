/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The IAM policy engine against vectors produced by MinIO's own
 * github.com/minio/pkg/v3/policy (tools/policygen). */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iam/policy.h"
#include "policy_vectors.inc"

static void test_wildcard(void **state) {
  (void)state;
  for (size_t i = 0; i < sizeof(k_wildcard_vectors) / sizeof(k_wildcard_vectors[0]); i++) {
    bool got = buckets_wildcard_match(k_wildcard_vectors[i].pattern, k_wildcard_vectors[i].name);
    if (got != k_wildcard_vectors[i].match) {
      fail_msg("wildcard.Match(%s, %s) = %d, want %d", k_wildcard_vectors[i].pattern, k_wildcard_vectors[i].name, got,
               k_wildcard_vectors[i].match);
    }
  }
}

static void test_parse(void **state) {
  (void)state;
  int bad = 0;
  for (size_t i = 0; i < sizeof(k_parse_vectors) / sizeof(k_parse_vectors[0]); i++) {
    buckets_policy *p;
    char err[256] = "";
    bool ok = buckets_policy_parse(k_parse_vectors[i].doc, strlen(k_parse_vectors[i].doc), &p, err, sizeof(err));
    if (ok != k_parse_vectors[i].valid) {
      print_error("parse #%zu: got %s (%s), want %s: %s\n", i, ok ? "valid" : "invalid", err,
                  k_parse_vectors[i].valid ? "valid" : "invalid", k_parse_vectors[i].doc);
      bad++;
    }
    if (ok) buckets_policy_free(p);
  }
  assert_int_equal(bad, 0);
}

/* "k=v1,v2;k2=v;" -> condition values */
typedef struct {
  buckets_cond_value v[16];
  const char *vals[16][8];
  char buf[512];
  size_t n;
} conds;

static void parse_conds(const char *s, conds *c) {
  memset(c, 0, sizeof(*c));
  snprintf(c->buf, sizeof(c->buf), "%s", s);
  for (char *p = c->buf, *semi; *p; p = semi + 1) {
    semi = strchr(p, ';');
    *semi = '\0';
    char *eq = strchr(p, '=');
    *eq = '\0';
    buckets_cond_value *cv = &c->v[c->n];
    cv->key = p;
    size_t k = 0;
    for (char *q = eq + 1, *comma;; q = comma + 1) {
      comma = strchr(q, ',');
      if (comma) *comma = '\0';
      c->vals[c->n][k++] = q;
      if (!comma) break;
    }
    cv->values = c->vals[c->n];
    cv->n = k;
    c->n++;
  }
}

static void test_eval(void **state) {
  (void)state;
  size_t nd = sizeof(k_parse_vectors) / sizeof(k_parse_vectors[0]);
  buckets_policy **ps = calloc(nd, sizeof(*ps));
  for (size_t i = 0; i < nd; i++) {
    char err[256];
    if (k_parse_vectors[i].valid) buckets_policy_parse(k_parse_vectors[i].doc, strlen(k_parse_vectors[i].doc), &ps[i], err, sizeof(err));
  }
  int bad = 0;
  for (size_t i = 0; i < sizeof(k_eval_vectors) / sizeof(k_eval_vectors[0]); i++) {
    conds c;
    parse_conds(k_eval_vectors[i].cond, &c);
    buckets_policy_args a = {.action = k_eval_vectors[i].action, .bucket = k_eval_vectors[i].bucket,
                             .object = k_eval_vectors[i].object, .owner = k_eval_vectors[i].owner,
                             .conds = c.v, .nconds = c.n};
    const buckets_policy *p = ps[k_eval_vectors[i].doc];
    assert_non_null(p);
    bool got = buckets_policy_allowed(p, &a);
    if (got != k_eval_vectors[i].allowed) {
      if (bad < 20) {
        print_error("eval #%zu: got %d want %d: %s %s/%s owner=%d cond=%s\n  %s\n", i, got, k_eval_vectors[i].allowed,
                    a.action, a.bucket, a.object, a.owner, k_eval_vectors[i].cond, k_parse_vectors[k_eval_vectors[i].doc].doc);
      }
      bad++;
    }
  }
  for (size_t i = 0; i < nd; i++) buckets_policy_free(ps[i]);
  free(ps);
  assert_int_equal(bad, 0);
}

static void test_canned(void **state) {
  (void)state;
  const char *names[] = {"readwrite", "readonly", "writeonly", "diagnostics", "consoleAdmin"};
  for (size_t i = 0; i < 5; i++) {
    const char *doc = buckets_policy_canned(names[i]);
    assert_non_null(doc);
    buckets_policy *p;
    char err[256];
    if (!buckets_policy_parse(doc, strlen(doc), &p, err, sizeof(err))) fail_msg("%s: %s", names[i], err);
    buckets_policy_args a = {.action = "s3:GetObject", .bucket = "b", .object = "o"};
    bool get = buckets_policy_allowed(p, &a);
    assert_int_equal(get, strcmp(names[i], "writeonly") != 0 && strcmp(names[i], "diagnostics") != 0);
    buckets_policy_free(p);
  }
  assert_null(buckets_policy_canned("nope"));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_wildcard), cmocka_unit_test(test_parse), cmocka_unit_test(test_eval),
      cmocka_unit_test(test_canned),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
