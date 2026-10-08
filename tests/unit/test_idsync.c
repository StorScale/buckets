/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iam/idsync.h"

#define DAY 86400LL

static void test_graph_state(void **state) {
  (void)state;
  const char *on = "{\"id\":\"u1\",\"accountEnabled\":true}",
             *off = "{\"id\":\"u1\",\"accountEnabled\":false}";
  assert_int_equal(buckets_idsync_graph_state(200, on, strlen(on)), BUCKETS_IDSYNC_ACTIVE);
  assert_int_equal(buckets_idsync_graph_state(200, off, strlen(off)), BUCKETS_IDSYNC_DISABLED);
  const char *gone =
      "{\"error\":{\"code\":\"Request_ResourceNotFound\",\"message\":\"Resource 'u1' does not exist\"}}";
  assert_int_equal(buckets_idsync_graph_state(404, gone, strlen(gone)), BUCKETS_IDSYNC_GONE);
  /* anything else is not an answer: nobody is removed on it */
  const char *other404 = "<html>Not Found</html>",
             *denied = "{\"error\":{\"code\":\"Authorization_RequestDenied\"}}";
  assert_int_equal(buckets_idsync_graph_state(404, other404, strlen(other404)), BUCKETS_IDSYNC_UNKNOWN);
  assert_int_equal(buckets_idsync_graph_state(403, denied, strlen(denied)), BUCKETS_IDSYNC_UNKNOWN);
  assert_int_equal(buckets_idsync_graph_state(200, "{\"id\":\"u1\"}", 11), BUCKETS_IDSYNC_UNKNOWN);
  assert_int_equal(buckets_idsync_graph_state(500, NULL, 0), BUCKETS_IDSYNC_UNKNOWN);
}

static void test_keycloak_okta_state(void **state) {
  (void)state;
  const char *on = "{\"id\":\"u1\",\"username\":\"ann\",\"enabled\":true}",
             *off = "{\"id\":\"u1\",\"enabled\":false}";
  assert_int_equal(buckets_idsync_keycloak_state(200, on, strlen(on)), BUCKETS_IDSYNC_ACTIVE);
  assert_int_equal(buckets_idsync_keycloak_state(200, off, strlen(off)), BUCKETS_IDSYNC_DISABLED);
  const char *gone = "{\"error\":\"User not found\"}", *realm = "{\"error\":\"Realm not found.\"}";
  assert_int_equal(buckets_idsync_keycloak_state(404, gone, strlen(gone)), BUCKETS_IDSYNC_GONE);
  assert_int_equal(buckets_idsync_keycloak_state(404, realm, strlen(realm)),
                   BUCKETS_IDSYNC_UNKNOWN); /* a wrong realm */
  const char *denied = "{\"error\":\"HTTP 403 Forbidden\"}";
  assert_int_equal(buckets_idsync_keycloak_state(403, denied, strlen(denied)), BUCKETS_IDSYNC_UNKNOWN);

  static const struct {
    const char *status;
    buckets_idsync_state want;
  } okta[] = {{"ACTIVE", BUCKETS_IDSYNC_ACTIVE},      {"PROVISIONED", BUCKETS_IDSYNC_ACTIVE},
              {"LOCKED_OUT", BUCKETS_IDSYNC_ACTIVE},  {"PASSWORD_EXPIRED", BUCKETS_IDSYNC_ACTIVE},
              {"RECOVERY", BUCKETS_IDSYNC_ACTIVE},    {"STAGED", BUCKETS_IDSYNC_ACTIVE},
              {"SUSPENDED", BUCKETS_IDSYNC_DISABLED}, {"DEPROVISIONED", BUCKETS_IDSYNC_DISABLED}};
  for (size_t i = 0; i < sizeof(okta) / sizeof(okta[0]); i++) {
    char body[128];
    snprintf(body, sizeof(body), "{\"id\":\"00u1\",\"status\":\"%s\"}", okta[i].status);
    assert_int_equal(buckets_idsync_okta_state(200, body, strlen(body)), okta[i].want);
  }
  const char *ogone =
      "{\"errorCode\":\"E0000007\",\"errorSummary\":\"Not found: Resource not found: 00u1 (User)\"}";
  const char *other =
      "{\"errorCode\":\"E0000007\",\"errorSummary\":\"Not found: Resource not found: x (AppInstance)\"}";
  const char *bad = "{\"errorCode\":\"E0000011\",\"errorSummary\":\"Invalid token provided\"}";
  assert_int_equal(buckets_idsync_okta_state(404, ogone, strlen(ogone)), BUCKETS_IDSYNC_GONE);
  assert_int_equal(buckets_idsync_okta_state(404, other, strlen(other)), BUCKETS_IDSYNC_UNKNOWN);
  assert_int_equal(buckets_idsync_okta_state(401, bad, strlen(bad)), BUCKETS_IDSYNC_UNKNOWN);
}

static void test_person_of(void **state) {
  (void)state;
  buckets_idsync_settings e = {.provider = "entra", .tenant = "t-1"};
  assert_string_equal(buckets_idsync_person_of(&e, "t-1", "o-1", "https://login/x", "s-1"), "o-1");
  assert_null(buckets_idsync_person_of(&e, "t-2", "o-1", NULL, NULL)); /* another tenant */
  assert_null(buckets_idsync_person_of(&e, "t-1", NULL, NULL, "s-1"));
  buckets_idsync_settings k = {.provider = "keycloak", .issuer = "https://kc.example.com/realms/corp"};
  assert_string_equal(buckets_idsync_person_of(&k, NULL, NULL, "https://kc.example.com/realms/corp", "u-1"),
                      "u-1");
  assert_string_equal(buckets_idsync_person_of(&k, NULL, NULL, "https://kc.example.com/realms/corp/", "u-1"),
                      "u-1");
  assert_null(buckets_idsync_person_of(&k, NULL, NULL, "https://kc.example.com/realms/other", "u-1"));
  assert_null(buckets_idsync_person_of(&k, NULL, NULL, "https://kc.example.com/realms/corpx", "u-1"));
  assert_null(buckets_idsync_person_of(&k, NULL, NULL, "https://kc.example.com/realms/corp", NULL));
  buckets_idsync_settings off = {0};
  assert_null(buckets_idsync_person_of(&off, "t-1", "o-1", "x", "y"));
}

static void test_settings_providers(void **state) {
  (void)state;
  buckets_idsync_settings s;
  char err[256] = "";
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "keycloak", 1);
  setenv("BUCKETS_OPENID_SYNC_URL", "https://kc.example.com/", 1);
  setenv("BUCKETS_OPENID_SYNC_CLIENT_ID", "buckets", 1);
  setenv("BUCKETS_OPENID_SYNC_CLIENT_SECRET", "s", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(strstr(err, "REALM"));
  setenv("BUCKETS_OPENID_SYNC_REALM", "corp", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_string_equal(s.url, "https://kc.example.com");
  assert_string_equal(s.issuer, "https://kc.example.com/realms/corp");
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "okta", 1);
  setenv("BUCKETS_OPENID_SYNC_URL", "https://example.okta.com", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(strstr(err, "API_TOKEN"));
  setenv("BUCKETS_OPENID_SYNC_API_TOKEN", "00abc", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(
      strstr(err, "ISSUER")); /* Okta's issuer is the authorization server's: given, not guessed */
  setenv("BUCKETS_OPENID_SYNC_ISSUER", "https://example.okta.com/oauth2/default", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_string_equal(s.api_token, "00abc");
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "ping", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(strstr(err, "entra, keycloak, okta or scim"));
  const char *vars[] = {"BUCKETS_OPENID_SYNC_PROVIDER",  "BUCKETS_OPENID_SYNC_URL",
                        "BUCKETS_OPENID_SYNC_CLIENT_ID", "BUCKETS_OPENID_SYNC_CLIENT_SECRET",
                        "BUCKETS_OPENID_SYNC_REALM",     "BUCKETS_OPENID_SYNC_API_TOKEN",
                        "BUCKETS_OPENID_SYNC_ISSUER"};
  for (size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); i++) unsetenv(vars[i]);
}

static void test_settings(void **state) {
  (void)state;
  buckets_idsync_settings s;
  char err[256] = "";
  unsetenv("BUCKETS_OPENID_SYNC_PROVIDER");
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_string_equal(s.provider, ""); /* off */
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "ping", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(strstr(err, "entra, keycloak, okta or scim"));
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "entra", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(strstr(err, "TENANT_ID"));
  setenv("BUCKETS_OPENID_SYNC_TENANT_ID", "t1", 1);
  setenv("BUCKETS_OPENID_SYNC_CLIENT_ID", "c1", 1);
  setenv("BUCKETS_OPENID_SYNC_CLIENT_SECRET", "s1", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_int_equal(s.interval_s, 3600);
  assert_int_equal(s.remove_after_s, 30 * DAY);
  assert_int_equal(s.remove_max, 10);
  assert_string_equal(s.graph_url, "https://graph.microsoft.com");
  setenv("BUCKETS_OPENID_REMOVE_AFTER", "7", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_int_equal(s.remove_after_s, 7 * DAY);
  setenv("BUCKETS_OPENID_REMOVE_AFTER", "90s", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_int_equal(s.remove_after_s, 90);
  setenv("BUCKETS_OPENID_REMOVE_AFTER", "a week", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  unsetenv("BUCKETS_OPENID_REMOVE_AFTER");
  setenv("BUCKETS_OPENID_SYNC_INTERVAL", "0", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  unsetenv("BUCKETS_OPENID_SYNC_INTERVAL");
  unsetenv("BUCKETS_OPENID_SYNC_PROVIDER");
}

static size_t count(const buckets_idsync_plan *p, buckets_idsync_action_kind k, const char *access_key) {
  size_t n = 0;
  for (size_t i = 0; i < p->n; i++)
    n += p->actions[i].kind == k && (!access_key || strcmp(p->actions[i].access_key, access_key) == 0);
  return n;
}

static void test_plan(void **state) {
  (void)state;
  const buckets_idsync_cred creds[] = {
      {"STS-ANN", "ann", true, true},   {"KEY-ANN", "ann", false, true}, {"KEY-ANN-OFF", "ann", false, false},
      {"KEY-BOB", "bob", false, true},  {"STS-CAT", "cat", true, true},  {"KEY-CAT", "cat", false, true},
      {"KEY-DAN", "dan", false, false}, {"KEY-EVE", "eve", false, true},
  };
  const char *people[] = {"ann", "bob", "cat", "dan", "eve"};
  /* ann gone, bob active, cat disabled, dan back (his key was turned off by the sync), eve not answered */
  buckets_idsync_state states[] = {BUCKETS_IDSYNC_GONE, BUCKETS_IDSYNC_ACTIVE, BUCKETS_IDSYNC_DISABLED,
                                   BUCKETS_IDSYNC_ACTIVE, BUCKETS_IDSYNC_UNKNOWN};
  buckets_idsync_answers ans = {people, states, 5};
  buckets_idsync_held held[] = {{"KEY-DAN", "dan", 1000}, {"KEY-GONE", "fay", 1000}};
  buckets_idsync_plan p;
  buckets_idsync_plan_make(creds, 8, &ans, held, 2, 2000, 30 * DAY, 10, &p);
  assert_false(p.held);
  assert_int_equal(p.people_leaving, 2); /* ann and cat */
  assert_int_equal(count(&p, BUCKETS_IDSYNC_REVOKE, "STS-ANN"), 1);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_REVOKE, "STS-CAT"), 1);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_DISABLE, "KEY-ANN"), 1);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_DISABLE, "KEY-CAT"), 1);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_DISABLE, "KEY-ANN-OFF"),
                   0); /* its owner turned it off: left as it is */
  assert_int_equal(count(&p, BUCKETS_IDSYNC_ENABLE, "KEY-DAN"), 1);  /* back within the grace period */
  assert_int_equal(count(&p, BUCKETS_IDSYNC_FORGET, "KEY-GONE"), 1); /* deleted meanwhile */
  assert_int_equal(
      count(&p, BUCKETS_IDSYNC_DISABLE, "KEY-BOB") + count(&p, BUCKETS_IDSYNC_DISABLE, "KEY-EVE"), 0);
  assert_int_equal(p.n, 6);
  buckets_idsync_plan_free(&p);

  /* a key the sync turned off: deleted once the grace period is over, not before */
  const buckets_idsync_cred off[] = {{"KEY-ANN", "ann", false, false}};
  buckets_idsync_held h1[] = {{"KEY-ANN", "ann", 0}};
  buckets_idsync_plan_make(off, 1, &ans, h1, 1, 30 * DAY - 1, 30 * DAY, 10, &p);
  assert_int_equal(p.n, 0);
  assert_int_equal(p.people_leaving, 0); /* nothing left to take away */
  buckets_idsync_plan_free(&p);
  buckets_idsync_plan_make(off, 1, &ans, h1, 1, 30 * DAY, 30 * DAY, 10, &p);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_DELETE, "KEY-ANN"), 1);
  buckets_idsync_plan_free(&p);

  /* a person whose state could not be learned keeps what the sync turned off, neither back on nor deleted */
  buckets_idsync_held h2[] = {{"KEY-EVE", "eve", 0}};
  const buckets_idsync_cred eve[] = {{"KEY-EVE", "eve", false, false}};
  buckets_idsync_plan_make(eve, 1, &ans, h2, 1, 100 * DAY, 30 * DAY, 10, &p);
  assert_int_equal(p.n, 0);
  buckets_idsync_plan_free(&p);
}

static void test_safety_limit(void **state) {
  (void)state;
  const buckets_idsync_cred creds[] = {{"K1", "p1", false, true},
                                       {"S1", "p1", true, true},
                                       {"K2", "p2", false, true},
                                       {"K3", "p3", false, true},
                                       {"K4", "p4", false, false}};
  const char *people[] = {"p1", "p2", "p3", "p4"};
  buckets_idsync_state gone[] = {BUCKETS_IDSYNC_GONE, BUCKETS_IDSYNC_GONE, BUCKETS_IDSYNC_GONE,
                                 BUCKETS_IDSYNC_ACTIVE};
  buckets_idsync_answers ans = {people, gone, 4};
  buckets_idsync_held held[] = {{"K4", "p4", 0}};
  buckets_idsync_plan p;
  buckets_idsync_plan_make(creds, 5, &ans, held, 1, 10, 30 * DAY, 2, &p);
  assert_true(p.held); /* 3 people at once, more than 2 */
  assert_int_equal(p.people_leaving, 3);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_REVOKE, NULL) + count(&p, BUCKETS_IDSYNC_DISABLE, NULL), 0);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_ENABLE, "K4"), 1); /* bringing keys back is not held */
  buckets_idsync_plan_free(&p);
  buckets_idsync_plan_make(creds, 5, &ans, held, 1, 10, 30 * DAY, 3, &p);
  assert_false(p.held);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_DISABLE, NULL), 3);
  assert_int_equal(count(&p, BUCKETS_IDSYNC_REVOKE, "S1"), 1);
  buckets_idsync_plan_free(&p);
}

static void test_held_json(void **state) {
  (void)state;
  buckets_idsync_held in[] = {{"K1", "p1", 1700000000}, {"K2", "p2", 5}};
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_idsync_held_json(in, 2, &b);
  buckets_idsync_held *out;
  size_t n;
  assert_true(buckets_idsync_held_parse(b.data, b.len, &out, &n));
  assert_int_equal(n, 2);
  assert_string_equal(out[0].access_key, "K1");
  assert_string_equal(out[1].person, "p2");
  assert_int_equal(out[0].since, 1700000000);
  buckets_idsync_held_free(out, n);
  assert_true(buckets_idsync_held_parse(NULL, 0, &out, &n)); /* never written: nothing held */
  assert_int_equal(n, 0);
  buckets_idsync_held_free(out, n);
  assert_false(buckets_idsync_held_parse("{\"held\":", 8, &out, &n));
  assert_false(buckets_idsync_held_parse("{\"held\":5}", 10, &out, &n));
  buckets_buf_free(&b);
}

/* SCIM only: no API; people by Entra's tid and oid, or by an issuer and sub */
static void test_scim_settings(void **state) {
  (void)state;
  buckets_idsync_settings s;
  char err[256] = "";
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "scim", 1);
  assert_false(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_non_null(strstr(err, "TENANT_ID"));
  setenv("BUCKETS_OPENID_SYNC_TENANT_ID", "t-1", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_true(s.scim);
  assert_string_equal(buckets_idsync_person_of(&s, "t-1", "oid-9", NULL, NULL), "oid-9");
  assert_null(buckets_idsync_person_of(&s, "t-2", "oid-9", NULL, NULL));
  unsetenv("BUCKETS_OPENID_SYNC_TENANT_ID");
  setenv("BUCKETS_OPENID_SYNC_ISSUER", "https://example.okta.com/oauth2/default", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_string_equal(buckets_idsync_person_of(&s, NULL, NULL, "https://example.okta.com/oauth2/default/", "00u1"), "00u1");
  /* beside an API provider, with BUCKETS_SCIM */
  setenv("BUCKETS_OPENID_SYNC_PROVIDER", "okta", 1);
  setenv("BUCKETS_OPENID_SYNC_URL", "https://example.okta.com", 1);
  setenv("BUCKETS_OPENID_SYNC_API_TOKEN", "00abc", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_false(s.scim);
  setenv("BUCKETS_SCIM", "on", 1);
  assert_true(buckets_idsync_settings_from_env(&s, err, sizeof(err)));
  assert_true(s.scim);
  const char *vars[] = {"BUCKETS_OPENID_SYNC_PROVIDER", "BUCKETS_OPENID_SYNC_URL", "BUCKETS_OPENID_SYNC_API_TOKEN",
                        "BUCKETS_OPENID_SYNC_ISSUER", "BUCKETS_SCIM"};
  for (size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); i++) unsetenv(vars[i]);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_scim_settings),
      cmocka_unit_test(test_graph_state), cmocka_unit_test(test_settings),
      cmocka_unit_test(test_plan),        cmocka_unit_test(test_safety_limit),
      cmocka_unit_test(test_held_json),   cmocka_unit_test(test_keycloak_okta_state),
      cmocka_unit_test(test_person_of),   cmocka_unit_test(test_settings_providers),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
