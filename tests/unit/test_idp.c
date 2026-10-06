/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Identity page's settings (src/iam/idpsettings.h): checks, bucketsd's
 * identity_openid / identity_ldap lines, the console's view, secrets. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "config/config.h"
#include "iam/idpsettings.h"

static yyjson_doc *J(const char *s) {
  yyjson_doc *d = yyjson_read(s, strlen(s), 0);
  assert_non_null(d);
  return d;
}

static char *server(const char *json) {
  yyjson_doc *d = J(json);
  buckets_buf b = BUCKETS_BUF_INIT;
  char err[256];
  bool ok = buckets_idp_server_config(yyjson_doc_get_root(d), &b, err, sizeof(err));
  yyjson_doc_free(d);
  if (!ok) {
    buckets_buf_free(&b);
    return NULL;
  }
  return b.data;
}

static void expect_error(const char *json, const char *words) {
  yyjson_doc *d = J(json);
  char err[256] = "";
  assert_false(buckets_idp_check(yyjson_doc_get_root(d), err, sizeof(err)));
  if (!strstr(err, words)) fail_msg("error %s, expected it to mention %s", err, words);
  yyjson_doc_free(d);
}

static void test_entra(void **state) {
  (void)state;
  char *c = server("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"11111111-2222-3333-4444-555555555555\","
                   "\"clientId\":\"app-1\",\"clientSecret\":\"s3cret\"}}");
  assert_non_null(c);
  assert_non_null(strstr(c, "identity_openid enable=\"on\" display_name=\"Microsoft Entra ID\" config_url=\"https://"
                            "login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0/.well-known/openid-configuration\""));
  assert_non_null(strstr(c, " client_id=\"app-1\" client_secret=\"s3cret\" claim_name=\"roles\" scopes=\"openid,profile,email\"\n"));
  assert_non_null(strstr(c, "identity_ldap enable=\"off\"\n"));
  free(c);
}

static void test_okta_keycloak_generic(void **state) {
  (void)state;
  char *c = server("{\"openid\":{\"provider\":\"okta\",\"domain\":\"https://example.okta.com/\",\"clientId\":\"a\","
                   "\"clientSecret\":\"b\"}}");
  assert_non_null(strstr(c, "config_url=\"https://example.okta.com/oauth2/default/.well-known/openid-configuration\""));
  assert_non_null(strstr(c, "claim_name=\"groups\" scopes=\"openid,profile,email,groups\""));
  free(c);
  c = server("{\"openid\":{\"provider\":\"keycloak\",\"url\":\"https://kc.example.com/\",\"realm\":\"corp\",\"clientId\":\"a\","
             "\"clientSecret\":\"b\",\"scopes\":\"openid, email\",\"displayName\":\"Corp SSO\"}}");
  assert_non_null(strstr(c, "display_name=\"Corp SSO\" config_url=\"https://kc.example.com/realms/corp/.well-known/openid-configuration\""));
  assert_non_null(strstr(c, "scopes=\"openid,email\""));
  free(c);
  c = server("{\"openid\":{\"provider\":\"generic\",\"configUrl\":\"https://idp.example.com/.well-known/openid-configuration\","
             "\"clientId\":\"a\",\"clientSecret\":\"b\",\"rolePolicy\":\"readonly\",\"claimUserinfo\":true}}");
  assert_non_null(strstr(c, "role_policy=\"readonly\" scopes=\"openid,profile,email\" claim_userinfo=\"on\"\n"));
  assert_null(strstr(c, "claim_name"));
  free(c);
}

static void test_ldap(void **state) {
  (void)state;
  char *c = server("{\"ldap\":{\"preset\":\"ad\",\"serverAddr\":\"dc1.corp.local:636\",\"lookupBindDn\":\"cn=svc,dc=corp,dc=local\","
                   "\"lookupBindPassword\":\"pw\",\"userSearchBase\":\"dc=corp,dc=local\",\"groupSearchBase\":\"ou=groups,dc=corp,dc=local\"}}");
  assert_non_null(c);
  assert_non_null(strstr(c, "identity_openid enable=\"off\"\n"));
  assert_non_null(strstr(c, "identity_ldap enable=\"on\" server_addr=\"dc1.corp.local:636\" lookup_bind_dn=\"cn=svc,dc=corp,dc=local\" "
                            "lookup_bind_password=\"pw\" user_dn_search_base_dn=\"dc=corp,dc=local\" "
                            "user_dn_search_filter=\"(&(objectCategory=user)(sAMAccountName=%s))\" "
                            "group_search_base_dn=\"ou=groups,dc=corp,dc=local\" group_search_filter=\"(&(objectClass=group)(member=%d))\" "
                            "server_starttls=\"off\" server_insecure=\"off\" tls_skip_verify=\"off\"\n"));
  free(c);
  c = server("{\"ldap\":{\"preset\":\"openldap\",\"serverAddr\":\"ldap:389\",\"tls\":\"starttls\",\"lookupBindDn\":\"cn=r\","
             "\"lookupBindPassword\":\"p\",\"userSearchBase\":\"ou=people,dc=x\"}}");
  assert_non_null(strstr(c, "user_dn_search_filter=\"(&(objectClass=inetOrgPerson)(uid=%s))\" server_starttls=\"on\""));
  assert_null(strstr(c, "group_search")); /* no group base: no group search */
  free(c);
}

static void test_errors(void **state) {
  (void)state;
  expect_error("{\"openid\":{\"provider\":\"ping\"}}", "Choose an identity provider");
  expect_error("{\"openid\":{\"provider\":\"entra\",\"clientId\":\"a\",\"clientSecret\":\"b\"}}", "tenant");
  expect_error("{\"openid\":{\"provider\":\"okta\",\"domain\":\"\",\"clientId\":\"a\",\"clientSecret\":\"b\"}}", "Okta domain");
  expect_error("{\"openid\":{\"provider\":\"keycloak\",\"url\":\"kc.example.com\",\"realm\":\"r\",\"clientId\":\"a\",\"clientSecret\":\"b\"}}",
               "base URL");
  expect_error("{\"openid\":{\"provider\":\"generic\",\"configUrl\":\"https://x\",\"clientId\":\"a\"}}", "client secret");
  expect_error("{\"openid\":{\"provider\":\"generic\",\"configUrl\":\"https://x\",\"clientId\":\"a\",\"clientSecret\":\"b\","
               "\"redirectUri\":\"https://console.example.com/callback\"}}",
               "/oauth_callback");
  expect_error("{\"ldap\":{\"serverAddr\":\"ldaps://dc1\"}}", "host or host:port");
  expect_error("{\"ldap\":{\"serverAddr\":\"dc1\",\"lookupBindDn\":\"cn=r\",\"lookupBindPassword\":\"p\",\"userSearchBase\":\"dc=x\","
               "\"preset\":\"custom\",\"userSearchFilter\":\"(uid=bob)\"}}",
               "%s");
  expect_error("{\"openid\":{\"provider\":\"generic\",\"configUrl\":\"https://x\",\"clientId\":\"a\\\"b\",\"clientSecret\":\"b\"}}",
               "double quotes");
}

static void test_console_view(void **state) {
  (void)state;
  yyjson_doc *d = J("{\"openid\":{\"provider\":\"okta\",\"domain\":\"example.okta.com\",\"clientId\":\"a\",\"clientSecret\":\"b\"},"
                    "\"ldap\":{\"preset\":\"ad\",\"serverAddr\":\"dc1\"}}");
  yyjson_mut_doc *m = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(m, buckets_idp_console_view(m, yyjson_doc_get_root(d)));
  char *s = yyjson_mut_write(m, 0, NULL);
  assert_string_equal(s, "{\"oidc\":{\"configUrl\":\"https://example.okta.com/oauth2/default/.well-known/openid-configuration\","
                         "\"clientId\":\"a\",\"clientSecret\":\"b\",\"scopes\":\"openid profile email groups\",\"displayName\":\"Okta\","
                         "\"redirectUri\":\"\"},\"ldap\":{\"displayName\":\"Active Directory\"}}");
  free(s);
  yyjson_mut_doc_free(m);
  yyjson_doc_free(d);
}

static void test_secrets(void **state) {
  (void)state;
  yyjson_doc *saved = J("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t\",\"clientId\":\"a\",\"clientSecret\":\"old\"},"
                        "\"ldap\":{\"serverAddr\":\"dc1\",\"lookupBindPassword\":\"pw\"}}");
  yyjson_mut_doc *m = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(m, buckets_idp_settings_redacted(m, yyjson_doc_get_root(saved)));
  char *s = yyjson_mut_write(m, 0, NULL);
  assert_null(strstr(s, "old"));
  assert_null(strstr(s, "\"pw\""));
  assert_non_null(strstr(s, "\"secretsSet\":[\"openid.clientSecret\",\"ldap.lookupBindPassword\"]"));
  free(s);
  yyjson_mut_doc_free(m);
  /* an edit that leaves the secrets empty keeps them; another provider or server does not */
  yyjson_doc *edit = J("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t2\",\"clientId\":\"a\",\"clientSecret\":\"\"},"
                       "\"ldap\":{\"serverAddr\":\"dc2\",\"lookupBindPassword\":\"\"},\"secretsSet\":[]}");
  m = yyjson_doc_mut_copy(edit, NULL);
  buckets_idp_settings_keep_secrets(m, yyjson_mut_doc_get_root(m), yyjson_doc_get_root(saved));
  s = yyjson_mut_write(m, 0, NULL);
  assert_non_null(strstr(s, "\"clientSecret\":\"old\""));
  assert_non_null(strstr(s, "\"lookupBindPassword\":\"\""));
  assert_null(strstr(s, "secretsSet"));
  free(s);
  yyjson_mut_doc_free(m);
  yyjson_doc_free(edit);
  yyjson_doc_free(saved);
}

static void test_describe(void **state) {
  (void)state;
  char out[256];
  yyjson_doc *d = J("{\"openid\":{\"provider\":\"keycloak\",\"url\":\"https://kc\",\"realm\":\"corp\"},\"ldap\":{\"preset\":\"openldap\","
                    "\"serverAddr\":\"ldap.corp\"}}");
  buckets_idp_settings_describe(yyjson_doc_get_root(d), out, sizeof(out));
  assert_string_equal(out, "Keycloak realm corp at https://kc; LDAP at ldap.corp");
  yyjson_doc_free(d);
  d = J("{}");
  buckets_idp_settings_describe(yyjson_doc_get_root(d), out, sizeof(out));
  assert_string_equal(out, "not configured");
  yyjson_doc_free(d);
}

/* openid.removal: Entra only, the sync's settings from the sign-in app's, not in bucketsd's configuration */
static void test_removal(void **state) {
  (void)state;
  const char *entra = "{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t-1\",\"clientId\":\"app-1\","
                      "\"clientSecret\":\"s3cret\",\"removal\":{\"enabled\":true,\"deleteAfterDays\":14}}}";
  yyjson_doc *d = J(entra);
  char err[256] = "", out[512];
  assert_true(buckets_idp_check(yyjson_doc_get_root(d), err, sizeof(err)));
  buckets_idp_removal rm;
  assert_true(buckets_idp_removal_of(yyjson_doc_get_root(d), &rm));
  assert_string_equal(rm.tenant, "t-1");
  assert_string_equal(rm.client_id, "app-1");
  assert_string_equal(rm.client_secret, "s3cret");
  assert_int_equal(rm.delete_after_days, 14);
  assert_int_equal(rm.max_per_sync, 10);
  buckets_idp_settings_describe(yyjson_doc_get_root(d), out, sizeof(out));
  assert_string_equal(out, "Microsoft Entra ID (tenant t-1), people who leave removed (keys deleted after 14 days)");
  yyjson_doc_free(d);
  char *c = server(entra);
  assert_non_null(c);
  assert_null(strstr(c, "removal"));
  assert_null(strstr(c, "14"));
  free(c);

  d = J("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t-1\",\"clientId\":\"a\",\"clientSecret\":\"b\","
        "\"removal\":{\"enabled\":false}}}");
  assert_false(buckets_idp_removal_of(yyjson_doc_get_root(d), &rm));
  yyjson_doc_free(d);
  expect_error("{\"openid\":{\"provider\":\"keycloak\",\"url\":\"https://kc\",\"realm\":\"r\",\"clientId\":\"a\","
               "\"clientSecret\":\"b\",\"removal\":{\"enabled\":true}}}",
               "Entra ID for now");
  expect_error("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t\",\"clientId\":\"a\",\"clientSecret\":\"b\","
               "\"removal\":{\"enabled\":true,\"deleteAfterDays\":0}}}",
               "1 to 3650 days");
  expect_error("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t\",\"clientId\":\"a\",\"clientSecret\":\"b\","
               "\"removal\":{\"enabled\":true,\"maxPerSync\":\"ten\"}}}",
               "most people removed");
}

/* bucketsd's own parser reads every line back as written: values with spaces
 * and commas (Active Directory DNs), filters with = inside, the secret. */
static void test_server_config_parses(void **state) {
  (void)state;
  char *text = server("{\"openid\":{\"provider\":\"entra\",\"tenantId\":\"t-1\",\"clientId\":\"app 1\",\"clientSecret\":\"a=b c\","
                      "\"displayName\":\"Sign in with Entra ID\"},"
                      "\"ldap\":{\"preset\":\"ad\",\"serverAddr\":\"dc1.corp.local:636\",\"lookupBindDn\":\"CN=Service Account,OU=Svc,DC=corp,DC=local\","
                      "\"lookupBindPassword\":\"p w=1\",\"userSearchBase\":\"OU=Staff,DC=corp,DC=local\",\"groupSearchBase\":\"OU=Groups,DC=corp,DC=local\"}}");
  assert_non_null(text);
  buckets_config *cfg = buckets_config_new();
  char *line = strtok(text, "\n");
  while (line) {
    bool dyn;
    char err[256];
    if (!buckets_config_set_text(cfg, line, &dyn, err, sizeof(err))) fail_msg("%s: %s", line, err);
    line = strtok(NULL, "\n");
  }
  static const char *const want[][3] = {
      {"identity_openid", "display_name", "Sign in with Entra ID"},
      {"identity_openid", "client_id", "app 1"},
      {"identity_openid", "client_secret", "a=b c"},
      {"identity_openid", "claim_name", "roles"},
      {"identity_openid", "scopes", "openid,profile,email"},
      {"identity_ldap", "lookup_bind_dn", "CN=Service Account,OU=Svc,DC=corp,DC=local"},
      {"identity_ldap", "lookup_bind_password", "p w=1"},
      {"identity_ldap", "user_dn_search_filter", "(&(objectCategory=user)(sAMAccountName=%s))"},
      {"identity_ldap", "group_search_filter", "(&(objectClass=group)(member=%d))"},
      {"identity_ldap", "server_starttls", "off"},
  };
  for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
    char *v = buckets_config_get_stored(cfg, want[i][0], "", want[i][1]);
    if (!v || strcmp(v, want[i][2]) != 0) fail_msg("%s %s = %s, want %s", want[i][0], want[i][1], v ? v : "(none)", want[i][2]);
    free(v);
  }
  buckets_config_free(cfg);
  free(text);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_entra),        cmocka_unit_test(test_okta_keycloak_generic), cmocka_unit_test(test_ldap),
      cmocka_unit_test(test_errors),       cmocka_unit_test(test_console_view),         cmocka_unit_test(test_secrets),
      cmocka_unit_test(test_describe),     cmocka_unit_test(test_server_config_parses), cmocka_unit_test(test_removal),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
