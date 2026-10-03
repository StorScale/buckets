/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "kms/kesutil.h"

/* ---- API keys and identities ------------------------------------------------------ */

static void test_identity_vector(void **state) {
  (void)state;
  char hex[65];
  /* kms-go's ExampleAPIKey_Identity */
  assert_true(buckets_kes_identity("kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs", hex));
  assert_string_equal(hex, "ea9826089311fe44d7590408ede9150f7c637b6cab0a91ee6fe1aa5d9fb366f6");
  assert_false(buckets_kes_identity("kes:v1:AQ==", hex));
  assert_false(buckets_kes_identity("kes:v1:AWaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs", hex)); /* type 1 */
}

static void test_api_key_new(void **state) {
  (void)state;
  char a[64], b[64], ha[65], hb[65];
  buckets_kes_api_key_new(a);
  buckets_kes_api_key_new(b);
  assert_int_equal(strlen(a), 7 + 44);
  assert_memory_equal(a, "kes:v1:A", 8); /* type byte 0 */
  assert_string_not_equal(a, b);
  assert_true(buckets_kes_identity(a, ha));
  assert_true(buckets_kes_identity(b, hb));
  assert_string_not_equal(ha, hb);
}

static void test_server_cert(void **state) {
  (void)state;
  const char *dns[] = {"store-kes", "store-kes.ns.svc", "store-kes.ns.svc.cluster.local"};
  buckets_buf cert = BUCKETS_BUF_INIT, key = BUCKETS_BUF_INIT;
  char err[128];
  assert_true(buckets_kes_server_cert(dns, 3, 3650, &cert, &key, err, sizeof(err)));
  assert_non_null(strstr(cert.data, "-----BEGIN CERTIFICATE-----"));
  assert_non_null(strstr(key.data, "PRIVATE KEY-----"));
  BIO *bio = BIO_new_mem_buf(cert.data, (int)cert.len);
  X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  assert_non_null(x);
  assert_int_equal(X509_check_host(x, "store-kes.ns.svc", 0, 0, NULL), 1);
  assert_int_equal(X509_check_host(x, "other.ns.svc", 0, 0, NULL), 0);
  assert_int_equal(X509_check_ca(x), 1); /* its own trust anchor */
  EVP_PKEY *pk = X509_get0_pubkey(x);
  assert_int_equal(X509_verify(x, pk), 1);
  X509_free(x);
  buckets_buf_free(&cert);
  buckets_buf_free(&key);
}

/* ---- key store settings ----------------------------------------------------------- */

/* the keystore rendered from settings JSON, as compact JSON; NULL and err on refusal */
static char *render(const char *settings, char *err, size_t errlen) {
  yyjson_doc *in = yyjson_read(settings, strlen(settings), 0);
  assert_non_null(in);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *ks = buckets_kes_keystore(d, yyjson_doc_get_root(in), "/etc/kes/keystore-ca.pem", err, errlen);
  char *out = NULL;
  if (ks) {
    yyjson_mut_doc_set_root(d, ks);
    out = yyjson_mut_write(d, YYJSON_WRITE_NOFLAG, NULL);
  }
  yyjson_mut_doc_free(d);
  yyjson_doc_free(in);
  return out;
}

static void expect_render(const char *settings, const char *want) {
  char err[256] = "";
  char *got = render(settings, err, sizeof(err));
  if (!got) fail_msg("refused: %s", err);
  assert_string_equal(got, want);
  free(got);
}

static void expect_refused(const char *settings, const char *why) {
  char err[256] = "";
  char *got = render(settings, err, sizeof(err));
  if (got) fail_msg("accepted: %s", got);
  if (!strstr(err, why)) fail_msg("message %s lacks %s", err, why);
}

static void test_keystore_vault(void **state) {
  (void)state;
  expect_render("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://vault:8200\",\"prefix\":\"buckets/store\","
                "\"approle\":{\"id\":\"rid\",\"secret\":\"sid\"}}}",
                "{\"vault\":{\"endpoint\":\"https://vault:8200\",\"engine\":\"kv\",\"version\":\"v2\",\"prefix\":"
                "\"buckets/store\",\"approle\":{\"engine\":\"approle\",\"id\":\"rid\",\"secret\":\"sid\"},\"status\":{"
                "\"ping\":\"10s\"}}}");
  expect_render("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://vault:8200\",\"engine\":\"secret\",\"version\":"
                "\"v1\",\"namespace\":\"team\",\"auth\":\"kubernetes\",\"kubernetes\":{\"role\":\"kes\",\"namespace\":\"/\"},\"transit\":{"
                "\"key\":\"wrap\"},\"caCert\":\"-----BEGIN CERTIFICATE-----\\nx\\n-----END CERTIFICATE-----\\n\"}}",
                "{\"vault\":{\"endpoint\":\"https://vault:8200\",\"engine\":\"secret\",\"version\":\"v1\",\"namespace\":"
                "\"team\",\"kubernetes\":{\"engine\":\"kubernetes\",\"namespace\":\"/\",\"role\":\"kes\",\"jwt\":"
                "\"/var/run/secrets/kubernetes.io/serviceaccount/token\"},\"transit\":{\"engine\":\"transit\",\"key\":"
                "\"wrap\"},\"tls\":{\"ca\":\"/etc/kes/keystore-ca.pem\"},\"status\":{\"ping\":\"10s\"}}}");
  expect_refused("{\"backend\":\"vault\",\"vault\":{}}", "Vault server's address");
  expect_refused("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"vault:8200\"}}", "must start with https://");
  expect_refused("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"approle\":{\"id\":\"r\"}}}", "secret ID");
  expect_refused("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"auth\":\"kubernetes\"}}", "Vault role");
  expect_refused("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"version\":\"v3\"}}", "v1 or v2");
  expect_refused("{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"approle\":{\"id\":\"r\",\"secret\":\"s\"},"
                 "\"caCert\":\"not pem\"}}",
                 "PEM");
}

static void test_keystore_aws_azure_gcp(void **state) {
  (void)state;
  expect_render("{\"backend\":\"aws\",\"aws\":{\"region\":\"us-east-2\"}}",
                "{\"aws\":{\"secretsmanager\":{\"endpoint\":\"secretsmanager.us-east-2.amazonaws.com\",\"region\":"
                "\"us-east-2\"}}}");
  expect_render("{\"backend\":\"aws\",\"aws\":{\"region\":\"eu-west-1\",\"kmsKey\":\"alias/kes\",\"accessKey\":\"AK\","
                "\"secretKey\":\"SK\"}}",
                "{\"aws\":{\"secretsmanager\":{\"endpoint\":\"secretsmanager.eu-west-1.amazonaws.com\",\"region\":"
                "\"eu-west-1\",\"kmskey\":\"alias/kes\",\"credentials\":{\"accesskey\":\"AK\",\"secretkey\":\"SK\"}}}}");
  expect_refused("{\"backend\":\"aws\",\"aws\":{\"region\":\"us-east-1\",\"accessKey\":\"AK\"}}", "secret access key");
  expect_refused("{\"backend\":\"aws\",\"aws\":{}}", "AWS region");

  expect_render("{\"backend\":\"azure\",\"azure\":{\"endpoint\":\"https://v.vault.azure.net\",\"tenantId\":\"t\","
                "\"clientId\":\"c\",\"clientSecret\":\"s\"}}",
                "{\"azure\":{\"keyvault\":{\"endpoint\":\"https://v.vault.azure.net\",\"credentials\":{\"tenant_id\":\"t\","
                "\"client_id\":\"c\",\"client_secret\":\"s\"}}}}");
  expect_render("{\"backend\":\"azure\",\"azure\":{\"endpoint\":\"https://v.vault.azure.net\",\"auth\":\"managedIdentity\","
                "\"managedIdentityClientId\":\"mi\"}}",
                "{\"azure\":{\"keyvault\":{\"endpoint\":\"https://v.vault.azure.net\",\"managed_identity\":{\"client_id\":"
                "\"mi\"}}}}");
  expect_refused("{\"backend\":\"azure\",\"azure\":{\"endpoint\":\"https://v.vault.azure.net\",\"auth\":\"managedIdentity\"}}",
                 "managed identity's client ID");
  expect_refused("{\"backend\":\"azure\",\"azure\":{\"endpoint\":\"https://v\",\"tenantId\":\"t\",\"clientId\":\"c\"}}",
                 "client secret");

  expect_render("{\"backend\":\"gcp\",\"gcp\":{\"credentials\":\"{\\\"type\\\":\\\"service_account\\\",\\\"project_id\\\":"
                "\\\"proj\\\",\\\"client_email\\\":\\\"kes@proj.iam\\\",\\\"client_id\\\":\\\"1\\\",\\\"private_key_id\\\":"
                "\\\"k1\\\",\\\"private_key\\\":\\\"PEM\\\"}\"}}",
                "{\"gcp\":{\"secretmanager\":{\"project_id\":\"proj\","
                "\"scopes\":[\"https://www.googleapis.com/auth/cloud-platform\"],\"credentials\":{\"client_email\":"
                "\"kes@proj.iam\",\"client_id\":\"1\",\"private_key_id\":\"k1\",\"private_key\":\"PEM\"}}}}");
  expect_refused("{\"backend\":\"gcp\",\"gcp\":{\"credentials\":\"nope\"}}", "not JSON");
  expect_refused("{\"backend\":\"gcp\",\"gcp\":{\"credentials\":\"{}\"}}", "lacks client_email");
  expect_refused("{\"backend\":\"fs\"}", "Choose where keys are kept");
}

static char *json_of(yyjson_mut_doc *d, yyjson_mut_val *v) {
  yyjson_mut_doc_set_root(d, v);
  return yyjson_mut_write(d, YYJSON_WRITE_NOFLAG, NULL);
}

static void test_settings_secrets(void **state) {
  (void)state;
  const char *saved = "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"approle\":{\"id\":\"r\","
                      "\"secret\":\"sid\"}}}";
  yyjson_doc *sd = yyjson_read(saved, strlen(saved), 0);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  char *red = json_of(d, buckets_kes_settings_redacted(d, yyjson_doc_get_root(sd)));
  assert_string_equal(red, "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"approle\":{\"id\":\"r\","
                           "\"secret\":\"\"}},\"secretsSet\":[\"vault.approle.secret\"]}");
  free(red);

  /* an edit that leaves the secret blank keeps it; a typed one replaces it */
  const char *edit = "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v2\",\"approle\":{\"id\":\"r2\","
                     "\"secret\":\"\"}},\"secretsSet\":[\"vault.approle.secret\"]}";
  yyjson_doc *ed = yyjson_read(edit, strlen(edit), 0);
  yyjson_mut_val *m = yyjson_val_mut_copy(d, yyjson_doc_get_root(ed));
  buckets_kes_settings_keep_secrets(d, m, yyjson_doc_get_root(sd));
  char *kept = json_of(d, m);
  assert_string_equal(kept, "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v2\",\"approle\":{\"id\":\"r2\","
                            "\"secret\":\"sid\"}}}");
  free(kept);
  /* a secret field absent altogether is filled in too */
  const char *bare = "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\"}}";
  yyjson_doc *bd = yyjson_read(bare, strlen(bare), 0);
  m = yyjson_val_mut_copy(d, yyjson_doc_get_root(bd));
  buckets_kes_settings_keep_secrets(d, m, yyjson_doc_get_root(sd));
  char *filled = json_of(d, m);
  assert_string_equal(filled, "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://v\",\"approle\":{\"secret\":"
                              "\"sid\"}}}");
  free(filled);
  /* another backend inherits nothing */
  const char *other = "{\"backend\":\"aws\",\"aws\":{\"region\":\"us-east-1\"}}";
  yyjson_doc *od = yyjson_read(other, strlen(other), 0);
  m = yyjson_val_mut_copy(d, yyjson_doc_get_root(od));
  buckets_kes_settings_keep_secrets(d, m, yyjson_doc_get_root(sd));
  char *o = json_of(d, m);
  assert_string_equal(o, other);
  free(o);

  char desc[128];
  buckets_kes_settings_describe(yyjson_doc_get_root(sd), desc, sizeof(desc));
  assert_string_equal(desc, "HashiCorp Vault at https://v");
  buckets_kes_settings_describe(yyjson_doc_get_root(od), desc, sizeof(desc));
  assert_string_equal(desc, "AWS Secrets Manager in us-east-1");
  yyjson_doc_free(sd);
  yyjson_doc_free(ed);
  yyjson_doc_free(bd);
  yyjson_doc_free(od);
  yyjson_mut_doc_free(d);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_identity_vector),       cmocka_unit_test(test_api_key_new),
      cmocka_unit_test(test_server_cert),           cmocka_unit_test(test_keystore_vault),
      cmocka_unit_test(test_keystore_aws_azure_gcp), cmocka_unit_test(test_settings_secrets),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
