/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "kms/kesutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"

/* ---- API keys and identities ------------------------------------------------------ */

void buckets_kes_api_key_new(char out[64]) {
  uint8_t raw[33] = {0};
  buckets_random_bytes(raw + 1, 32);
  memcpy(out, "kes:v1:", 7);
  buckets_base64_encode(raw, sizeof(raw), out + 7);
  OPENSSL_cleanse(raw, sizeof(raw));
}

bool buckets_kes_identity(const char *api_key, char hex[65]) {
  const char *b = strncmp(api_key, "kes:v1:", 7) == 0 ? api_key + 7 : api_key;
  uint8_t raw[64];
  long n = strlen(b) < 60 ? buckets_base64_decode(b, strlen(b), raw) : -1;
  if (n != 33 || raw[0] != 0) return false;
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw + 1, 32);
  OPENSSL_cleanse(raw, sizeof(raw));
  if (!k) return false;
  unsigned char *der = NULL;
  int dn = i2d_PUBKEY(k, &der);
  EVP_PKEY_free(k);
  if (dn <= 0) return false;
  uint8_t h[32];
  buckets_sha256(der, (size_t)dn, h);
  OPENSSL_free(der);
  buckets_hex_encode(h, 32, hex);
  hex[64] = '\0';
  return true;
}

/* ---- the server certificate ------------------------------------------------------- */

static bool pem_of(int (*write)(BIO *, void *), void *obj, buckets_buf *out) {
  BIO *bio = BIO_new(BIO_s_mem());
  bool ok = bio && write(bio, obj) == 1;
  if (ok) {
    char *p;
    long n = BIO_get_mem_data(bio, &p);
    buckets_buf_append(out, p, (size_t)n);
  }
  BIO_free(bio);
  return ok;
}
static int write_cert(BIO *b, void *x) { return PEM_write_bio_X509(b, x); }
static int write_key(BIO *b, void *k) { return PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL); }

bool buckets_kes_server_cert(const char *const *dns, size_t ndns, int days, buckets_buf *cert, buckets_buf *key,
                             char *err, size_t errlen) {
  EVP_PKEY *k = EVP_EC_gen("P-256");
  X509 *x = X509_new();
  bool ok = false;
  if (!k || !x || !ndns) goto out;
  ASN1_INTEGER *serial = ASN1_INTEGER_new();
  BIGNUM *bn = BN_new();
  BN_rand(bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  BN_to_ASN1_INTEGER(bn, serial);
  X509_set_serialNumber(x, serial);
  ASN1_INTEGER_free(serial);
  BN_free(bn);
  X509_set_version(x, 2);
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 24 * 3600);
  X509_NAME *name = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)dns[0], -1, -1, 0);
  X509_set_issuer_name(x, name);
  X509_set_pubkey(x, k);
  buckets_buf san = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < ndns; i++) buckets_buf_appendf(&san, "%sDNS:%s", i ? "," : "", dns[i]);
  X509V3_CTX v3;
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, x, x, NULL, NULL, 0);
  /* its own trust anchor: a CA that only ever signed itself */
  const char *exts[][2] = {{"basicConstraints", "critical,CA:TRUE,pathlen:0"},
                           {"keyUsage", "critical,digitalSignature,keyCertSign"},
                           {"extendedKeyUsage", "serverAuth"},
                           {"subjectAltName", san.data}};
  bool ext_ok = true;
  for (size_t i = 0; i < 4; i++) {
    X509_EXTENSION *e = X509V3_EXT_conf(NULL, &v3, exts[i][0], exts[i][1]);
    if (!e) ext_ok = false;
    else X509_add_ext(x, e, -1), X509_EXTENSION_free(e);
  }
  buckets_buf_free(&san);
  if (!ext_ok || X509_sign(x, k, EVP_sha256()) <= 0) goto out;
  ok = pem_of(write_cert, x, cert) && pem_of(write_key, k, key);
out:
  if (!ok) snprintf(err, errlen, "creating the KES server certificate failed");
  X509_free(x);
  EVP_PKEY_free(k);
  return ok;
}

/* ---- key store settings ----------------------------------------------------------- */

const char *const buckets_kes_secret_fields[] = {"vault.approle.secret", "aws.secretKey", "aws.sessionToken",
                                                 "azure.clientSecret", "gcp.credentials", NULL};

#define K8S_SA_TOKEN "/var/run/secrets/kubernetes.io/serviceaccount/token"

/* settings["a.b.c"], or NULL */
static yyjson_val *at(yyjson_val *o, const char *path) {
  char key[64];
  while (o && *path) {
    const char *dot = strchr(path, '.');
    size_t n = dot ? (size_t)(dot - path) : strlen(path);
    snprintf(key, sizeof(key), "%.*s", (int)n, path);
    o = yyjson_obj_get(o, key);
    path = dot ? dot + 1 : path + n;
  }
  return o;
}
/* a string setting, trimmed of nothing: "" when absent */
static const char *str(yyjson_val *o, const char *path) {
  const char *s = yyjson_get_str(at(o, path));
  return s ? s : "";
}
static const char *str_or(yyjson_val *o, const char *path, const char *dflt) {
  const char *s = str(o, path);
  return *s ? s : dflt;
}

#define FAIL(...) return (snprintf(err, errlen, __VA_ARGS__), (yyjson_mut_val *)NULL)

static bool is_url(const char *s) { return strncmp(s, "https://", 8) == 0 || strncmp(s, "http://", 7) == 0; }

static yyjson_mut_val *vault(yyjson_mut_doc *d, yyjson_val *v, const char *ca_path, char *err, size_t errlen) {
  const char *ep = str(v, "endpoint");
  if (!*ep) FAIL("Enter the Vault server's address, such as https://vault.example.com:8200.");
  if (!is_url(ep)) FAIL("The Vault address must start with https:// (or http:// for a test server).");
  const char *version = str_or(v, "version", "v2");
  if (strcmp(version, "v1") != 0 && strcmp(version, "v2") != 0) FAIL("The KV engine version must be v1 or v2.");
  const char *auth = str_or(v, "auth", "approle");
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "endpoint", ep);
  yyjson_mut_obj_add_strcpy(d, o, "engine", str_or(v, "engine", "kv"));
  yyjson_mut_obj_add_strcpy(d, o, "version", version);
  if (*str(v, "namespace")) yyjson_mut_obj_add_strcpy(d, o, "namespace", str(v, "namespace"));
  if (*str(v, "prefix")) yyjson_mut_obj_add_strcpy(d, o, "prefix", str(v, "prefix"));
  if (strcmp(auth, "approle") == 0) {
    if (!*str(v, "approle.id")) FAIL("Enter the AppRole's role ID.");
    if (!*str(v, "approle.secret")) FAIL("Enter the AppRole's secret ID.");
    yyjson_mut_val *a = yyjson_mut_obj_add_obj(d, o, "approle");
    yyjson_mut_obj_add_strcpy(d, a, "engine", str_or(v, "approle.engine", "approle"));
    if (*str(v, "approle.namespace")) yyjson_mut_obj_add_strcpy(d, a, "namespace", str(v, "approle.namespace"));
    yyjson_mut_obj_add_strcpy(d, a, "id", str(v, "approle.id"));
    yyjson_mut_obj_add_strcpy(d, a, "secret", str(v, "approle.secret"));
  } else if (strcmp(auth, "kubernetes") == 0) {
    if (!*str(v, "kubernetes.role")) FAIL("Enter the Vault role bound to KES's service account.");
    yyjson_mut_val *a = yyjson_mut_obj_add_obj(d, o, "kubernetes");
    yyjson_mut_obj_add_strcpy(d, a, "engine", str_or(v, "kubernetes.engine", "kubernetes"));
    if (*str(v, "kubernetes.namespace")) yyjson_mut_obj_add_strcpy(d, a, "namespace", str(v, "kubernetes.namespace"));
    yyjson_mut_obj_add_strcpy(d, a, "role", str(v, "kubernetes.role"));
    yyjson_mut_obj_add_str(d, a, "jwt", K8S_SA_TOKEN);
  } else {
    FAIL("Choose how KES signs in to Vault: AppRole or Kubernetes.");
  }
  if (*str(v, "transit.key")) {
    yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, o, "transit");
    yyjson_mut_obj_add_strcpy(d, t, "engine", str_or(v, "transit.engine", "transit"));
    yyjson_mut_obj_add_strcpy(d, t, "key", str(v, "transit.key"));
  }
  const char *ca = str(v, "caCert");
  if (*ca) {
    if (!strstr(ca, "-----BEGIN CERTIFICATE-----")) FAIL("The CA certificate must be in PEM form (-----BEGIN CERTIFICATE-----).");
    yyjson_mut_obj_add_strcpy(d, yyjson_mut_obj_add_obj(d, o, "tls"), "ca", ca_path);
  }
  yyjson_mut_obj_add_str(d, yyjson_mut_obj_add_obj(d, o, "status"), "ping", "10s");
  return o;
}

static yyjson_mut_val *aws(yyjson_mut_doc *d, yyjson_val *v, char *err, size_t errlen) {
  const char *region = str(v, "region");
  if (!*region) FAIL("Choose the AWS region that holds the secrets.");
  bool ak = *str(v, "accessKey"), sk = *str(v, "secretKey");
  if (ak != sk) FAIL(ak ? "Enter the secret access key that goes with the access key ID." : "Enter the access key ID.");
  yyjson_mut_val *o = yyjson_mut_obj(d), *sm = yyjson_mut_obj_add_obj(d, o, "secretsmanager");
  char ep[160];
  snprintf(ep, sizeof(ep), "secretsmanager.%s.amazonaws.com", region);
  yyjson_mut_obj_add_strcpy(d, sm, "endpoint", str_or(v, "endpoint", ep));
  yyjson_mut_obj_add_strcpy(d, sm, "region", region);
  if (*str(v, "kmsKey")) yyjson_mut_obj_add_strcpy(d, sm, "kmskey", str(v, "kmsKey"));
  if (ak) { /* none: the SDK's own chain (IAM roles for service accounts, instance profiles) */
    yyjson_mut_val *c = yyjson_mut_obj_add_obj(d, sm, "credentials");
    yyjson_mut_obj_add_strcpy(d, c, "accesskey", str(v, "accessKey"));
    yyjson_mut_obj_add_strcpy(d, c, "secretkey", str(v, "secretKey"));
    if (*str(v, "sessionToken")) yyjson_mut_obj_add_strcpy(d, c, "token", str(v, "sessionToken"));
  }
  return o;
}

static yyjson_mut_val *azure(yyjson_mut_doc *d, yyjson_val *v, char *err, size_t errlen) {
  const char *ep = str(v, "endpoint");
  if (!*ep) FAIL("Enter the Key Vault's URL, such as https://my-vault.vault.azure.net.");
  if (strncmp(ep, "https://", 8) != 0) FAIL("The Key Vault URL must start with https://.");
  const char *auth = str_or(v, "auth", "secret");
  yyjson_mut_val *o = yyjson_mut_obj(d), *kv = yyjson_mut_obj_add_obj(d, o, "keyvault");
  yyjson_mut_obj_add_strcpy(d, kv, "endpoint", ep);
  if (strcmp(auth, "secret") == 0) {
    if (!*str(v, "tenantId")) FAIL("Enter the directory (tenant) ID.");
    if (!*str(v, "clientId")) FAIL("Enter the application (client) ID.");
    if (!*str(v, "clientSecret")) FAIL("Enter the client secret.");
    yyjson_mut_val *c = yyjson_mut_obj_add_obj(d, kv, "credentials");
    yyjson_mut_obj_add_strcpy(d, c, "tenant_id", str(v, "tenantId"));
    yyjson_mut_obj_add_strcpy(d, c, "client_id", str(v, "clientId"));
    yyjson_mut_obj_add_strcpy(d, c, "client_secret", str(v, "clientSecret"));
  } else if (strcmp(auth, "managedIdentity") == 0) {
    if (!*str(v, "managedIdentityClientId")) FAIL("Enter the managed identity's client ID.");
    yyjson_mut_obj_add_strcpy(d, yyjson_mut_obj_add_obj(d, kv, "managed_identity"), "client_id",
                              str(v, "managedIdentityClientId"));
  } else {
    FAIL("Choose how KES signs in to Azure: a client secret or a managed identity.");
  }
  return o;
}

static yyjson_mut_val *gcp(yyjson_mut_doc *d, yyjson_val *v, char *err, size_t errlen) {
  const char *cj = str(v, "credentials");
  if (!*cj) FAIL("Paste or upload the service account's JSON key.");
  yyjson_doc *c = yyjson_read(cj, strlen(cj), 0);
  yyjson_val *r = yyjson_doc_get_root(c);
  if (!yyjson_is_obj(r)) {
    yyjson_doc_free(c);
    FAIL("The service account key is not JSON: download it again from the Google Cloud console (Keys > Add key > JSON).");
  }
  if (!*str(r, "private_key") || !*str(r, "client_email")) {
    yyjson_doc_free(c);
    FAIL("The service account key lacks client_email or private_key: use a JSON key of type service_account.");
  }
  const char *project = str_or(v, "projectId", str(r, "project_id"));
  if (!*project) {
    yyjson_doc_free(c);
    FAIL("Enter the Google Cloud project ID.");
  }
  yyjson_mut_val *o = yyjson_mut_obj(d), *sm = yyjson_mut_obj_add_obj(d, o, "secretmanager");
  yyjson_mut_obj_add_strcpy(d, sm, "project_id", project);
  if (*str(v, "endpoint")) yyjson_mut_obj_add_strcpy(d, sm, "endpoint", str(v, "endpoint")); /* else the SDK's */
  yyjson_mut_arr_add_str(d, yyjson_mut_obj_add_arr(d, sm, "scopes"), "https://www.googleapis.com/auth/cloud-platform");
  yyjson_mut_val *cr = yyjson_mut_obj_add_obj(d, sm, "credentials");
  yyjson_mut_obj_add_strcpy(d, cr, "client_email", str(r, "client_email"));
  yyjson_mut_obj_add_strcpy(d, cr, "client_id", str(r, "client_id"));
  yyjson_mut_obj_add_strcpy(d, cr, "private_key_id", str(r, "private_key_id"));
  yyjson_mut_obj_add_strcpy(d, cr, "private_key", str(r, "private_key"));
  yyjson_doc_free(c);
  return o;
}

yyjson_mut_val *buckets_kes_keystore(yyjson_mut_doc *d, yyjson_val *settings, const char *ca_path, char *err,
                                     size_t errlen) {
  const char *b = str(settings, "backend");
  yyjson_mut_val *inner = NULL, *ks;
  if (strcmp(b, "vault") == 0) inner = vault(d, at(settings, "vault"), ca_path, err, errlen);
  else if (strcmp(b, "aws") == 0) inner = aws(d, at(settings, "aws"), err, errlen);
  else if (strcmp(b, "azure") == 0) inner = azure(d, at(settings, "azure"), err, errlen);
  else if (strcmp(b, "gcp") == 0) inner = gcp(d, at(settings, "gcp"), err, errlen);
  else FAIL("Choose where keys are kept: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault or Google Secret Manager.");
  if (!inner) return NULL;
  ks = yyjson_mut_obj(d);
  yyjson_mut_obj_add(ks, yyjson_mut_strcpy(d, b), inner);
  return ks;
}

/* settings[path] in a mutable document, made on the way when make */
static yyjson_mut_val *mut_at(yyjson_mut_doc *d, yyjson_mut_val *o, const char *path, bool make, const char **leaf) {
  char key[64];
  for (;;) {
    const char *dot = strchr(path, '.');
    if (!dot) {
      *leaf = path;
      return o;
    }
    snprintf(key, sizeof(key), "%.*s", (int)(dot - path), path);
    yyjson_mut_val *next = yyjson_mut_obj_get(o, key);
    if (!yyjson_mut_is_obj(next)) {
      if (!make) return NULL;
      if (next) yyjson_mut_obj_remove_key(o, key);
      next = yyjson_mut_obj(d);
      yyjson_mut_obj_add(o, yyjson_mut_strcpy(d, key), next);
    }
    o = next;
    path = dot + 1;
  }
}

yyjson_mut_val *buckets_kes_settings_redacted(yyjson_mut_doc *d, yyjson_val *settings) {
  yyjson_mut_val *c = yyjson_val_mut_copy(d, settings);
  if (!yyjson_mut_is_obj(c)) c = yyjson_mut_obj(d);
  yyjson_mut_val *set = yyjson_mut_arr(d);
  for (const char *const *f = buckets_kes_secret_fields; *f; f++) {
    const char *leaf;
    yyjson_mut_val *parent = mut_at(d, c, *f, false, &leaf);
    if (!parent) continue;
    const char *v = yyjson_mut_get_str(yyjson_mut_obj_get(parent, leaf));
    if (!v || !*v) continue;
    yyjson_mut_obj_remove_key(parent, leaf);
    yyjson_mut_obj_add_str(d, parent, leaf, "");
    yyjson_mut_arr_add_str(d, set, *f);
  }
  yyjson_mut_obj_remove_key(c, "secretsSet");
  yyjson_mut_obj_add_val(d, c, "secretsSet", set);
  return c;
}

void buckets_kes_settings_keep_secrets(yyjson_mut_doc *d, yyjson_mut_val *settings, yyjson_val *saved) {
  const char *b = yyjson_mut_get_str(yyjson_mut_obj_get(settings, "backend"));
  if (!b || strcmp(b, str(saved, "backend")) != 0) return;
  for (const char *const *f = buckets_kes_secret_fields; *f; f++) {
    if (strncmp(*f, b, strlen(b)) != 0 || (*f)[strlen(b)] != '.') continue;
    const char *old = str(saved, *f);
    if (!*old) continue;
    const char *leaf;
    yyjson_mut_val *parent = mut_at(d, settings, *f, true, &leaf);
    const char *now = yyjson_mut_get_str(yyjson_mut_obj_get(parent, leaf));
    if (now && *now) continue;
    yyjson_mut_obj_remove_key(parent, leaf);
    yyjson_mut_obj_add_strcpy(d, parent, leaf, old);
  }
  yyjson_mut_obj_remove_key(settings, "secretsSet");
}

void buckets_kes_settings_describe(yyjson_val *s, char *out, size_t cap) {
  const char *b = str(s, "backend");
  if (strcmp(b, "vault") == 0) snprintf(out, cap, "HashiCorp Vault at %s", str(s, "vault.endpoint"));
  else if (strcmp(b, "aws") == 0) snprintf(out, cap, "AWS Secrets Manager in %s", str(s, "aws.region"));
  else if (strcmp(b, "azure") == 0) snprintf(out, cap, "Azure Key Vault %s", str(s, "azure.endpoint"));
  else if (strcmp(b, "gcp") == 0) {
    const char *p = str(s, "gcp.projectId");
    snprintf(out, cap, "Google Secret Manager%s%s", *p ? ", project " : "", p);
  } else snprintf(out, cap, "not configured");
}
