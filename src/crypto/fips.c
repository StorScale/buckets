/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/fips.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static bool g_fips, g_strict;
static char g_module[128];

static bool env_on(const char *name) {
  const char *v = getenv(name);
  return v && (!strcmp(v, "on") || !strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "yes"));
}

static const char *env_or(const char *name, const char *def) {
  const char *v = getenv(name);
  return v && *v ? v : def;
}

/* openssl fipsinstall -module MODULE -out DIR/fipsmodule.cnf: the module's self-tests and its configuration, for
 * this machine (the 3.1.2 module's security policy forbids copying them from another). */
static bool fipsinstall(const char *openssl, const char *module, const char *out, const char *log, char *err,
                        size_t errlen) {
  char *argv[] = {(char *)openssl, "fipsinstall", "-module", (char *)module, "-out", (char *)out, NULL};
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  /* the self-tests' report, kept beside the configuration */
  posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
  pid_t pid;
  int rc = posix_spawn(&pid, openssl, &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  if (rc != 0) {
    snprintf(err, errlen, "running %s: %s", openssl, strerror(rc));
    return false;
  }
  int st;
  while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
    char tail[256] = "";
    FILE *f = fopen(log, "r");
    if (f) { /* the report's last line says what failed */
      char line[256];
      while (fgets(line, sizeof(line), f))
        if (line[0] != '\n') snprintf(tail, sizeof(tail), "%s", line);
      fclose(f);
      tail[strcspn(tail, "\n")] = '\0';
    }
    snprintf(err, errlen,
             "openssl fipsinstall failed for %s: the module's self-tests or integrity check did not pass%s%s",
             module, *tail ? ": " : "", tail);
    return false;
  }
  return true;
}

static bool openssl_error(const char *what, char *err, size_t errlen) {
  unsigned long e = ERR_get_error();
  char reason[256] = "";
  if (e) ERR_error_string_n(e, reason, sizeof(reason));
  snprintf(err, errlen, "%s%s%s", what, *reason ? ": " : "", reason);
  ERR_clear_error();
  return false;
}

static bool fips_init(char *err, size_t errlen) {
  const char *module = env_or("BUCKETS_FIPS_MODULE", "/usr/lib/buckets/fips/fips.so");
  const char *openssl = env_or("BUCKETS_FIPS_OPENSSL", "/usr/lib/buckets/fips/openssl");
  if (access(module, R_OK) != 0) {
    snprintf(err, errlen, "the FIPS provider %s: %s (BUCKETS_FIPS_MODULE)", module, strerror(errno));
    return false;
  }
  char dir[512];
  const char *d = getenv("BUCKETS_FIPS_DIR");
  if (d && *d) {
    snprintf(dir, sizeof(dir), "%s", d);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
      snprintf(err, errlen, "%s: %s (BUCKETS_FIPS_DIR)", dir, strerror(errno));
      return false;
    }
  } else {
    snprintf(dir, sizeof(dir), "%s/buckets-fips-XXXXXX", env_or("TMPDIR", "/tmp"));
    if (!mkdtemp(dir)) {
      snprintf(err, errlen, "a directory for the FIPS configuration in %s: %s", env_or("TMPDIR", "/tmp"),
               strerror(errno));
      return false;
    }
  }
  char modcnf[600], cnf[600], log[600];
  snprintf(modcnf, sizeof(modcnf), "%s/fipsmodule.cnf", dir);
  snprintf(cnf, sizeof(cnf), "%s/openssl.cnf", dir);
  snprintf(log, sizeof(log), "%s/fipsinstall.log", dir);
  if (!fipsinstall(openssl, module, modcnf, log, err, errlen)) return false;
  FILE *f = fopen(cnf, "w");
  if (!f) {
    snprintf(err, errlen, "%s: %s", cnf, strerror(errno));
    return false;
  }
  /* the FIPS provider for everything (fips=yes); base for encoders; default only for what is asked for by name
   * outside the module (-fips): MD5 ETags, and Argon2id admin payloads unless strict */
  fprintf(f,
          "config_diagnostics = 1\n"
          "openssl_conf = openssl_init\n"
          ".include %s\n"
          "[openssl_init]\n"
          "providers = provider_sect\n"
          "alg_section = algorithm_sect\n"
          "[provider_sect]\n"
          "fips = fips_sect\n"
          "base = base_sect\n"
          "default = default_sect\n"
          "[base_sect]\n"
          "activate = 1\n"
          "[default_sect]\n"
          "activate = 1\n"
          "[algorithm_sect]\n"
          "default_properties = fips=yes\n",
          modcnf);
  if (fclose(f) != 0) {
    snprintf(err, errlen, "%s: %s", cnf, strerror(errno));
    return false;
  }
  /* the provider is found next to where it was installed */
  char mdir[512];
  snprintf(mdir, sizeof(mdir), "%s", module);
  char *slash = strrchr(mdir, '/');
  if (slash) *slash = '\0';
  setenv("OPENSSL_MODULES", slash ? mdir : ".", 1);
  if (OSSL_LIB_CTX_load_config(NULL, cnf) != 1)
    return openssl_error("loading the FIPS configuration", err, errlen);
  if (!OSSL_PROVIDER_available(NULL, "fips") || EVP_default_properties_is_fips_enabled(NULL) != 1)
    return openssl_error("the FIPS provider is not active", err, errlen);
  OSSL_PROVIDER *p = OSSL_PROVIDER_load(NULL, "fips"); /* the one loaded: its name and version */
  const char *name = NULL, *version = NULL;
  OSSL_PARAM q[] = {OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&name, 0),
                    OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&version, 0),
                    OSSL_PARAM_END};
  if (p && OSSL_PROVIDER_get_params(p, q) == 1 && name && version)
    snprintf(g_module, sizeof(g_module), "%s %s", name, version);
  else
    snprintf(g_module, sizeof(g_module), "OpenSSL FIPS Provider");
  OSSL_PROVIDER_unload(p);
  /* a digest from the module proves its self-tests passed */
  EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
  bool ok = md && !strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)), "fips");
  EVP_MD_free(md);
  if (!ok) return openssl_error("SHA-256 does not come from the FIPS provider", err, errlen);
  return true;
}

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static bool g_init_ok;
static char g_init_err[512];

static void init_once(void) {
  g_fips = env_on("BUCKETS_FIPS");
  g_strict = g_fips && env_on("BUCKETS_FIPS_STRICT");
  g_init_ok = !g_fips || fips_init(g_init_err, sizeof(g_init_err));
}

bool buckets_crypto_init(char *err, size_t errlen) {
  pthread_once(&g_init_once, init_once);
  if (!g_init_ok) snprintf(err, errlen, "%s", g_init_err);
  return g_init_ok;
}

bool buckets_fips_mode(void) {
  pthread_once(&g_init_once, init_once);
  return g_fips && g_init_ok;
}

bool buckets_fips_strict(void) { return buckets_fips_mode() && g_strict; }
const char *buckets_fips_module(void) { return buckets_fips_mode() ? g_module : ""; }
const char *buckets_crypto_nonfips_props(void) { return buckets_fips_mode() ? "-fips" : ""; }

/* ---- algorithms, fetched once ------------------------------------------------------------------------------- */

static pthread_once_t g_fetch_once = PTHREAD_ONCE_INIT;
static EVP_MD *g_sha1, *g_sha256, *g_sha512, *g_md5;
static EVP_CIPHER *g_aes, *g_chacha, *g_chacha_madmin;

static void fetch_once(void) {
  pthread_once(&g_init_once, init_once);
  const char *nf = buckets_crypto_nonfips_props();
  g_sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
  g_sha256 = EVP_MD_fetch(NULL, "SHA2-256", NULL);
  g_sha512 = EVP_MD_fetch(NULL, "SHA2-512", NULL);
  g_md5 = EVP_MD_fetch(NULL, "MD5", nf);
  g_aes = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
  g_chacha = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL); /* none from the FIPS provider */
  g_chacha_madmin = buckets_fips_strict() ? NULL : EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", nf);
  ERR_clear_error();
  if (!g_sha1 || !g_sha256 || !g_sha512 || !g_md5 || !g_aes) {
    fprintf(stderr, "crypto: a required algorithm is missing from OpenSSL\n");
    abort();
  }
}

#define FETCHED(type, fn, var)               \
  const type *fn(void) {                     \
    pthread_once(&g_fetch_once, fetch_once); \
    return var;                              \
  }
FETCHED(EVP_MD, buckets_md_sha1, g_sha1)
FETCHED(EVP_MD, buckets_md_sha256, g_sha256)
FETCHED(EVP_MD, buckets_md_sha512, g_sha512)
FETCHED(EVP_MD, buckets_md_md5, g_md5)
FETCHED(EVP_CIPHER, buckets_cipher_aes256gcm, g_aes)
FETCHED(EVP_CIPHER, buckets_cipher_chacha20poly1305, g_chacha)
FETCHED(EVP_CIPHER, buckets_cipher_chacha20poly1305_madmin, g_chacha_madmin)
