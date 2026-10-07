/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* FIPS mode (crypto/fips.h, docs/fips.md): with the OpenSSL FIPS provider loaded, the security functions come from
 * it, what is not approved is refused, and MD5 (ETags) comes from outside. Needs a FIPS provider: the build's
 * (BUCKETS_TEST_FIPS_DIR, from .deps/fips-<version>) or BUCKETS_FIPS_MODULE and BUCKETS_FIPS_OPENSSL; skipped
 * without one. */
#include <cmocka.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/aead.h"
#include "crypto/fips.h"
#include "crypto/hex.h"
#include "crypto/madmin.h"
#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "kes/key.h"
#include "madmin_vectors.inc"

static const char *provider_of(const EVP_MD *md) { return OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)); }

static void test_module(void **state) {
  (void)state;
  assert_true(buckets_fips_mode());
  assert_non_null(strstr(buckets_fips_module(), "FIPS"));
  /* the security digests from the module; MD5 (ETags) from the default provider */
  assert_string_equal(provider_of(buckets_md_sha256()), "fips");
  assert_string_equal(provider_of(buckets_md_sha1()), "fips");
  assert_string_equal(provider_of(buckets_md_sha512()), "fips");
  assert_string_equal(provider_of(buckets_md_md5()), "default");
  assert_string_equal(OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(buckets_cipher_aes256gcm())), "fips");
  /* nothing else is fetched from outside unless asked by name */
  EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", NULL);
  assert_null(md5);
  EVP_KDF *argon = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
  assert_null(argon);
}

static void test_digests(void **state) {
  (void)state;
  /* the same answers as ever, through the module */
  uint8_t d[32], h[32], s1[20], m[16];
  buckets_sha256("abc", 3, d);
  assert_memory_equal(d,
                      "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
                      "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
                      32);
  buckets_hmac_sha256("key", 3, "The quick brown fox jumps over the lazy dog", 43, h);
  assert_memory_equal(h,
                      "\xf7\xbc\x83\xf4\x30\x53\x84\x24\xb1\x32\x98\xe6\xaa\x6f\xb1\x43"
                      "\xef\x4d\x59\xa1\x49\x46\x17\x59\x97\x47\x9d\xbc\x2d\x1a\x3c\xd8",
                      32);
  buckets_hmac_sha1("key", 3, "The quick brown fox jumps over the lazy dog", 43, s1);
  assert_memory_equal(s1, "\xde\x7c\x9b\x85\xb8\xb7\x8a\xa6\xbc\x8a\x7a\x36\xf7\x0a\x90\x70\x1c\x9d\xb4\xd9",
                      20);
  buckets_md5("abc", 3, m);
  assert_memory_equal(m, "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72", 16);
  /* a context left unfinished is freed by cleanup, and cleanup after final does nothing */
  buckets_sha256_ctx c;
  buckets_sha256_init(&c);
  buckets_sha256_update(&c, "x", 1);
  buckets_sha256_cleanup(&c);
  buckets_sha256_cleanup(&c);
}

static void test_refused(void **state) {
  (void)state;
  uint8_t key[32] = {1}, nonce[12] = {2}, out[64];
  assert_null(buckets_cipher_chacha20poly1305());
  assert_null(buckets_aead_new(BUCKETS_AEAD_CHACHA20_POLY1305, key));
  assert_false(buckets_aead_seal1(BUCKETS_AEAD_CHACHA20_POLY1305, key, nonce, NULL, 0, "data", 4, out));
  assert_true(buckets_aead_seal1(BUCKETS_AEAD_AES_256_GCM, key, nonce, NULL, 0, "data", 4, out));
  /* KES keys: AES-256 only */
  buckets_kes_key k;
  buckets_kes_key_new(&k, "test");
  assert_string_equal(buckets_kes_cipher_name(k.cipher), "AES256");
  assert_false(buckets_kes_key_import(&k, "ChaCha20", key, "test"));
  assert_true(buckets_kes_key_import(&k, "AES256", key, "test"));
}

static void test_madmin(void **state) {
  (void)state;
  /* sent with PBKDF2 (id 0x02), as madmin-go's FIPS build does */
  buckets_buf ct = BUCKETS_BUF_INIT, pt = BUCKETS_BUF_INIT;
  assert_true(buckets_madmin_encrypt("secretkey123", "hello", 5, &ct));
  assert_int_equal((uint8_t)ct.data[32], 0x02);
  assert_true(buckets_madmin_decrypt("secretkey123", ct.data, ct.len, &pt));
  assert_int_equal(pt.len, 5);
  /* Argon2id from a standard mc is still accepted (outside the module), unless strict */
  buckets_buf_free(&pt);
  size_t hl = strlen(k_madmin_vectors[0].hex);
  uint8_t *go = malloc(hl / 2);
  assert_true(buckets_hex_decode(k_madmin_vectors[0].hex, hl, go));
  assert_int_not_equal(go[32], 0x02);
  assert_true(buckets_madmin_decrypt(k_madmin_password, go, hl / 2, &pt));
  assert_false(buckets_madmin_fips_refused(go, hl / 2)); /* not strict */
  free(go);
  buckets_buf_free(&ct);
  buckets_buf_free(&pt);
}

int main(void) {
  char dir[1024] = "";
#ifdef BUCKETS_TEST_FIPS_DIR
  snprintf(dir, sizeof(dir), "%s", BUCKETS_TEST_FIPS_DIR);
#endif
  char module[1200], tool[1200];
  snprintf(module, sizeof(module), "%s/lib/ossl-modules/fips.so", dir);
  snprintf(tool, sizeof(tool), "%s/bin/openssl", dir);
  if (!getenv("BUCKETS_FIPS_MODULE") && *dir) setenv("BUCKETS_FIPS_MODULE", module, 1);
  if (!getenv("BUCKETS_FIPS_OPENSSL") && *dir) setenv("BUCKETS_FIPS_OPENSSL", tool, 1);
  if (!getenv("BUCKETS_FIPS_MODULE") || access(getenv("BUCKETS_FIPS_MODULE"), R_OK) != 0) {
    printf("test_fips: skipped (no FIPS provider; build one into .deps, see docs/fips.md)\n");
    return 0;
  }
  setenv("BUCKETS_FIPS", "on", 1);
  char err[512];
  if (!buckets_crypto_init(err, sizeof(err))) {
    fprintf(stderr, "test_fips: %s\n", err);
    return 1;
  }
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_module),
      cmocka_unit_test(test_digests),
      cmocka_unit_test(test_refused),
      cmocka_unit_test(test_madmin),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
