/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/highwayhash.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"

static void sha256_hex(const void *data, size_t n, char *out) {
  uint8_t d[32];
  buckets_sha256(data, n, d);
  buckets_hex_encode(d, 32, out);
}

/* FIPS 180-2 examples. */
static void test_sha256_vectors(void **state) {
  char hex[65];
  sha256_hex("", 0, hex);
  assert_string_equal(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  sha256_hex("abc", 3, hex);
  assert_string_equal(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  sha256_hex(two, strlen(two), hex);
  assert_string_equal(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void test_sha256_streaming_million_a(void **state) {
  buckets_sha256_ctx ctx;
  buckets_sha256_init(&ctx);
  char chunk[1000];
  memset(chunk, 'a', sizeof(chunk));
  /* Odd-sized updates exercise the partial-block path. */
  for (int i = 0; i < 1000; i++) {
    buckets_sha256_update(&ctx, chunk, 333);
    buckets_sha256_update(&ctx, chunk, 667);
  }
  uint8_t d[32];
  char hex[65];
  buckets_sha256_final(&ctx, d);
  buckets_hex_encode(d, 32, hex);
  assert_string_equal(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

/* RFC 4231 test cases 1 and 2. */
static void test_hmac_sha256(void **state) {
  uint8_t mac[32];
  char hex[65];
  uint8_t key1[20];
  memset(key1, 0x0b, sizeof(key1));
  buckets_hmac_sha256(key1, sizeof(key1), "Hi There", 8, mac);
  buckets_hex_encode(mac, 32, hex);
  assert_string_equal(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  const char *msg = "what do ya want for nothing?";
  buckets_hmac_sha256("Jefe", 4, msg, strlen(msg), mac);
  buckets_hex_encode(mac, 32, hex);
  assert_string_equal(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

/* RFC 1321 appendix. */
static void test_md5(void **state) {
  uint8_t d[16];
  char hex[33];
  buckets_md5("", 0, d);
  buckets_hex_encode(d, 16, hex);
  assert_string_equal(hex, "d41d8cd98f00b204e9800998ecf8427e");
  buckets_md5("abc", 3, d);
  buckets_hex_encode(d, 16, hex);
  assert_string_equal(hex, "900150983cd24fb0d6963f7d28e17f72");
  const char *digits = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  buckets_md5(digits, strlen(digits), d);
  buckets_hex_encode(d, 16, hex);
  assert_string_equal(hex, "57edf4a22be3c955ac49da2e2107b67a");
}

/* RFC 4648 section 10. */
static void test_base64(void **state) {
  static const char *const plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
  static const char *const enc[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
  for (size_t i = 0; i < 7; i++) {
    char out[16];
    buckets_base64_encode((const uint8_t *)plain[i], strlen(plain[i]), out);
    assert_string_equal(out, enc[i]);
    uint8_t dec[16];
    long n = buckets_base64_decode(enc[i], strlen(enc[i]), dec);
    assert_int_equal(n, (long)strlen(plain[i]));
    assert_memory_equal(dec, plain[i], (size_t)n);
  }
  uint8_t dec[16];
  assert_int_equal(buckets_base64_decode("Zg=", 3, dec), -1);
  assert_int_equal(buckets_base64_decode("Z===", 4, dec), -1);
  assert_int_equal(buckets_base64_decode("Zm9v!A==", 8, dec), -1);
}

static void test_ct_equal(void **state) {
  assert_true(buckets_ct_equal("abcd", "abcd", 4));
  assert_false(buckets_ct_equal("abcd", "abce", 4));
}

static void test_hh_simd_matches_scalar(void **state) {
  (void)state;
  uint8_t *buf = malloc(70000);
  for (size_t i = 0; i < 70000; i++) buf[i] = (uint8_t)(i * 2654435761u >> 13);
  static const size_t lens[] = {0, 1, 31, 32, 33, 63, 64, 65, 100, 1000, 4096, 65536, 69999};
  for (size_t k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
    uint8_t a[32], b[32];
    buckets_hh_set_simd(false);
    buckets_hh256(buckets_bitrot_key, buf + (k & 7), lens[k], a);
    buckets_hh_set_simd(true);
    buckets_hh256(buckets_bitrot_key, buf + (k & 7), lens[k], b);
    assert_memory_equal(a, b, 32);
  }
  free(buf);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_hh_simd_matches_scalar),
      cmocka_unit_test(test_sha256_vectors), cmocka_unit_test(test_sha256_streaming_million_a),
      cmocka_unit_test(test_hmac_sha256),    cmocka_unit_test(test_md5),
      cmocka_unit_test(test_base64),         cmocka_unit_test(test_ct_equal),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
