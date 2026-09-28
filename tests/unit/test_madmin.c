/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* madmin EncryptData/DecryptData against ciphertexts from madmin-go. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hex.h"
#include "crypto/madmin.h"
#include "madmin_vectors.inc"

static void expected(size_t n, uint8_t *out) {
  for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(i * 7 + n);
}

static void test_decrypt_go(void **state) {
  (void)state;
  for (size_t v = 0; v < sizeof(k_madmin_vectors) / sizeof(k_madmin_vectors[0]); v++) {
    size_t hl = strlen(k_madmin_vectors[v].hex);
    uint8_t *ct = malloc(hl / 2 + 1);
    assert_true(buckets_hex_decode(k_madmin_vectors[v].hex, hl, ct));
    assert_true(buckets_madmin_is_encrypted(ct, hl / 2));
    buckets_buf pt = BUCKETS_BUF_INIT;
    if (!buckets_madmin_decrypt(k_madmin_password, ct, hl / 2, &pt)) fail_msg("decrypt of %zu bytes failed", k_madmin_vectors[v].len);
    assert_int_equal(pt.len, k_madmin_vectors[v].len);
    uint8_t *want = malloc(pt.len + 1);
    expected(pt.len, want);
    assert_memory_equal(pt.data ? pt.data : "", want, pt.len);
    /* Tampering anywhere is detected. */
    ct[hl / 2 - 1] ^= 1;
    buckets_buf bad = BUCKETS_BUF_INIT;
    assert_false(buckets_madmin_decrypt(k_madmin_password, ct, hl / 2, &bad));
    buckets_buf_free(&bad);
    assert_false(buckets_madmin_decrypt("wrong-password", ct, hl / 2, &bad));
    buckets_buf_free(&bad);
    free(want);
    buckets_buf_free(&pt);
    free(ct);
  }
}

static void test_roundtrip(void **state) {
  (void)state;
  size_t sizes[] = {0, 3, 16384, 16385, 50000};
  for (size_t i = 0; i < 5; i++) {
    uint8_t *data = malloc(sizes[i] + 1);
    expected(sizes[i], data);
    buckets_buf ct = BUCKETS_BUF_INIT, pt = BUCKETS_BUF_INIT;
    assert_true(buckets_madmin_encrypt("pw", data, sizes[i], &ct));
    assert_true(buckets_madmin_decrypt("pw", ct.data, ct.len, &pt));
    assert_int_equal(pt.len, sizes[i]);
    if (sizes[i]) assert_memory_equal(pt.data, data, sizes[i]);
    buckets_buf_free(&ct);
    buckets_buf_free(&pt);
    free(data);
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_decrypt_go), cmocka_unit_test(test_roundtrip)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
