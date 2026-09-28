/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/dare.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"

/* From github.com/minio/sio v0.4.1: sio.Encrypt with key 00..1f, nonce
 * a0..ab, AES-256-GCM, plaintext[i] = i*7. */
static const struct {
  size_t n, enc;
  const char *sha, *head;
} k_vec[] = {
    {1, 33, "c5900906f0706f93dd2a732602c15dbb9bd6395f43961087e15727cd17cf7b2a",
     "20000000a0a1a2a3a4a5a6a7a8a9aaabe664697845631f3276a74fa53df63dd00b000000000000000000000000000000"},
    {100, 132, "a65af83a57690a00b5a78c2d843742b20cd39fb261e8b888730c1b72ceb10d87",
     "20006300a0a1a2a3a4a5a6a7a8a9aaabe61f723859e8288e5a5ac19e5321a2b700db27951e24d8cd34a1903bbb60a7d8"},
    {65535, 65567, "0410553d830b0acbba300e0d06d3efc7234110aeb7b826ea92c09f1034613cd6",
     "2000feffa0a1a2a3a4a5a6a7a8a9aaabe61f723859e8288e5a5ac19e5321a2b700db27951e24d8cd34a1903bbb60a7d8"},
    {65536, 65568, "5fc21fa1d1a9940120e761f4460790be486b68c1c3e39c2f3ebeb13cb5bb9d96",
     "2000ffffa0a1a2a3a4a5a6a7a8a9aaabe61f723859e8288e5a5ac19e5321a2b700db27951e24d8cd34a1903bbb60a7d8"},
    {65537, 65601, "4f93044e98319008e1eb54b57c2585c210672377262c6b458a8911ecc3365fcf",
     "2000ffff20a1a2a3a4a5a6a7a8a9aaab52e2e8e8d04d456d75775ceaef6cca392bbcacd46bd907bb8412481d869601a6"},
    {200000, 200128, "b7a28e3ab820d05968f11ce8a9916b45eb9de9cf8e0a5dbd13eb32ad72de8599",
     "2000ffff20a1a2a3a4a5a6a7a8a9aaab52e2e8e8d04d456d75775ceaef6cca392bbcacd46bd907bb8412481d869601a6"},
};
static const char *k_chacha = "20011100a0a1a2a3a4a5a6a7a8a9aaab64ce143322c6a1c5c16c9b75dc8d9289f13a638cccd51c79d6a03f84cd4f1a3c89e4";

static uint8_t key[32], nonce[12];

static void setup_keys(void) {
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0xa0 + i);
}

/* sio's writer with a fixed nonce */
static size_t encrypt_fixed(const uint8_t *in, size_t n, uint8_t *out) {
  buckets_dare_enc e;
  buckets_dare_enc_init(&e, key, nonce, 0);
  size_t w = 0;
  while (n > BUCKETS_DARE_PAYLOAD) {
    w += buckets_dare_seal(&e, in, BUCKETS_DARE_PAYLOAD, false, out + w);
    in += BUCKETS_DARE_PAYLOAD;
    n -= BUCKETS_DARE_PAYLOAD;
  }
  if (n) w += buckets_dare_seal(&e, in, n, true, out + w);
  buckets_dare_enc_free(&e);
  return w;
}

static void test_vectors(void **state) {
  setup_keys();
  for (size_t v = 0; v < sizeof(k_vec) / sizeof(k_vec[0]); v++) {
    size_t n = k_vec[v].n;
    uint8_t *pt = malloc(n), *ct = malloc(buckets_dare_encrypted_size(n)), *back = malloc(n);
    for (size_t i = 0; i < n; i++) pt[i] = (uint8_t)(i * 7);
    size_t w = encrypt_fixed(pt, n, ct);
    assert_int_equal(w, k_vec[v].enc);
    assert_int_equal(buckets_dare_encrypted_size(n), k_vec[v].enc);
    uint64_t dn;
    assert_true(buckets_dare_decrypted_size(w, &dn));
    assert_int_equal(dn, n);
    uint8_t sum[32];
    char hex[65], head[97];
    buckets_sha256(ct, w, sum);
    buckets_hex_encode(sum, 32, hex);
    assert_string_equal(hex, k_vec[v].sha);
    buckets_hex_encode(ct, 48, head);
    assert_string_equal(head, k_vec[v].head);
    assert_int_equal(buckets_dare_decrypt_buffer(key, ct, w, back), (long)n);
    assert_memory_equal(back, pt, n);
    free(pt), free(ct), free(back);
  }
}

static void test_chacha_and_tamper(void **state) {
  setup_keys();
  uint8_t ct[64], pt[64];
  size_t n = strlen(k_chacha) / 2;
  assert_true(buckets_hex_decode(k_chacha, strlen(k_chacha), ct));
  assert_int_equal(buckets_dare_decrypt_buffer(key, ct, n, pt), 18);
  assert_memory_equal(pt, "hello chacha world", 18);
  ct[20] ^= 1;
  assert_int_equal(buckets_dare_decrypt_buffer(key, ct, n, pt), -1);
}

static void test_mid_stream_and_truncation(void **state) {
  setup_keys();
  size_t n = 3 * BUCKETS_DARE_PAYLOAD + 10;
  uint8_t *pt = malloc(n), *ct = malloc(buckets_dare_encrypted_size(n)), *out = malloc(BUCKETS_DARE_PAYLOAD);
  for (size_t i = 0; i < n; i++) pt[i] = (uint8_t)(i * 13);
  size_t w = buckets_dare_encrypt_buffer(key, pt, n, ct);
  /* a range read starting at the second package */
  buckets_dare_dec d;
  buckets_dare_dec_init(&d, key, 1);
  assert_int_equal(buckets_dare_open(&d, ct + BUCKETS_DARE_PACKAGE, BUCKETS_DARE_PACKAGE, out), BUCKETS_DARE_PAYLOAD);
  assert_memory_equal(out, pt + BUCKETS_DARE_PAYLOAD, BUCKETS_DARE_PAYLOAD);
  buckets_dare_dec_free(&d);
  /* the wrong sequence number fails */
  buckets_dare_dec_init(&d, key, 0);
  assert_int_equal(buckets_dare_open(&d, ct + BUCKETS_DARE_PACKAGE, BUCKETS_DARE_PACKAGE, out), BUCKETS_DARE_ERR_TAG);
  buckets_dare_dec_free(&d);
  /* a stream cut before its final package */
  uint8_t *back = malloc(n);
  assert_int_equal(buckets_dare_decrypt_buffer(key, ct, 2 * BUCKETS_DARE_PACKAGE, back), -1);
  assert_int_equal(buckets_dare_decrypt_buffer(key, ct, w, back), (long)n);
  assert_int_equal(buckets_dare_decrypt_buffer(key, ct, 0, back), 0);
  free(pt), free(ct), free(out), free(back);
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_vectors), cmocka_unit_test(test_chacha_and_tamper),
                                     cmocka_unit_test(test_mid_stream_and_truncation)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
