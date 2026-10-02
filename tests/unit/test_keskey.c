/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "core/msgpack.h"
#include "crypto/base64.h"
#include "kes/key.h"

/* Made by MinIO KES 2024-09-11 (its fs key store's files, and its API's
 * replies): what buckets-kes must read and decrypt as it does. */
#define AES_KEY "CiQKIH4LrKex5rB4zUGgwQQ13aKiHUgn76QyqwwxgCZhJGgFEAESJAogEZcby784RPghT51F1qIFLsYVevvZUj86YBYp4j7rMloQARoMCLa8gNYGEL6t16ABIkA3YWIyN2FiYjg0N2M2MmU4NzFmZTcxMTFkYjg3ODNkOGQwZDAxMDgxMTg0MDJhOTRmYmJmNWNlYjA3YzMxNjVm"
#define AES_DEK_PT "HhgyVNXFvXXl3z/Dxg4r4nYmhh3vL1ET/NQBWwRewYg="
#define AES_DEK_CT "2obpEbrw7CdyVjsfJhJwHqfQsFMFnJ3tyhSu5aAO8SYYmyTIdEVa3CVblF8ukXh8ZNp2mnanmkBYQVKKeNICWGrA5VK7jrvN8sfKMw==" /* context "bucket-ctx" */
#define AES_HMAC "zz0YG63Hhfi0QHafSFe1Fn2KT33j8RgS572RmVP7rx0="     /* of "mac me" */
#define CHACHA_KEY "CiQKIFmWfduCNrkcY4Qb8kG6yEoFtQxLWbi+aMTGcWsrAb0tEAISJAogOY5zIZgFk4CEzcYzCKImPTPNmXicem11dcBBqphSuFUQARoMCO28gNYGEKzA4akCIkBlZjc5NWYyMTZkZWIyNmFlYjY1YzE2YTA3MTdhZjFlNWMzOWQ1NTJmMTM0ZWQ0MGNkZTFmZjFlZTYwODMzMTgz"
#define CHACHA_CT "7l2Srr7m+Ab5GLQePKawmtWEYP4GlJcEwTG3lDH1jO+FabFJUwrbsSObsRTIvMx/5D0CX5wso0d5pw==" /* "chacha says hi", context "ctx2" */

static size_t b64(const char *s, uint8_t *out) {
  long n = buckets_base64_decode(s, strlen(s), out);
  assert_true(n >= 0);
  return (size_t)n;
}

static void decode(const char *s, buckets_kes_key *k) {
  char err[128];
  if (!buckets_kes_key_decode(s, strlen(s), k, err, sizeof(err))) fail_msg("decode: %s", err);
}

static void test_minio_keys(void **state) {
  (void)state;
  buckets_kes_key k;
  decode(AES_KEY, &k);
  assert_int_equal(k.cipher, BUCKETS_KES_AES256);
  assert_true(k.has_hmac);
  assert_int_equal(strlen(k.created_by), 64);
  assert_true(k.created_sec > 1700000000);
  /* encoded again, byte for byte what KES stored */
  buckets_buf enc = BUCKETS_BUF_INIT;
  buckets_kes_key_encode(&k, &enc);
  assert_string_equal(enc.data, AES_KEY);
  buckets_buf_free(&enc);

  uint8_t ct[256], pt[64];
  size_t cn = b64(AES_DEK_CT, ct), pn = b64(AES_DEK_PT, pt);
  buckets_buf out = BUCKETS_BUF_INIT;
  assert_true(buckets_kes_decrypt(&k, ct, cn, "bucket-ctx", 10, &out));
  assert_int_equal(out.len, pn);
  assert_memory_equal(out.data, pt, pn);
  buckets_buf_reset(&out);
  assert_false(buckets_kes_decrypt(&k, ct, cn, "other-ctx", 9, &out)); /* the context is bound */
  ct[0] ^= 1;
  assert_false(buckets_kes_decrypt(&k, ct, cn, "bucket-ctx", 10, &out));

  uint8_t mac[32], want[64];
  buckets_kes_hmac(&k, "mac me", 6, mac);
  assert_int_equal(b64(AES_HMAC, want), 32);
  assert_memory_equal(mac, want, 32);

  buckets_kes_key c;
  decode(CHACHA_KEY, &c);
  assert_int_equal(c.cipher, BUCKETS_KES_CHACHA20);
  cn = b64(CHACHA_CT, ct);
  buckets_buf_reset(&out);
  assert_true(buckets_kes_decrypt(&c, ct, cn, "ctx2", 4, &out));
  assert_int_equal(out.len, 14);
  assert_memory_equal(out.data, "chacha says hi", 14);
  buckets_buf_free(&out);
}

static void test_roundtrip(void **state) {
  (void)state;
  for (int cipher = 1; cipher <= 2; cipher++) {
    buckets_kes_key k, back;
    uint8_t raw[32];
    memset(raw, 7, 32);
    if (cipher == 1) buckets_kes_key_new(&k, "abc");
    else assert_true(buckets_kes_key_import(&k, "XCHACHA20-POLY1305", raw, "abc"));
    buckets_buf s = BUCKETS_BUF_INIT, ct = BUCKETS_BUF_INIT, pt = BUCKETS_BUF_INIT;
    buckets_kes_key_encode(&k, &s);
    decode(s.data, &back);
    assert_memory_equal(back.key, k.key, 32);
    assert_memory_equal(back.hmac, k.hmac, 32);
    assert_int_equal(back.cipher, k.cipher);
    assert_string_equal(back.created_by, "abc");
    assert_int_equal(back.created_sec, k.created_sec);
    buckets_kes_encrypt(&k, "data key", 8, "ctx", 3, &ct);
    assert_int_equal(ct.len, 8 + 16 + 28);
    assert_true(buckets_kes_decrypt(&back, ct.data, ct.len, "ctx", 3, &pt));
    assert_memory_equal(pt.data, "data key", 8);
    buckets_buf_free(&s);
    buckets_buf_free(&ct);
    buckets_buf_free(&pt);
  }
  buckets_kes_key k;
  assert_false(buckets_kes_key_import(&k, "DES", (const uint8_t *)"0123456789abcdef0123456789abcdef", ""));
}

/* the forms before KES 2024: JSON keys, msgpack and JSON ciphertexts */
static void test_legacy(void **state) {
  (void)state;
  buckets_kes_key k;
  decode("{\"bytes\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"algorithm\":\"AES256-GCM_SHA256\","
         "\"created_at\":\"2022-01-02T03:04:05Z\",\"created_by\":\"me\"}",
         &k);
  assert_int_equal(k.cipher, BUCKETS_KES_AES256);
  assert_int_equal(k.key[31], 31);
  assert_false(k.has_hmac);
  assert_int_equal(k.created_sec, 1641092645);
  buckets_buf ct = BUCKETS_BUF_INIT, pt = BUCKETS_BUF_INIT;
  buckets_kes_encrypt(&k, "old", 3, NULL, 0, &ct);
  const uint8_t *b = (const uint8_t *)ct.data;
  size_t body = ct.len - 28;
  /* msgpack [alg, id, iv, nonce, bytes] */
  buckets_buf mp = BUCKETS_BUF_INIT;
  buckets_mp_array(&mp, 5);
  buckets_mp_str(&mp, "AES-256-GCM-HMAC-SHA-256", 24);
  buckets_mp_str(&mp, "", 0);
  buckets_mp_bin(&mp, b + body, 16);
  buckets_mp_bin(&mp, b + body + 16, 12);
  buckets_mp_bin(&mp, b, body);
  assert_true(buckets_kes_decrypt(&k, mp.data, mp.len, NULL, 0, &pt));
  assert_memory_equal(pt.data, "old", 3);
  /* JSON */
  char e1[64], e2[64], e3[64];
  buckets_base64_encode(b, body, e1);
  buckets_base64_encode(b + body, 16, e2);
  buckets_base64_encode(b + body + 16, 12, e3);
  char js[300];
  snprintf(js, sizeof(js), "{\"aead\":\"AES-256-GCM-HMAC-SHA-256\",\"iv\":\"%s\",\"nonce\":\"%s\",\"bytes\":\"%s\"}", e2, e3, e1);
  buckets_buf_reset(&pt);
  assert_true(buckets_kes_decrypt(&k, js, strlen(js), NULL, 0, &pt));
  assert_memory_equal(pt.data, "old", 3);
  buckets_buf_free(&mp);
  buckets_buf_free(&ct);
  buckets_buf_free(&pt);
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_minio_keys), cmocka_unit_test(test_roundtrip),
                                     cmocka_unit_test(test_legacy)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
