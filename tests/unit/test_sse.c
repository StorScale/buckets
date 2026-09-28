/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>

#include "crypto/hex.h"
#include "crypto/objkey.h"
#include "kms/kms.h"

/* Vectors from MinIO's own internal/crypto and internal/kms packages. */
static void hexin(const char *h, uint8_t *out) { assert_true(buckets_hex_decode(h, strlen(h), out)); }
static void hexeq(const uint8_t *b, size_t n, const char *want) {
  char h[512];
  buckets_hex_encode(b, n, h);
  assert_string_equal(h, want);
}

static void test_object_key(void **state) {
  uint8_t ext[32], nonce[32], key[32], iv[32], sealed[64], back[32];
  for (int i = 0; i < 32; i++) ext[i] = (uint8_t)(0x40 + i), nonce[i] = (uint8_t)(1 + i), iv[i] = (uint8_t)(0x80 + i);
  buckets_objkey_generate(ext, nonce, key);
  hexeq(key, 32, "e24440c94570604af4cc6ed9962464bad82516742de7242251e1d38cc72de968");
  /* MinIO's sealed key (ChaCha20, from sio's cipher choice on that machine) */
  hexin("20011f00a1c61d098b6fa545e569157c86385c9c2b026ecac0d8833fbf37e0a091b5c05ee35af5f176644b056f6d4707be0afff7b93933e1aa90fda55d8cdc6d",
        sealed);
  assert_true(buckets_objkey_unseal(ext, sealed, iv, BUCKETS_SEAL_ALGORITHM, "SSE-S3", "bkt", "dir/obj.txt", back));
  assert_memory_equal(back, key, 32);
  assert_false(buckets_objkey_unseal(ext, sealed, iv, BUCKETS_SEAL_ALGORITHM, "SSE-S3", "bkt", "dir/other.txt", back));
  assert_false(buckets_objkey_unseal(ext, sealed, iv, BUCKETS_SEAL_ALGORITHM, "SSE-C", "bkt", "dir/obj.txt", back));
  /* ours, back through the same path */
  uint8_t iv2[32], sealed2[64];
  buckets_objkey_seal(key, ext, NULL, "SSE-KMS", "bkt", "dir/", iv2, sealed2);
  assert_true(buckets_objkey_unseal(ext, sealed2, iv2, BUCKETS_SEAL_ALGORITHM, "SSE-KMS", "bkt", "dir", back)); /* path.Join cleans */
  assert_memory_equal(back, key, 32);
  uint8_t part[32];
  buckets_objkey_part_key(key, 3, part);
  hexeq(part, 32, "1a373a1c4d027138361f4dbaaaa499eb40f847e7eca2de28434f329e66def1bb");
  uint8_t sealed_etag[48], etag[16];
  hexin("20010f00e8317627b908fdb181daad631e44301c784a6a369dbb2679246278e73218ec850a4e31f26552acf0c455ab34", sealed_etag);
  buckets_buf b = BUCKETS_BUF_INIT;
  assert_true(buckets_objkey_unseal_etag(key, sealed_etag, 48, &b));
  hexeq((uint8_t *)b.data, b.len, "5d41402abc4b2a76b9719d911017c592");
  hexin("5d41402abc4b2a76b9719d911017c592", etag);
  buckets_buf_reset(&b);
  buckets_objkey_seal_etag(key, etag, 16, &b);
  assert_int_equal(b.len, 48);
  buckets_buf e2 = BUCKETS_BUF_INIT;
  assert_true(buckets_objkey_unseal_etag(key, (uint8_t *)b.data, b.len, &e2));
  assert_memory_equal(e2.data, etag, 16);
  buckets_buf_free(&b);
  buckets_buf_free(&e2);
}

static void test_builtin_kms(void **state) {
  char err[128];
  buckets_kms *k = buckets_kms_builtin("my-key:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=", err, sizeof(err));
  assert_non_null(k);
  uint8_t ct[76], pt[32];
  hexin("9e02e6e2695f36e4d5a7cc32669eee74b926a2bee14b1ec67fe3e8fb09d6070db72c6a3b9fe96ced6616ebe1e9d0f32ba8347d2f39fffc96cf28e41dacb1e485aae627133a7186baa537680b",
        ct);
  const char *ctx = "{\"bkt\":\"bkt/dir/obj.txt\"}";
  assert_int_equal(buckets_kms_decrypt(k, "my-key", ct, sizeof(ct), ctx, pt), BUCKETS_KMS_OK);
  hexeq(pt, 32, "11814d0b2450ed9d9f4c9970de565045cb4cbdc8cc5d629710abc8690f040df6");
  assert_int_equal(buckets_kms_decrypt(k, "my-key", ct, sizeof(ct), "{}", pt), BUCKETS_KMS_ERR_DECRYPT);
  assert_int_equal(buckets_kms_decrypt(k, "other", ct, sizeof(ct), ctx, pt), BUCKETS_KMS_ERR_KEY_NOT_FOUND);
  buckets_buf c = BUCKETS_BUF_INIT;
  uint8_t plain[32], back[32];
  char id[64];
  assert_int_equal(buckets_kms_generate(k, NULL, ctx, plain, &c, id, sizeof(id)), BUCKETS_KMS_OK);
  assert_string_equal(id, "my-key");
  assert_int_equal(c.len, 76);
  assert_int_equal(buckets_kms_decrypt(k, "my-key", (uint8_t *)c.data, c.len, ctx, back), BUCKETS_KMS_OK);
  assert_memory_equal(back, plain, 32);
  buckets_buf_free(&c);
  assert_null(buckets_kms_builtin("nokey", err, sizeof(err)));
  assert_null(buckets_kms_builtin("k:c2hvcnQ=", err, sizeof(err)));
  assert_string_equal(err, "kms: invalid key length 5");
  buckets_kms_free(k);
}

static void test_context_and_path(void **state) {
  const char *keys[] = {"b", "a"}, *vals[] = {"x<y>&\"z\"\n", "1"};
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_kms_context_text(keys, vals, 2, &b);
  assert_string_equal(b.data, "{\"a\":\"1\",\"b\":\"x\\u003cy\\u003e\\u0026\\\"z\\\"\\n\"}");
  buckets_buf_reset(&b);
  buckets_kms_context_text(NULL, NULL, 0, &b);
  assert_string_equal(b.data, "{}");
  static const struct {
    const char *a, *b, *want;
  } j[] = {{"bkt", "dir/obj", "bkt/dir/obj"}, {"bkt", "dir/", "bkt/dir"},      {"bkt", "a//b/./c/../d", "bkt/a/b/d"},
           {"bkt", "../x", "x"},            {"bkt", "../../x", "../x"},        {"bkt", "", "bkt"},
           {"", "obj", "obj"},              {"bkt", "/abs", "bkt/abs"}};
  for (size_t i = 0; i < sizeof(j) / sizeof(j[0]); i++) {
    buckets_buf_reset(&b);
    buckets_path_join(j[i].a, j[i].b, &b);
    assert_string_equal(b.data, j[i].want);
  }
  buckets_buf_free(&b);
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_object_key), cmocka_unit_test(test_builtin_kms),
                                     cmocka_unit_test(test_context_and_path)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
