/* Checks the C ports against outputs of the Go libraries MinIO links
 * (tools/golden generates golden_vectors.inc).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/msgpack.h"
#include "crypto/cksum.h"
#include "crypto/crc.h"
#include "crypto/hex.h"
#include "crypto/sha1.h"
#include "crypto/siphash.h"
#include "crypto/highwayhash.h"
#include "crypto/xxhash.h"

#include "golden_vectors.inc"

static uint8_t *pattern(size_t n) {
  uint8_t *b = malloc(n ? n : 1);
  for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(i * 7 + 3);
  return b;
}

static void test_xxhash(void **state) {
  for (size_t i = 0; i < sizeof(golden_xxh) / sizeof(golden_xxh[0]); i++) {
    uint8_t *p = pattern(golden_xxh[i].len);
    if (buckets_xxh64(p, golden_xxh[i].len) != golden_xxh[i].xxh64) fail_msg("xxh64 len %zu", golden_xxh[i].len);
    if (buckets_xxh3_64(p, golden_xxh[i].len) != golden_xxh[i].xxh3) fail_msg("xxh3 len %zu", golden_xxh[i].len);
    free(p);
  }
}

static void test_checksums(void **state) {
  for (size_t i = 0; i < sizeof(golden_cks) / sizeof(golden_cks[0]); i++) {
    size_t n = golden_cks[i].len;
    uint8_t *p = pattern(n);
    if (buckets_crc32_ieee(0, p, n) != golden_cks[i].crc32) fail_msg("crc32 len %zu", n);
    if (buckets_crc32c(0, p, n) != golden_cks[i].crc32c) fail_msg("crc32c len %zu", n);
    if (buckets_crc64_nvme(0, p, n) != golden_cks[i].crc64nvme) fail_msg("crc64nvme len %zu", n);
    /* Streaming in two pieces gives the same CRC. */
    size_t half = n / 3;
    if (buckets_crc64_nvme(buckets_crc64_nvme(0, p, half), p + half, n - half) != golden_cks[i].crc64nvme) {
      fail_msg("crc64nvme streaming len %zu", n);
    }
    if (buckets_crc32c(buckets_crc32c(0, p, half), p + half, n - half) != golden_cks[i].crc32c) {
      fail_msg("crc32c streaming len %zu", n);
    }
    buckets_sha1_ctx ctx;
    uint8_t d[20];
    buckets_sha1_init(&ctx);
    buckets_sha1_update(&ctx, p, half);
    buckets_sha1_update(&ctx, p + half, n - half);
    buckets_sha1_final(&ctx, d);
    if (memcmp(d, golden_cks[i].sha1, 20) != 0) fail_msg("sha1 len %zu", n);
    free(p);
  }
  /* combine(crc(A), crc(B), len(B)) == crc(A||B) for every CRC type. */
  static const uint32_t types[] = {BUCKETS_CKSUM_CRC32, BUCKETS_CKSUM_CRC32C, BUCKETS_CKSUM_CRC64NVME};
  uint8_t *p = pattern(10000);
  for (size_t t = 0; t < 3; t++) {
    for (size_t split = 0; split <= 10000; split += 1237) {
      buckets_cksum_hasher h;
      uint8_t a[8], b[8], whole[8];
      buckets_cksum_hasher_init(&h, types[t]);
      buckets_cksum_hasher_update(&h, p, split);
      size_t n = buckets_cksum_hasher_final(&h, a);
      buckets_cksum_hasher_init(&h, types[t]);
      buckets_cksum_hasher_update(&h, p + split, 10000 - split);
      buckets_cksum_hasher_final(&h, b);
      buckets_cksum_hasher_init(&h, types[t]);
      buckets_cksum_hasher_update(&h, p, 10000);
      buckets_cksum_hasher_final(&h, whole);
      assert_true(buckets_cksum_combine(types[t], a, b, (int64_t)(10000 - split)));
      if (memcmp(a, whole, n) != 0) fail_msg("combine type %u split %zu", types[t], split);
    }
  }
  free(p);

  /* Catalogue check values for "123456789". */
  assert_true(buckets_crc32_ieee(0, "123456789", 9) == 0xcbf43926u);
  assert_true(buckets_crc32c(0, "123456789", 9) == 0xe3069283u);
  assert_true(buckets_crc64_nvme(0, "123456789", 9) == 0xae8b14860a799888ull);
}

static void test_siphash(void **state) {
  for (size_t i = 0; i < sizeof(golden_sip) / sizeof(golden_sip[0]); i++) {
    uint8_t *p = pattern(golden_sip[i].len);
    if (buckets_siphash24(golden_sip[i].k0, golden_sip[i].k1, p, golden_sip[i].len) != golden_sip[i].sum) {
      fail_msg("siphash len %zu", golden_sip[i].len);
    }
    free(p);
  }
}

static void test_highwayhash(void **state) {
  for (size_t i = 0; i < sizeof(golden_hh) / sizeof(golden_hh[0]); i++) {
    size_t n = golden_hh[i].len;
    uint8_t *p = pattern(n);
    uint8_t one[32], inc[32];
    buckets_hh256(buckets_bitrot_key, p, n, one);
    if (memcmp(one, golden_hh[i].hh256, 32) != 0) fail_msg("hh256 len %zu", n);
    /* Same result when fed in awkward pieces. */
    buckets_hh_ctx ctx;
    buckets_hh_init(&ctx, buckets_bitrot_key);
    for (size_t off = 0; off < n;) {
      size_t step = BUCKETS_MIN((off % 13) + 1, n - off);
      buckets_hh_update(&ctx, p + off, step);
      off += step;
    }
    buckets_hh_final256(&ctx, inc);
    if (memcmp(inc, golden_hh[i].hh256, 32) != 0) fail_msg("hh256 incremental len %zu", n);
    free(p);
  }
}

/* MinIO's bitrotSelfTest (cmd/bitrot.go) for HighwayHash256S. */
static void test_bitrot_selftest(void **state) {
  uint8_t msg[32 * 32];
  size_t len = 0;
  uint8_t sum[32];
  for (int i = 0; i < 32 * 32; i += 32) {
    buckets_hh256(buckets_bitrot_key, msg, len, sum);
    memcpy(msg + len, sum, 32);
    len += 32;
  }
  char hex[65];
  buckets_hex_encode(sum, 32, hex);
  assert_string_equal(hex, "39c0407ed3f01b18d22c85db4aeff11e060ca5f43131b0126731ca197cd42313");
}

static void test_msgpack_encodings(void **state) {
  for (size_t i = 0; i < sizeof(golden_msgp) / sizeof(golden_msgp[0]); i++) {
    const char *name = golden_msgp[i].name;
    buckets_buf b = BUCKETS_BUF_INIT;
    char kind[8];
    char num[32];
    sscanf(name, "%7s %31s", kind, num);
    if (strcmp(kind, "int") == 0) {
      buckets_mp_int(&b, strtoll(num, NULL, 10));
    } else if (strcmp(kind, "uint") == 0) {
      buckets_mp_uint(&b, strtoull(num, NULL, 10));
    } else if (strcmp(kind, "str") == 0) {
      size_t n = strtoul(num, NULL, 10);
      char *s = malloc(n + 1);
      memset(s, 'a', n);
      buckets_mp_str(&b, s, n);
      free(s);
    } else if (strcmp(kind, "bin") == 0) {
      size_t n = strtoul(num, NULL, 10);
      void *z = calloc(1, n + 1);
      buckets_mp_bin(&b, z, n);
      free(z);
    } else if (strcmp(kind, "map") == 0) {
      buckets_mp_map(&b, (uint32_t)strtoul(num, NULL, 10));
    } else {
      buckets_mp_array(&b, (uint32_t)strtoul(num, NULL, 10));
    }
    size_t cmp = golden_msgp[i].n;
    if (b.len < cmp || memcmp(b.data, golden_msgp[i].bytes, cmp) != 0) fail_msg("msgpack encoding: %s", name);

    /* And the reader round-trips integers. */
    buckets_mp_reader r = buckets_mp_reader_init(b.data, b.len);
    if (strcmp(kind, "int") == 0) {
      int64_t v;
      assert_true(buckets_mp_read_int(&r, &v));
      assert_int_equal(v, strtoll(num, NULL, 10));
    } else if (strcmp(kind, "uint") == 0) {
      uint64_t v;
      assert_true(buckets_mp_read_uint(&r, &v));
      assert_true(v == strtoull(num, NULL, 10));
    }
    buckets_buf_free(&b);
  }
}

static void test_msgpack_reader(void **state) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_mp_map(&b, 2);
  buckets_mp_cstr(&b, "k");
  buckets_mp_array(&b, 3);
  buckets_mp_nil(&b);
  buckets_mp_bool(&b, true);
  buckets_mp_bin(&b, "xyz", 3);
  buckets_mp_cstr(&b, "n");
  buckets_mp_int(&b, -5);

  buckets_mp_reader r = buckets_mp_reader_init(b.data, b.len);
  uint32_t n;
  buckets_str s;
  assert_true(buckets_mp_read_map(&r, &n));
  assert_int_equal(n, 2);
  assert_true(buckets_mp_read_str(&r, &s));
  assert_true(buckets_str_eq_c(s, "k"));
  assert_true(buckets_mp_skip(&r));
  assert_true(buckets_mp_read_str(&r, &s));
  int64_t v;
  assert_true(buckets_mp_read_int(&r, &v));
  assert_int_equal(v, -5);
  assert_int_equal(buckets_mp_remaining(&r), 0);

  /* Truncated input fails cleanly and stays failed. */
  r = buckets_mp_reader_init(b.data, b.len - 1);
  assert_true(buckets_mp_read_map(&r, &n));
  assert_true(buckets_mp_read_str(&r, &s));
  assert_true(buckets_mp_skip(&r));
  assert_true(buckets_mp_read_str(&r, &s));
  assert_false(buckets_mp_read_int(&r, &v));
  assert_true(r.err);
  buckets_buf_free(&b);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_xxhash),
      cmocka_unit_test(test_checksums),
      cmocka_unit_test(test_siphash),
      cmocka_unit_test(test_highwayhash),
      cmocka_unit_test(test_bitrot_selftest),
      cmocka_unit_test(test_msgpack_encodings),
      cmocka_unit_test(test_msgpack_reader),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
