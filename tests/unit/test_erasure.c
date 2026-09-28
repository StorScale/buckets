/* Reed-Solomon compatibility: MinIO's erasureSelfTest (cmd/erasure-coding.go).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/xxhash.h"
#include "erasure/rs.h"

/* Expected xxh64 over (index byte || shard) for every shard, from MinIO. */
static const struct {
  int data, parity;
  uint64_t hash;
} k_want[] = {
    {2, 2, 0x23fb21be2496f5d3ull},
    {2, 3, 0xa5cd5600ba0d8e7cull},
    {3, 1, 0x60ab052148b010b4ull},
    {3, 2, 0xe64927daef76435aull},
    {3, 3, 0x672f6f242b227b21ull},
    {3, 4, 0x571e41ba23a6dc6ull},
    {4, 1, 0x524eaa814d5d86e2ull},
    {4, 2, 0x62b9552945504fefull},
    {4, 3, 0xcbf9065ee053e518ull},
    {4, 4, 0x9a07581dcd03da8ull},
    {4, 5, 0xbf2d27b55370113full},
    {5, 1, 0xf71031a01d70dafull},
    {5, 2, 0x8e5845859939d0f4ull},
    {5, 3, 0x7ad9161acbb4c325ull},
    {5, 4, 0xc446b88830b4f800ull},
    {5, 5, 0xabf1573cc6f76165ull},
    {5, 6, 0x7b5598a85045bfb8ull},
    {6, 1, 0xe2fc1e677cc7d872ull},
    {6, 2, 0x7ed133de5ca6a58eull},
    {6, 3, 0x39ef92d0a74cc3c0ull},
    {6, 4, 0xcfc90052bc25d20ull},
    {6, 5, 0x71c96f6baeef9c58ull},
    {6, 6, 0x4b79056484883e4cull},
    {6, 7, 0xb1a0e2427ac2dc1aull},
    {7, 1, 0x937ba2b7af467a22ull},
    {7, 2, 0x5fd13a734d27d37aull},
    {7, 3, 0x3be2722d9b66912full},
    {7, 4, 0x14c628e59011be3dull},
    {7, 5, 0xcc3b39ad4c083b9full},
    {7, 6, 0x45af361b7de7a4ffull},
    {7, 7, 0x456cc320cec8a6e6ull},
    {7, 8, 0x1867a9f4db315b5cull},
    {8, 1, 0xbc5756b9a9ade030ull},
    {8, 2, 0xdfd7d9d0b3e36503ull},
    {8, 3, 0x72bb72c2cdbcf99dull},
    {8, 4, 0x3ba5e9b41bf07f0ull},
    {8, 5, 0xd7dabc15800f9d41ull},
    {8, 6, 0xb482a6169fd270full},
    {8, 7, 0x50748e0099d657e8ull},
    {9, 1, 0xc77ae0144fcaeb6eull},
    {9, 2, 0x8a86c7dbebf27b68ull},
    {9, 3, 0xa64e3be6d6fe7e92ull},
    {9, 4, 0x239b71c41745d207ull},
    {9, 5, 0x2d0803094c5a86ceull},
    {9, 6, 0xa3c2539b3af84874ull},
    {10, 1, 0x7d30d91b89fcec21ull},
    {10, 2, 0xfa5af9aa9f1857a3ull},
    {10, 3, 0x84bc4bda8af81f90ull},
    {10, 4, 0x6c1cba8631de994aull},
    {10, 5, 0x4383e58a086cc1acull},
    {11, 1, 0x4ed2929a2df690bull},
    {11, 2, 0xecd6f1b1399775c0ull},
    {11, 3, 0xc78cfbfc0dc64d01ull},
    {11, 4, 0xb2643390973702d6ull},
    {12, 1, 0x3b2a88686122d082ull},
    {12, 2, 0xfd2f30a48a8e2e9ull},
    {12, 3, 0xd5ce58368ae90b13ull},
    {13, 1, 0x9c88e2a9d1b8fff8ull},
    {13, 2, 0xcb8460aa4cf6613ull},
    {14, 1, 0x78a28bbaec57996eull}
};

/* EncodeData: Split (zero-padded ceil(n/data) shards) then Encode. */
static uint8_t **encode(buckets_rs *rs, const uint8_t *data, size_t n, size_t *shard_len) {
  int d = buckets_rs_data(rs), t = d + buckets_rs_parity(rs);
  size_t sz = buckets_rs_shard_size(rs, n);
  uint8_t **shards = calloc((size_t)t, sizeof(uint8_t *));
  for (int i = 0; i < t; i++) {
    shards[i] = calloc(1, sz);
    if (i < d && (size_t)i * sz < n) memcpy(shards[i], data + (size_t)i * sz, BUCKETS_MIN(sz, n - (size_t)i * sz));
  }
  buckets_rs_encode(rs, shards, sz);
  *shard_len = sz;
  return shards;
}

static void test_minio_selftest(void **state) {
  uint8_t data[256];
  for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
  size_t checked = 0;
  for (size_t k = 0; k < sizeof(k_want) / sizeof(k_want[0]); k++) {
    buckets_rs *rs = buckets_rs_new(k_want[k].data, k_want[k].parity);
    size_t sz;
    uint8_t **shards = encode(rs, data, sizeof(data), &sz);
    int t = k_want[k].data + k_want[k].parity;
    uint8_t *buf = malloc((size_t)t * (sz + 1));
    size_t off = 0;
    for (int i = 0; i < t; i++) {
      buf[off++] = (uint8_t)i;
      memcpy(buf + off, shards[i], sz);
      off += sz;
    }
    if (buckets_xxh64(buf, off) != k_want[k].hash) fail_msg("d=%d p=%d hash mismatch", k_want[k].data, k_want[k].parity);
    /* DecodeDataBlocks after losing shard 0. */
    uint8_t *first = malloc(sz);
    memcpy(first, shards[0], sz);
    memset(shards[0], 0xAA, sz);
    bool present[256];
    for (int i = 0; i < t; i++) present[i] = i != 0;
    assert_true(buckets_rs_reconstruct(rs, shards, present, sz, true));
    assert_memory_equal(first, shards[0], sz);
    for (int i = 0; i < t; i++) free(shards[i]);
    free(shards);
    free(first);
    free(buf);
    buckets_rs_free(rs);
    checked++;
  }
  assert_int_equal(checked, 60); /* every entry in MinIO's table */
}

/* Any `parity` losses (data or parity) are recoverable; one more is not. */
static void test_reconstruct_any(void **state) {
  uint8_t data[10000];
  for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 31 + 7);
  buckets_rs *rs = buckets_rs_new(8, 4);
  size_t sz;
  uint8_t **shards = encode(rs, data, sizeof(data), &sz);
  uint8_t *orig[12];
  for (int i = 0; i < 12; i++) {
    orig[i] = malloc(sz);
    memcpy(orig[i], shards[i], sz);
  }
  static const int lose[][4] = {{0, 1, 2, 3}, {8, 9, 10, 11}, {0, 5, 9, 11}, {3, 4, 6, 7}};
  for (size_t c = 0; c < 4; c++) {
    bool present[12];
    for (int i = 0; i < 12; i++) present[i] = true;
    for (int j = 0; j < 4; j++) {
      present[lose[c][j]] = false;
      memset(shards[lose[c][j]], 0, sz);
    }
    assert_true(buckets_rs_reconstruct(rs, shards, present, sz, false));
    for (int i = 0; i < 12; i++) assert_memory_equal(orig[i], shards[i], sz);
  }
  bool present[12];
  for (int i = 0; i < 12; i++) present[i] = i >= 5;
  assert_false(buckets_rs_reconstruct(rs, shards, present, sz, false));
  for (int i = 0; i < 12; i++) {
    free(orig[i]);
    free(shards[i]);
  }
  free(shards);
  buckets_rs_free(rs);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_minio_selftest),
      cmocka_unit_test(test_reconstruct_any),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
