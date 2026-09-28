/* xl.meta compatibility against files written by real MinIO
 * (RELEASE.2025-10-15T17-29-55Z) in tests/data/minio-ref.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/highwayhash.h"
#include "bucket/metadata.h"
#include "storage/xlmeta.h"

static uint8_t *read_fixture(const char *name, size_t *n) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/minio-ref/%s", BUCKETS_TEST_DATA_DIR, name);
  FILE *f = fopen(path, "rb");
  if (!f) fail_msg("missing fixture %s", path);
  fseek(f, 0, SEEK_END);
  *n = (size_t)ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(*n);
  assert_int_equal(fread(b, 1, *n, f), *n);
  fclose(f);
  return b;
}

static const char *const k_objects[] = {"small.xl.meta", "big.xl.meta", "empty.xl.meta", "folder.xl.meta",
                                        "bucket-metadata.xl.meta"};

/* parse -> serialize reproduces MinIO's bytes exactly. */
static void test_roundtrip_bytes(void **state) {
  for (size_t i = 0; i < sizeof(k_objects) / sizeof(k_objects[0]); i++) {
    size_t n;
    uint8_t *raw = read_fixture(k_objects[i], &n);
    buckets_xlmeta x;
    assert_int_equal(buckets_xlmeta_parse(raw, n, &x), BUCKETS_XL_OK);
    assert_int_equal(x.n, 1);
    buckets_buf out = BUCKETS_BUF_INIT;
    buckets_xlmeta_serialize(&x, &out);
    if (out.len != n || memcmp(out.data, raw, n) != 0) fail_msg("%s: re-serialized bytes differ", k_objects[i]);
    buckets_buf_free(&out);
    buckets_xlmeta_free(&x);
    free(raw);
  }
}

/* decode -> encode derives the same header MinIO wrote, including the
 * xxh3/xxh64-based version signature. */
static void test_reencode_header_and_signature(void **state) {
  for (size_t i = 0; i < sizeof(k_objects) / sizeof(k_objects[0]); i++) {
    size_t n;
    uint8_t *raw = read_fixture(k_objects[i], &n);
    buckets_xlmeta x;
    assert_int_equal(buckets_xlmeta_parse(raw, n, &x), BUCKETS_XL_OK);
    buckets_xl_object o;
    assert_int_equal(buckets_xl_object_decode(&x.versions[0], &o), BUCKETS_XL_OK);
    assert_int_equal(o.type, BUCKETS_XL_TYPE_OBJECT);

    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_xl_header hdr;
    buckets_xl_object_encode(&o, &meta, &hdr);
    const buckets_xl_header *want = &x.versions[0].hdr;
    if (memcmp(hdr.signature, want->signature, 4) != 0) fail_msg("%s: signature mismatch", k_objects[i]);
    assert_int_equal(hdr.flags, want->flags);
    assert_int_equal(hdr.mod_time, want->mod_time);
    assert_int_equal(hdr.ec_m, want->ec_m);
    assert_int_equal(hdr.ec_n, want->ec_n);
    /* Map order is random in Go; with at most one entry per map the encoding is unique. */
    if (o.nmeta_user <= 1 && o.nmeta_sys <= 1) {
      if (meta.len != x.versions[0].meta_len || memcmp(meta.data, x.versions[0].meta, meta.len) != 0) {
        fail_msg("%s: version encoding differs", k_objects[i]);
      }
    }
    buckets_buf_free(&meta);
    buckets_xl_object_free(&o);
    buckets_xlmeta_free(&x);
    free(raw);
  }
}

static void test_decode_fields(void **state) {
  size_t n;
  uint8_t *raw = read_fixture("small.xl.meta", &n);
  buckets_xlmeta x;
  assert_int_equal(buckets_xlmeta_parse(raw, n, &x), BUCKETS_XL_OK);
  buckets_xl_object o;
  assert_int_equal(buckets_xl_object_decode(&x.versions[0], &o), BUCKETS_XL_OK);
  assert_int_equal(o.size, 14);
  assert_int_equal(o.ec_m, 1);
  assert_int_equal(o.ec_n, 0);
  assert_int_equal(o.ec_block_size, 1048576);
  assert_int_equal(o.ec_index, 1);
  assert_int_equal(o.nparts, 1);
  assert_int_equal(o.parts[0].number, 1);
  assert_int_equal(o.parts[0].size, 14);
  assert_string_equal((char *)buckets_xl_kv_get(o.meta_user, o.nmeta_user, "etag")->value,
                      "af9819ec825e118e2e218f007964fcd8");
  assert_string_equal((char *)buckets_xl_kv_get(o.meta_user, o.nmeta_user, "X-Amz-Meta-Color")->value, "blue");
  assert_non_null(buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE));

  /* Inline shard: 32-byte HighwayHash-256 of the block, then the block. */
  buckets_str data;
  assert_true(buckets_xlmeta_inline_get(&x, "null", &data));
  assert_int_equal(data.n, 32 + 14);
  assert_memory_equal(data.p + 32, "hello buckets\n", 14);
  uint8_t h[32];
  buckets_hh256(buckets_bitrot_key, data.p + 32, 14, h);
  assert_memory_equal(h, data.p, 32);

  buckets_xl_object_free(&o);
  buckets_xlmeta_free(&x);
  free(raw);
}

static void test_corruption_detected(void **state) {
  size_t n;
  uint8_t *raw = read_fixture("big.xl.meta", &n);
  buckets_xlmeta x;
  raw[40] ^= 0x01; /* inside the checksummed metadata section */
  assert_int_equal(buckets_xlmeta_parse(raw, n, &x), BUCKETS_XL_ERR_CORRUPT);
  raw[40] ^= 0x01;
  raw[6] = 2; /* minor 2: legacy layout */
  assert_int_equal(buckets_xlmeta_parse(raw, n, &x), BUCKETS_XL_ERR_UNSUPPORTED);
  assert_int_equal(buckets_xlmeta_parse(raw, 6, &x), BUCKETS_XL_ERR_CORRUPT);
  free(raw);
}

static void test_versions_and_inline(void **state) {
  buckets_xlmeta x = {0};
  for (int i = 0; i < 3; i++) {
    buckets_xl_object o = {0};
    o.type = BUCKETS_XL_TYPE_OBJECT;
    o.version_id[0] = (uint8_t)(i + 1);
    o.mod_time = 1000 + i; /* newest last: must sort to the front */
    o.ec_m = 1;
    o.ec_block_size = 1048576;
    o.ec_index = 1;
    o.ec_dist[0] = 1;
    o.ec_dist_n = 1;
    buckets_xl_part_add(&o, 1, 5, 5, NULL);
    o.size = 5;
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", "abc", 3);
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_xl_header hdr;
    buckets_xl_object_encode(&o, &meta, &hdr);
    buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)meta.data, meta.len);
    buckets_xl_object_free(&o);
  }
  assert_int_equal(x.n, 3);
  assert_int_equal(x.versions[0].hdr.version_id[0], 3);
  assert_int_equal(x.versions[2].hdr.version_id[0], 1);

  buckets_xlmeta_inline_put(&x, "a", "one", 3);
  buckets_xlmeta_inline_put(&x, "b", "two", 3);
  buckets_xlmeta_inline_put(&x, "a", "uno", 3);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(&x, &out);

  buckets_xlmeta y;
  assert_int_equal(buckets_xlmeta_parse(out.data, out.len, &y), BUCKETS_XL_OK);
  assert_int_equal(y.n, 3);
  buckets_str v;
  assert_true(buckets_xlmeta_inline_get(&y, "a", &v));
  assert_true(buckets_str_eq_c(v, "uno"));
  assert_true(buckets_xlmeta_inline_get(&y, "b", &v));
  uint8_t id[16] = {2};
  assert_true(buckets_xlmeta_remove_version(&y, id));
  assert_int_equal(buckets_xlmeta_find(&y, id), -1);
  buckets_xlmeta_inline_remove(&y, "a");
  buckets_xlmeta_inline_remove(&y, "b");
  assert_int_equal(y.inline_len, 0);

  buckets_buf_free(&out);
  buckets_xlmeta_free(&x);
  buckets_xlmeta_free(&y);
}

static void test_version_ids(void **state) {
  uint8_t id[16];
  char s[37];
  assert_true(buckets_xl_version_id_parse("null", id));
  buckets_xl_version_id_string(id, s);
  assert_string_equal(s, "null");
  assert_true(buckets_xl_version_id_parse("9e82e11d-6206-4445-b705-1c36ebcb405a", id));
  buckets_xl_version_id_string(id, s);
  assert_string_equal(s, "9e82e11d-6206-4445-b705-1c36ebcb405a");
  assert_false(buckets_xl_version_id_parse("9e82e11d62064445b7051c36ebcb405a", id));
  assert_false(buckets_xl_version_id_parse("9e82e11d-6206-4445-b705-1c36ebcb40zz", id));
}

/* MinIO's .metadata.bin decodes and re-encodes to identical bytes. */
static void test_bucket_metadata(void **state) {
  size_t n;
  uint8_t *raw = read_fixture("bucket-metadata.xl.meta", &n);
  buckets_xlmeta x;
  assert_int_equal(buckets_xlmeta_parse(raw, n, &x), BUCKETS_XL_OK);
  buckets_str shard;
  assert_true(buckets_xlmeta_inline_get(&x, "null", &shard));
  buckets_str data = {shard.p + 32, shard.n - 32}; /* skip the bitrot hash */
  buckets_bucket_meta m;
  assert_true(buckets_bucket_meta_decode(data.p, data.n, &m));
  assert_string_equal(m.name, "ref");
  assert_true(buckets_bucket_meta_created_ns(&m) > 0);
  assert_int_equal(m.updated[BUCKETS_BCFG_POLICY].sec, BUCKETS_GO_ZERO_TIME_SEC);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_bucket_meta_encode(&m, &out);
  assert_int_equal(out.len, data.n);
  assert_memory_equal(out.data, data.p, data.n);

  /* A fresh record for the same name/time encodes identically too. */
  buckets_bucket_meta fresh;
  buckets_bucket_meta_init(&fresh, "ref", buckets_bucket_meta_created_ns(&m));
  buckets_buf out2 = BUCKETS_BUF_INIT;
  buckets_bucket_meta_encode(&fresh, &out2);
  assert_memory_equal(out2.data, data.p, data.n);

  buckets_buf_free(&out);
  buckets_buf_free(&out2);
  buckets_bucket_meta_free(&m);
  buckets_bucket_meta_free(&fresh);
  buckets_xlmeta_free(&x);
  free(raw);
}

/* PartIdx (compressed parts' S2 indexes): omitempty, one bin per part, empty
 * for parts without one, and back only when there is one per part. */
static void test_part_indexes(void **state) {
  (void)state;
  for (int with = 0; with < 2; with++) {
    buckets_xl_object o = {0};
    o.type = BUCKETS_XL_TYPE_OBJECT;
    o.ec_m = 1;
    o.ec_block_size = 1048576;
    o.ec_index = 1;
    o.ec_dist[0] = 1;
    o.ec_dist_n = 1;
    buckets_xl_part_add(&o, 1, 100, 9000000, NULL);
    buckets_xl_part_add(&o, 2, 50, 70, NULL);
    if (with) buckets_xl_part_set_index(&o.parts[0], "\x01\x02\x03", 3);
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_xl_header hdr;
    buckets_xl_object_encode(&o, &meta, &hdr);
    bool has_key = memmem(meta.data, meta.len, "\xa7PartIdx\x92\xc4\x03\x01\x02\x03\xc4\x00", 15) != NULL;
    assert_int_equal(has_key, with);
    buckets_xl_version v = {.hdr = hdr, .meta = (uint8_t *)meta.data, .meta_len = meta.len};
    buckets_xl_object back;
    assert_int_equal(buckets_xl_object_decode(&v, &back), BUCKETS_XL_OK);
    assert_int_equal(back.nparts, 2);
    assert_int_equal(back.parts[0].actual_size, 9000000);
    assert_int_equal(back.parts[0].index_len, with ? 3 : 0);
    if (with) assert_memory_equal(back.parts[0].index, "\x01\x02\x03", 3);
    assert_null(back.parts[1].index);
    buckets_xl_object_free(&back);
    buckets_xl_object_free(&o);
    buckets_buf_free(&meta);
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_roundtrip_bytes),     cmocka_unit_test(test_reencode_header_and_signature),
      cmocka_unit_test(test_decode_fields),       cmocka_unit_test(test_corruption_detected),
      cmocka_unit_test(test_versions_and_inline), cmocka_unit_test(test_version_ids),
      cmocka_unit_test(test_bucket_metadata),     cmocka_unit_test(test_part_indexes),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
