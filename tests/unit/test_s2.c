/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compress/s2.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"

#include "s2_vectors.inc"

/* The generator of the s2vec tool. */
static uint8_t *gen(int kind, size_t n, uint64_t seed) {
  static const char *words[] = {"bucket ", "object ", "erasure ", "the ", "a ", "minio ", "buckets ", "drive ", "set ", "pool ", "\n"};
  uint64_t s = seed * 2654435761u + 1;
#define NEXT() (s ^= s << 13, s ^= s >> 7, s ^= s << 17, s)
  uint8_t *b = malloc(n + 400);
  size_t k = 0;
  while (k < n) {
    switch (kind) {
    case 0: b[k++] = (uint8_t)(NEXT() & 3); break;
    case 1: {
      const char *w = words[NEXT() % 11];
      size_t l = strlen(w);
      memcpy(b + k, w, l);
      k += l;
      break;
    }
    case 2: b[k++] = (uint8_t)(NEXT() >> 24); break;
    case 3: b[k++] = 0; break;
    default: {
      uint8_t c = (uint8_t)('a' + NEXT() % 4);
      size_t r = NEXT() % 300;
      memset(b + k, c, r);
      k += r;
      break;
    }
    }
  }
#undef NEXT
  return b;
}

typedef struct {
  const uint8_t *p;
  size_t n, pos, chunk;
} mem_src;

/* Serves at most chunk bytes per call, to exercise partial reads. */
static long mem_read(void *ud, void *buf, size_t n) {
  mem_src *m = ud;
  size_t k = m->n - m->pos;
  if (k > n) k = n;
  if (m->chunk && k > m->chunk) k = m->chunk;
  memcpy(buf, m->p + m->pos, k);
  m->pos += k;
  return (long)k;
}

static uint8_t *drain(buckets_s2_read_fn rd, void *ud, size_t *len) {
  size_t cap = 1 << 16, n = 0;
  uint8_t *out = malloc(cap);
  for (;;) {
    if (cap - n < 7777) out = realloc(out, cap *= 2);
    long k = rd(ud, out + n, 7777);
    if (k < 0) {
      free(out);
      return NULL;
    }
    if (k == 0) break;
    n += (size_t)k;
  }
  *len = n;
  return out;
}

static void test_writer_matches_go(void **state) {
  (void)state;
  for (size_t v = 0; v < sizeof(s2_enc_vectors) / sizeof(s2_enc_vectors[0]); v++) {
    size_t n = s2_enc_vectors[v].n;
    uint8_t *data = gen(s2_enc_vectors[v].kind, n, s2_enc_vectors[v].seed);
    mem_src src = {data, n, 0, 100000};
    buckets_s2_writer w;
    buckets_s2_writer_init(&w, mem_read, &src, v % 2 ? (int64_t)n : -1, 0);
    size_t len;
    uint8_t *st = drain(buckets_s2_writer_read, &w, &len);
    assert_non_null(st);
    uint8_t sum[32];
    char hex[65];
    buckets_sha256(st, len, sum);
    buckets_hex_encode(sum, 32, hex);
    if (strcmp(hex, s2_enc_vectors[v].sha)) fprintf(stderr, "vector %zu (n=%zu) differs\n", v, n);
    assert_string_equal(hex, s2_enc_vectors[v].sha);
    buckets_buf idx = BUCKETS_BUF_INIT;
    assert_true(buckets_s2_writer_index(&w, -1, &idx));
    assert_int_equal(idx.len, s2_enc_vectors[v].idx_len);
    assert_memory_equal(idx.data, s2_enc_vectors[v].idx, idx.len);
    /* ... and it reads back */
    mem_src ss = {st, len, 0, 3333};
    buckets_s2_reader *r = buckets_s2_reader_new(mem_read, &ss, false);
    size_t dlen;
    uint8_t *dec = drain(buckets_s2_reader_read, r, &dlen);
    assert_non_null(dec);
    assert_int_equal(dlen, n);
    assert_memory_equal(dec, data, n);
    buckets_s2_reader_free(r);
    buckets_buf_free(&idx);
    buckets_s2_writer_free(&w);
    free(dec), free(st), free(data);
  }
}

static void test_reader_other_encoders(void **state) {
  (void)state;
  for (size_t v = 0; v < sizeof(s2_dec_vectors) / sizeof(s2_dec_vectors[0]); v++) {
    size_t n = s2_dec_vectors[v].n;
    uint8_t *data = gen(s2_dec_vectors[v].kind, n, s2_dec_vectors[v].seed);
    mem_src ss = {(const uint8_t *)s2_dec_vectors[v].stream, s2_dec_vectors[v].len, 0, 0};
    buckets_s2_reader *r = buckets_s2_reader_new(mem_read, &ss, false);
    size_t dlen;
    uint8_t *dec = drain(buckets_s2_reader_read, r, &dlen);
    assert_non_null(dec);
    assert_int_equal(dlen, n);
    assert_memory_equal(dec, data, n);
    buckets_s2_reader_free(r);
    /* skip */
    ss.pos = 0;
    r = buckets_s2_reader_new(mem_read, &ss, false);
    assert_true(buckets_s2_reader_skip(r, (int64_t)n / 3));
    uint8_t *rest = drain(buckets_s2_reader_read, r, &dlen);
    assert_int_equal(dlen, n - n / 3);
    assert_memory_equal(rest, data + n / 3, dlen);
    assert_false(buckets_s2_reader_skip(r, 1));
    buckets_s2_reader_free(r);
    free(rest), free(dec), free(data);
  }
}

static void test_index_find(void **state) {
  (void)state;
  const size_t v = 6; /* the 9 MiB vector */
  buckets_s2_index x = {0};
  assert_true(buckets_s2_index_load(&x, (const uint8_t *)s2_enc_vectors[v].idx, s2_enc_vectors[v].idx_len));
  assert_int_equal(x.total_uncompressed, (int64_t)s2_enc_vectors[v].n);
  for (size_t i = 0; i < sizeof(s2_find_vectors) / sizeof(s2_find_vectors[0]); i++) {
    int64_t c, u;
    assert_true(buckets_s2_index_find(&x, s2_find_vectors[i].off, &c, &u));
    assert_int_equal(c, s2_find_vectors[i].comp);
    assert_int_equal(u, s2_find_vectors[i].uncomp);
  }
  int64_t c, u;
  assert_false(buckets_s2_index_find(&x, (int64_t)s2_enc_vectors[v].n + 1, &c, &u));
  buckets_s2_index_free(&x);
}

static void test_padding_concat_and_corruption(void **state) {
  (void)state;
  size_t n = 300000;
  uint8_t *data = gen(1, n, 99);
  /* two padded streams back to back, as a two-part encrypted object stores them */
  buckets_buf both = BUCKETS_BUF_INIT;
  for (int part = 0; part < 2; part++) {
    mem_src src = {data + part * (n / 2), n / 2, 0, 0};
    buckets_s2_writer w;
    buckets_s2_writer_init(&w, mem_read, &src, (int64_t)(n / 2), 256);
    size_t len;
    uint8_t *st = drain(buckets_s2_writer_read, &w, &len);
    assert_int_equal(len % 256, 0);
    buckets_buf_append(&both, st, len);
    buckets_buf idx = BUCKETS_BUF_INIT;
    assert_false(buckets_s2_writer_index(&w, 8 << 20, &idx));
    buckets_s2_writer_free(&w);
    free(st);
  }
  mem_src ss = {(uint8_t *)both.data, both.len, 0, 1000};
  buckets_s2_reader *r = buckets_s2_reader_new(mem_read, &ss, false);
  size_t dlen;
  uint8_t *dec = drain(buckets_s2_reader_read, r, &dlen);
  assert_int_equal(dlen, n);
  assert_memory_equal(dec, data, n);
  buckets_s2_reader_free(r);
  free(dec);
  /* a flipped byte fails the CRC or the decode */
  ((uint8_t *)both.data)[5000] ^= 0x40;
  ss.pos = 0;
  r = buckets_s2_reader_new(mem_read, &ss, false);
  assert_null(drain(buckets_s2_reader_read, r, &dlen));
  buckets_s2_reader_free(r);
  /* starting at a chunk needs ignore_stream_id */
  ((uint8_t *)both.data)[5000] ^= 0x40;
  mem_src mid = {(uint8_t *)both.data + BUCKETS_S2_MAGIC_LEN, both.len - BUCKETS_S2_MAGIC_LEN, 0, 0};
  r = buckets_s2_reader_new(mem_read, &mid, false);
  assert_null(drain(buckets_s2_reader_read, r, &dlen));
  buckets_s2_reader_free(r);
  mid.pos = 0;
  r = buckets_s2_reader_new(mem_read, &mid, true);
  dec = drain(buckets_s2_reader_read, r, &dlen);
  assert_int_equal(dlen, n);
  buckets_s2_reader_free(r);
  free(dec);
  /* a short body fails the writer */
  mem_src src = {data, 1000, 0, 0};
  buckets_s2_writer w;
  buckets_s2_writer_init(&w, mem_read, &src, 2000, 0);
  assert_null(drain(buckets_s2_writer_read, &w, &dlen));
  buckets_s2_writer_free(&w);
  /* an empty stream is empty */
  src = (mem_src){data, 0, 0, 0};
  buckets_s2_writer_init(&w, mem_read, &src, -1, 256);
  uint8_t *e = drain(buckets_s2_writer_read, &w, &dlen);
  assert_int_equal(dlen, 0);
  free(e);
  buckets_s2_writer_free(&w);
  buckets_buf_free(&both);
  free(data);
}

static void test_blocks(void **state) {
  (void)state;
  for (size_t n = 0; n < 5000; n += 37) {
    uint8_t *data = gen((int)(n % 5), n, n);
    uint8_t *enc = malloc(buckets_s2_max_encoded_len(n) + 1), *dec = malloc(n + 1);
    size_t k = buckets_s2_encode(enc, data, n);
    assert_true(k <= buckets_s2_max_encoded_len(n));
    assert_int_equal(buckets_s2_decode(dec, n, enc, k), (long)n);
    assert_memory_equal(dec, data, n);
    if (n) assert_int_equal(buckets_s2_decode(dec, n - 1, enc, k), -1);
    /* truncations never crash */
    for (size_t t = 0; t < k; t += 1 + k / 13) (void)buckets_s2_decode(dec, n, enc, t);
    free(enc), free(dec), free(data);
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_writer_matches_go), cmocka_unit_test(test_reader_other_encoders),
                                     cmocka_unit_test(test_index_find), cmocka_unit_test(test_padding_concat_and_corruption),
                                     cmocka_unit_test(test_blocks)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
