/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* S2 decoding of untrusted bytes: blocks, streams (with skips) and indexes
 * must fail cleanly, and what decodes must re-encode and round-trip. */
#include <stdlib.h>
#include <string.h>

#include "compress/s2.h"

typedef struct {
  const uint8_t *p;
  size_t n, pos;
} src;

static long src_read(void *ud, void *buf, size_t n) {
  src *s = ud;
  size_t k = s->n - s->pos < n ? s->n - s->pos : n;
  if (k > 97) k = 97; /* short reads, to cross chunk boundaries */
  memcpy(buf, s->p + s->pos, k);
  s->pos += k;
  return (long)k;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* a block */
  uint8_t *out = malloc(1 << 16);
  long n = buckets_s2_decode(out, 1 << 16, data, size);
  if (n >= 0) {
    uint8_t *enc = malloc(buckets_s2_max_encoded_len((size_t)n)), *back = malloc((size_t)n + 1);
    size_t k = buckets_s2_encode(enc, out, (size_t)n);
    if (buckets_s2_decode(back, (size_t)n, enc, k) != n || memcmp(back, out, (size_t)n) != 0) abort();
    free(enc);
    free(back);
  }
  /* a stream, with and without a stream identifier, then skipping */
  for (int ignore = 0; ignore < 2; ignore++) {
    src s = {data, size, 0};
    buckets_s2_reader *r = buckets_s2_reader_new(src_read, &s, ignore);
    if (ignore) (void)buckets_s2_reader_skip(r, size % 5000);
    while (buckets_s2_reader_read(r, out, 1 << 16) > 0) {
    }
    buckets_s2_reader_free(r);
  }
  /* an index */
  buckets_s2_index x = {0};
  if (buckets_s2_index_load(&x, data, size)) {
    int64_t c, u;
    (void)buckets_s2_index_find(&x, (int64_t)(size * 1000), &c, &u);
  }
  buckets_s2_index_free(&x);
  free(out);
  return 0;
}
