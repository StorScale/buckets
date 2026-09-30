/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The msgpack reader under internode messages and xl.meta: walking a value
 * with the typed readers must end where skipping it does, and neither may
 * read past the input. */
#include <stdlib.h>
#include <string.h>

#include "core/msgpack.h"

static bool walk(buckets_mp_reader *r, int depth) {
  if (depth > 64) return false;
  uint32_t n;
  buckets_str s;
  int64_t i;
  uint64_t u;
  double f;
  bool b;
  switch (buckets_mp_peek(r)) {
  case BUCKETS_MP_NIL: return buckets_mp_read_nil(r);
  case BUCKETS_MP_BOOL: return buckets_mp_read_bool(r, &b);
  case BUCKETS_MP_INT: {
    buckets_mp_reader c = *r;
    if (buckets_mp_read_int(&c, &i)) {
      *r = c;
      return true;
    }
    return buckets_mp_read_uint(r, &u);
  }
  case BUCKETS_MP_FLOAT: return buckets_mp_read_float64(r, &f);
  case BUCKETS_MP_STR: return buckets_mp_read_str(r, &s);
  case BUCKETS_MP_BIN: return buckets_mp_read_bin(r, &s);
  case BUCKETS_MP_ARRAY:
    if (!buckets_mp_read_array(r, &n)) return false;
    for (uint32_t k = 0; k < n; k++)
      if (!walk(r, depth + 1)) return false;
    return true;
  case BUCKETS_MP_MAP:
    if (!buckets_mp_read_map(r, &n)) return false;
    for (uint32_t k = 0; k < n; k++)
      if (!walk(r, depth + 1) || !walk(r, depth + 1)) return false;
    return true;
  case BUCKETS_MP_EXT: {
    buckets_mp_reader c = *r;
    int64_t ns;
    if (buckets_mp_read_time(&c, &ns)) {
      *r = c;
      return true;
    }
    return buckets_mp_skip(r);
  }
  default: return false;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* a copy of exactly size bytes, so reading past it is caught */
  uint8_t *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  buckets_mp_reader a = buckets_mp_reader_init(buf, size), b = a;
  while (buckets_mp_remaining(&a) > 0) {
    bool wa = walk(&a, 0), sb = buckets_mp_skip(&b);
    if (wa && (!sb || a.p != b.p)) abort(); /* walked a value that skip could not */
    if (!wa || !sb) break;
  }
  free(buf);
  return 0;
}
