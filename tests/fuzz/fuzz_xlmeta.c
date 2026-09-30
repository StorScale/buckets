/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* xl.meta from a drive: parsing must fail cleanly, and what parses must
 * serialize to bytes that parse again to the same serialization. Object
 * versions must decode or fail cleanly, and what decodes must re-encode. */
#include <stdlib.h>
#include <string.h>

#include "storage/xlmeta.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  buckets_xlmeta x = {0};
  if (buckets_xlmeta_parse(data, size, &x) != BUCKETS_XL_OK) {
    buckets_xlmeta_free(&x);
    return 0;
  }
  for (size_t i = 0; i < x.n; i++) {
    buckets_xl_object o = {0};
    if (x.versions[i].hdr.type == BUCKETS_XL_TYPE_OBJECT && buckets_xl_object_decode(&x.versions[i], &o) == BUCKETS_XL_OK) {
      buckets_buf meta = BUCKETS_BUF_INIT;
      buckets_xl_header hdr;
      buckets_xl_object_encode(&o, &meta, &hdr);
      buckets_xl_version v = {hdr, (uint8_t *)meta.data, meta.len};
      buckets_xl_object o2 = {0};
      if (buckets_xl_object_decode(&v, &o2) != BUCKETS_XL_OK) abort();
      buckets_xl_object_free(&o2);
      buckets_buf_free(&meta);
    }
    buckets_xl_object_free(&o);
    (void)buckets_xlmeta_find(&x, x.versions[i].hdr.version_id);
  }
  buckets_str s;
  (void)buckets_xlmeta_inline_get(&x, "null", &s);
  buckets_buf a = BUCKETS_BUF_INIT, b = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(&x, &a);
  buckets_xlmeta y = {0};
  if (buckets_xlmeta_parse(a.data, a.len, &y) != BUCKETS_XL_OK) abort();
  buckets_xlmeta_serialize(&y, &b);
  if (a.len != b.len || memcmp(a.data, b.data, a.len) != 0) abort();
  buckets_xlmeta_free(&y);
  buckets_buf_free(&a);
  buckets_buf_free(&b);
  buckets_xlmeta_free(&x);
  return 0;
}
