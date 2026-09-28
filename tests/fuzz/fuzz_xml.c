/* Fuzzes the request XML reader and entity unescaping.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdint.h>

#include "s3/xml.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  buckets_xml_doc doc;
  if (!buckets_xml_parse((buckets_str){(const char *)data, size}, &doc)) return 0;
  buckets_buf out = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < doc.count; i++) {
    buckets_xml_unescape(doc.nodes[i].text, &out);
    buckets_buf_reset(&out);
    buckets_xml_child(&doc, i, "Key");
  }
  buckets_buf_free(&out);
  buckets_xml_doc_free(&doc);
  return 0;
}
