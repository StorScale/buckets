/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/errors.h"

#include "s3/xml.h"

void buckets_s3_error_xml(buckets_buf *out, buckets_s3_error e, const char *resource, const char *bucket,
                          const char *key, const char *request_id, const char *host_id) {
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  buckets_xml_header(out);
  buckets_xml_open(out, "Error");
  buckets_xml_elem(out, "Code", info->code);
  buckets_xml_elem(out, "Message", info->message);
  if (key && *key) buckets_xml_elem(out, "Key", key);
  if (bucket && *bucket) buckets_xml_elem(out, "BucketName", bucket);
  buckets_xml_elem(out, "Resource", resource);
  buckets_xml_elem(out, "RequestId", request_id);
  buckets_xml_elem(out, "HostId", host_id);
  buckets_xml_close(out, "Error");
}
