/* Fuzzes SigV4 header and presigned-URL verification. Input layout:
 *   line 1: request-target (path?query)
 *   remaining lines: "Name: value" headers
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdint.h>
#include <string.h>

#include "core/query.h"
#include "s3/sigv4.h"

static const char *lookup(void *ud, buckets_str ak) {
  return buckets_str_eq_c(ak, "AKIAIOSFODNN7EXAMPLE") ? "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" : NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  buckets_http_request req;
  memset(&req, 0, sizeof(req));
  req.method = buckets_str_c("GET");
  buckets_str in = {(const char *)data, size}, line;
  buckets_str_cut(in, '\n', &line, &in);
  req.target = line;
  buckets_str_cut(req.target, '?', &req.path, &req.query);
  while (in.n && req.nheaders < BUCKETS_HTTP_MAX_HEADERS) {
    buckets_str_cut(in, '\n', &line, &in);
    buckets_str name, value;
    if (!buckets_str_cut(line, ':', &name, &value)) continue;
    req.headers[req.nheaders].name = name;
    req.headers[req.nheaders].value = buckets_str_trim(value);
    req.nheaders++;
  }

  buckets_query q;
  buckets_query_parse(req.query, &q);
  buckets_sigv4_config cfg = {.region = "", .service = "s3", .now = 1369353600, .lookup = lookup};
  buckets_sigv4_result res;
  switch (buckets_auth_classify(&req, &q)) {
    case BUCKETS_AUTH_SIGV4_HEADER: buckets_sigv4_verify_header(&cfg, &req, &q, &res); break;
    case BUCKETS_AUTH_SIGV4_PRESIGNED: buckets_sigv4_verify_presigned(&cfg, &req, &q, &res); break;
    default: break;
  }
  buckets_query_free(&q);
  return 0;
}
