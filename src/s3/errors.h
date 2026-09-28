/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_ERRORS_H
#define BUCKETS_S3_ERRORS_H

#include "core/buf.h"
#include "s3/errors_gen.h"

typedef struct {
  const char *code;
  const char *message;
  int status;
} buckets_s3_error_info;

extern const buckets_s3_error_info buckets_s3_errors[BUCKETS_ERR__COUNT];

static inline const buckets_s3_error_info *buckets_s3_error_get(buckets_s3_error e) {
  return &buckets_s3_errors[e];
}

/* Serializes an S3 <Error> document. bucket/key may be NULL. */
void buckets_s3_error_xml(buckets_buf *out, buckets_s3_error e, const char *resource, const char *bucket,
                          const char *key, const char *request_id, const char *host_id);

#endif
