/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_QUOTA_H
#define BUCKETS_BUCKET_QUOTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* madmin.BucketQuota: the bucket metadata's QuotaConfigJSON. Only "hard"
 * quotas exist; `quota` is the deprecated spelling of `size`. */
typedef struct {
  uint64_t quota, size, rate, requests;
  char type[16]; /* "" or "hard" (anything else is kept, and only rejected when quota > 0) */
} buckets_quota;

/* parseBucketQuota: JSON with Go's decoding rules (case-insensitive keys,
 * unknown keys ignored, "null" is the empty quota). err gets the reason. */
bool buckets_quota_parse(const char *json, size_t len, buckets_quota *out, char *err, size_t errlen);
/* json.Marshal(quota). */
void buckets_quota_json(const buckets_quota *q, buckets_buf *out);
/* The hard limit in bytes, or 0 for none. */
uint64_t buckets_quota_hard_limit(const buckets_quota *q);
/* enforceQuotaHard: whether writing `size` more bytes to a bucket already
 * holding `used` (0 when unknown) exceeds the quota. */
bool buckets_quota_exceeded(const buckets_quota *q, int64_t size, uint64_t used);

#endif
