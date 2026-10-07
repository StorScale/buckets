/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SCANNER_COMPLIANCE_H
#define BUCKETS_SCANNER_COMPLIANCE_H

/* What the compliance reports count (docs/design/compliance-reports.md): per bucket, the versions and bytes
 * by encryption, under retention and under legal hold. The scanner adds every version it keeps on each cycle,
 * and the leader stores the cycle's figures in .minio.sys/buckets/compliance.json, beside MinIO's own
 * .usage.json (which stays exactly as MinIO writes it). */

#include <stdbool.h>
#include <stdint.h>

#include "core/buf.h"
#include "object/object.h"

#define BUCKETS_COMPLIANCE_PATH "buckets/compliance.json"

typedef struct {
  uint64_t versions, bytes;
} buckets_compliance_count;

typedef struct {
  buckets_compliance_count sse_s3, sse_kms, sse_c, plain; /* every version but delete markers */
  buckets_compliance_count governance, compliance;        /* retention in force now, by mode */
  buckets_compliance_count legal_hold;
  int64_t latest_until; /* the furthest retain-until in force (unix seconds), 0 when none */
} buckets_compliance_counts;

/* One version, size bytes (as usage counts them), at now (unix seconds). Delete markers count nowhere. */
void buckets_compliance_add(buckets_compliance_counts *c, const buckets_object_info *v, int64_t size,
                            int64_t now);

/* A cycle's figures: {"scannedAt": unix seconds, "buckets": {"<name>": {...}}}. */
typedef struct {
  char *name;
  buckets_compliance_counts c;
} buckets_compliance_bucket;
void buckets_compliance_json(const buckets_compliance_bucket *b, size_t n, int64_t scanned_at,
                             buckets_buf *out);
/* The counts of bucket in a stored document; false when it has none. */
bool buckets_compliance_lookup(const char *json, size_t len, const char *bucket,
                               buckets_compliance_counts *out, int64_t *scanned_at);

#endif
