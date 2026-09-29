/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SCANNER_SCANTRACE_H
#define BUCKETS_SCANNER_SCANTRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "object/object.h"

/* The scanner's trace records (mc admin trace --call scanner), as MinIO's
 * scanner writes them: scanner.ScanCycle for each cycle, and for each
 * bucket walked scanner.ScanObject (drive, <bucket>/<key>/xl.meta, the
 * metadata size, size, versions), scanner.CompactFolder and
 * scanner.ScanFolder (type new or existing) for every folder level, closing
 * children before parents, and scanner.ScanBucketDrive. Our scanner walks
 * listings rather than drives, so the drive reported is the first online
 * drive of the key's set, and every folder is visited every cycle. */

typedef struct buckets_scantrace buckets_scantrace;

/* Folders seen while tracing, kept across cycles for "existing". */
buckets_scantrace *buckets_scantrace_new(void);
void buckets_scantrace_free(buckets_scantrace *t);

void buckets_scantrace_cycle(uint64_t cycle, int64_t start_ns);

/* A bucket walk: begin (false when nobody traces the scanner), one call per
 * key in listing order, then end. */
bool buckets_scantrace_bucket_begin(buckets_scantrace *t, buckets_objlayer *L, const char *bucket);
void buckets_scantrace_key(buckets_scantrace *t, const char *key, int64_t start_ns, uint64_t size, uint64_t versions);
void buckets_scantrace_bucket_end(buckets_scantrace *t);
/* The end of a cycle: this cycle's folders become the previous ones. */
void buckets_scantrace_cycle_done(buckets_scantrace *t);

#endif
