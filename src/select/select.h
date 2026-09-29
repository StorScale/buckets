/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SELECT_SELECT_H
#define BUCKETS_SELECT_SELECT_H

/* S3 Select (SelectObjectContent): MinIO's internal/s3select. A request is
 * parsed, opened on the object's plaintext, and then pulled as an AWS event
 * stream (Records, Cont, Progress, Stats, End or an error message). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "s3/xml.h"

typedef struct {
  const char *code; /* NULL: none */
  char msg[512];
  int status;
} buckets_select_err;

/* The object's plaintext: a sequential reader opened at an offset, and
 * random access for Parquet. */
typedef struct {
  void *ud;
  /* opens the plaintext from off to the end; false on failure */
  bool (*open)(void *ud, int64_t off);
  long (*read)(void *ud, void *buf, size_t n); /* after open: 0 at the end, -1 on failure */
  bool (*read_at)(void *ud, int64_t off, void *buf, size_t n);
  int64_t size;
} buckets_select_source;

typedef struct buckets_select buckets_select;

/* The request document; parquet: MINIO_API_SELECT_PARQUET is on. */
buckets_select *buckets_select_parse(const char *xml, size_t n, bool parquet, buckets_select_err *e);
/* The same request under a parsed document's node (a restore's SelectParameters). */
buckets_select *buckets_select_parse_node(const buckets_xml_doc *doc, size_t node, bool parquet, buckets_select_err *e);
void buckets_select_free(buckets_select *s);
/* Opens the input and makes the checks MinIO makes before it answers (the
 * CSV header, the first block's encoding, the compression header). The
 * source is not owned and must outlive s. */
bool buckets_select_open(buckets_select *s, const buckets_select_source *src, buckets_select_err *e);
/* The event stream, pulled: bytes (0 at the end). */
long buckets_select_read(void *s, void *buf, size_t n);

#endif
