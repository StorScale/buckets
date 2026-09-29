/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_COMPRESS_STREAM_H
#define BUCKETS_COMPRESS_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Streaming decompression of what clients upload compressed: gzip (any
 * number of members), bzip2 (concatenated streams too), zstd and LZ4 frames,
 * and S2 or Snappy framed streams, as MinIO's S3 Select and snowball
 * extraction read them. */

typedef enum {
  BUCKETS_DECOMP_NONE = 0,
  BUCKETS_DECOMP_GZIP,
  BUCKETS_DECOMP_BZIP2,
  BUCKETS_DECOMP_ZSTD,
  BUCKETS_DECOMP_LZ4,
  BUCKETS_DECOMP_S2,
  BUCKETS_DECOMP_SNAPPY,
} buckets_decomp_type;

/* How a stream failed: its format is wrong (a bad header, magic or
 * checksum), it ended early, or the source failed. */
typedef enum {
  BUCKETS_DECOMP_ERR_NONE = 0,
  BUCKETS_DECOMP_ERR_FORMAT,
  BUCKETS_DECOMP_ERR_TRUNCATED,
  BUCKETS_DECOMP_ERR_SOURCE,
} buckets_decomp_err;

/* A source: bytes read (0 at the end, -1 on failure). */
typedef long (*buckets_decomp_read_fn)(void *ud, void *buf, size_t n);

typedef struct buckets_decomp buckets_decomp;

/* Reads from src; the source is not owned. */
buckets_decomp *buckets_decomp_new(buckets_decomp_type t, buckets_decomp_read_fn src, void *src_ud);
void buckets_decomp_free(buckets_decomp *d);
/* Plaintext bytes (0 at the end, -1 on failure: see buckets_decomp_error). */
long buckets_decomp_read(void *d, void *buf, size_t n);
buckets_decomp_err buckets_decomp_error(const buckets_decomp *d);
/* The failure as the Go decoders MinIO uses word it ("s2: corrupt input", ...). */
const char *buckets_decomp_message(const buckets_decomp *d);
/* Bytes taken from the source so far. */
int64_t buckets_decomp_consumed(const buckets_decomp *d);

/* Recognizes a stream by its first bytes (NONE when unknown), as MinIO's
 * snowball extraction does. */
buckets_decomp_type buckets_decomp_detect(const uint8_t *p, size_t n);

#endif
