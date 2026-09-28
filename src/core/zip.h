/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_ZIP_H
#define BUCKETS_CORE_ZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "core/buf.h"

/* Zip archives in memory: what Go's archive/zip writes (deflated entries,
 * a central directory) and what it reads back (stored or deflated,
 * ZIP64 not needed for configuration exports). */

typedef struct {
  buckets_buf out;
  buckets_buf central;
  size_t count;
} buckets_zip_writer;

void buckets_zip_writer_init(buckets_zip_writer *w);
/* Adds a deflated file. */
void buckets_zip_add(buckets_zip_writer *w, const char *name, const void *data, size_t len, time_t mtime);
/* Finishes the archive; the bytes are in w->out (w->central is freed). */
void buckets_zip_finish(buckets_zip_writer *w);
void buckets_zip_writer_free(buckets_zip_writer *w);

typedef struct {
  const unsigned char *data;
  size_t len;
  size_t cd_off, cd_count;
} buckets_zip_reader;

/* false when data is not a zip archive. */
bool buckets_zip_open(buckets_zip_reader *r, const void *data, size_t len);
typedef enum { BUCKETS_ZIP_OK = 0, BUCKETS_ZIP_NOT_FOUND, BUCKETS_ZIP_CORRUPT } buckets_zip_status;
/* Reads the named file into out (replacing its content). */
buckets_zip_status buckets_zip_read(const buckets_zip_reader *r, const char *name, buckets_buf *out);

#endif
