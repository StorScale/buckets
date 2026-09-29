/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_ZIPINDEX_H
#define BUCKETS_S3_ZIPINDEX_H

/* The index of a zip object's files, as github.com/minio/zipindex builds and
 * serializes it (MinIO keeps it in x-minio-internal-archive-info), so either
 * server reads what the other stored. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

typedef struct {
  char *name;
  size_t name_len;
  uint64_t csize, usize;
  int64_t offset; /* of the local file header */
  uint32_t crc;
  uint16_t method, flags;
} buckets_zipfile;

typedef struct {
  buckets_zipfile *f;
  size_t n;
} buckets_zipfiles;

void buckets_zipfiles_free(buckets_zipfiles *z);

typedef enum { BUCKETS_ZIP_DIR_OK, BUCKETS_ZIP_DIR_MORE, BUCKETS_ZIP_DIR_BAD } buckets_zip_dir_status;
/* zipindex.ReadDir over the archive's last n bytes (size: the whole
 * archive): its regular files with a method we can read (store, deflate,
 * zstd). MORE: *need bytes from the end are needed. */
buckets_zip_dir_status buckets_zipindex_read_dir(const uint8_t *buf, size_t n, int64_t size, buckets_zipfiles *out,
                                                 int64_t *need, char *err, size_t errcap);
/* Files.OptimizeSize: by offset, CRCs dropped where a data descriptor has them. */
void buckets_zipindex_optimize(buckets_zipfiles *z);
/* Files.Serialize, and DeserializeFiles (any of its four versions). */
void buckets_zipindex_serialize(const buckets_zipfiles *z, buckets_buf *out);
bool buckets_zipindex_deserialize(const uint8_t *p, size_t n, buckets_zipfiles *out);
/* A file by name, or NULL. */
const buckets_zipfile *buckets_zipindex_find(const buckets_zipfiles *z, const char *name, size_t n);

/* File.Open: reads the local header and yields the file's contents, with its
 * CRC checked at the end. The source reads the archive from f->offset. */
typedef long (*buckets_zip_read_fn)(void *ud, void *buf, size_t n);
typedef struct buckets_zip_reader buckets_zip_reader;
buckets_zip_reader *buckets_zip_reader_new(const buckets_zipfile *f, buckets_zip_read_fn rd, void *ud);
void buckets_zip_reader_free(buckets_zip_reader *r);
/* Bytes (0 at the end, -1 on a format, decompression or checksum error). */
long buckets_zip_reader_read(void *r, void *buf, size_t n);

#endif
