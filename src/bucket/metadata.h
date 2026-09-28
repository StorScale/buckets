/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_METADATA_H
#define BUCKETS_BUCKET_METADATA_H

#include "core/buf.h"
#include "core/msgpack.h"
#include "storage/drive.h"

/* Per-bucket metadata, byte-compatible with MinIO's BucketMetadata
 * (cmd/bucket-metadata.go): a 4-byte header (format=1, version=1, LE) and a
 * 25-field msgpack map, stored as the object
 * .minio.sys/buckets/<bucket>/.metadata.bin. */

typedef enum {
  BUCKETS_BCFG_POLICY = 0, /* PolicyConfigJSON */
  BUCKETS_BCFG_NOTIFICATION,
  BUCKETS_BCFG_LIFECYCLE,
  BUCKETS_BCFG_OBJECT_LOCK,
  BUCKETS_BCFG_VERSIONING,
  BUCKETS_BCFG_ENCRYPTION,
  BUCKETS_BCFG_TAGGING,
  BUCKETS_BCFG_QUOTA,
  BUCKETS_BCFG_REPLICATION,
  BUCKETS_BCFG_TARGETS,
  BUCKETS_BCFG_TARGETS_META,
  BUCKETS_BCFG__COUNT,
} buckets_bucket_cfg;

/* A Go time.Time: seconds may be BUCKETS_GO_ZERO_TIME_SEC for "unset". */
typedef struct {
  int64_t sec;
  int32_t nsec;
} buckets_gotime;

typedef struct {
  char *name;
  buckets_gotime created;
  bool lock_enabled; /* legacy field, preserved */
  buckets_buf config[BUCKETS_BCFG__COUNT];
  buckets_gotime updated[BUCKETS_BCFG__COUNT];
} buckets_bucket_meta;

void buckets_bucket_meta_init(buckets_bucket_meta *m, const char *name, int64_t created_ns);
void buckets_bucket_meta_free(buckets_bucket_meta *m);
void buckets_bucket_meta_encode(const buckets_bucket_meta *m, buckets_buf *out);
bool buckets_bucket_meta_decode(const void *data, size_t n, buckets_bucket_meta *m);

/* Load/save through the object layer. load returns false when absent/unreadable. */
bool buckets_bucket_meta_load(buckets_drive *d, const char *bucket, buckets_bucket_meta *m);
bool buckets_bucket_meta_save(buckets_drive *d, const buckets_bucket_meta *m);
void buckets_bucket_meta_delete(buckets_drive *d, const char *bucket);
/* Creation time in unix nanoseconds, or 0 when unknown. */
int64_t buckets_bucket_meta_created_ns(const buckets_bucket_meta *m);

#endif
