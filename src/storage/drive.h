/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_DRIVE_H
#define BUCKETS_STORAGE_DRIVE_H

#include <time.h>

#include "core/common.h"
#include "core/uuid.h"

/* A local drive, laid out like MinIO so existing drives can be adopted:
 *
 *   <root>/.minio.sys/format.json     deployment + drive identity
 *   <root>/.minio.sys/{tmp,buckets,multipart,config}
 *   <root>/<bucket>/...               one directory per bucket ("volume")
 *
 * Replaces the volume half of MinIO's cmd/xl-storage.go. Object data
 * (xl.meta v2 + part files) lands with the erasure object layer. */

#define BUCKETS_META_BUCKET ".minio.sys"

typedef enum {
  BUCKETS_DRIVE_OK = 0,
  BUCKETS_DRIVE_ERR_EXISTS,
  BUCKETS_DRIVE_ERR_NOT_FOUND,
  BUCKETS_DRIVE_ERR_NOT_EMPTY,
  BUCKETS_DRIVE_ERR_CORRUPT,  /* format.json present but unreadable */
  BUCKETS_DRIVE_ERR_FOREIGN,  /* format.json from an unsupported layout */
  BUCKETS_DRIVE_ERR_IO,
} buckets_drive_err;

typedef struct {
  char *root;
  char deployment_id[BUCKETS_UUID_STR_LEN + 1];
  char drive_id[BUCKETS_UUID_STR_LEN + 1];
  bool freshly_formatted;
} buckets_drive;

typedef struct {
  char *name;
  time_t created;
} buckets_vol_info;

const char *buckets_drive_strerror(buckets_drive_err e);

/* Opens (creating and formatting if empty) a single-drive deployment. */
buckets_drive_err buckets_drive_open(const char *path, buckets_drive **out);
void buckets_drive_close(buckets_drive *d);

buckets_drive_err buckets_drive_make_vol(buckets_drive *d, const char *name);
buckets_drive_err buckets_drive_stat_vol(buckets_drive *d, const char *name, time_t *created);
buckets_drive_err buckets_drive_delete_vol(buckets_drive *d, const char *name);
/* Lists top-level volumes, excluding dot-directories, sorted by name. */
buckets_drive_err buckets_drive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n);
void buckets_vol_info_free(buckets_vol_info *vols, size_t n);

#endif
