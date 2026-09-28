/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_DRIVE_H
#define BUCKETS_STORAGE_DRIVE_H

#include <time.h>

#include "core/buf.h"
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
/* Opens a drive without touching format.json (multi-drive formats are
 * negotiated across all drives by storage/format.c). */
buckets_drive_err buckets_drive_open_raw(const char *path, buckets_drive **out);
void buckets_drive_close(buckets_drive *d);

buckets_drive_err buckets_drive_make_vol(buckets_drive *d, const char *name);
buckets_drive_err buckets_drive_stat_vol(buckets_drive *d, const char *name, time_t *created);
buckets_drive_err buckets_drive_delete_vol(buckets_drive *d, const char *name);
/* Lists top-level volumes, excluding dot-directories, sorted by name. */
buckets_drive_err buckets_drive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n);
void buckets_vol_info_free(buckets_vol_info *vols, size_t n);

/* ---- StorageAPI: file operations relative to a volume --------------------
 * These mirror MinIO's StorageAPI calls one-to-one so a remote drive can
 * implement the same surface over internode RPC. */

buckets_drive_err buckets_drive_read_all(buckets_drive *d, const char *vol, const char *path, buckets_buf *out);
/* Atomic replace via .minio.sys/tmp + rename + fsync. Creates parent dirs. */
buckets_drive_err buckets_drive_write_all(buckets_drive *d, const char *vol, const char *path, const void *data,
                                          size_t n);

typedef struct buckets_drive_writer buckets_drive_writer;
/* Streams a new file (parents created); nothing is visible until committed
 * by a later rename. */
buckets_drive_err buckets_drive_create_file(buckets_drive *d, const char *vol, const char *path,
                                            buckets_drive_writer **w);
buckets_drive_err buckets_drive_writer_write(buckets_drive_writer *w, const void *data, size_t n);
/* Flushes to stable storage and closes. */
buckets_drive_err buckets_drive_writer_close(buckets_drive_writer *w);
void buckets_drive_writer_abort(buckets_drive_writer *w);

/* Reads up to n bytes at off; *got < n only at end of file. */
buckets_drive_err buckets_drive_read_at(buckets_drive *d, const char *vol, const char *path, int64_t off, void *buf,
                                        size_t n, size_t *got);

/* RenameData: moves <src_vol>/<src_dir>/<data_dir> (if data_dir is non-NULL)
 * to <dst_vol>/<dst_path>/<data_dir>, then atomically writes xl.meta there. */
buckets_drive_err buckets_drive_rename_data(buckets_drive *d, const char *src_vol, const char *src_dir,
                                            const char *data_dir, const char *dst_vol, const char *dst_path,
                                            const void *xlmeta, size_t xlmeta_len);

/* Renames a single file (parents of dst created). */
buckets_drive_err buckets_drive_rename_file(buckets_drive *d, const char *src_vol, const char *src,
                                            const char *dst_vol, const char *dst);

/* Removes a file or (recursive) directory; with prune, also removes empty
 * parent directories up to the volume root. */
buckets_drive_err buckets_drive_delete(buckets_drive *d, const char *vol, const char *path, bool recursive,
                                       bool prune);

typedef struct {
  char **names; /* directories end in '/' */
  size_t n;
} buckets_dir_list;
buckets_drive_err buckets_drive_list_dir(buckets_drive *d, const char *vol, const char *dir, buckets_dir_list *out);
void buckets_dir_list_free(buckets_dir_list *l);

/* 0 = missing, 1 = file, 2 = directory */
int buckets_drive_stat(buckets_drive *d, const char *vol, const char *path);

/* A unique path under .minio.sys/tmp for staging (caller frees). */
char *buckets_drive_tmp_name(void);

#endif
