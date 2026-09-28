/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_REMOTE_H
#define BUCKETS_STORAGE_REMOTE_H

#include "net/client.h"
#include "storage/drive.h"

/* A drive on another node, reached over internode RPC (dist/storage_server.c
 * serves the other end). buckets_drive_* dispatches here when d->remote is
 * set, so the object layer cannot tell local and remote drives apart.
 *
 * A remote drive that stops answering is marked offline for a moment, so
 * calls fail fast instead of each waiting out a connect timeout. */

/* peer is shared by every drive of the node and must outlive them.
 * disk_path is the drive's path on the peer; endpoint labels it in logs. */
buckets_drive *buckets_drive_open_remote(buckets_http_client *peer, const char *disk_path, const char *endpoint);
bool buckets_drive_is_online(buckets_drive *d);

struct buckets_rwriter;
buckets_drive_writer *buckets_drive_writer_wrap_remote(struct buckets_rwriter *rw);

/* Implementations behind buckets_drive_* (not for direct use). */
void buckets_rdrive_free(struct buckets_remote *r);
buckets_drive_err buckets_rdrive_make_vol(buckets_drive *d, const char *name);
buckets_drive_err buckets_rdrive_stat_vol(buckets_drive *d, const char *name, time_t *created);
buckets_drive_err buckets_rdrive_delete_vol(buckets_drive *d, const char *name);
buckets_drive_err buckets_rdrive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n);
buckets_drive_err buckets_rdrive_read_all(buckets_drive *d, const char *vol, const char *path, buckets_buf *out);
buckets_drive_err buckets_rdrive_write_all(buckets_drive *d, const char *vol, const char *path, const void *data, size_t n);
buckets_drive_err buckets_rdrive_create_file(buckets_drive *d, const char *vol, const char *path, buckets_drive_writer **w);
buckets_drive_err buckets_rdrive_append(buckets_drive *d, const char *vol, const char *path, int64_t off, const void *data,
                                        size_t n);
buckets_drive_err buckets_rdrive_fsync_file(buckets_drive *d, const char *vol, const char *path);
buckets_drive_err buckets_rdrive_read_at(buckets_drive *d, const char *vol, const char *path, int64_t off, void *buf,
                                         size_t n, size_t *got);
buckets_drive_err buckets_rdrive_rename_data(buckets_drive *d, const char *src_vol, const char *src_dir,
                                             const char *data_dir, const char *dst_vol, const char *dst_path,
                                             const void *xlmeta, size_t xlmeta_len);
buckets_drive_err buckets_rdrive_rename_file(buckets_drive *d, const char *src_vol, const char *src, const char *dst_vol,
                                             const char *dst);
buckets_drive_err buckets_rdrive_delete(buckets_drive *d, const char *vol, const char *path, bool recursive, bool prune);
buckets_drive_err buckets_rdrive_list_dir(buckets_drive *d, const char *vol, const char *dir, buckets_dir_list *out);
buckets_drive_err buckets_rdrive_disk_info(buckets_drive *d, uint64_t *total, uint64_t *free_bytes);
buckets_drive_err buckets_rdrive_file_size(buckets_drive *d, const char *vol, const char *path, int64_t *size);
int buckets_rdrive_stat(buckets_drive *d, const char *vol, const char *path);
buckets_drive_err buckets_rwriter_write(struct buckets_rwriter *w, const void *data, size_t n);
buckets_drive_err buckets_rwriter_close(struct buckets_rwriter *w);
void buckets_rwriter_abort(struct buckets_rwriter *w);

#endif
