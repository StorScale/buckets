/* Helpers shared by the single-drive object layer's translation units.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OBJECT_INTERNAL_H
#define BUCKETS_OBJECT_INTERNAL_H

#include "core/buf.h"
#include "object/object.h"

typedef enum { BUCKETS_OBJX_LOAD_OK, BUCKETS_OBJX_LOAD_MISSING, BUCKETS_OBJX_LOAD_ERR } buckets_objx_load_result;

int64_t buckets_objx_now_ns(void);
char *buckets_objx_object_dir(buckets_drive *d, const char *bucket, const char *object);
char *buckets_objx_tmp_path(buckets_drive *d);
bool buckets_objx_is_file(const char *path);
bool buckets_objx_bucket_exists(buckets_drive *d, const char *bucket);
void buckets_objx_rm_rf(const char *path);
int buckets_objx_mkdir_all(const char *path);
void buckets_objx_fsync_path(const char *path);
bool buckets_objx_write_full(int fd, const void *p, size_t n);
buckets_obj_err buckets_objx_write_xlmeta(buckets_drive *d, const char *dir, const buckets_xlmeta *x);
buckets_objx_load_result buckets_objx_load_xlmeta(const char *dir, buckets_xlmeta *x);
void buckets_objx_fill_info(buckets_object_info *oi, const char *name, const buckets_xl_object *o);
buckets_obj_err buckets_objx_pick_version(const buckets_xlmeta *x, const char *version_id, buckets_xl_object *o);
buckets_obj_err buckets_objx_check_namespace(buckets_drive *d, const char *bucket, const char *object);

void buckets_objx_new_data_dir(uint8_t id[16], char str[37]);
void buckets_objx_init_version(buckets_xl_object *o, const uint8_t data_dir[16], int64_t size);

/* Streams `size` bytes from rd into either an inline shard (when allowed and
 * small) or <tmp_dir>/<data_dir>/part.<part_number>, bitrot-framed, enforcing
 * the digests in opts. */
buckets_obj_err buckets_objx_write_data(buckets_drive *d, buckets_read_fn rd, void *rd_ud, int64_t size,
                                       const buckets_put_opts *opts, bool allow_inline, const char *tmp_dir,
                                       const char *data_dir, int part_number, buckets_buf *inline_shard,
                                       uint8_t md5_out[16], buckets_checksum *cksum_out);

/* Installs version o for bucket/object: moves src_data_dir (if any) into the
 * object directory, writes xl.meta, and removes a replaced version's data. */
buckets_obj_err buckets_objx_commit(buckets_drive *d, const char *bucket, const char *object, const buckets_xl_object *o,
                                    const buckets_buf *inline_shard, const char *src_data_dir,
                                    buckets_object_info *out);

#endif
