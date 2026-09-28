/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OBJECT_EPOOL_H
#define BUCKETS_OBJECT_EPOOL_H

#include "object/object.h"

/* One server pool: erasure sets over its drives (MinIO's erasureSets). The
 * public buckets_obj_* API (object/pools.c) routes each call to one or all
 * pools; everything below operates within a single pool. Namespace locks and
 * the degraded hook are shared through `top`. */
typedef struct buckets_epool {
  struct buckets_objlayer *top;
  size_t index;
  buckets_eset *sets;
  size_t nsets;
  uint8_t deployment_id[16];
  char deployment_id_str[BUCKETS_UUID_STR_LEN + 1];
  buckets_drive **all; /* every slot, set-major */
  size_t nall;
} buckets_epool;

buckets_epool *buckets_epool_new(struct buckets_objlayer *top, size_t index, buckets_format_result *f, int parity);
void buckets_epool_free(buckets_epool *P);
size_t buckets_ep_online(const buckets_epool *P);
buckets_eset *buckets_ep_set_for(buckets_epool *P, const char *object);

buckets_obj_err buckets_ep_make_bucket(buckets_epool *P, const char *bucket);
buckets_obj_err buckets_ep_stat_bucket(buckets_epool *P, const char *bucket);
buckets_obj_err buckets_ep_delete_bucket(buckets_epool *P, const char *bucket);
buckets_obj_err buckets_ep_list_buckets(buckets_epool *P, buckets_bucket_info **out, size_t *n);

buckets_obj_err buckets_ep_put(buckets_epool *P, const char *bucket, const char *object, buckets_read_fn rd, void *rd_ud,
                               int64_t size, const buckets_put_opts *opts, buckets_object_info *out);
buckets_obj_err buckets_ep_stat(buckets_epool *P, const char *bucket, const char *object, const char *version_id,
                                buckets_object_info *out);
buckets_obj_err buckets_ep_open(buckets_epool *P, const char *bucket, const char *object, const char *version_id,
                                int64_t offset, int64_t length, buckets_obj_reader **out, buckets_object_info *info);
buckets_obj_err buckets_ep_delete(buckets_epool *P, const char *bucket, const char *object, const char *version_id);
buckets_obj_err buckets_ep_delete_ex(buckets_epool *P, const char *bucket, const char *object,
                                     const buckets_delete_opts *opts, buckets_delete_result *res);
buckets_obj_err buckets_ep_update_meta(buckets_epool *P, const char *bucket, const char *object,
                                       const char *version_id, buckets_meta_edit_fn fn, void *ud,
                                       buckets_object_info *out);
buckets_obj_err buckets_ep_list_versions(buckets_epool *P, const char *bucket, const char *prefix,
                                         const char *key_marker, const char *version_marker, const char *delimiter,
                                         int max_keys, buckets_obj_listing *out);
buckets_obj_err buckets_ep_list(buckets_epool *P, const char *bucket, const char *prefix, const char *marker,
                                const char *delimiter, int max_keys, buckets_obj_listing *out);
buckets_obj_err buckets_ep_heal(buckets_epool *P, const char *bucket, const char *object, const char *version_id,
                                const buckets_heal_opts *opts, buckets_heal_result *res);
size_t buckets_ep_heal_bucket(buckets_epool *P, const char *bucket);

buckets_obj_err buckets_ep_mpu_new(buckets_epool *P, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                   size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]);
buckets_obj_err buckets_ep_mpu_put_part(buckets_epool *P, const char *bucket, const char *object, const char *upload_id,
                                        int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                        const buckets_put_opts *opts, buckets_part_info *out);
buckets_obj_err buckets_ep_mpu_list_parts(buckets_epool *P, const char *bucket, const char *object,
                                          const char *upload_id, int marker, int max, buckets_part_info **parts,
                                          size_t *nparts, bool *truncated);
buckets_obj_err buckets_ep_mpu_abort(buckets_epool *P, const char *bucket, const char *object, const char *upload_id);
buckets_obj_err buckets_ep_mpu_complete(buckets_epool *P, const char *bucket, const char *object,
                                        const char *upload_id, const buckets_complete_part *parts, size_t nparts,
                                        const buckets_checksum *want, bool versioned, buckets_object_info *out);
buckets_obj_err buckets_ep_mpu_list_uploads(buckets_epool *P, const char *bucket, const char *object,
                                            buckets_upload_info **uploads, size_t *n);

#endif
