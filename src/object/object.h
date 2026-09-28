/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OBJECT_OBJECT_H
#define BUCKETS_OBJECT_OBJECT_H

#include "storage/drive.h"
#include "crypto/cksum.h"
#include "storage/xlmeta.h"

/* The object layer. This is the single-drive ("xl-single") implementation,
 * laid out exactly like MinIO so either server can read the other's drive:
 *
 *   <bucket>/<object>/xl.meta                     metadata (+ inline data < 128 KiB)
 *   <bucket>/<object>/<data-dir-uuid>/part.N      bitrot-framed part data
 *   <bucket>/<dir-object>__XLDIR__/xl.meta        keys ending in '/'
 *
 * Part data is framed in 1 MiB blocks, each preceded by its HighwayHash-256
 * (MinIO's streaming bitrot format, EC 1+0). Replaces the single-set path of
 * MinIO's cmd/erasure-object.go + cmd/xl-storage.go. */

#define BUCKETS_BLOCK_SIZE (1024 * 1024)
#define BUCKETS_INLINE_THRESHOLD (128 * 1024)
#define BUCKETS_MAX_OBJECT_NAME 1024
#define BUCKETS_MAX_LIST_KEYS 1000

typedef enum {
  BUCKETS_OBJ_OK = 0,
  BUCKETS_OBJ_ERR_NO_SUCH_BUCKET,
  BUCKETS_OBJ_ERR_NO_SUCH_KEY,
  BUCKETS_OBJ_ERR_NO_SUCH_VERSION,
  BUCKETS_OBJ_ERR_INVALID_NAME,
  BUCKETS_OBJ_ERR_NAME_TOO_LONG,
  BUCKETS_OBJ_ERR_NAME_PREFIX_SLASH,
  BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY, /* also: a parent path is an object */
  BUCKETS_OBJ_ERR_BAD_DIGEST,          /* Content-MD5 mismatch */
  BUCKETS_OBJ_ERR_SHA256_MISMATCH,     /* x-amz-content-sha256 mismatch */
  BUCKETS_OBJ_ERR_INCOMPLETE_BODY,
  BUCKETS_OBJ_ERR_READER,  /* the data source failed (e.g. bad chunk signature) */
  BUCKETS_OBJ_ERR_CORRUPT, /* bitrot or unreadable metadata */
  BUCKETS_OBJ_ERR_IO,
  BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD,
  BUCKETS_OBJ_ERR_INVALID_PART,       /* missing part or ETag mismatch */
  BUCKETS_OBJ_ERR_INVALID_PART_ORDER, /* parts not in ascending order */
  BUCKETS_OBJ_ERR_PART_TOO_SMALL,     /* a non-final part below 5 MiB */
  BUCKETS_OBJ_ERR_BAD_CHECKSUM,       /* x-amz-checksum-* mismatch */
} buckets_obj_err;

const char *buckets_obj_strerror(buckets_obj_err e);

/* Pull-style data source. Returns bytes read, 0 at EOF, -1 on error. */
typedef long (*buckets_read_fn)(void *ud, void *buf, size_t n);

typedef struct {
  char *name;
  char version_id[37];
  int64_t size;
  int64_t mod_time_ns;
  char etag[80];
  buckets_xl_kv *meta; /* user-defined metadata (MinIO MetaUser, incl. content-type) */
  size_t nmeta;
  size_t nparts;
  bool delete_marker;
  uint8_t *checksum; /* stored x-minio-internal-crc bytes, or NULL */
  size_t checksum_len;
  buckets_xl_part *parts; /* numbers and sizes, in object order (etags unset) */
} buckets_object_info;

void buckets_object_info_free(buckets_object_info *oi);
/* Value of a user-metadata key, or NULL. */
const char *buckets_object_meta(const buckets_object_info *oi, const char *key);

typedef struct {
  const buckets_xl_kv *meta; /* user-defined metadata to store */
  size_t nmeta;
  const uint8_t *want_md5;     /* Content-MD5 to enforce, or NULL */
  const uint8_t *want_sha256;  /* signed payload hash to enforce, or NULL */
  uint32_t checksum_type;      /* BUCKETS_CKSUM_* to compute while writing, or 0 */
  /* Runs after the data is fully read and before anything becomes visible.
   * `computed` holds the checksum_type digest; o is the version about to be
   * committed (NULL for multipart parts). Returning an error aborts. */
  buckets_obj_err (*pre_commit)(void *ud, const buckets_checksum *computed, buckets_xl_object *o);
  void *pre_commit_ud;
} buckets_put_opts;

buckets_obj_err buckets_obj_check_name(const char *object);

buckets_obj_err buckets_obj_put(buckets_drive *d, const char *bucket, const char *object, buckets_read_fn rd,
                                void *rd_ud, int64_t size, const buckets_put_opts *opts, buckets_object_info *out);

buckets_obj_err buckets_obj_stat(buckets_drive *d, const char *bucket, const char *object, const char *version_id,
                                 buckets_object_info *out);

typedef struct buckets_obj_reader buckets_obj_reader;

/* Opens [offset, offset+length) of an object for reading. */
buckets_obj_err buckets_obj_open(buckets_drive *d, const char *bucket, const char *object, const char *version_id,
                                 int64_t offset, int64_t length, buckets_obj_reader **out,
                                 buckets_object_info *info);
/* Returns bytes read, 0 at the end of the range, -1 on bitrot or I/O error. */
long buckets_obj_read(buckets_obj_reader *r, void *buf, size_t n);
void buckets_obj_reader_free(buckets_obj_reader *r);

buckets_obj_err buckets_obj_delete(buckets_drive *d, const char *bucket, const char *object, const char *version_id);

typedef struct {
  buckets_object_info *objects;
  size_t nobjects;
  char **prefixes;
  size_t nprefixes;
  bool truncated;
  char *next_marker; /* last key or common prefix returned, when truncated */
} buckets_obj_listing;

buckets_obj_err buckets_obj_list(buckets_drive *d, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out);
void buckets_obj_list_free(buckets_obj_listing *l);
/* True if the bucket has no objects (used by DeleteBucket). */
bool buckets_obj_bucket_empty(buckets_drive *d, const char *bucket);

/* ---- multipart uploads ----
 * .minio.sys/multipart/<sha256(bucket/object)>/<upload-uuid>/xl.meta
 *                                               /<data-dir>/part.N{,.meta}
 * Upload IDs are base64url("<deployment-id>.<upload-uuid>") as in MinIO. */

#define BUCKETS_MIN_PART_SIZE (5LL * 1024 * 1024)
#define BUCKETS_MAX_PART_SIZE (5LL * 1024 * 1024 * 1024)
#define BUCKETS_MAX_PARTS 10000
#define BUCKETS_UPLOAD_ID_MAX 160

typedef struct {
  int number;
  char etag[80];
  int64_t size;
  int64_t actual_size;
  int64_t mod_time_ns;
  buckets_checksum cksum; /* type 0 when the part has none */
} buckets_part_info;

typedef struct {
  int number;
  const char *etag;     /* as sent by the client; quotes are ignored */
  const char *checksum; /* the part's checksum for the upload's algorithm, or NULL */
} buckets_complete_part;

#define BUCKETS_MPU_CKSUM_META "x-minio-multipart-checksum"
#define BUCKETS_MPU_CKSUM_TYPE_META "x-minio-multipart-checksum-type"

typedef struct {
  char *object;
  char upload_id[BUCKETS_UPLOAD_ID_MAX];
  int64_t initiated_ns;
} buckets_upload_info;

buckets_obj_err buckets_obj_mpu_new(buckets_drive *d, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                    size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]);
buckets_obj_err buckets_obj_mpu_put_part(buckets_drive *d, const char *bucket, const char *object, const char *upload_id,
                                         int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out);
/* Parts numbered > marker, ascending, at most max. */
buckets_obj_err buckets_obj_mpu_list_parts(buckets_drive *d, const char *bucket, const char *object,
                                           const char *upload_id, int marker, int max, buckets_part_info **parts,
                                           size_t *n, bool *truncated);
buckets_obj_err buckets_obj_mpu_abort(buckets_drive *d, const char *bucket, const char *object, const char *upload_id);
/* want: the final checksum from the request's x-amz-checksum-* header, or NULL. */
buckets_obj_err buckets_obj_mpu_complete(buckets_drive *d, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *parts, size_t nparts,
                                         const buckets_checksum *want, buckets_object_info *out);
/* Pending uploads for exactly this object (MinIO lists per object). */
buckets_obj_err buckets_obj_mpu_list_uploads(buckets_drive *d, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n);
void buckets_upload_info_free(buckets_upload_info *u, size_t n);

#endif
