/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OBJECT_OBJECT_H
#define BUCKETS_OBJECT_OBJECT_H

#include "crypto/cksum.h"
#include "storage/drive.h"
#include "storage/format.h"
#include "storage/xlmeta.h"

/* The object layer: erasure sets over drives, laid out exactly like MinIO so
 * either server can serve the other's drives. On every drive of the object's
 * set:
 *
 *   <bucket>/<object>/xl.meta                  metadata (+ inline shard when small)
 *   <bucket>/<object>/<data-dir-uuid>/part.N   this drive's bitrot-framed shards
 *   <bucket>/<dir-object>__XLDIR__/xl.meta     keys ending in '/'
 *
 * Each 1 MiB block is split into `data` shards plus `parity` Reed-Solomon
 * shards; shard k goes to the drive whose hashOrder slot is k+1 (EcIndex).
 * Every shard block is preceded by its HighwayHash-256. A single drive is one
 * set with EC 1+0 (MinIO's "xl-single"). Replaces MinIO's cmd/erasure-*.go. */

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
  BUCKETS_OBJ_ERR_READ_QUORUM,        /* too few drives agree / are readable */
  BUCKETS_OBJ_ERR_WRITE_QUORUM,       /* too few drives accepted the write */
  BUCKETS_OBJ_ERR_BUCKET_EXISTS,
  BUCKETS_OBJ_ERR_BUCKET_NOT_EMPTY,
  BUCKETS_OBJ_ERR_TIMEOUT, /* a namespace lock was not granted in time */
} buckets_obj_err;

const char *buckets_obj_strerror(buckets_obj_err e);

/* ---- the layer ---- */

typedef struct {
  buckets_drive **drives; /* set_size entries; NULL = offline */
  size_t n;
  int parity; /* default parity for new objects */
} buckets_eset;

/* The object layer: one or more server pools (MinIO's erasureServerPools),
 * each a set of erasure sets over its own drives. New objects go to a pool
 * chosen by free space; existing objects stay in the pool holding them. */
typedef struct buckets_objlayer {
  struct buckets_epool **pools;
  size_t npools;
  uint8_t deployment_id[16];
  char deployment_id_str[BUCKETS_UUID_STR_LEN + 1];
  buckets_drive **all; /* every slot of every pool, pool-major (owned by the pools) */
  size_t nall;
  struct buckets_nslock *locks;
  void (*on_degraded)(void *ud, const char *bucket, const char *object, const char *version_id, bool deep);
  void *on_degraded_ud;
} buckets_objlayer;

/* Called (from any thread) for objects found or left short of a drive: reads
 * that met a missing or rotten shard, and writes that missed a drive. The
 * healer queues them (MinIO's MRF). deep asks for bitrot verification, since a
 * rotten shard keeps its size. */
typedef void (*buckets_degraded_fn)(void *ud, const char *bucket, const char *object, const char *version_id,
                                    bool deep);
void buckets_objlayer_set_degraded_hook(buckets_objlayer *L, buckets_degraded_fn fn, void *ud);

/* One format result per pool, all of the same deployment. Takes ownership of
 * their drives (slots are cleared). parity < 0 uses MinIO's default for each
 * pool's set size. */
buckets_objlayer *buckets_objlayer_new(buckets_format_result *pools, size_t npools, int parity);
void buckets_objlayer_free(buckets_objlayer *L);
/* An online drive to use for local scratch space (spooling). */
buckets_drive *buckets_objlayer_scratch(const buckets_objlayer *L);
size_t buckets_objlayer_online(const buckets_objlayer *L);
/* Distributed mode: namespace locks also take this cluster-wide lock. */
void buckets_objlayer_set_locker(buckets_objlayer *L, void *(*lock)(void *ud, const char *resource, bool write, int timeout_ms),
                                 void (*unlock)(void *ud, void *handle), void *ud);
/* Every erasure set of every pool has write (else read) quorum of online drives. */
bool buckets_objlayer_has_quorum(buckets_objlayer *L, bool write);
/* Where drive all[i] sits, and the shape of its pool. */
typedef struct {
  size_t pool, set;
  size_t pool_first, pool_drives; /* its pool's slice of all[] */
  size_t set_size, nsets;
  int parity;
} buckets_drive_place;
void buckets_objlayer_place(const buckets_objlayer *L, size_t i, buckets_drive_place *out);
/* Whether this node leads a set's background work: its lowest-numbered
 * online drive is local. Exactly one node leads each set. */
bool buckets_objlayer_set_is_led_here(const buckets_objlayer *L, size_t pool, size_t set);
/* The erasure set an object hashes to within a pool. */
size_t buckets_objlayer_object_set(const buckets_objlayer *L, size_t pool, const char *object);

/* ---- buckets ---- */
typedef struct {
  char *name;
  time_t created;
} buckets_bucket_info;

buckets_obj_err buckets_obj_make_bucket(buckets_objlayer *L, const char *bucket);
buckets_obj_err buckets_obj_stat_bucket(buckets_objlayer *L, const char *bucket);
/* Fails with BUCKET_NOT_EMPTY if objects remain. */
buckets_obj_err buckets_obj_delete_bucket(buckets_objlayer *L, const char *bucket);
buckets_obj_err buckets_obj_list_buckets(buckets_objlayer *L, buckets_bucket_info **out, size_t *n);
void buckets_bucket_info_free(buckets_bucket_info *b, size_t n);

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

buckets_obj_err buckets_obj_put(buckets_objlayer *L, const char *bucket, const char *object, buckets_read_fn rd,
                                void *rd_ud, int64_t size, const buckets_put_opts *opts, buckets_object_info *out);

buckets_obj_err buckets_obj_stat(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 buckets_object_info *out);

typedef struct buckets_obj_reader buckets_obj_reader;

/* Opens [offset, offset+length) of an object for reading. */
buckets_obj_err buckets_obj_open(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 int64_t offset, int64_t length, buckets_obj_reader **out,
                                 buckets_object_info *info);
/* Returns bytes read, 0 at the end of the range, -1 on bitrot or I/O error. */
long buckets_obj_read(buckets_obj_reader *r, void *buf, size_t n);
void buckets_obj_reader_free(buckets_obj_reader *r);

buckets_obj_err buckets_obj_delete(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id);

typedef struct {
  buckets_object_info *objects;
  size_t nobjects;
  char **prefixes;
  size_t nprefixes;
  bool truncated;
  char *next_marker; /* last key or common prefix returned, when truncated */
} buckets_obj_listing;

buckets_obj_err buckets_obj_list(buckets_objlayer *L, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out);
void buckets_obj_list_free(buckets_obj_listing *l);

/* ---- healing ----
 * Replaces MinIO's cmd/erasure-healing.go. Healing rebuilds every shard an
 * online drive is missing, from the drives that agree on the version. */

#define BUCKETS_MAX_SET_DRIVES 16

typedef enum {
  BUCKETS_HEAL_OK = 0,
  BUCKETS_HEAL_OFFLINE, /* drive unavailable: nothing can be done now */
  BUCKETS_HEAL_MISSING, /* no (or a different) copy of the version */
  BUCKETS_HEAL_CORRUPT, /* part files missing, truncated or (deep) bitrotten */
} buckets_heal_state;

typedef struct {
  bool deep;            /* verify every shard's bitrot hash, not just sizes */
  bool dry_run;         /* report only */
  bool remove_dangling; /* delete versions that can never reach read quorum */
} buckets_heal_opts;

typedef struct {
  size_t ndrives;
  buckets_heal_state before[BUCKETS_MAX_SET_DRIVES], after[BUCKETS_MAX_SET_DRIVES];
  size_t versions;      /* versions examined */
  size_t healed;        /* drive copies rewritten */
  size_t dangling;      /* versions removed as dangling */
  int64_t size;         /* of the latest version examined */
} buckets_heal_result;

/* Heals one version, or with version_id NULL every version found on any
 * drive. Takes the object's write lock. */
buckets_obj_err buckets_obj_heal(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 const buckets_heal_opts *opts, buckets_heal_result *res);
/* Creates the bucket's volume on online drives that lack it. Returns the number created. */
size_t buckets_obj_heal_bucket(buckets_objlayer *L, const char *bucket);

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

buckets_obj_err buckets_obj_mpu_new(buckets_objlayer *L, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                    size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]);
buckets_obj_err buckets_obj_mpu_put_part(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id,
                                         int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out);
/* Parts numbered > marker, ascending, at most max. */
buckets_obj_err buckets_obj_mpu_list_parts(buckets_objlayer *L, const char *bucket, const char *object,
                                           const char *upload_id, int marker, int max, buckets_part_info **parts,
                                           size_t *n, bool *truncated);
buckets_obj_err buckets_obj_mpu_abort(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id);
/* want: the final checksum from the request's x-amz-checksum-* header, or NULL. */
buckets_obj_err buckets_obj_mpu_complete(buckets_objlayer *L, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *parts, size_t nparts,
                                         const buckets_checksum *want, buckets_object_info *out);
/* Pending uploads for exactly this object (MinIO lists per object). */
buckets_obj_err buckets_obj_mpu_list_uploads(buckets_objlayer *L, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n);
void buckets_upload_info_free(buckets_upload_info *u, size_t n);

#endif
