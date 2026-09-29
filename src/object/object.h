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
  BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED, /* a delete marker asked for by its version ID */
  BUCKETS_OBJ_ERR_TIER,               /* the remote tier holding a transitioned version failed */
  BUCKETS_OBJ_ERR_DISK_FULL,          /* no pool can take the object */
  BUCKETS_OBJ_ERR_DATA_MOVEMENT,      /* data movement would write into its own source pool */
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
  struct buckets_mp_cache *mp_cache; /* uploads started through this node (MinIO's mpCache) */
  /* Opens [off, off+len) of a transitioned version's remote copy (the
   * object's stored bytes): *rd and *rd_free with *rd_ud, or false. */
  bool (*tier_open)(void *ud, const char *tier, const char *remote, const char *remote_version, int64_t off,
                    int64_t len, long (**rd)(void *, void *, size_t), void (**rd_free)(void *), void **rd_ud);
  void *tier_ud;
  /* Pools new data avoids (MinIO's IsSuspended and IsPoolRebalancing, as
   * bit masks), and each pool's command-line argument (its CmdLine). */
  _Atomic uint64_t pool_suspended, pool_rebalancing;
  char **pool_cmdline;
  bool legacy; /* drives given without ellipses (globalEndpoints.Legacy()) */
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
/* DeleteBucket with Force: the bucket goes with every object in it. */
buckets_obj_err buckets_obj_delete_bucket_force(buckets_objlayer *L, const char *bucket);
/* Site replication keeps the state of deleted buckets until the sites agree
 * (MinIO's MarkDelete): the volume .minio.sys/buckets/.deleted/<bucket>,
 * whose modification time is the deletion time. */
void buckets_obj_mark_bucket_deleted(buckets_objlayer *L, const char *bucket);
void buckets_obj_purge_bucket_deleted(buckets_objlayer *L, const char *bucket);
/* When the bucket was marked deleted (0: it is not). */
time_t buckets_obj_bucket_deleted_at(buckets_objlayer *L, const char *bucket);
/* The marked buckets, with created holding the deletion time. */
buckets_obj_err buckets_obj_list_deleted_buckets(buckets_objlayer *L, buckets_bucket_info **out, size_t *n);
buckets_obj_err buckets_obj_list_buckets(buckets_objlayer *L, buckets_bucket_info **out, size_t *n);
void buckets_bucket_info_free(buckets_bucket_info *b, size_t n);

/* Pull-style data source. Returns bytes read, 0 at EOF, -1 on error. */
typedef long (*buckets_read_fn)(void *ud, void *buf, size_t n);

typedef struct buckets_object_info_s {
  char *name;
  char version_id[37];
  int64_t size;
  int64_t mod_time_ns;
  char etag[128]; /* sealed ETags of encrypted objects are 96 hex digits */
  buckets_xl_kv *meta; /* user-defined metadata (MinIO MetaUser, incl. content-type) */
  size_t nmeta;
  buckets_xl_kv *meta_sys; /* internal metadata (MinIO MetaSys: encryption keys, ...) */
  size_t nmeta_sys;
  size_t nparts;
  bool delete_marker;
  bool is_latest; /* the newest version of its key (listings, stat and open) */
  size_t num_versions;          /* versions of its key (stat and open) */
  int64_t successor_mod_time_ns; /* the next newer version's modification time, or 0 */
  uint8_t *checksum; /* stored x-minio-internal-crc bytes, or NULL */
  size_t checksum_len;
  buckets_xl_part *parts; /* numbers and sizes, in object order (etags unset) */
  int data_blocks, parity_blocks; /* the version's erasure coding (EcM, EcN) */
  bool free_version; /* a deleted transitioned version's remnant (buckets_obj_list_versions_all only) */
} buckets_object_info;

void buckets_object_info_free(buckets_object_info *oi);
/* Value of a user-metadata key, or NULL. */
const char *buckets_object_meta(const buckets_object_info *oi, const char *key);
/* A system-metadata entry (case-insensitive key), or NULL. */
const buckets_xl_kv *buckets_object_sys(const buckets_object_info *oi, const char *key);
/* The remote tier holding a transitioned version (TransitionedObject.Tier),
 * or NULL; remote/version (may be NULL) get its remote name and version. */
const char *buckets_object_tier(const buckets_object_info *oi, const char **remote, const char **version);
/* ObjectInfo.IsRemote: transitioned and not restored on the drives. */
bool buckets_object_is_remote(const buckets_object_info *oi);
/* The restore state from x-amz-restore (RestoreOngoing, RestoreExpires in
 * unix seconds, 0 when none). */
void buckets_object_restore_state(const buckets_object_info *oi, bool *ongoing, int64_t *expires);

struct buckets_part_info_s;

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
  /* Multipart parts: may adjust the part's recorded ETag, actual size and
   * checksum (encrypted parts record plaintext values) before it is stored. */
  void (*part_commit)(void *ud, struct buckets_part_info_s *pi);
  void *part_commit_ud;
  /* Versioning: a new version ID (bucket versioning enabled), or the given
   * one (replication, imports); otherwise the "null" version is replaced. */
  bool versioned;
  const char *version_id;
  int64_t mod_time_ns; /* 0: now */
  const char *preserve_etag; /* store this ETag instead of the computed one (replication) */
  /* Puts of unknown size (-1, compressed streams): the plaintext size, which
   * decides inlining. */
  int64_t actual_size;
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

/* DeleteObject with the bucket's versioning (MinIO's ObjectOptions):
 * - with version_id: that version is removed for good;
 * - otherwise, versioned: a delete marker with a new version ID;
 *   suspended: a "null" delete marker, replacing any null version;
 *   neither: the null version is removed. */
typedef struct {
  const char *version_id;
  bool versioned, suspended;
  /* Replication (MinIO's ObjectOptions.DeleteMarker, MTime and
   * DeleteReplication); any of these takes MinIO's full DeleteObject path,
   * which records replication states in the versions' system metadata. */
  bool replica_marker;     /* DeleteMarker: a delete marker replicated by its version ID (need not exist here) */
  bool replica;            /* ReplicaStatus REPLICA: an incoming replicated delete */
  int64_t mod_time_ns;     /* MTime: the marker's modification time (0: now) */
  const char *repl_status; /* ReplicationStatusInternal ("arn=PENDING;") of the marker */
  int64_t repl_ts_ns;      /* ReplicationTimeStamp (0: Go's zero time) */
  const char *purge_status; /* VersionPurgeStatusInternal of a versioned delete */
  const char *const *reset_keys, *const *reset_values; /* ResetStatusesMap (full metadata keys) */
  size_t nreset;
  /* EvalMetadataFn: sees the version as found (found false: none) and may
   * return the statuses to record (malloc'd, or NULL). */
  void (*decide)(void *ud, const struct buckets_object_info_s *goi, bool found, char **repl_status,
                 char **purge_status);
  void *decide_ud;
  /* SkipFreeVersion: the remote copy of a transitioned version is already
   * gone, so no free version is left to sweep it. */
  bool skip_free_version;
} buckets_delete_opts;
typedef struct {
  bool delete_marker;      /* a marker was created, or the removed version was one */
  char version_id[37];     /* the marker's or the removed version's ID ("null" for none) */
  int64_t mod_time_ns;     /* replication path: the version's modification time */
  char repl_status[1024];  /* replication path: the ReplicationStatusInternal recorded */
  char purge_status[1024]; /* replication path: the VersionPurgeStatusInternal recorded */
} buckets_delete_result;
buckets_obj_err buckets_obj_delete_ex(buckets_objlayer *L, const char *bucket, const char *object,
                                      const buckets_delete_opts *opts, buckets_delete_result *res);

typedef struct {
  buckets_object_info *objects;
  size_t nobjects;
  char **prefixes;
  size_t nprefixes;
  bool truncated;
  char *next_marker; /* last key or common prefix returned, when truncated */
  char *next_version_marker; /* version listings: the last version returned */
} buckets_obj_listing;

buckets_obj_err buckets_obj_list(buckets_objlayer *L, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out);
void buckets_obj_list_free(buckets_obj_listing *l);

/* PutObjectMetadata: rewrites one version's metadata in place (the data
 * and modification time stay). fn gets the current version and edits its
 * user and system metadata; returning an error aborts. A delete marker is
 * METHOD_NOT_ALLOWED. */
typedef buckets_obj_err (*buckets_meta_edit_fn)(void *ud, const buckets_object_info *cur, buckets_xl_kv **user,
                                                size_t *nuser, buckets_xl_kv **sys, size_t *nsys);
buckets_obj_err buckets_obj_update_meta(buckets_objlayer *L, const char *bucket, const char *object,
                                        const char *version_id, buckets_meta_edit_fn fn, void *ud,
                                        buckets_object_info *out);

/* ListObjectVersions: every version (delete markers included, newest first
 * within a key), after key_marker (and, within it, version_marker). When
 * truncated, next_marker / next_version_marker say where to resume. */
buckets_obj_err buckets_obj_list_versions(buckets_objlayer *L, const char *bucket, const char *prefix,
                                          const char *key_marker, const char *version_marker, const char *delimiter,
                                          int max_keys, buckets_obj_listing *out);
/* ---- tiering ---- */

/* TransitionObject: moves a version's stored bytes to a remote tier and
 * leaves its metadata behind (x-minio-internal-transition-*). The version
 * must still have mod_time_ns and etag (it was not replaced since it was
 * queued). upload gets the stored bytes (size of them) and returns the
 * remote object's name and version ID. An already transitioned version is OK. */
typedef buckets_obj_err (*buckets_tier_upload_fn)(void *ud, buckets_read_fn rd, void *rd_ud, int64_t size,
                                                   char *remote, size_t rcap, char *rv, size_t rvcap);
buckets_obj_err buckets_obj_transition(buckets_objlayer *L, const char *bucket, const char *object,
                                       const char *version_id, int64_t mod_time_ns, const char *etag, const char *tier,
                                       buckets_tier_upload_fn upload, void *ud, buckets_object_info *out);
/* RestoreTransitionedObject: writes a transitioned version's stored bytes
 * (from rd, as the remote tier holds them) back to the drives, laid out as
 * its parts were, and sets its x-amz-restore metadata to restore_hdr. */
buckets_obj_err buckets_obj_rehydrate(buckets_objlayer *L, const char *bucket, const char *object,
                                      const char *version_id, buckets_read_fn rd, void *rd_ud,
                                      const char *restore_hdr);
/* The expiry of a restored copy (ExpireRestored): its local data goes, the
 * restore headers are removed, the transitioned version stays. */
buckets_obj_err buckets_obj_expire_restored(buckets_objlayer *L, const char *bucket, const char *object,
                                            const char *version_id);
/* Removes a free version (after its remote copy was deleted). */
buckets_obj_err buckets_obj_delete_free_version(buckets_objlayer *L, const char *bucket, const char *object,
                                                const char *version_id);

/* The same with free versions (free_version set), for the scanner to sweep. */
buckets_obj_err buckets_obj_list_versions_all(buckets_objlayer *L, const char *bucket, const char *prefix,
                                              const char *key_marker, const char *version_marker, int max_keys,
                                              buckets_obj_listing *out);
/* Merges per-source version listings (each sorted) into out, keeping the
 * first max_keys entries; the sources are emptied. */
void buckets_obj_listing_merge_versions(buckets_obj_listing *src, size_t n, int max_keys, buckets_obj_listing *out);

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
  int scan_mode;        /* madmin.HealScanMode, for traces: 0 unknown, 1 normal, 2 deep */
  bool quiet_clean;     /* no trace or audit for versions found healthy (the scanner's checks) */
} buckets_heal_opts;

typedef struct {
  size_t ndrives;
  buckets_heal_state before[BUCKETS_MAX_SET_DRIVES], after[BUCKETS_MAX_SET_DRIVES];
  size_t versions;      /* versions examined */
  size_t healed;        /* drive copies rewritten */
  size_t dangling;      /* versions removed as dangling */
  int64_t size;         /* of the latest version examined */
  int data_blocks, parity_blocks;
  size_t pool, set;     /* where the object lives (its drives are that set's, in order) */
} buckets_heal_result;

/* Heals one version, or with version_id NULL every version found on any
 * drive. Takes the object's write lock. */
buckets_obj_err buckets_obj_heal(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 const buckets_heal_opts *opts, buckets_heal_result *res);
/* Creates the bucket's volume on online drives that lack it. Returns the number created. */
size_t buckets_obj_heal_bucket(buckets_objlayer *L, const char *bucket);
/* For scanner traces: the drive (root) whose copy of object the scanner
 * reports, in the first pool, and optionally the xl.meta size there. */
const char *buckets_obj_scan_drive(buckets_objlayer *L, const char *bucket, const char *object, int64_t *meta_size);

/* ---- multipart uploads ----
 * .minio.sys/multipart/<sha256(bucket/object)>/<upload-uuid>/xl.meta
 *                                               /<data-dir>/part.N{,.meta}
 * Upload IDs are base64url("<deployment-id>.<upload-uuid>") as in MinIO. */

#define BUCKETS_MIN_PART_SIZE (5LL * 1024 * 1024)
#define BUCKETS_MAX_PART_SIZE (5LL * 1024 * 1024 * 1024)
#define BUCKETS_MAX_PARTS 10000
#define BUCKETS_UPLOAD_ID_MAX 160

typedef struct buckets_part_info_s {
  int number;
  char etag[128];
  int64_t size;
  int64_t actual_size;
  int64_t mod_time_ns;
  buckets_checksum cksum; /* type 0 when the part has none */
  /* The S2 index of a compressed part, set by a part_commit hook for the
   * part record only (borrowed; never set in results). */
  const uint8_t *index;
  size_t index_len;
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
typedef struct {
  bool versioned;
  /* The form of a stored part ETag clients were given (encrypted uploads
   * keep sealed part ETags); NULL: as stored. */
  void (*client_etag)(void *ud, const char *stored, char out[128]);
  /* Runs on the final version before it is installed. */
  buckets_obj_err (*pre_commit)(void *ud, buckets_xl_object *o);
  void *ud;
} buckets_complete_opts;

/* want: the final checksum from the request's x-amz-checksum-* header, or NULL. */
buckets_obj_err buckets_obj_mpu_complete(buckets_objlayer *L, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *parts, size_t nparts,
                                         const buckets_checksum *want, const buckets_complete_opts *co,
                                         buckets_object_info *out);
/* An upload's metadata (user and system), as object info. */
buckets_obj_err buckets_obj_mpu_stat(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id,
                                     buckets_object_info *out);
/* Pending uploads for exactly this object (MinIO lists per object). */
buckets_obj_err buckets_obj_mpu_list_uploads(buckets_objlayer *L, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n);
void buckets_upload_info_free(buckets_upload_info *u, size_t n);

/* ---- pools: decommission and rebalance ---- */
/* The pools' command-line arguments (copied). */
void buckets_objlayer_set_cmdlines(buckets_objlayer *L, char *const *cmdlines, size_t n);
const char *buckets_objlayer_pool_cmdline(const buckets_objlayer *L, size_t pool);
/* Whether new objects stay off a pool (decommissioned or rebalancing out). */
void buckets_objlayer_set_pool_state(buckets_objlayer *L, size_t pool, bool suspended, bool rebalancing);
bool buckets_objlayer_pool_suspended(const buckets_objlayer *L, size_t pool);
/* A pool's usable capacity and free space (drives holding data shards, as
 * GetTotalUsableCapacity counts them), and raw totals over all its drives. */
void buckets_objlayer_pool_space(buckets_objlayer *L, size_t pool, uint64_t *usable_total, uint64_t *usable_free,
                                 uint64_t *raw_total, uint64_t *raw_free);
/* ListObjectVersions over one pool only (free versions not included). */
buckets_obj_err buckets_obj_pool_list_versions(buckets_objlayer *L, size_t pool, const char *bucket, const char *prefix,
                                               const char *key_marker, const char *version_marker, int max_keys,
                                               buckets_obj_listing *out);
/* Moves one version out of pool src (DataMovement with SrcPoolIdx): to the
 * pool the object already lives in elsewhere, else to where a new object
 * would go; never to src or a pool new data avoids. *bytes gets what was
 * stored. DATA_MOVEMENT when no other pool can take it. */
buckets_obj_err buckets_obj_move_version(buckets_objlayer *L, size_t src, const char *bucket, const char *object,
                                         const char *version_id, int64_t *bytes);
/* Removes an object, every version, from one pool (DeletePrefixObject). */
buckets_obj_err buckets_obj_pool_delete_object(buckets_objlayer *L, size_t pool, const char *bucket,
                                               const char *object);
/* A configuration object in one pool's .minio.sys (pool.bin is kept in each). */
buckets_obj_err buckets_obj_pool_config_write(buckets_objlayer *L, size_t pool, const char *path, const void *data,
                                              size_t n);
buckets_obj_err buckets_obj_pool_config_read(buckets_objlayer *L, size_t pool, const char *path, buckets_buf *out);

#endif
