/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_XLMETA_H
#define BUCKETS_STORAGE_XLMETA_H

#include "core/buf.h"
#include "core/str.h"

/* xl.meta v2 (format 1.3), byte-compatible with MinIO cmd/xl-storage-format-v2.go:
 *
 *   "XL2 " | u16le major=1 | u16le minor=3
 *   bin32 {                                   <- metadata section
 *     uint headerVersion(3) | uint metaVersion(3) | int nversions
 *     nversions x ( bin(header: array[7]) , bin(version: map) )
 *   }
 *   uint32 xxh64(metadata section)            <- integrity check
 *   inline data: 0x01 | map{ versionID-string: bin(bitrot-framed shard) }
 *
 * Versions are kept sorted newest first, exactly as MinIO sorts them. */

#define BUCKETS_XL_TYPE_OBJECT 1
#define BUCKETS_XL_TYPE_DELETE 2
#define BUCKETS_XL_TYPE_LEGACY 3

#define BUCKETS_XL_FLAG_FREE_VERSION 0x1
#define BUCKETS_XL_FLAG_USES_DATA_DIR 0x2
#define BUCKETS_XL_FLAG_INLINE_DATA 0x4

#define BUCKETS_XL_RESERVED_PREFIX "x-minio-internal-"
#define BUCKETS_XL_META_INLINE "x-minio-internal-inline-data"

/* MinIO release timestamp recorded as the writer version (WrittenByVersion). */
#define BUCKETS_XL_WRITTEN_BY 1760549395ull

typedef struct {
  uint8_t version_id[16]; /* all zero for the "null" version */
  int64_t mod_time;       /* unix nanoseconds */
  uint8_t signature[4];
  uint8_t type;
  uint8_t flags;
  uint8_t ec_n, ec_m;
} buckets_xl_header;

typedef struct {
  buckets_xl_header hdr;
  uint8_t *meta; /* encoded xlMetaV2Version (owned) */
  size_t meta_len;
} buckets_xl_version;

typedef struct {
  buckets_xl_version *versions;
  size_t n;
  uint8_t *inline_data; /* raw xlMetaInlineData, may be NULL */
  size_t inline_len;
} buckets_xlmeta;

typedef enum {
  BUCKETS_XL_OK = 0,
  BUCKETS_XL_ERR_CORRUPT,     /* bad structure or checksum */
  BUCKETS_XL_ERR_UNSUPPORTED, /* legacy (pre-1.3) or future major version */
} buckets_xl_err;

buckets_xl_err buckets_xlmeta_parse(const void *buf, size_t n, buckets_xlmeta *out);
void buckets_xlmeta_serialize(const buckets_xlmeta *x, buckets_buf *out);
void buckets_xlmeta_free(buckets_xlmeta *x);

/* Adds a version, replacing any with the same version ID; keeps sort order.
 * Takes ownership of meta. */
void buckets_xlmeta_put_version(buckets_xlmeta *x, const buckets_xl_header *hdr, uint8_t *meta, size_t meta_len);
/* Removes the version with this ID; returns false if absent. */
bool buckets_xlmeta_remove_version(buckets_xlmeta *x, const uint8_t version_id[16]);
/* Index of the version with this ID, or -1. */
long buckets_xlmeta_find(const buckets_xlmeta *x, const uint8_t version_id[16]);

/* Inline data, keyed by version ID string ("null" or a UUID). */
bool buckets_xlmeta_inline_get(const buckets_xlmeta *x, const char *key, buckets_str *out);
void buckets_xlmeta_inline_put(buckets_xlmeta *x, const char *key, const void *data, size_t n);
void buckets_xlmeta_inline_remove(buckets_xlmeta *x, const char *key);

/* ---- decoded object version (MinIO's xlMetaV2Object / FileInfo subset) ---- */

typedef struct {
  char *key;
  uint8_t *value; /* NUL-terminated for convenience; may contain binary */
  size_t value_len;
} buckets_xl_kv;

typedef struct {
  int number;
  int64_t size;
  int64_t actual_size;
  char *etag; /* NULL when unset */
  uint8_t *index; /* S2 index of a compressed part (headers removed), or NULL */
  size_t index_len;
} buckets_xl_part;

typedef struct {
  uint8_t type;
  uint8_t version_id[16];
  uint8_t data_dir[16];
  int64_t mod_time;
  int64_t size;
  int ec_m, ec_n, ec_index;
  int64_t ec_block_size;
  uint8_t ec_dist[256];
  size_t ec_dist_n;
  buckets_xl_part *parts;
  size_t nparts;
  buckets_xl_kv *meta_sys;
  size_t nmeta_sys;
  buckets_xl_kv *meta_user;
  size_t nmeta_user;
  uint64_t written_by;
} buckets_xl_object;

buckets_xl_err buckets_xl_object_decode(const buckets_xl_version *v, buckets_xl_object *out);
/* Encodes the version map and derives its header (flags, signature, EC). */
void buckets_xl_object_encode(const buckets_xl_object *o, buckets_buf *meta, buckets_xl_header *hdr);
void buckets_xl_object_free(buckets_xl_object *o);

void buckets_xl_kv_set(buckets_xl_kv **kvs, size_t *n, const char *key, const void *value, size_t len);
const buckets_xl_kv *buckets_xl_kv_get(const buckets_xl_kv *kvs, size_t n, const char *key);
void buckets_xl_part_add(buckets_xl_object *o, int number, int64_t size, int64_t actual_size, const char *etag);
/* Sets (a copy of) part i's compression index. */
void buckets_xl_part_set_index(buckets_xl_part *p, const void *index, size_t len);

/* "null" for the zero ID, otherwise the canonical UUID string (out: 37 bytes). */
void buckets_xl_version_id_string(const uint8_t id[16], char *out);
bool buckets_xl_version_id_parse(const char *s, uint8_t id[16]);

/* ---- tiering (MinIO's transition metadata and free versions) ---- */

#define BUCKETS_XL_META_TIER_STATUS "x-minio-internal-transition-status"
#define BUCKETS_XL_META_TIER_OBJECT "x-minio-internal-transitioned-object"
#define BUCKETS_XL_META_TIER_VERSION "x-minio-internal-transitioned-versionID"
#define BUCKETS_XL_META_TIER_NAME "x-minio-internal-transition-tier"
#define BUCKETS_XL_META_FREE_VERSION "x-minio-internal-free-version"
#define BUCKETS_XL_META_TIER_FVID "x-minio-internal-tier-free-versionID"
#define BUCKETS_XL_META_TIER_FVMARKER "x-minio-internal-tier-free-marker"
#define BUCKETS_XL_META_SKIP_TIER_FV "x-minio-internal-skip-tier-free-version"

/* The version's content lives in a remote tier (transition-status "complete"). */
bool buckets_xl_transitioned(const buckets_xl_object *o);
/* x-amz-restore says the content is back on the drives and not yet expired. */
bool buckets_xl_restored_on_disk(const buckets_xl_object *o);
/* xlMetaV2Object.UsesDataDir */
bool buckets_xl_object_uses_data_dir(const buckets_xl_object *o);
/* A free version: what is left of a deleted transitioned version until its
 * remote copy is removed; never shown. */
bool buckets_xl_is_free_version(const buckets_xl_header *h);
/* parseRestoreObjStatus: `ongoing-request="true"` or
 * `ongoing-request="false", expiry-date="<http date>"`. */
bool buckets_restore_parse(const char *hdr, bool *ongoing, int64_t *expiry_sec);

#endif
