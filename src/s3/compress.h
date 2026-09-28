/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_COMPRESS_H
#define BUCKETS_S3_COMPRESS_H

#include "compress/s2.h"
#include "s3/internal.h"

/* Transparent object compression (MinIO's `compression` subsystem and
 * cmd/object-api-utils.go): writes that qualify are stored as S2 streams
 * (per part, for multipart uploads), with the plaintext size in the part
 * records and X-Minio-Internal-actual-size. Encrypted objects compress
 * before they encrypt; their streams are padded to 256 bytes and their
 * part indexes are sealed with the object key. */

#define BUCKETS_COMPRESS_META "X-Minio-Internal-compression"
#define BUCKETS_COMPRESS_ALGO_V1 "golang/snappy/LZ77"
#define BUCKETS_COMPRESS_ALGO_V2 "klauspost/compress/s2"
#define BUCKETS_ACTUAL_SIZE_META "X-Minio-Internal-actual-size"
#define BUCKETS_COMPRESS_MIN_SIZE 4096                /* minCompressibleSize */
#define BUCKETS_COMPRESS_PAD_ENCRYPTED 256            /* compPadEncrypted */
#define BUCKETS_COMPRESS_MIN_INDEX_SIZE (8LL << 20)   /* compMinIndexSize */

/* isCompressible: compression is enabled and the object qualifies by name
 * and Content-Type. encrypted: the write will be encrypted (requested, or by
 * the bucket's default, which MinIO applies to the request first). */
bool buckets_s3_compressible(s3_ctx *c, const char *object, bool encrypted);
/* excludeForCompression with an explicit configuration (tests). */
bool buckets_s3_compress_excluded(const char *object, const char *content_type, bool enabled, bool allow_encrypted,
                                  bool encrypted, const char *extensions, const char *mime_types);

/* ObjectInfo.IsCompressed */
bool buckets_s3_is_compressed(const buckets_object_info *oi);
/* ObjectInfo.GetActualSize: the size clients see (-1 when it cannot be told). */
int64_t buckets_s3_actual_size(const buckets_object_info *oi);

/* compressionIndexEncrypter / compressionIndexDecrypt. */
void buckets_s3_compress_seal_index(const uint8_t key[32], const void *idx, size_t n, buckets_buf *out);
bool buckets_s3_compress_open_index(const uint8_t key[32], const void *sealed, size_t n, buckets_buf *out);

/* getCompressedOffsets: where a read of plaintext from off starts. The
 * stored object is read from stored_off to its end; with encryption, the
 * DARE stream resumes at part first_part, package seq, and decrypt_skip
 * bytes into it. part_skip plaintext bytes are then decompressed and
 * dropped. key: the object key of an encrypted object (for its indexes). */
typedef struct {
  int64_t stored_off, part_skip, decrypt_skip;
  uint32_t seq;
  size_t first_part;
} buckets_comp_range;

void buckets_s3_compressed_range(const buckets_object_info *oi, const uint8_t *key, int64_t off, buckets_comp_range *out);

/* The plaintext [off, off+len) of a compressed object from its stored bytes
 * (rd, from rg->stored_off on). stored_size: the object's stored size.
 * Takes ownership of rd via free_rd. */
typedef struct buckets_comp_reader buckets_comp_reader;
buckets_comp_reader *buckets_comp_reader_new(const buckets_object_info *oi, int64_t stored_size, const uint8_t *key,
                                             const buckets_comp_range *rg, int64_t len, buckets_read_fn rd, void *rd_ud,
                                             void (*free_rd)(void *));
long buckets_comp_reader_read(void *ud, void *buf, size_t n);
void buckets_comp_reader_free(void *ud);

#endif
