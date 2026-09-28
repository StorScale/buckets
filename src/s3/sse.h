/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SSE_H
#define BUCKETS_S3_SSE_H

#include "crypto/dare.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "crypto/cksum.h"
#include "s3/internal.h"

/* Server-side encryption of object data (MinIO's cmd/encryption-v1.go and
 * internal/crypto): SSE-S3 and SSE-KMS keys come from the KMS, SSE-C keys
 * from the request. Object data is stored as DARE 2.0 (per part, with part
 * keys, for multipart objects); the sealed object key and friends live in
 * the version's system metadata under MinIO's names. */

typedef enum { BUCKETS_SSE_NONE = 0, BUCKETS_SSE_S3, BUCKETS_SSE_KMS, BUCKETS_SSE_C } buckets_sse_kind;

#define BUCKETS_SSE_META_MULTIPART "X-Minio-Internal-Encrypted-Multipart"
#define BUCKETS_SSE_META_IV "X-Minio-Internal-Server-Side-Encryption-Iv"
#define BUCKETS_SSE_META_ALGORITHM "X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm"
#define BUCKETS_SSE_META_SEALED_SSEC "X-Minio-Internal-Server-Side-Encryption-Sealed-Key"
#define BUCKETS_SSE_META_SEALED_S3 "X-Minio-Internal-Server-Side-Encryption-S3-Sealed-Key"
#define BUCKETS_SSE_META_SEALED_KMS "X-Minio-Internal-Server-Side-Encryption-Kms-Sealed-Key"
#define BUCKETS_SSE_META_KEY_ID "X-Minio-Internal-Server-Side-Encryption-S3-Kms-Key-Id"
#define BUCKETS_SSE_META_DATA_KEY "X-Minio-Internal-Server-Side-Encryption-S3-Kms-Sealed-Key"
#define BUCKETS_SSE_META_CONTEXT "X-Minio-Internal-Server-Side-Encryption-Context"

/* What a request asks for (crypto.IsRequested + ParseHTTP). */
typedef struct {
  buckets_sse_kind kind;
  char key_id[256];     /* SSE-KMS key, ARN prefix trimmed ("" = the default key) */
  buckets_buf context;  /* SSE-KMS context as kms.Context text, when given */
  bool has_context;
  uint8_t ssec_key[32]; /* SSE-C */
} buckets_sse_req;

void buckets_sse_req_free(buckets_sse_req *r);

/* KMS failures, beyond the S3 error table (MinIO's kms.Error): write them
 * with buckets_s3_sse_write_error. */
#define BUCKETS_SSE_ERR_KMS_KEY_NOT_FOUND ((buckets_s3_error)0x10001)
#define BUCKETS_SSE_ERR_KMS_DECRYPT ((buckets_s3_error)0x10002)
void buckets_s3_sse_write_error(s3_ctx *c, buckets_s3_error e);

/* The encryption a write asks for, validated as MinIO's PutObject does
 * (SSE-C copy headers are refused; SSE-C with SSE-S3/KMS is incompatible). */
buckets_s3_error buckets_s3_sse_parse(s3_ctx *c, buckets_sse_req *r);
/* The same for a copy's destination (copy-source SSE-C headers are allowed). */
buckets_s3_error buckets_s3_sse_parse_copy_dest(s3_ctx *c, buckets_sse_req *r);
/* putOptsFromHeaders: the SSE-KMS (else SSE-C) headers must parse; false
 * with MinIO's crypto message, which the caller wraps in InvalidArgument. */
bool buckets_s3_sse_put_opts(s3_ctx *c, char *why, size_t cap);
/* crypto.Requested: SSE-S3, SSE-KMS or SSE-C headers. */
bool buckets_s3_sse_requested(s3_ctx *c);
/* SSE-S3 or SSE-KMS headers (GET and HEAD refuse them with BadRequest). */
bool buckets_s3_sse_s3_or_kms_requested(s3_ctx *c);
/* SSE-C headers on a read: they must parse (getOpts). */
buckets_s3_error buckets_s3_sse_get_opts(s3_ctx *c);
/* An SSE-C key from the request (copy: the x-amz-copy-source-... headers). */
buckets_s3_error buckets_s3_ssec_key(s3_ctx *c, bool copy, uint8_t key[32]);

/* newEncryptMetadata: a new object key for bucket/object, sealed; its system
 * metadata is added to sys. */
buckets_s3_error buckets_s3_sse_new_key(s3_ctx *c, const buckets_sse_req *r, const char *bucket, const char *object,
                                        uint8_t key[32], buckets_xl_kv **sys, size_t *nsys);

/* Stored objects */
buckets_sse_kind buckets_s3_sse_kind_of(const buckets_object_info *oi);
bool buckets_s3_sse_encrypted(const buckets_object_info *oi); /* crypto.IsEncrypted */
bool buckets_s3_sse_is_multipart(const buckets_object_info *oi);
/* decryptObjectMeta: the object key (SSE-C: from the request's key, copy
 * headers when copy is set). */
buckets_s3_error buckets_s3_sse_object_key(s3_ctx *c, const buckets_object_info *oi, const char *bucket, const char *object,
                                           bool copy, uint8_t key[32]);
/* DecryptObjectInfo's request checks for GET/HEAD (copy: a copy source). */
buckets_s3_error buckets_s3_sse_check_read(s3_ctx *c, const buckets_object_info *oi, bool copy);
/* The plaintext size (GetActualSize); -1 when the stored sizes are not DARE sizes. */
int64_t buckets_s3_sse_actual_size(const buckets_object_info *oi);
/* The ETag clients see: SSE-S3 single-part ETags are unsealed with key (NULL:
 * unseal via the KMS); others keep their last 32 hex digits. */
void buckets_s3_sse_client_etag(s3_ctx *c, const buckets_object_info *oi, const uint8_t *key, char out[80]);
/* Replaces an encrypted object's stored checksum (sealed with the object
 * key, metadataEncrypter "object-checksum") with its plaintext; false when
 * it does not open. */
bool buckets_s3_sse_unseal_checksum(const uint8_t key[32], buckets_object_info *oi);
/* metadataEncrypter(key)(base, data): DARE under HMAC-SHA256(key, base);
 * empty data stays empty. meta_open reverses it (false when it does not open). */
void buckets_s3_meta_seal(const uint8_t key[32], const char *base, const void *data, size_t n, buckets_buf *out);
bool buckets_s3_meta_open(const uint8_t key[32], const char *base, const void *data, size_t n, buckets_buf *out);
/* x-amz-server-side-encryption* response headers for an encrypted object. */
void buckets_s3_sse_headers(s3_ctx *c, const buckets_object_info *oi);
/* The KMS key ID as AWS shows it ("arn:aws:kms:" + id), or "". */
void buckets_s3_sse_kms_key_arn(const buckets_object_info *oi, char *out, size_t cap);

/* PutObject of size plaintext bytes from rd, encrypted as r asks (objects.c;
 * POST policy uploads). etag_out gets the ETag clients see. */
buckets_s3_error buckets_s3_sse_put(s3_ctx *c, const buckets_sse_req *r, const char *object, buckets_read_fn rd, void *ud,
                                    int64_t size, const buckets_xl_kv *meta, size_t nmeta, const buckets_checksum *want,
                                    buckets_object_info *out, char etag_out[80]);

/* ---- writing: plaintext in, DARE out ---- */
typedef struct {
  buckets_read_fn rd;
  void *rd_ud;
  int64_t remaining; /* plaintext still to read */
  buckets_dare_enc enc;
  buckets_md5_ctx md5;
  buckets_sha256_ctx sha;
  buckets_cksum_hasher cks;
  uint32_t cks_type;
  uint8_t *in, *out;
  size_t out_pos, out_len;
  int64_t plain_size;
  bool unknown, eof, have_peek; /* size -1: read to EOF, looking one byte ahead */
  uint8_t peek;
  bool no_hash; /* the plaintext is hashed upstream (compressed writes) */
} buckets_sse_writer;

/* key: the object key, or a part key. size: the plaintext length, or -1 to
 * read to EOF. cks_type: a checksum to compute over the plaintext (0 none). */
void buckets_sse_writer_init(buckets_sse_writer *w, const uint8_t key[32], buckets_read_fn rd, void *rd_ud, int64_t size,
                             uint32_t cks_type);
/* The same with a given DARE nonce (multipart parts use a derived one). */
void buckets_sse_writer_init_nonce(buckets_sse_writer *w, const uint8_t key[32], const uint8_t *nonce, buckets_read_fn rd,
                                   void *rd_ud, int64_t size, uint32_t cks_type);
void buckets_sse_writer_free(buckets_sse_writer *w);
long buckets_sse_writer_read(void *ud, void *buf, size_t n);

/* ---- reading: DARE in, a plaintext range out ---- */
typedef struct buckets_sse_reader buckets_sse_reader;

/* The stored byte range covering plaintext [off, off+len) (GetDecryptedRange). */
typedef struct {
  int64_t enc_off, enc_len, skip;
  uint32_t seq;
  size_t part; /* index of the first part */
} buckets_sse_range;
bool buckets_s3_sse_range(const buckets_object_info *oi, int64_t off, int64_t len, buckets_sse_range *out);
/* Decrypts rd (the stored bytes of rg) into len plaintext bytes. Takes
 * ownership of rd's reader via free_rd. */
buckets_sse_reader *buckets_sse_reader_new(const buckets_object_info *oi, const uint8_t key[32], const buckets_sse_range *rg,
                                           int64_t len, buckets_read_fn rd, void *rd_ud, void (*free_rd)(void *));
long buckets_sse_reader_read(void *ud, void *buf, size_t n);
void buckets_sse_reader_free(void *ud);

#endif
