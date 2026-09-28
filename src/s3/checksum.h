/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_CHECKSUM_H
#define BUCKETS_S3_CHECKSUM_H

#include "core/buf.h"
#include "crypto/cksum.h"
#include "net/http.h"
#include "s3/errors.h"

/* S3 additional checksums (x-amz-checksum-*), port of MinIO internal/hash/checksum.go.
 * Type flags and the stored binary form ("x-minio-internal-crc") are identical. */

const char *buckets_cksum_name(uint32_t type);   /* "CRC32", ... */
const char *buckets_cksum_header(uint32_t type); /* "X-Amz-Checksum-Crc32", ... */

/* GetContentChecksum: the checksum a request carries in headers, or a
 * TRAILING type whose value arrives in the aws-chunked trailer. */
buckets_s3_error buckets_checksum_from_request(const buckets_http_request *req, buckets_checksum *out);

/* ReadCheckSums(b, part): emits X-Amz-Checksum-* and X-Amz-Checksum-Type headers. */
void buckets_checksum_write_headers(const uint8_t *b, size_t n, int part, buckets_http_response *resp);

#endif
