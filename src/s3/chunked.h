/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_CHUNKED_H
#define BUCKETS_S3_CHUNKED_H

#include "net/http.h"
#include "s3/errors.h"
#include "s3/sigv4.h"

/* Decoder for aws-chunked request bodies (MinIO cmd/streaming-signature-v4.go
 * and streaming-v4-unsigned.go):
 *
 *   STREAMING-AWS4-HMAC-SHA256-PAYLOAD          hex;chunk-signature=SIG\r\nDATA\r\n ... 0;...\r\n\r\n
 *   STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER  as above, then "k:v\r\nx-amz-trailer-signature:SIG\r\n\r\n"
 *   STREAMING-UNSIGNED-PAYLOAD-TRAILER          hex\r\nDATA\r\n ... 0\r\nk:v\r\n\r\n
 *
 * Every chunk signature chains from the previous one, starting at the seed
 * signature of the request, so a tampered or reordered chunk fails. */

typedef struct buckets_chunked buckets_chunked;

/* Returns NULL if content_sha256 is not an aws-chunked mode. sig may be NULL
 * for the unsigned mode. */
buckets_chunked *buckets_chunked_new(const buckets_http_request *req, buckets_str content_sha256,
                                     const buckets_sigv4_result *sig);
void buckets_chunked_free(buckets_chunked *ch);

/* buckets_read_fn-compatible: decoded payload bytes, 0 at end, -1 on error. */
long buckets_chunked_read(void *ch, void *buf, size_t n);

/* After an error: which S3 error to report. */
buckets_s3_error buckets_chunked_error(const buckets_chunked *ch);
/* After the payload is fully read: a trailer value (e.g. "x-amz-checksum-crc32"), or NULL. */
const char *buckets_chunked_trailer(const buckets_chunked *ch, const char *name);

#endif
