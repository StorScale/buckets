/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_BUCKETNAME_H
#define BUCKETS_S3_BUCKETNAME_H

#include "core/common.h"

/* Mirrors minio-go s3utils.CheckValidBucketNameStrict (used for CreateBucket):
 * 3-63 chars of [a-z0-9.-], alphanumeric at both ends, no "..", ".-", "-.",
 * and not formatted like an IPv4 address. */
bool buckets_bucket_name_valid_strict(const char *name);
/* Mirrors s3utils.CheckValidBucketName (used for every other bucket request):
 * like strict but also allows upper case, '_' and ':'. */
bool buckets_bucket_name_valid(const char *name);
/* ".minio.sys" and "minio" are reserved (cmd/generic-handlers.go). */
bool buckets_bucket_name_reserved(const char *name);

#endif
