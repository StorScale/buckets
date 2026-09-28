/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_SSECONFIG_H
#define BUCKETS_BUCKET_SSECONFIG_H

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* A bucket's default encryption (MinIO internal/bucket/encryption): one
 * rule applying SSE-S3 ("AES256") or SSE-KMS ("aws:kms" with a key) to
 * writes that ask for no encryption. Stored as the bucket metadata's
 * EncryptionConfigXML. */
typedef struct {
  char algorithm[16]; /* "AES256", "aws:kms" or "" */
  char key_id[256];   /* KMSMasterKeyID as sent */
  char xmlns[128];
} buckets_sse_config;

/* ParseBucketSSEConfig: false with Go's (or MinIO's) reason. */
bool buckets_sse_config_parse(const char *xml, size_t len, buckets_sse_config *out, char *err, size_t errlen);
/* xml.Marshal(config) */
void buckets_sse_config_xml(const buckets_sse_config *c, buckets_buf *out);
/* KeyID(): the key without the ARN prefix. */
const char *buckets_sse_config_key(const buckets_sse_config *c);

#endif
