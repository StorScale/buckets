/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_VERSIONING_H
#define BUCKETS_BUCKET_VERSIONING_H

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* A bucket's versioning configuration (MinIO's internal/bucket/versioning),
 * with MinIO's excluded-prefix and exclude-folders extensions. */
typedef enum {
  BUCKETS_VERSIONING_UNSET = 0,
  BUCKETS_VERSIONING_ENABLED,
  BUCKETS_VERSIONING_SUSPENDED,
} buckets_versioning_status;

typedef struct {
  buckets_versioning_status status;
  char **excluded; /* prefixes, each ending in '/' */
  size_t nexcluded;
  bool exclude_folders;
} buckets_versioning;

void buckets_versioning_free(buckets_versioning *v);
/* ParseConfig + Validate. err gets the reason (as the error's message). */
bool buckets_versioning_parse(const char *xml, size_t len, buckets_versioning *out, char *err, size_t errlen);
/* The stored and returned document (xml.Marshal of the configuration). */
void buckets_versioning_xml(const buckets_versioning *v, buckets_buf *out);

/* PrefixEnabled / PrefixSuspended for an object name ("" for the bucket). */
bool buckets_versioning_enabled_for(const buckets_versioning *v, const char *object);
bool buckets_versioning_suspended_for(const buckets_versioning *v, const char *object);

#endif
