/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_METASYS_H
#define BUCKETS_BUCKET_METASYS_H

#include <stdatomic.h>

#include "bucket/metadata.h"
#include "bucket/versioning.h"
#include "iam/policy.h"

/* The bucket metadata cache (MinIO's BucketMetadataSys): immutable,
 * reference-counted snapshots of each bucket's metadata with its parsed
 * configurations, loaded on first use and replaced on update. */

typedef struct {
  _Atomic int refs;
  bool exists; /* .metadata.bin was found */
  buckets_bucket_meta meta;
  buckets_policy *policy; /* parsed PolicyConfigJSON, or NULL */
  buckets_versioning versioning; /* parsed VersioningConfigXML (status UNSET when none) */
  long long loaded_ns;
} buckets_bucket_state;

typedef struct buckets_metasys buckets_metasys;

/* ttl_ms: how long a snapshot is trusted before reloading (0 = until
 * invalidated; use a TTL when other servers can change metadata). */
buckets_metasys *buckets_metasys_new(buckets_objlayer *layer, int ttl_ms);
void buckets_metasys_free(buckets_metasys *m);

/* The bucket's snapshot (never NULL; exists=false when it has none). */
buckets_bucket_state *buckets_metasys_get(buckets_metasys *m, const char *bucket);
void buckets_bucket_state_release(buckets_bucket_state *st);

/* Sets (data != NULL) or clears one configuration, saves, and publishes the
 * new snapshot. Creates the metadata if the bucket had none. */
bool buckets_metasys_update(buckets_metasys *m, const char *bucket, buckets_bucket_cfg cfg, const void *data,
                            size_t len);
void buckets_metasys_invalidate(buckets_metasys *m, const char *bucket);
/* Called after a local change to a bucket's metadata (or the bucket being
 * created or deleted), to tell other servers. */
void buckets_metasys_set_notify(buckets_metasys *m, void (*fn)(void *ud, const char *bucket), void *ud);
/* Invalidates and notifies: for changes made outside buckets_metasys_update. */
void buckets_metasys_changed(buckets_metasys *m, const char *bucket);

#endif
