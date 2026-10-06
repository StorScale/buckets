/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_BUCKETSPEC_H
#define BUCKETS_OPERATOR_BUCKETSPEC_H

/* A Bucket resource's settings (docs/design/declarative-buckets.md), turned
 * into what the S3 and admin APIs take. Pure: no I/O, unit tested.
 *
 *   versioning: true | false                 Enabled / Suspended
 *   objectLock: true | {mode: GOVERNANCE|COMPLIANCE, days | years}
 *   quota: "100Gi" | "" | null               a hard quota; empty: none
 *   encryption: {kmsKey} | {sse: "S3"} | {}    {} removes it
 *   lifecycle: [{id, prefix?, expireDays?, noncurrentExpireDays?, abortIncompleteUploadDays?,
 *                expireDeleteMarkers?}]      [] removes the rules
 *   replication: {target: {cluster} | {endpoint, bucket, credsSecret: {name}},
 *                 deletes?, deleteMarkers?, existingObjects?} | {}   {} removes it
 * (Not null for removing: Kubernetes drops a null field, and a dropped field is not managed.)
 * A field left out of the spec is not managed. */

#include <stdbool.h>
#include <stdint.h>
#include <yyjson.h>

#include "core/buf.h"

/* Checks the settings; false and why, in words for the person who wrote them. */
bool bspec_check(yyjson_val *spec, char *err, size_t errlen);

/* A hash of the managed settings (16 hex digits): the same settings give the same hash whatever the key
 * order. */
void bspec_hash(yyjson_val *spec, char out[17]);

/* "100Gi", "1.5T", "500000" -> bytes; false when it is not a size. "" and NULL -> 0 (no quota). */
bool bspec_size(const char *s, uint64_t *out);

void bspec_versioning_xml(bool on, buckets_buf *out);
/* Whether objectLock asks for a default retention, and its XML. */
bool bspec_object_lock_xml(yyjson_val *lock, buckets_buf *out);
void bspec_quota_json(uint64_t bytes, buckets_buf *out);
/* {} or null: a setting removed. */
bool bspec_empty(yyjson_val *v);
/* false when encryption is {} (remove it). */
bool bspec_encryption_xml(yyjson_val *enc, buckets_buf *out);
/* false when rules is empty (remove them). */
bool bspec_lifecycle_xml(yyjson_val *rules, buckets_buf *out);

/* The replication configuration sending everything to the remote target arn. */
void bspec_replication_xml(yyjson_val *repl, const char *arn, buckets_buf *out);
/* The policy of the user a source cluster replicates into bucket with. */
void bspec_replication_policy(const char *bucket, buckets_buf *out);
/* That user's access key (20 characters) for a source cluster's bucket replicating into target_bucket, and
 * its secret key, derived from the target cluster's root secret key (41 bytes each with the NUL). */
void bspec_replication_user(const char *ns, const char *cluster, const char *bucket,
                            const char *target_cluster, const char *target_bucket, const char *target_root_sk,
                            char ak[21], char sk[41]);

/* What a configuration document says, for comparing what was applied with what the bucket has:
 * "Tag=value;" for each element named in tags (NULL-ended) that holds text, in document order. The
 * same tags over the document sent and the one read back give the same signature when nothing
 * drifted, whatever the formatting and the elements the server adds. */
void bspec_xml_sig(const char *xml, size_t n, const char *const *tags, buckets_buf *out);
extern const char *const bspec_versioning_tags[],
    *const bspec_object_lock_tags[], *const bspec_encryption_tags[], *const bspec_lifecycle_tags[],
                                                                         *const bspec_replication_tags[];

#endif
