/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_REPLICATION_H
#define BUCKETS_BUCKET_REPLICATION_H

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* Bucket replication configuration (MinIO internal/bucket/replication): the
 * ReplicationConfiguration document with Go's decoding rules and MinIO's
 * validation, its marshalled form (the bucket metadata's
 * ReplicationConfigXML), and rule evaluation. */

typedef struct {
  char *key, *value;
} buckets_repl_tag;

typedef struct {
  char *id;
  char *status;   /* "Enabled", "Disabled", or as sent */
  long priority;
  char *dm_status;  /* DeleteMarkerReplication */
  char *del_status; /* DeleteReplication (MinIO extension; Disabled when absent) */
  char *existing_status; /* ExistingObjectReplication ("" when absent) */
  char *replica_mod_status; /* SourceSelectionCriteria.ReplicaModifications (Enabled when unset) */
  char *dest_bucket;  /* Destination.Bucket after parseDestination (the ARN, for MinIO ARNs) */
  char *dest_arn;     /* Destination.ARN */
  char *dest_sc;      /* Destination.StorageClass */
  /* Filter */
  char *prefix;
  buckets_repl_tag tag; /* key NULL when unset */
  char *and_prefix;
  buckets_repl_tag *and_tags;
  size_t nand_tags;
} buckets_repl_rule;

typedef struct {
  buckets_repl_rule *rules;
  size_t n;
  char *role; /* Role (legacy single-target ARN), "" when unset */
} buckets_replication;

/* ParseConfig. On failure err holds the description MinIO puts in its
 * MalformedXML response. */
bool buckets_replication_parse(const char *xml, size_t len, buckets_replication *out, char *err, size_t errlen);
void buckets_replication_free(buckets_replication *c);
/* Config.Validate; err as MinIO's replication.Error (a MalformedXML description). */
bool buckets_replication_validate(const buckets_replication *c, const char *bucket, bool same_target, char *err,
                                  size_t errlen);
/* xml.Marshal(config) */
void buckets_replication_xml(const buckets_replication *c, buckets_buf *out);

/* replication.Type */
typedef enum {
  BUCKETS_REPL_UNSET = 0,
  BUCKETS_REPL_OBJECT,
  BUCKETS_REPL_DELETE,
  BUCKETS_REPL_METADATA,
  BUCKETS_REPL_HEAL,
  BUCKETS_REPL_EXISTING,
  BUCKETS_REPL_RESYNC,
  BUCKETS_REPL_ALL,
} buckets_repl_type;

/* replication.ObjectOpts */
typedef struct {
  const char *name;
  const char *user_tags;
  const char *version_id;
  bool delete_marker;
  bool ssec;
  buckets_repl_type op;
  bool replica;
  bool existing;
  const char *target_arn;
} buckets_repl_obj;

/* FilterTargetArns: distinct ARNs, owned (free each, then the array). */
size_t buckets_replication_target_arns(const buckets_replication *c, const buckets_repl_obj *o, char ***arns);
void buckets_replication_arns_free(char **arns, size_t n);
/* Config.Replicate */
bool buckets_replication_replicate(const buckets_replication *c, const buckets_repl_obj *o);
/* HasActiveRules */
bool buckets_replication_has_active_rules(const buckets_replication *c, const char *prefix, bool recursive);
/* HasExistingObjectReplication(arn) */
void buckets_replication_has_existing(const buckets_replication *c, const char *arn, bool *has_arn, bool *enabled);

/* ---- replication status strings ----
 * Per-target statuses are stored as "arn1=PENDING;arn2=COMPLETED;" (the
 * x-minio-internal-replication-status / -purgestatus values). */
#define BUCKETS_RS_PENDING "PENDING"
#define BUCKETS_RS_COMPLETED "COMPLETED"
#define BUCKETS_RS_FAILED "FAILED"
#define BUCKETS_RS_REPLICA "REPLICA"
#define BUCKETS_VPS_PENDING "PENDING"
#define BUCKETS_VPS_COMPLETE "COMPLETE"
#define BUCKETS_VPS_FAILED "FAILED"

/* The status for arn in an internal status string, copied into out ("" when absent). */
void buckets_repl_target_status(const char *internal, const char *arn, char *out, size_t cap);
/* getCompositeReplicationStatus over an internal status string ("" when empty). */
const char *buckets_repl_composite_status(const char *internal);
/* getCompositeVersionPurgeStatus */
const char *buckets_repl_composite_purge(const char *internal);
/* Sets arn's status in an internal status string (appending when absent). */
void buckets_repl_status_set(buckets_buf *internal, const char *arn, const char *status);

/* Reserved metadata keys (x-minio-internal-...). */
#define BUCKETS_META_REPL_STATUS "x-minio-internal-replication-status"
#define BUCKETS_META_REPL_TS "x-minio-internal-replication-timestamp"
#define BUCKETS_META_REPLICA_STATUS "x-minio-internal-replica-status"
#define BUCKETS_META_REPLICA_TS "x-minio-internal-replica-timestamp"
#define BUCKETS_META_PURGE_STATUS "x-minio-internal-purgestatus"
#define BUCKETS_META_REPL_RESET "x-minio-internal-replication-reset"
#define BUCKETS_META_TAGGING_TS "x-minio-internal-tagging-timestamp"
#define BUCKETS_META_RETENTION_TS "x-minio-internal-objectlock-retention-timestamp"
#define BUCKETS_META_LEGALHOLD_TS "x-minio-internal-objectlock-legalhold-timestamp"

#endif
