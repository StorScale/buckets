/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_NOTIFICATION_H
#define BUCKETS_BUCKET_NOTIFICATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"
#include "s3/errors.h"

/* Bucket notification configuration (MinIO's internal/event: names, ARNs,
 * Config, RulesMap). Queue configurations name targets by ARN,
 * arn:minio:sqs:<region>:<id>:<type>, and select events by name and an
 * optional key prefix/suffix. */

typedef enum {
  BUCKETS_EV_NONE = 0,
  BUCKETS_EV_OBJECT_ACCESSED_GET,
  BUCKETS_EV_OBJECT_ACCESSED_GET_RETENTION,
  BUCKETS_EV_OBJECT_ACCESSED_GET_LEGAL_HOLD,
  BUCKETS_EV_OBJECT_ACCESSED_HEAD,
  BUCKETS_EV_OBJECT_ACCESSED_ATTRIBUTES,
  BUCKETS_EV_OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD,
  BUCKETS_EV_OBJECT_CREATED_COPY,
  BUCKETS_EV_OBJECT_CREATED_POST,
  BUCKETS_EV_OBJECT_CREATED_PUT,
  BUCKETS_EV_OBJECT_CREATED_PUT_RETENTION,
  BUCKETS_EV_OBJECT_CREATED_PUT_LEGAL_HOLD,
  BUCKETS_EV_OBJECT_CREATED_PUT_TAGGING,
  BUCKETS_EV_OBJECT_CREATED_DELETE_TAGGING,
  BUCKETS_EV_OBJECT_REMOVED_DELETE,
  BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED,
  BUCKETS_EV_OBJECT_REMOVED_DELETE_ALL_VERSIONS,
  BUCKETS_EV_OBJECT_REMOVED_NOOP,
  BUCKETS_EV_BUCKET_CREATED,
  BUCKETS_EV_BUCKET_REMOVED,
  BUCKETS_EV_OBJECT_REPLICATION_FAILED,
  BUCKETS_EV_OBJECT_REPLICATION_COMPLETE,
  BUCKETS_EV_OBJECT_REPLICATION_MISSED_THRESHOLD,
  BUCKETS_EV_OBJECT_REPLICATION_REPLICATED_AFTER_THRESHOLD,
  BUCKETS_EV_OBJECT_REPLICATION_NOT_TRACKED,
  BUCKETS_EV_OBJECT_RESTORE_POST,
  BUCKETS_EV_OBJECT_RESTORE_COMPLETED,
  BUCKETS_EV_OBJECT_TRANSITION_FAILED,
  BUCKETS_EV_OBJECT_TRANSITION_COMPLETE,
  BUCKETS_EV_OBJECT_MANY_VERSIONS,
  BUCKETS_EV_OBJECT_LARGE_VERSIONS,
  BUCKETS_EV_PREFIX_MANY_FOLDERS,
  BUCKETS_EV_ILM_DEL_MARKER_EXPIRATION_DELETE,
  BUCKETS_EV__SINGLE_END,
  /* compound names, expanded to the single ones */
  BUCKETS_EV_OBJECT_ACCESSED_ALL,
  BUCKETS_EV_OBJECT_CREATED_ALL,
  BUCKETS_EV_OBJECT_REMOVED_ALL,
  BUCKETS_EV_OBJECT_REPLICATION_ALL,
  BUCKETS_EV_OBJECT_RESTORE_ALL,
  BUCKETS_EV_OBJECT_TRANSITION_ALL,
  BUCKETS_EV_OBJECT_SCANNER_ALL,
  BUCKETS_EV_EVERYTHING,
} buckets_event_name;

const char *buckets_event_name_str(buckets_event_name n);
buckets_event_name buckets_event_name_parse(const char *s); /* NONE when unknown */
uint64_t buckets_event_name_mask(buckets_event_name n);     /* compound names expanded */

/* A target, as named in an ARN: ID ("1", "_", "primary") and type ("webhook"). */
typedef struct {
  char id[128];
  char type[32];
} buckets_target_id;

typedef struct {
  char id[256]; /* <Id> */
  struct {
    char name[8]; /* "prefix" or "suffix" */
    char value[1025];
  } rules[2]; /* <Filter><S3Key><FilterRule>, in document order */
  size_t nrules;
  buckets_event_name *events;
  size_t nevents;
  buckets_target_id target;
  char region[64];
} buckets_notify_queue;

typedef struct {
  char xmlns[256];
  buckets_notify_queue *queues;
  size_t nqueues;
} buckets_notify_config;

/* Whether a target exists (TargetList.Exists). */
typedef bool (*buckets_target_exists_fn)(void *ud, const buckets_target_id *id);

/* ParseConfig: decodes, validates against region and the targets, and sets
 * the region into every ARN. On failure *err is MinIO's S3 error
 * (MalformedXML, or an InvalidArgument / UnsupportedNotification from the
 * event package) and msg says why. */
bool buckets_notify_config_parse(const char *xml, size_t n, const char *region, buckets_target_exists_fn exists,
                                 void *ud, buckets_notify_config *out, buckets_s3_error *err, char *msg, size_t cap);
/* A stored configuration, decoded without checking the targets (they may
 * have been removed since). */
bool buckets_notify_config_load(const char *xml, size_t n, buckets_notify_config *out);
void buckets_notify_config_free(buckets_notify_config *c);
/* xml.Marshal of the configuration (region set as given). */
void buckets_notify_config_xml(const buckets_notify_config *c, const char *region, buckets_buf *out);
/* Removes queues whose target is gone (GetBucketNotificationHandler). */
void buckets_notify_config_prune(buckets_notify_config *c, buckets_target_exists_fn exists, void *ud);

/* The targets a configuration selects for an event on key (RulesMap.Match);
 * returns how many were written to out. */
size_t buckets_notify_config_match(const buckets_notify_config *c, buckets_event_name ev, const char *key,
                                   buckets_target_id *out, size_t cap);

#endif
