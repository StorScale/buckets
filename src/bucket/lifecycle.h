/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_LIFECYCLE_H
#define BUCKETS_BUCKET_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* Bucket lifecycle (MinIO internal/bucket/lifecycle): the configuration's
 * XML with Go's decoding rules and MinIO's validation, its marshalled form
 * (the bucket metadata's LifecycleConfigXML), and rule evaluation. */

typedef struct {
  char *key, *value;
} buckets_lc_tag;

typedef struct {
  bool set; /* <Filter> was present */
  bool prefix_set;
  char *prefix;
  int64_t size_gt, size_lt;
  bool tag_set; /* <Tag> directly in the filter */
  buckets_lc_tag tag;
  /* <And> */
  bool and_prefix_set;
  char *and_prefix;
  int64_t and_size_gt, and_size_lt;
  buckets_lc_tag *and_tags;
  size_t nand_tags;
} buckets_lc_filter;

typedef struct {
  char *id;
  char *status; /* "Enabled", "Disabled", or whatever was sent */
  buckets_lc_filter filter;
  bool prefix_set; /* the deprecated rule-level <Prefix> */
  char *prefix;
  /* <Expiration> */
  bool exp_set;
  int64_t exp_days;
  int64_t exp_date; /* unix seconds of a midnight UTC, 0 when unset */
  bool exp_dm_set, exp_dm;   /* ExpiredObjectDeleteMarker */
  bool exp_all_set, exp_all; /* ExpiredObjectAllVersions */
  /* <Transition> */
  bool tr_set;
  int64_t tr_days;
  int64_t tr_date;
  char *tr_class;
  /* <DelMarkerExpiration> */
  int64_t dm_days;
  /* <NoncurrentVersionExpiration> */
  bool nve_set;
  int64_t nve_days, nve_newer;
  /* <NoncurrentVersionTransition> */
  bool nvt_set;
  int64_t nvt_days;
  char *nvt_class;
} buckets_lc_rule;

typedef struct {
  buckets_lc_rule *rules;
  size_t n;
  int64_t expiry_updated_ns; /* ExpiryUpdatedAt, 0 when unset */
} buckets_lifecycle;

/* How a parse or validation failure maps to an S3 error (toAPIError):
 * lifecycle.Error is InvalidArgument; Go decoder errors are internal
 * errors, or MalformedXML for syntax, BadRequest for out-of-range numbers. */
typedef enum {
  BUCKETS_LC_OK = 0,
  BUCKETS_LC_ERR_INVALID,   /* InvalidArgument: msg */
  BUCKETS_LC_ERR_INTERNAL,  /* InternalError: cause(msg) */
  BUCKETS_LC_ERR_MALFORMED, /* MalformedXML */
  BUCKETS_LC_ERR_RANGE,     /* BadRequest: msg */
  BUCKETS_LC_ERR_STORAGE_CLASS, /* InvalidStorageClass: no such tier */
} buckets_lc_err;

typedef struct {
  buckets_lc_err code;
  char msg[256];
} buckets_lc_error;

void buckets_lifecycle_free(buckets_lifecycle *lc);
/* ParseLifecycleConfigWithID (with_ids: missing rule IDs get a random UUID)
 * or ParseLifecycleConfig. */
bool buckets_lifecycle_parse(const char *xml, size_t len, bool with_ids, buckets_lifecycle *out, buckets_lc_error *err);
/* Lifecycle.Validate, plus validateTransitionTier (tier_valid NULL: no tiers). */
bool buckets_lifecycle_validate(const buckets_lifecycle *lc, bool lock_enabled, bool (*tier_valid)(void *ud, const char *tier),
                                void *ud, buckets_lc_error *err);
/* xml.Marshal: with_updated_at includes ExpiryUpdatedAt. */
void buckets_lifecycle_xml(const buckets_lifecycle *lc, bool with_updated_at, buckets_buf *out);
bool buckets_lifecycle_has_expiry(const buckets_lifecycle *lc);
bool buckets_lc_rule_has_expiry(const buckets_lc_rule *r);

typedef enum {
  BUCKETS_LC_NONE = 0,
  BUCKETS_LC_DELETE,
  BUCKETS_LC_DELETE_VERSION,
  BUCKETS_LC_TRANSITION,
  BUCKETS_LC_TRANSITION_VERSION,
  BUCKETS_LC_DELETE_RESTORED,
  BUCKETS_LC_DELETE_RESTORED_VERSION,
  BUCKETS_LC_DELETE_ALL_VERSIONS,
  BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS,
} buckets_lc_action;

/* lifecycle.ObjectOpts */
typedef struct {
  const char *name;
  const char *user_tags;  /* X-Amz-Tagging, or NULL */
  int64_t mod_time_ns;
  int64_t size;
  const char *version_id; /* "" for the null version of an unversioned bucket */
  bool is_latest, delete_marker;
  size_t num_versions;
  int64_t successor_mod_time_ns;
  bool locked; /* a legal hold, or retention in the future (Evaluator.IsObjectLocked) */
} buckets_lc_obj;

typedef struct {
  buckets_lc_action action;
  const char *rule_id; /* into the configuration */
  int64_t due_ns;
  const char *storage_class;
} buckets_lc_event;

/* Lifecycle.eval: now_ns 0 is Go's zero time (every rule is due; used for
 * the prediction headers). */
buckets_lc_event buckets_lifecycle_eval(const buckets_lifecycle *lc, const buckets_lc_obj *obj, int64_t now_ns,
                                        size_t remaining_versions);
/* Evaluator.eval over every version of one object, newest first. */
void buckets_lifecycle_eval_versions(const buckets_lifecycle *lc, bool lock_enabled, const buckets_lc_obj *objs, size_t n,
                                     int64_t now_ns, buckets_lc_event *events);
/* SetPredictionHeaders: "x-amz-expiration" (or "x-minio-transition") value
 * for obj, into value; returns the header name or NULL. */
const char *buckets_lifecycle_prediction(const buckets_lifecycle *lc, const buckets_lc_obj *obj, char *value, size_t cap);
/* ExpectedExpiryTime */
int64_t buckets_lc_expected_expiry(int64_t mod_time_ns, int64_t days);

#endif
