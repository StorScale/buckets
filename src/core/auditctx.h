/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_AUDITCTX_H
#define BUCKETS_CORE_AUDITCTX_H

#include "core/buf.h"

/* The request being audited on this thread (MinIO's ReqInfo tags): the
 * object layer tags the operations it performs; later tags of a key replace
 * earlier ones, as in the audit entry's map. */

typedef struct {
  char **keys, **values;
  size_t n, cap;
  const char *delete_op; /* the name deletes are tagged with ("DeleteObject" when NULL) */
  bool sys_ops;          /* tag the server's own metadata too (bucket configuration updates) */
  bool paused;           /* tag nothing (a handler's own lookups MinIO does not make) */
} buckets_audit_tags;

/* Starts (t) or stops (NULL) collecting on this thread. */
void buckets_audit_tags_set(buckets_audit_tags *t);
buckets_audit_tags *buckets_audit_tags_current(void);
/* Appends key=value to the current request's tags (nothing when none). */
void buckets_audit_tag(const char *key, const char *value);
void buckets_audit_tags_free(buckets_audit_tags *t);

/* Entries for what the server does on its own (MinIO's auditLogInternal:
 * healing, lifecycle expiry): event (also the trigger), the API name (may
 * be empty), the object and its version, an error (NULL: none) and tags. */
typedef void (*buckets_audit_internal_fn)(void *ud, const char *event, const char *api_name, const char *bucket,
                                          const char *object, const char *version_id, const char *error,
                                          const char *const *keys, const char *const *values, size_t ntags);
void buckets_audit_internal_set(buckets_audit_internal_fn fn, void *ud);
void buckets_audit_internal(const char *event, const char *api_name, const char *bucket, const char *object,
                            const char *version_id, const char *error, const char *const *keys,
                            const char *const *values, size_t ntags);

#endif
