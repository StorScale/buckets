/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_OBJECTLOCK_H
#define BUCKETS_BUCKET_OBJECTLOCK_H

#include <stdbool.h>
#include <stdint.h>

#include "core/buf.h"

/* Object lock (MinIO's internal/bucket/object/lock): the bucket's
 * ObjectLockConfiguration and per-object retention and legal hold, which
 * live in the object's metadata under these keys. */
#define BUCKETS_LOCK_MODE_META "x-amz-object-lock-mode"
#define BUCKETS_LOCK_UNTIL_META "x-amz-object-lock-retain-until-date"
#define BUCKETS_LOCK_HOLD_META "x-amz-object-lock-legal-hold"
#define BUCKETS_LOCK_RET_TS_META "x-minio-internal-objectlock-retention-timestamp"
#define BUCKETS_LOCK_HOLD_TS_META "x-minio-internal-objectlock-legalhold-timestamp"

typedef enum { BUCKETS_RET_NONE = 0, BUCKETS_RET_GOVERNANCE, BUCKETS_RET_COMPLIANCE } buckets_ret_mode;

typedef struct {
  bool enabled;         /* ObjectLockEnabled */
  buckets_ret_mode mode; /* default retention, NONE without a rule */
  uint64_t days, years;  /* one of them, with a rule */
  char xmlns[128];       /* the document's namespace ("" for none) */
} buckets_lock_config;

/* ParseObjectLockConfig; err gets the message. */
bool buckets_lock_config_parse(const char *xml, size_t len, buckets_lock_config *out, char *err, size_t errlen);
void buckets_lock_config_xml(const buckets_lock_config *c, buckets_buf *out);
/* The default retention's length from now (ToRetention), in seconds; 0 without a rule. */
int64_t buckets_lock_config_validity(const buckets_lock_config *c, int64_t now_sec);

const char *buckets_ret_mode_name(buckets_ret_mode m); /* "GOVERNANCE", "COMPLIANCE", "" */
buckets_ret_mode buckets_ret_mode_parse(const char *s); /* case-insensitive; NONE when neither */

typedef enum {
  BUCKETS_LOCK_OK = 0,
  BUCKETS_LOCK_MALFORMED_XML,
  BUCKETS_LOCK_INVALID_DATE,  /* ErrInvalidRetentionDate */
  BUCKETS_LOCK_PAST_DATE,     /* ErrPastObjectLockRetainDate */
  BUCKETS_LOCK_UNKNOWN_MODE,  /* ErrUnknownWORMModeDirective */
  BUCKETS_LOCK_INVALID_HEADERS, /* ErrObjectLockInvalidHeaders */
} buckets_lock_err;

/* ParseObjectRetention: mode NONE with until 0 clears the retention. */
buckets_lock_err buckets_lock_parse_retention(const char *xml, size_t len, int64_t now_ns, buckets_ret_mode *mode,
                                              int64_t *until_ns, char *err, size_t errlen);
/* ParseObjectLegalHold: *on. */
buckets_lock_err buckets_lock_parse_legal_hold(const char *xml, size_t len, bool *on, char *err, size_t errlen);
/* ParseObjectLockRetentionHeaders (mode and date strings, either may be NULL). */
buckets_lock_err buckets_lock_parse_retention_headers(const char *mode, const char *date, int64_t now_ns,
                                                      buckets_ret_mode *out_mode, int64_t *until_ns);

/* The message MinIO gives each error (the Go error text). */
const char *buckets_lock_strerror(buckets_lock_err e);

#endif
