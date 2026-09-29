/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NOTIFY_TARGETS_H
#define BUCKETS_NOTIFY_TARGETS_H

#include "config/config.h"
#include "notify/target.h"

/* The notification targets of every enabled notify_* target in the
 * configuration (config/notify.FetchEnabledTargets). */
bool buckets_targets_build(const buckets_config *cfg, const char *ca_file, buckets_target ***out, size_t *n, char *err,
                           size_t errlen);
/* The same checks without starting anything. */
bool buckets_targets_check(const buckets_config *cfg, char *err, size_t errlen);

/* Target implementations: each validates its target's settings and, when
 * impl is not NULL, creates it. */
typedef struct {
  const char *subsys; /* "notify_webhook" */
  const buckets_target_ops *ops;
  bool (*create)(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen);
} buckets_target_kind;

extern const buckets_target_kind buckets_target_webhook;

#endif
