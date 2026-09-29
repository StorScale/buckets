/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_LOGGER_LOGGER_H
#define BUCKETS_LOGGER_LOGGER_H

#include <stdbool.h>
#include <stddef.h>

#include "config/config.h"
#include "core/log.h"
#include "logger/httptarget.h"

/* The server's log and audit targets (MinIO's internal/logger): HTTP
 * targets from the logger_webhook and audit_webhook sub-systems. */

typedef struct buckets_logger buckets_logger;

buckets_logger *buckets_logger_new(void);
void buckets_logger_free(buckets_logger *l);

/* (Re)builds the targets from cfg (for subsys, or all when NULL). The old
 * ones stay when the new configuration is invalid (err says why). */
bool buckets_logger_configure(buckets_logger *l, const buckets_config *cfg, const char *subsys, const char *ca_file,
                              const char *deployment_id, char *err, size_t errlen);
/* The config validators of logger_webhook and audit_webhook. */
bool buckets_logger_validate(const buckets_config *cfg, char *err, size_t errlen);

bool buckets_logger_audit_enabled(buckets_logger *l);
/* An audit entry (JSON) to every audit target. */
void buckets_logger_audit(buckets_logger *l, const char *json, size_t n);
/* A log entry (JSON) to every logger target. */
void buckets_logger_log(buckets_logger *l, const char *json, size_t n);
/* A server warning or error as MinIO's log.Entry, to every logger target. */
void buckets_logger_entry(buckets_logger *l, const char *deployment_id, buckets_log_level level, const char *msg,
                          size_t n);

typedef struct {
  char name[160], endpoint[512];
  bool audit;
  buckets_http_target_stats st;
} buckets_logger_target_info;
/* The targets, logger ones first (SystemTargets, then AuditTargets). */
size_t buckets_logger_targets(buckets_logger *l, buckets_logger_target_info **out);

#endif
