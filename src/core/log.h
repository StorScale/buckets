/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_LOG_H
#define BUCKETS_CORE_LOG_H

#include "core/common.h"

/* Structured logging: one JSON object per line on stderr, which is what
 * Kubernetes log collectors expect. */
typedef enum {
  BUCKETS_LOG_DEBUG = 0,
  BUCKETS_LOG_INFO,
  BUCKETS_LOG_WARN,
  BUCKETS_LOG_ERROR,
} buckets_log_level;

void buckets_log_set_level(buckets_log_level level);
bool buckets_log_parse_level(const char *s, buckets_log_level *out);
void buckets_log(buckets_log_level level, const char *fmt, ...) BUCKETS_PRINTF(2, 3);
/* Warnings and errors logged since start (whatever the level): what the
 * console log target has sent, for the metrics. */
uint64_t buckets_log_problems(void);

#define buckets_log_debug(...) buckets_log(BUCKETS_LOG_DEBUG, __VA_ARGS__)
#define buckets_log_info(...) buckets_log(BUCKETS_LOG_INFO, __VA_ARGS__)
#define buckets_log_warn(...) buckets_log(BUCKETS_LOG_WARN, __VA_ARGS__)
#define buckets_log_error(...) buckets_log(BUCKETS_LOG_ERROR, __VA_ARGS__)

#endif
