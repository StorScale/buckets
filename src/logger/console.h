/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_LOGGER_CONSOLE_H
#define BUCKETS_LOGGER_CONSOLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The console log (MinIO's HTTPConsoleLoggerSys, for mc admin logs): the
 * last 10000 log records (log.Info JSON) and their subscribers. */

/* madmin.LogMask bits */
enum {
  BUCKETS_LOGMASK_MINIO = 1u << 0,
  BUCKETS_LOGMASK_APPLICATION = 1u << 1,
  BUCKETS_LOGMASK_FATAL = 1u << 2,
  BUCKETS_LOGMASK_WARNING = 1u << 3,
  BUCKETS_LOGMASK_ERROR = 1u << 4,
  BUCKETS_LOGMASK_EVENT = 1u << 5,
  BUCKETS_LOGMASK_INFO = 1u << 6,
  BUCKETS_LOGMASK_ALL = (1u << 7) - 1,
};
/* LogKind.LogMask ("ERROR", "WARNING", ...; anything else: all) */
uint32_t buckets_log_kind_mask(const char *kind);

/* A record: its kind's mask (ALL for plain console messages), whether it
 * has a time (node filters need one), and its log.Info JSON. */
void buckets_console_add(uint32_t mask, bool timed, const char *node, const char *json, size_t n);

typedef struct buckets_console_sub buckets_console_sub;
/* The last `last` records matching node and mask (0 or > 10000: all kept),
 * then new ones as they come. */
buckets_console_sub *buckets_console_subscribe(const char *node, int last, uint32_t mask);
/* Stream reads: records as JSON lines, or " " each idle half second. */
long buckets_console_sub_read(void *sub, char *buf, size_t cap);
/* Adds a record received from a peer (a JSON line). */
void buckets_console_sub_push(buckets_console_sub *s, const char *line, size_t n);
void buckets_console_sub_free(void *sub);

#endif
