/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_ZIPWRITE_H
#define BUCKETS_CORE_ZIPWRITE_H

/* A zip archive built in memory (what Go's archive/zip writes for the
 * admin API's exports): deflated entries, then the central directory. */

#include <stddef.h>
#include <time.h>

#include "core/buf.h"

typedef struct buckets_zipw buckets_zipw;
buckets_zipw *buckets_zipw_new(buckets_buf *out);
/* Adds a file (deflated), modified at mtime, with Unix mode 0600. */
void buckets_zipw_add(buckets_zipw *z, const char *name, const void *data, size_t len, time_t mtime);
/* Writes the central directory and frees z. */
void buckets_zipw_finish(buckets_zipw *z);

#endif
