/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_ADMIN_JOBSTREAM_H
#define BUCKETS_ADMIN_JOBSTREAM_H

/* A response written by a long job in its own thread: what the job emits
 * goes out as it comes, and while nothing does, a keepalive is repeated
 * every so often (MinIO's speedtests write their last result, or an empty
 * one, every 500 ms; internode answers write whitespace). The job is told
 * to stop when the client goes away. */

#include <stdbool.h>
#include <stddef.h>

#include "net/http.h"

typedef struct buckets_jobstream buckets_jobstream;
typedef void (*buckets_job_fn)(buckets_jobstream *j, void *ud);

/* Starts fn(ud); ud_free (may be NULL) runs once the job has finished and
 * the response is done. keepalive: the first keepalive (NULL for none). */
void buckets_jobstream_start(buckets_http_response *resp, buckets_job_fn fn, void *ud, void (*ud_free)(void *),
                             int keepalive_ms, const char *keepalive);
void buckets_jobstream_emit(buckets_jobstream *j, const char *data, size_t n);
void buckets_jobstream_set_keepalive(buckets_jobstream *j, const char *data, size_t n);
bool buckets_jobstream_cancelled(buckets_jobstream *j);

#endif
