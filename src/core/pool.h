/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_POOL_H
#define BUCKETS_CORE_POOL_H

#include <stddef.h>

/* A fork/join worker pool for blocking drive I/O. buckets_parallel runs
 * fn(ctx, 0..n-1) across the workers and returns once every call finished;
 * the calling thread takes part, so nested and concurrent calls are safe.
 * Replaces the per-drive goroutines of MinIO's erasure code paths. */
typedef struct buckets_pool buckets_pool;
typedef void (*buckets_par_fn)(void *ctx, size_t i);

buckets_pool *buckets_pool_new(int nthreads);
void buckets_pool_free(buckets_pool *p);
/* With a NULL pool, or n <= 1, runs inline on the caller. */
void buckets_parallel(buckets_pool *p, size_t n, buckets_par_fn fn, void *ctx);

/* The process-wide drive I/O pool (NULL until set: everything runs inline). */
void buckets_io_pool_set(buckets_pool *p);
buckets_pool *buckets_io_pool(void);
/* buckets_parallel on the process-wide pool. */
void buckets_io_parallel(size_t n, buckets_par_fn fn, void *ctx);

#endif
