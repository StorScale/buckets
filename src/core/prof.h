/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_PROF_H
#define BUCKETS_CORE_PROF_H

/* Profiles in pprof's format (gzipped profile.proto), which `go tool pprof`
 * reads (it symbolizes the addresses against the binary, as for any native
 * program): CPU samples taken by SIGPROF at 100 Hz, a heap snapshot, the
 * threads, and empty block and mutex profiles (the types MinIO's profiling
 * API offers). */

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* One CPU profile at a time; false (err set) when one is running. */
bool buckets_prof_cpu_start(char *err, size_t errcap);
/* Stops it and writes the profile. */
void buckets_prof_cpu_stop(buckets_buf *out);

/* The heap in use now (one sample: what the allocator holds). */
void buckets_prof_heap(buckets_buf *out);
/* The threads (threadcreate: one sample per thread). */
void buckets_prof_threads(buckets_buf *out);
/* A profile of the given sample types with no samples ("contentions/count,
 * delay/nanoseconds" for block and mutex). */
void buckets_prof_empty(const char *type1, const char *unit1, const char *type2, const char *unit2, buckets_buf *out);
/* The threads as text (the goroutine profile's place). */
void buckets_prof_threads_text(buckets_buf *out);

#endif
