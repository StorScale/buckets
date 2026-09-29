/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_METRICS_SYS_H
#define BUCKETS_METRICS_SYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Process and host figures for the metrics (what MinIO takes from Go's
 * runtime, client_golang's process collector and gopsutil). Fields a
 * platform cannot provide are left 0 and their have_* flag false. */

typedef struct {
  double cpu_seconds;         /* user + system */
  double start_time;          /* unix seconds */
  uint64_t open_fds, max_fds;
  double vm_max;              /* RLIMIT_AS (as a float; "unlimited" is 2^63-1) */
  uint64_t resident, virtual_size;
  bool have_memory;           /* resident and virtual sizes */
  uint64_t threads;
  /* /proc/self/io (Linux) */
  bool have_io;
  uint64_t rchar, wchar, read_bytes, write_bytes, syscr, syscw;
  /* allocator statistics standing in for Go's memstats */
  uint64_t heap_in_use, heap_system, allocations, frees;
} buckets_proc_stats;
void buckets_proc_stats_get(buckets_proc_stats *out);

typedef struct {
  uint64_t total, used, free, shared, buffers, cache, available;
} buckets_mem_stats;
bool buckets_mem_stats_get(buckets_mem_stats *out);

typedef struct {
  double load1, load5, load15;
  int cpus;
  bool have_times; /* user..steal: shares of all CPU time since boot */
  double user, system, idle, iowait, nice, steal;
} buckets_cpu_stats;
bool buckets_cpu_stats_get(buckets_cpu_stats *out);

/* Cumulative I/O counters of the block device holding path (Linux
 * /proc/diskstats); false elsewhere or when the device is not found. */
typedef struct {
  uint64_t reads, read_sectors, read_ms, writes, write_sectors, write_ms, busy_ms;
} buckets_disk_io;
bool buckets_disk_io_get(const char *path, buckets_disk_io *out);

/* The first non-loopback interface's cumulative counters (Linux). */
typedef struct {
  char name[64];
  uint64_t rx_bytes, rx_errors, tx_bytes, tx_errors;
} buckets_net_stats;
bool buckets_net_stats_get(buckets_net_stats *out);

#endif
