/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_OSMETRICS_H
#define BUCKETS_STORAGE_OSMETRICS_H

/* The drives' system calls, counted and timed as MinIO's os-instrumented.go
 * does (osMetrics: calls since start and the last minute's latency, for the
 * realtime metrics), and traced as os.<Call> records (mc admin trace --call
 * os). The wrappers behave as the calls they wrap, errno included. */

#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef enum {
  BUCKETS_OSM_REMOVE_ALL,
  BUCKETS_OSM_MKDIR_ALL,
  BUCKETS_OSM_MKDIR,
  BUCKETS_OSM_RENAME,
  BUCKETS_OSM_OPEN_FILE_W,
  BUCKETS_OSM_OPEN_FILE_R,
  BUCKETS_OSM_OPEN_FILE_WFD,
  BUCKETS_OSM_OPEN_FILE_RFD,
  BUCKETS_OSM_OPEN,
  BUCKETS_OSM_OPEN_FILE_DIRECT_IO,
  BUCKETS_OSM_LSTAT,
  BUCKETS_OSM_REMOVE,
  BUCKETS_OSM_STAT,
  BUCKETS_OSM_ACCESS,
  BUCKETS_OSM_CREATE,
  BUCKETS_OSM_READ_DIRENT,
  BUCKETS_OSM_FDATASYNC,
  BUCKETS_OSM_SYNC,
  BUCKETS_OSM__N
} buckets_os_metric;

const char *buckets_os_metric_name(buckets_os_metric m);

/* mode is read when flags hold O_CREAT, as for open(2) */
int buckets_os_open(const char *path, int flags, ...);
int buckets_os_mkdir(const char *path, mode_t mode);
int buckets_os_rename(const char *from, const char *to);
int buckets_os_unlink(const char *path);
int buckets_os_rmdir(const char *path);
int buckets_os_stat(const char *path, struct stat *st);
int buckets_os_lstat(const char *path, struct stat *st);
int buckets_os_access(const char *path, int mode);
DIR *buckets_os_opendir(const char *path);
/* fdatasync where the platform has it, fsync elsewhere (os.Fdatasync). */
int buckets_os_fdatasync(int fd);
int buckets_os_fsync(int fd);

typedef struct {
  uint64_t total[BUCKETS_OSM__N];  /* calls since start */
  uint64_t count[BUCKETS_OSM__N];  /* calls in the last minute */
  uint64_t acc_ns[BUCKETS_OSM__N]; /* their summed latency */
} buckets_os_stats;
void buckets_os_stats_get(buckets_os_stats *out);

#endif
