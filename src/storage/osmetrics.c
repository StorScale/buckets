/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/osmetrics.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/timefmt.h"
#include "notify/event.h"
#include "trace/trace.h"

static const char *const k_names[BUCKETS_OSM__N] = {
    "RemoveAll", "MkdirAll", "Mkdir",           "Rename", "OpenFileW", "OpenFileR", "OpenFileWFd", "OpenFileRFd",
    "Open",      "OpenFileDirectIO", "Lstat",   "Remove", "Stat",      "Access",    "Create",      "ReadDirent",
    "Fdatasync", "Sync"};

const char *buckets_os_metric_name(buckets_os_metric m) { return m < BUCKETS_OSM__N ? k_names[m] : ""; }

/* lastMinuteLatency: one slot per second */
typedef struct {
  int64_t sec;
  uint64_t n, ns;
} slot;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static slot g_win[BUCKETS_OSM__N][60];
static _Atomic uint64_t g_total[BUCKETS_OSM__N];

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* osTrace: the paths joined by " -> ", the error as Go's PathError or
 * LinkError reads ("open /a: no such file or directory"). */
static void os_trace(buckets_os_metric m, int64_t dur, const char *op, const char *p1, const char *p2, int err) {
  struct timespec w;
  clock_gettime(CLOCK_REALTIME, &w);
  int64_t start = (int64_t)w.tv_sec * 1000000000LL + w.tv_nsec - dur;
  char when[64];
  buckets_time_rfc3339_nano(start / 1000000000LL, (long)(start % 1000000000LL), when);
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&path, p1 ? p1 : "");
  if (p2) buckets_buf_append_c(&path, " -> "), buckets_buf_append_c(&path, p2);
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&j, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_OS);
  const char *node = buckets_trace_node();
  buckets_json_go_string(&j, node, strlen(node));
  buckets_buf_appendf(&j, ",\"funcname\":\"os.%s\",\"time\":\"%s\",\"path\":", k_names[m], when);
  buckets_json_go_string(&j, path.data ? path.data : "", path.len);
  buckets_buf_appendf(&j, ",\"dur\":%lld", (long long)dur);
  if (err) {
    char msg[512], es[128];
    snprintf(es, sizeof(es), "%s", strerror(err));
    if (es[0]) es[0] = (char)tolower((unsigned char)es[0]);
    if (p2) snprintf(msg, sizeof(msg), "%s %s %s: %s", op, p1, p2, es);
    else snprintf(msg, sizeof(msg), "%s %s: %s", op, p1 ? p1 : "", es);
    buckets_buf_append_c(&j, ",\"error\":");
    buckets_json_go_string(&j, msg, strlen(msg));
  }
  buckets_buf_append_char(&j, '}');
  buckets_trace_meta tm = {.type = BUCKETS_TRACE_OS, .dur_ns = dur};
  buckets_trace_publish(&tm, j.data, j.len);
  buckets_buf_free(&j);
  buckets_buf_free(&path);
}

static void done(buckets_os_metric m, int64_t t0, const char *op, const char *p1, const char *p2, int rc_failed) {
  int saved = errno;
  int64_t dur = mono_ns() - t0;
  atomic_fetch_add(&g_total[m], 1);
  int64_t sec = (t0 + dur) / 1000000000LL;
  pthread_mutex_lock(&g_mu);
  slot *sl = &g_win[m][sec % 60];
  if (sl->sec != sec) *sl = (slot){sec, 0, 0};
  sl->n++;
  sl->ns += dur > 0 ? (uint64_t)dur : 0;
  pthread_mutex_unlock(&g_mu);
  if (buckets_trace_wanted(BUCKETS_TRACE_OS)) os_trace(m, dur, op, p1, p2, rc_failed ? saved : 0);
  errno = saved;
}

int buckets_os_open(const char *path, int flags, ...) {
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  buckets_os_metric m = BUCKETS_OSM_OPEN_FILE_R;
#ifdef O_DIRECT
  if (flags & O_DIRECT) m = BUCKETS_OSM_OPEN_FILE_DIRECT_IO;
  else
#endif
  if (flags & (O_WRONLY | O_RDWR)) m = BUCKETS_OSM_OPEN_FILE_W;
  int64_t t0 = mono_ns();
  int fd = open(path, flags, mode);
  done(m, t0, "open", path, NULL, fd < 0);
  return fd;
}

int buckets_os_mkdir(const char *path, mode_t mode) {
  int64_t t0 = mono_ns();
  int rc = mkdir(path, mode);
  done(BUCKETS_OSM_MKDIR, t0, "mkdir", path, NULL, rc != 0);
  return rc;
}

int buckets_os_rename(const char *from, const char *to) {
  int64_t t0 = mono_ns();
  int rc = rename(from, to);
  done(BUCKETS_OSM_RENAME, t0, "rename", from, to, rc != 0);
  return rc;
}

int buckets_os_unlink(const char *path) {
  int64_t t0 = mono_ns();
  int rc = unlink(path);
  done(BUCKETS_OSM_REMOVE, t0, "remove", path, NULL, rc != 0);
  return rc;
}

int buckets_os_rmdir(const char *path) {
  int64_t t0 = mono_ns();
  int rc = rmdir(path);
  done(BUCKETS_OSM_REMOVE, t0, "remove", path, NULL, rc != 0);
  return rc;
}

int buckets_os_stat(const char *path, struct stat *st) {
  int64_t t0 = mono_ns();
  int rc = stat(path, st);
  done(BUCKETS_OSM_STAT, t0, "stat", path, NULL, rc != 0);
  return rc;
}

int buckets_os_lstat(const char *path, struct stat *st) {
  int64_t t0 = mono_ns();
  int rc = lstat(path, st);
  done(BUCKETS_OSM_LSTAT, t0, "lstat", path, NULL, rc != 0);
  return rc;
}

int buckets_os_access(const char *path, int mode) {
  int64_t t0 = mono_ns();
  int rc = access(path, mode);
  done(BUCKETS_OSM_ACCESS, t0, "access", path, NULL, rc != 0);
  return rc;
}

DIR *buckets_os_opendir(const char *path) {
  int64_t t0 = mono_ns();
  DIR *d = opendir(path);
  done(BUCKETS_OSM_READ_DIRENT, t0, "open", path, NULL, d == NULL);
  return d;
}

int buckets_os_fdatasync(int fd) {
  int64_t t0 = mono_ns();
#if defined(__linux__)
  int rc = fdatasync(fd);
#else
  int rc = fsync(fd);
#endif
  done(BUCKETS_OSM_FDATASYNC, t0, "fdatasync", "", NULL, rc != 0);
  return rc;
}

int buckets_os_fsync(int fd) {
  int64_t t0 = mono_ns();
  int rc = fsync(fd);
  done(BUCKETS_OSM_SYNC, t0, "sync", "", NULL, rc != 0);
  return rc;
}

void buckets_os_stats_get(buckets_os_stats *out) {
  memset(out, 0, sizeof(*out));
  int64_t now = mono_ns() / 1000000000LL;
  pthread_mutex_lock(&g_mu);
  for (int m = 0; m < BUCKETS_OSM__N; m++) {
    out->total[m] = atomic_load(&g_total[m]);
    for (int i = 0; i < 60; i++) {
      const slot *sl = &g_win[m][i];
      if (sl->n && now - sl->sec < 60) out->count[m] += sl->n, out->acc_ns[m] += sl->ns;
    }
  }
  pthread_mutex_unlock(&g_mu);
}
