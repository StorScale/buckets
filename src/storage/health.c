/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/health.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yyjson.h>

#include "core/log.h"
#include "crypto/aead.h"
#include "crypto/hex.h"

#define PROBE_SIZE 4096

static long long now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static long long wall_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static long env_seconds(const char *name, long dflt) {
  const char *v = getenv(name);
  if (!v || !*v) return dflt;
  char *end;
  long n = strtol(v, &end, 10);
  return *end || n < 0 ? dflt : n;
}

static long long timeout_ms(void) { return env_seconds("BUCKETS_DRIVE_CHECK_TIMEOUT", 30) * 1000; }

/* ---- one check ----------------------------------------------------------------------------- */

/* format.json still names this drive: 0, else an errno (ENOENT: gone; ESTALE: another drive's). */
static int check_identity(buckets_drive *d) {
  if (!*d->drive_id) return 0; /* not formatted yet: nothing to compare */
  char path[4096];
  snprintf(path, sizeof(path), "%s/" BUCKETS_META_BUCKET "/format.json", d->root);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return errno;
  char buf[16384];
  ssize_t n = read(fd, buf, sizeof(buf));
  int e = n < 0 ? errno : 0;
  close(fd);
  if (e) return e;
  yyjson_doc *doc = yyjson_read(buf, (size_t)n, 0);
  const char *self = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(doc), "xl"), "this"));
  e = self && strcasecmp(self, d->drive_id) == 0 ? 0 : ESTALE;
  yyjson_doc_free(doc);
  return e;
}

/* Writes, syncs, reads back and removes a probe file: 0, else an errno. */
static int check_writable(buckets_drive *d) {
  uint8_t data[PROBE_SIZE], back[PROBE_SIZE], r[8];
  buckets_random(r, sizeof(r));
  char hex[17], path[4096];
  buckets_hex_encode(r, sizeof(r), hex);
  hex[16] = '\0';
  snprintf(path, sizeof(path), "%s/" BUCKETS_META_BUCKET "/tmp/.drive-check-%s", d->root, hex);
  buckets_random(data, sizeof(data));
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  if (fd < 0) return errno;
  int e = 0;
  if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data) || fsync(fd) != 0) e = errno ? errno : EIO;
  close(fd);
  if (!e) {
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) e = errno;
    else {
      ssize_t got = pread(fd, back, sizeof(back), 0);
      if (got != (ssize_t)sizeof(back) || memcmp(data, back, sizeof(back)) != 0) e = got < 0 ? errno : EIO;
      close(fd);
    }
  }
  if (unlink(path) != 0 && !e && errno != ENOENT) e = errno;
  return e;
}

static const char *state_name(buckets_drive_health h) {
  switch (h) {
    case BUCKETS_DRIVE_HEALTH_OK: return "ok";
    case BUCKETS_DRIVE_HEALTH_FAULTY: return "faulty";
    case BUCKETS_DRIVE_HEALTH_CHANGED: return "changed";
    case BUCKETS_DRIVE_HEALTH_HUNG: return "hung";
  }
  return "unknown";
}

buckets_drive_health buckets_drive_health_check(buckets_drive *d) {
  if (!d || d->remote) return BUCKETS_DRIVE_HEALTH_OK;
  if (atomic_exchange(&d->checking, true)) return buckets_drive_health_state(d); /* one is running: its answer */
  long long started = now_ms();
  atomic_store(&d->check_started_ms, started);
  int e = check_identity(d);
  buckets_drive_health h = BUCKETS_DRIVE_HEALTH_OK;
  if (e) {
    h = BUCKETS_DRIVE_HEALTH_CHANGED;
    /* a drive that cannot be read at all is faulty, not changed */
    if (e != ENOENT && e != ESTALE) h = BUCKETS_DRIVE_HEALTH_FAULTY;
  } else if ((e = check_writable(d)) != 0) {
    h = BUCKETS_DRIVE_HEALTH_FAULTY;
  }
  long long took = now_ms() - started;
  if (!e && took > timeout_ms()) h = BUCKETS_DRIVE_HEALTH_FAULTY, e = ETIMEDOUT; /* answered, but too slowly */
  buckets_drive_health was = (buckets_drive_health)atomic_exchange(&d->health, (int)h);
  if (h == BUCKETS_DRIVE_HEALTH_CHANGED && was != h) atomic_store(&d->changed_since_ms, wall_ms());
  if (h != BUCKETS_DRIVE_HEALTH_CHANGED) atomic_store(&d->changed_since_ms, 0);
  atomic_store(&d->health_errno, e);
  atomic_store(&d->check_started_ms, 0);
  atomic_store(&d->checking, false);
  if (was != h) {
    char why[256];
    buckets_drive_health_describe(d, why, sizeof(why));
    if (h == BUCKETS_DRIVE_HEALTH_OK) buckets_log_info("drive %s is back online", d->root);
    else buckets_log_warn("drive %s is offline: %s", d->root, why);
  }
  return h;
}

/* ---- the state ---------------------------------------------------------------------------- */

static bool hung(buckets_drive *d) {
  long long started = atomic_load(&d->check_started_ms);
  return started && now_ms() - started > timeout_ms();
}

buckets_drive_health buckets_drive_health_state(buckets_drive *d) {
  if (d && d->health_of) d = d->health_of;
  if (!d || d->remote) return BUCKETS_DRIVE_HEALTH_OK;
  if (hung(d)) return BUCKETS_DRIVE_HEALTH_HUNG;
  return (buckets_drive_health)atomic_load(&d->health);
}

void buckets_drive_health_share(buckets_drive *const *copies, size_t ncopies, buckets_drive *const *drives, size_t n) {
  for (size_t i = 0; i < ncopies; i++) {
    for (size_t j = 0; copies[i] && !copies[i]->remote && j < n; j++) {
      if (drives[j] && !drives[j]->remote && drives[j] != copies[i] && strcmp(drives[j]->root, copies[i]->root) == 0)
        copies[i]->health_of = drives[j];
    }
  }
}

void buckets_drive_health_describe(buckets_drive *d, char *out, size_t cap) {
  if (d && d->health_of) d = d->health_of;
  buckets_drive_health h = buckets_drive_health_state(d);
  int e = d ? atomic_load(&d->health_errno) : 0;
  switch (h) {
    case BUCKETS_DRIVE_HEALTH_OK: snprintf(out, cap, "ok"); break;
    case BUCKETS_DRIVE_HEALTH_HUNG:
      snprintf(out, cap, "hung: a check has not finished in %lld seconds", timeout_ms() / 1000);
      break;
    case BUCKETS_DRIVE_HEALTH_CHANGED:
      snprintf(out, cap, "changed: %s", e == ESTALE ? "format.json names another drive"
                                                    : "format.json is gone (an empty or replaced drive)");
      break;
    default:
      snprintf(out, cap, "%s: %s", state_name(h), e == ETIMEDOUT ? "a check took longer than the timeout" : strerror(e));
  }
}

bool buckets_drive_health_unformatted(buckets_drive *d) {
  return buckets_drive_health_state(d) == BUCKETS_DRIVE_HEALTH_CHANGED && atomic_load(&d->health_errno) == ENOENT;
}

long buckets_drive_health_interval(void) { return env_seconds("BUCKETS_DRIVE_CHECK_INTERVAL", 15); }

/* MinIO's per-call disk ID check: at most once a second, whether format.json is still there. Gone, the drive is
 * changed at once, so the calls in flight stop landing on an emptied disk. */
static void quick_identity(buckets_drive *d) {
  if (!d || d->remote || !*d->drive_id || atomic_load(&d->checking)) return;
  long long now = now_ms(), last = atomic_load(&d->identity_checked_ms);
  if (now - last < 1000 || !atomic_compare_exchange_strong(&d->identity_checked_ms, &last, now)) return;
  char path[4096];
  snprintf(path, sizeof(path), "%s/" BUCKETS_META_BUCKET "/format.json", d->root);
  struct stat st;
  if (stat(path, &st) == 0 || errno != ENOENT) return;
  int ok = BUCKETS_DRIVE_HEALTH_OK;
  if (atomic_compare_exchange_strong(&d->health, &ok, BUCKETS_DRIVE_HEALTH_CHANGED)) {
    atomic_store(&d->health_errno, ENOENT);
    atomic_store(&d->changed_since_ms, wall_ms());
    buckets_log_warn("drive %s is offline: changed: format.json is gone (an empty or replaced drive)", d->root);
  }
}

bool buckets_drive_health_refuses(buckets_drive *d) {
  /* every offline state: a changed drive taking writes would fill an emptied disk with new objects, which
   * then could no longer be told from data and formatted as a replacement */
  if (d && d->health_of) d = d->health_of;
  quick_identity(d);
  return buckets_drive_health_state(d) != BUCKETS_DRIVE_HEALTH_OK;
}

long long buckets_drive_health_changed_since(buckets_drive *d) {
  if (d && d->health_of) d = d->health_of;
  return d ? atomic_load(&d->changed_since_ms) : 0;
}

/* ---- the checkers -------------------------------------------------------------------------- */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static bool g_stop;
static pthread_t *g_threads;
static size_t g_nthreads;

static void *checker(void *arg) {
  buckets_drive *d = arg;
  long interval = env_seconds("BUCKETS_DRIVE_CHECK_INTERVAL", 15);
  for (;;) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += interval;
    pthread_mutex_lock(&g_mu);
    while (!g_stop && pthread_cond_timedwait(&g_cv, &g_mu, &until) == 0) {
    }
    bool stop = g_stop;
    pthread_mutex_unlock(&g_mu);
    if (stop) break;
    buckets_drive_health_check(d);
  }
  return NULL;
}

void buckets_drive_health_start(buckets_drive *const *drives, size_t n) {
  if (env_seconds("BUCKETS_DRIVE_CHECK_INTERVAL", 15) == 0) return;
  pthread_mutex_lock(&g_mu);
  g_stop = false;
  for (size_t i = 0; i < n; i++) {
    if (!drives[i] || drives[i]->remote) continue;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, 256 * 1024);
    pthread_t t;
    if (pthread_create(&t, &a, checker, drives[i]) == 0) {
      g_threads = buckets_xrealloc(g_threads, (g_nthreads + 1) * sizeof(*g_threads));
      g_threads[g_nthreads++] = t;
    } else {
      buckets_log_warn("drive %s: no health checks", drives[i]->root);
    }
    pthread_attr_destroy(&a);
  }
  pthread_mutex_unlock(&g_mu);
}

void buckets_drive_health_stop(void) {
  pthread_mutex_lock(&g_mu);
  g_stop = true;
  pthread_cond_broadcast(&g_cv);
  pthread_t *threads = g_threads;
  size_t n = g_nthreads;
  g_threads = NULL;
  g_nthreads = 0;
  pthread_mutex_unlock(&g_mu);
  for (size_t i = 0; i < n; i++) pthread_join(threads[i], NULL); /* a check in flight finishes first */
  free(threads);
}
