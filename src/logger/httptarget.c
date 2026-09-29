/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "logger/httptarget.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "compress/s2.h"
#include "core/buf.h"
#include "core/common.h"
#include "core/log.h"
#include "core/uuid.h"
#include "net/fetch.h"

#define STORE_EXT ".http.log"

typedef struct entry {
  struct entry *next;
  char *json;
  size_t n;
} entry;

struct buckets_http_target {
  buckets_http_target_cfg cfg; /* strings owned */
  char *store_dir;             /* NULL: memory */
  pthread_mutex_t mu;
  pthread_cond_t cv;
  entry *head, *tail;
  size_t n;
  bool stop;
  pthread_t worker, replayer;
  bool worker_started, replayer_started;
  uint64_t total, failed;
  bool online;
};

static char *dup_or_null(const char *s) { return s && *s ? buckets_xstrdup(s) : NULL; }

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Waits up to ms (or until woken); false once stopping. Called locked. */
static bool wait_locked(buckets_http_target *t, int64_t ms) {
  if (t->stop) return false;
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += ms / 1000;
  until.tv_nsec += (long)(ms % 1000) * 1000000L;
  if (until.tv_nsec >= 1000000000L) until.tv_sec++, until.tv_nsec -= 1000000000L;
  pthread_cond_timedwait(&t->cv, &t->mu, &until);
  return !t->stop;
}

/* send(): one POST of count entries */
static bool post(buckets_http_target *t, const char *body, size_t len, size_t count) {
  char cnt[24];
  snprintf(cnt, sizeof(cnt), "%zu", count);
  buckets_http_kv h[6];
  size_t nh = 0;
  h[nh++] = (buckets_http_kv){"Content-Type", "application/json"};
  h[nh++] = (buckets_http_kv){"x-minio-webhook-payload-count", cnt};
  h[nh++] = (buckets_http_kv){"x-minio-version", BUCKETS_VERSION};
  h[nh++] = (buckets_http_kv){"x-minio-deployment-id", t->cfg.deployment_id ? t->cfg.deployment_id : ""};
  if (t->cfg.user_agent) h[nh++] = (buckets_http_kv){"User-Agent", t->cfg.user_agent};
  if (t->cfg.auth_token) h[nh++] = (buckets_http_kv){"Authorization", t->cfg.auth_token};
  buckets_http_result r;
  char err[256];
  bool ok = buckets_fetch("POST", t->cfg.endpoint, t->cfg.ca_file, h, nh, body, len, t->cfg.http_timeout_ms, &r, err,
                          sizeof(err));
  bool reached = ok;
  if (ok) {
    ok = r.status >= 200 && r.status <= 299;
    if (!ok) snprintf(err, sizeof(err), "%s returned '%d', please check your endpoint configuration", t->cfg.endpoint, r.status);
    buckets_http_result_free(&r);
  }
  pthread_mutex_lock(&t->mu);
  if (!ok) t->failed += count;
  t->online = ok || reached;
  pthread_mutex_unlock(&t->mu);
  if (!ok) buckets_log_warn("unable to send audit/log entry(s) to '%s' err '%s': %zu", t->cfg.name, err, count);
  return ok;
}

/* ---- the queue store (MinIO's QueueStore.PutMultiple / GetMultiple) ---- */

static size_t store_count(const char *dir) {
  DIR *d = opendir(dir);
  if (!d) return 0;
  size_t n = 0;
  struct dirent *e;
  while ((e = readdir(d)))
    if (e->d_name[0] != '.' && strstr(e->d_name, STORE_EXT)) n++;
  closedir(d);
  return n;
}

/* count entries as one compressed file: "[<count>:]<uuid>.http.log.snappy" */
static bool store_put(buckets_http_target *t, const buckets_buf *lines, size_t count) {
  char id[40], name[128], path[4096], tmp[4200];
  buckets_uuid_v4(id);
  if (count > 1) snprintf(name, sizeof(name), "%zu:%s" STORE_EXT ".snappy", count, id);
  else snprintf(name, sizeof(name), "%s" STORE_EXT ".snappy", id);
  snprintf(path, sizeof(path), "%s/%s", t->store_dir, name);
  snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", t->store_dir, id);
  uint8_t *enc = buckets_xmalloc(buckets_s2_max_encoded_len(lines->len));
  size_t en = buckets_s2_encode(enc, (const uint8_t *)lines->data, lines->len);
  FILE *f = fopen(tmp, "w");
  bool ok = f && fwrite(enc, 1, en, f) == en;
  if (f) ok = fclose(f) == 0 && ok;
  free(enc);
  if (ok) ok = rename(tmp, path) == 0;
  if (!ok) unlink(tmp);
  return ok;
}

static bool store_oldest(const char *dir, char *out, size_t cap) {
  DIR *d = opendir(dir);
  if (!d) return false;
  bool found = false;
  int64_t best = 0;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] == '.' || !strstr(e->d_name, STORE_EXT)) continue;
    char p[4096];
    snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
    struct stat st;
    if (stat(p, &st) != 0) continue;
#ifdef __APPLE__
    int64_t mt = (int64_t)st.st_mtimespec.tv_sec * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
    int64_t mt = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
#endif
    if (!found || mt < best) {
      snprintf(out, cap, "%s", e->d_name);
      best = mt;
      found = true;
    }
  }
  closedir(d);
  return found;
}

/* The replay loop (store.StreamItems): the oldest entry first, kept until sent. */
static void *replay_main(void *arg) {
  buckets_http_target *t = arg;
  buckets_log_sink_suppress(true); /* our own delivery failures are not log entries for us */
  pthread_mutex_lock(&t->mu);
  while (!t->stop) {
    char name[256];
    if (!store_oldest(t->store_dir, name, sizeof(name))) {
      wait_locked(t, 1000);
      continue;
    }
    pthread_mutex_unlock(&t->mu);
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", t->store_dir, name);
    buckets_buf raw = BUCKETS_BUF_INIT, lines = BUCKETS_BUF_INIT;
    FILE *f = fopen(path, "r");
    if (f) {
      char chunk[8192];
      size_t k;
      while ((k = fread(chunk, 1, sizeof(chunk), f)) > 0) buckets_buf_append(&raw, chunk, k);
      fclose(f);
    }
    bool ok = raw.len > 0;
    size_t nl = strlen(name);
    if (ok && nl > 7 && strcmp(name + nl - 7, ".snappy") == 0) {
      size_t len, prefix;
      ok = buckets_s2_decoded_len((const uint8_t *)raw.data, raw.len, &len, &prefix) && len <= (64u << 20);
      if (ok) {
        buckets_buf_reserve(&lines, len + 1);
        long got = buckets_s2_decode((uint8_t *)lines.data, len, (const uint8_t *)raw.data, raw.len);
        ok = got >= 0;
        if (ok) lines.len = (size_t)got;
      }
    } else if (ok) {
      buckets_buf_append(&lines, raw.data, raw.len);
    }
    size_t count = 0;
    for (size_t i = 0; i < lines.len; i++) count += lines.data[i] == '\n';
    if (lines.len && lines.data[lines.len - 1] != '\n') {
      buckets_buf_append_char(&lines, '\n');
      count++;
    }
    bool sent = !ok || post(t, lines.data, lines.len, count ? count : 1);
    if (sent) unlink(path); /* unreadable entries are dropped, as MinIO */
    buckets_buf_free(&raw);
    buckets_buf_free(&lines);
    pthread_mutex_lock(&t->mu);
    if (!sent) wait_locked(t, t->cfg.retry_interval_ms);
  }
  pthread_mutex_unlock(&t->mu);
  return NULL;
}

/* ---- the queue processor ------------------------------------------------------ */

static void *worker_main(void *arg) {
  buckets_http_target *t = arg;
  buckets_log_sink_suppress(true);
  int64_t last_batch = mono_ms();
  pthread_mutex_lock(&t->mu);
  while (!t->stop) {
    if (!t->head) {
      wait_locked(t, 1000);
      continue;
    }
    /* a batch: batch_size entries, or what arrived within a second */
    if (t->cfg.batch_size > 1 && (int)t->n < t->cfg.batch_size && mono_ms() - last_batch < 1000) {
      wait_locked(t, 1000 - (mono_ms() - last_batch));
      continue;
    }
    buckets_buf body = BUCKETS_BUF_INIT;
    size_t count = 0;
    while (t->head && (int)count < t->cfg.batch_size) {
      entry *e = t->head;
      t->head = e->next;
      if (!t->head) t->tail = NULL;
      t->n--;
      buckets_buf_append(&body, e->json, e->n);
      buckets_buf_append_char(&body, '\n');
      free(e->json);
      free(e);
      count++;
    }
    pthread_mutex_unlock(&t->mu);
    last_batch = mono_ms();
    if (t->store_dir) {
      if (!store_put(t, &body, count)) {
        buckets_log_warn("unable to send audit/log entry(s) to '%s': the queue store is unwritable", t->cfg.name);
        pthread_mutex_lock(&t->mu);
        t->failed += count;
        pthread_mutex_unlock(&t->mu);
      }
      pthread_mutex_lock(&t->mu);
      pthread_cond_broadcast(&t->cv); /* the replayer */
    } else {
      int retries = 0;
      bool ok = post(t, body.data, body.len, count);
      pthread_mutex_lock(&t->mu);
      while (!ok && !t->stop && (t->cfg.max_retry == 0 || retries++ < t->cfg.max_retry)) {
        if (!wait_locked(t, t->cfg.retry_interval_ms)) break;
        pthread_mutex_unlock(&t->mu);
        ok = post(t, body.data, body.len, count);
        pthread_mutex_lock(&t->mu);
      }
    }
    buckets_buf_free(&body);
  }
  pthread_mutex_unlock(&t->mu);
  return NULL;
}

static bool mkdir_p(const char *path) {
  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s", path);
  for (char *p = tmp + 1; *p; p++) {
    if (*p != '/') continue;
    *p = '\0';
    if (mkdir(tmp, 0770) != 0 && errno != EEXIST) return false;
    *p = '/';
  }
  return mkdir(tmp, 0770) == 0 || errno == EEXIST;
}

buckets_http_target *buckets_http_target_new(const buckets_http_target_cfg *cfg, char *err, size_t errlen) {
  buckets_http_target *t = buckets_xcalloc(1, sizeof(*t));
  t->cfg = *cfg;
  t->cfg.name = buckets_xstrdup(cfg->name);
  t->cfg.endpoint = buckets_xstrdup(cfg->endpoint);
  t->cfg.auth_token = dup_or_null(cfg->auth_token);
  t->cfg.ca_file = dup_or_null(cfg->ca_file);
  t->cfg.user_agent = dup_or_null(cfg->user_agent);
  t->cfg.deployment_id = dup_or_null(cfg->deployment_id);
  t->cfg.queue_dir = dup_or_null(cfg->queue_dir);
  if (t->cfg.batch_size <= 0) t->cfg.batch_size = 1;
  if (t->cfg.batch_size > 100) t->cfg.batch_size = 100;
  if (t->cfg.queue_size <= 0) t->cfg.queue_size = 100000;
  if (t->cfg.retry_interval_ms <= 0) t->cfg.retry_interval_ms = 3000;
  if (t->cfg.http_timeout_ms <= 0) t->cfg.http_timeout_ms = 5000;
  t->online = true;
  pthread_mutex_init(&t->mu, NULL);
  pthread_cond_init(&t->cv, NULL);
  if (t->cfg.queue_dir) {
    buckets_buf d = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&d, "%s/minio-http-%s", t->cfg.queue_dir, t->cfg.name);
    t->store_dir = d.data;
    if (!mkdir_p(t->store_dir)) {
      snprintf(err, errlen, "unable to initialize the queue store of %s webhook: %s", t->cfg.name, strerror(errno));
      buckets_http_target_free(t);
      return NULL;
    }
    t->replayer_started = pthread_create(&t->replayer, NULL, replay_main, t) == 0;
  }
  t->worker_started = pthread_create(&t->worker, NULL, worker_main, t) == 0;
  return t;
}

void buckets_http_target_free(buckets_http_target *t) {
  if (!t) return;
  pthread_mutex_lock(&t->mu);
  t->stop = true;
  pthread_cond_broadcast(&t->cv);
  pthread_mutex_unlock(&t->mu);
  if (t->worker_started) pthread_join(t->worker, NULL);
  if (t->replayer_started) pthread_join(t->replayer, NULL);
  for (entry *e = t->head, *next; e; e = next) {
    next = e->next;
    free(e->json);
    free(e);
  }
  pthread_cond_destroy(&t->cv);
  pthread_mutex_destroy(&t->mu);
  free((char *)t->cfg.name);
  free((char *)t->cfg.endpoint);
  free((char *)t->cfg.auth_token);
  free((char *)t->cfg.ca_file);
  free((char *)t->cfg.user_agent);
  free((char *)t->cfg.deployment_id);
  free((char *)t->cfg.queue_dir);
  free(t->store_dir);
  free(t);
}

bool buckets_http_target_send(buckets_http_target *t, const char *json, size_t n) {
  pthread_mutex_lock(&t->mu);
  size_t pending = t->n + (t->store_dir ? store_count(t->store_dir) : 0);
  bool ok = (int)pending < t->cfg.queue_size;
  t->total++;
  if (ok) {
    entry *e = buckets_xcalloc(1, sizeof(*e));
    e->json = buckets_xstrndup(json, n);
    e->n = n;
    if (t->tail) t->tail->next = e;
    else t->head = e;
    t->tail = e;
    t->n++;
    pthread_cond_broadcast(&t->cv);
  } else {
    t->failed++;
  }
  pthread_mutex_unlock(&t->mu);
  return ok;
}

const char *buckets_http_target_name(const buckets_http_target *t) { return t->cfg.name; }
const char *buckets_http_target_endpoint(const buckets_http_target *t) { return t->cfg.endpoint; }

void buckets_http_target_stats_get(buckets_http_target *t, buckets_http_target_stats *out) {
  pthread_mutex_lock(&t->mu);
  out->total = t->total;
  out->failed = t->failed;
  out->queued = t->n;
  out->online = t->online;
  pthread_mutex_unlock(&t->mu);
  if (t->store_dir) out->queued += store_count(t->store_dir);
}
