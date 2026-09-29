/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "notify/target.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/log.h"
#include "compress/s2.h"
#include "core/str.h"
#include "core/uuid.h"
#include <yyjson.h>

#define MEMORY_QUEUE 10000
#define RETRY_MS 3000

typedef struct item {
  struct item *next;
  char *record, *name, *key;
  size_t n;
} item;

struct buckets_target {
  buckets_target_id id;
  const buckets_target_ops *ops;
  void *impl;
  char *store_dir; /* NULL: memory */
  uint64_t limit;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  item *head, *tail;
  size_t nmem;
  bool stop;
  pthread_t worker;
  bool started;
  buckets_target_stats st;
};

/* ---- the queue store ---------------------------------------------------------
 * MinIO's QueueStore: <dir>/<uuid>.event holding the event record (JSON), so
 * a store MinIO left behind is replayed, and the other way round. Oldest
 * first by modification time. MinIO's batched ("<n>:<uuid>.event": records
 * one per line) and compressed ("<name>.snappy": an S2 block) entries are
 * read too. */

static bool store_entry(const char *name) {
  return name[0] != '.' && strstr(name, ".event") != NULL;
}

static size_t store_count(const char *dir) {
  DIR *d = opendir(dir);
  if (!d) return 0;
  size_t n = 0;
  struct dirent *e;
  while ((e = readdir(d)))
    if (store_entry(e->d_name)) n++;
  closedir(d);
  return n;
}

static int64_t mtime_ns(const char *dir, const char *name) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/%s", dir, name);
  struct stat st;
  if (stat(path, &st) != 0) return INT64_MAX;
#ifdef __APPLE__
  return (int64_t)st.st_mtimespec.tv_sec * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
  return (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
#endif
}

static bool store_oldest(const char *dir, char *out, size_t cap) {
  DIR *d = opendir(dir);
  if (!d) return false;
  bool found = false;
  int64_t best = 0;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (!store_entry(e->d_name)) continue;
    int64_t t = mtime_ns(dir, e->d_name);
    if (!found || t < best || (t == best && strcmp(e->d_name, out) < 0)) {
      snprintf(out, cap, "%s", e->d_name);
      best = t;
      found = true;
    }
  }
  closedir(d);
  return found;
}

static bool store_put(buckets_target *t, const char *record, size_t n) {
  char id[40], path[4096], tmp[4200];
  buckets_uuid_v4(id);
  snprintf(path, sizeof(path), "%s/%s.event", t->store_dir, id);
  snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", t->store_dir, id);
  FILE *f = fopen(tmp, "w");
  if (!f) return false;
  bool ok = fwrite(record, 1, n, f) == n;
  ok = fflush(f) == 0 && ok;
  ok = fsync(fileno(f)) == 0 && ok;
  ok = fclose(f) == 0 && ok;
  if (ok) ok = rename(tmp, path) == 0;
  if (!ok) unlink(tmp);
  return ok;
}

/* The records of an entry, one per line in out. */
static bool store_get(const char *dir, const char *file, buckets_buf *out) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/%s", dir, file);
  FILE *f = fopen(path, "r");
  if (!f) return false;
  buckets_buf b = BUCKETS_BUF_INIT;
  char chunk[8192];
  size_t k;
  while ((k = fread(chunk, 1, sizeof(chunk), f)) > 0) buckets_buf_append(&b, chunk, k);
  fclose(f);
  size_t fl = strlen(file);
  bool ok = b.len > 0;
  if (ok && fl > 7 && strcmp(file + fl - 7, ".snappy") == 0) {
    size_t len, prefix;
    ok = buckets_s2_decoded_len((const uint8_t *)b.data, b.len, &len, &prefix) && len <= (64u << 20);
    if (ok) {
      buckets_buf_reserve(out, len + 1);
      long got = buckets_s2_decode((uint8_t *)out->data, len, (const uint8_t *)b.data, b.len);
      ok = got >= 0;
      if (ok) out->len = (size_t)got;
    }
  } else if (ok) {
    buckets_buf_append(out, b.data, b.len);
  }
  buckets_buf_free(&b);
  return ok;
}

/* The event name and "bucket/key" (unescaped) of a record. */
static bool record_meta(const char *record, size_t n, char **name, char **key) {
  yyjson_doc *d = yyjson_read(record, n, 0);
  yyjson_val *r = d ? yyjson_doc_get_root(d) : NULL;
  const char *ev = yyjson_get_str(yyjson_obj_get(r, "eventName"));
  yyjson_val *s3 = yyjson_obj_get(r, "s3");
  const char *bucket = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(s3, "bucket"), "name"));
  const char *obj = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(s3, "object"), "key"));
  bool ok = ev && bucket && obj;
  if (ok) {
    char *dec = buckets_xmalloc(strlen(obj) + 1);
    long k = buckets_url_decode(buckets_str_c(obj), dec, true);
    ok = k >= 0;
    if (ok) {
      buckets_buf kb = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&kb, "%s/%.*s", bucket, (int)k, dec);
      *name = buckets_xstrdup(ev);
      *key = kb.data;
    }
    free(dec);
  }
  yyjson_doc_free(d);
  return ok;
}

static void item_free(item *it) {
  free(it->record);
  free(it->name);
  free(it->key);
}

/* ---- the worker ------------------------------------------------------------------ */

/* Sleeps up to ms unless stopped or woken. Returns false when stopping. */
static bool wait_ms(buckets_target *t, int ms) {
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += ms / 1000;
  until.tv_nsec += (long)(ms % 1000) * 1000000L;
  if (until.tv_nsec >= 1000000000L) until.tv_sec++, until.tv_nsec -= 1000000000L;
  pthread_mutex_lock(&t->mu);
  if (!t->stop) pthread_cond_timedwait(&t->cv, &t->mu, &until);
  bool stop = t->stop;
  pthread_mutex_unlock(&t->mu);
  return !stop;
}

static buckets_send_result deliver(buckets_target *t, const item *it) {
  char err[512] = "";
  buckets_send_result r = t->ops->send(t->impl, it->record, it->n, it->name, it->key, err, sizeof(err));
  pthread_mutex_lock(&t->mu);
  t->st.online = r != BUCKETS_SEND_NOT_CONNECTED;
  if (r == BUCKETS_SEND_OK) t->st.sent++;
  else t->st.failed++;
  pthread_mutex_unlock(&t->mu);
  if (r != BUCKETS_SEND_OK)
    buckets_log_warn("notify %s:%s: %s", t->id.id, t->id.type, *err ? err : "delivery failed");
  return r;
}

static void *worker_main(void *arg) {
  buckets_target *t = arg;
  for (;;) {
    if (t->store_dir) {
      char file[256];
      if (!store_oldest(t->store_dir, file, sizeof(file))) {
        if (!wait_ms(t, 1000)) break;
        continue;
      }
      char path[4096];
      snprintf(path, sizeof(path), "%s/%s", t->store_dir, file);
      buckets_buf recs = BUCKETS_BUF_INIT;
      if (!store_get(t->store_dir, file, &recs)) {
        buckets_buf_free(&recs);
        unlink(path); /* unreadable: drop it, as MinIO */
        continue;
      }
      /* every record of the entry must go through before it is removed */
      buckets_send_result r = BUCKETS_SEND_OK;
      for (size_t off = 0; off < recs.len && r == BUCKETS_SEND_OK;) {
        char *nl = memchr(recs.data + off, '\n', recs.len - off);
        size_t len = nl ? (size_t)(nl - (recs.data + off)) : recs.len - off;
        item it = {.record = recs.data + off, .n = len};
        if (len && record_meta(it.record, len, &it.name, &it.key)) {
          r = deliver(t, &it);
          free(it.name);
          free(it.key);
        }
        off += len + 1;
      }
      buckets_buf_free(&recs);
      if (r == BUCKETS_SEND_OK) {
        unlink(path);
      } else if (!wait_ms(t, RETRY_MS)) { /* MinIO keeps a stored event until it goes through */
        break;
      }
      continue;
    }
    pthread_mutex_lock(&t->mu);
    while (!t->head && !t->stop) pthread_cond_wait(&t->cv, &t->mu);
    if (t->stop && !t->head) {
      pthread_mutex_unlock(&t->mu);
      break;
    }
    item *it = t->head;
    t->head = it->next;
    if (!t->head) t->tail = NULL;
    t->nmem--;
    t->st.queued = t->nmem;
    bool stopping = t->stop;
    pthread_mutex_unlock(&t->mu);
    if (!stopping) deliver(t, it); /* without a store a failed event is lost, as in MinIO */
    item_free(it);
    free(it);
  }
  return NULL;
}

/* ---- the target ------------------------------------------------------------------ */

static bool mkdir_p(const char *path) {
  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s", path);
  for (char *p = tmp + 1; *p; p++) {
    if (*p != '/') continue;
    *p = '\0';
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return false;
    *p = '/';
  }
  return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

buckets_target *buckets_target_new(const char *id, const buckets_target_ops *ops, void *impl, const char *queue_dir,
                                   uint64_t queue_limit, char *err, size_t errlen) {
  buckets_target *t = buckets_xcalloc(1, sizeof(*t));
  snprintf(t->id.id, sizeof(t->id.id), "%s", id);
  snprintf(t->id.type, sizeof(t->id.type), "%s", ops->type);
  t->ops = ops;
  t->impl = impl;
  t->limit = queue_limit ? queue_limit : 100000;
  t->st.online = true;
  pthread_mutex_init(&t->mu, NULL);
  pthread_cond_init(&t->cv, NULL);
  if (queue_dir && *queue_dir) {
    buckets_buf d = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&d, "%s/minio-%s-%s", queue_dir, ops->type, id);
    t->store_dir = d.data;
    if (!mkdir_p(t->store_dir)) {
      snprintf(err, errlen, "unable to initialize the queue store of %s `%s`: %s", ops->type, id, strerror(errno));
      buckets_target_free(t);
      return NULL;
    }
  }
  t->started = pthread_create(&t->worker, NULL, worker_main, t) == 0;
  return t;
}

void buckets_target_free(buckets_target *t) {
  if (!t) return;
  pthread_mutex_lock(&t->mu);
  t->stop = true;
  pthread_cond_broadcast(&t->cv);
  pthread_mutex_unlock(&t->mu);
  if (t->started) pthread_join(t->worker, NULL);
  for (item *it = t->head, *next; it; it = next) {
    next = it->next;
    item_free(it);
    free(it);
  }
  if (t->ops && t->ops->free) t->ops->free(t->impl);
  pthread_cond_destroy(&t->cv);
  pthread_mutex_destroy(&t->mu);
  free(t->store_dir);
  free(t);
}

const buckets_target_id *buckets_target_id_of(const buckets_target *t) { return &t->id; }

bool buckets_target_enqueue(buckets_target *t, const char *record, size_t n, const char *event_name, const char *key) {
  if (t->store_dir) {
    (void)event_name, (void)key; /* the record holds both */
    bool ok = store_count(t->store_dir) < t->limit && store_put(t, record, n);
    pthread_mutex_lock(&t->mu);
    if (!ok) t->st.dropped++;
    pthread_cond_broadcast(&t->cv);
    pthread_mutex_unlock(&t->mu);
    if (!ok) buckets_log_warn("notify %s:%s: the queue store is full or unwritable; event dropped", t->id.id, t->id.type);
    return ok;
  }
  pthread_mutex_lock(&t->mu);
  bool ok = t->nmem < MEMORY_QUEUE;
  if (ok) {
    item *it = buckets_xcalloc(1, sizeof(*it));
    it->record = buckets_xstrndup(record, n);
    it->n = n;
    it->name = buckets_xstrdup(event_name);
    it->key = buckets_xstrdup(key);
    if (t->tail) t->tail->next = it;
    else t->head = it;
    t->tail = it;
    t->nmem++;
    t->st.queued = t->nmem;
    pthread_cond_broadcast(&t->cv);
  } else {
    t->st.dropped++;
  }
  pthread_mutex_unlock(&t->mu);
  return ok;
}

void buckets_target_stats_get(buckets_target *t, buckets_target_stats *out) {
  pthread_mutex_lock(&t->mu);
  *out = t->st;
  pthread_mutex_unlock(&t->mu);
  if (t->store_dir) out->queued = store_count(t->store_dir);
}
