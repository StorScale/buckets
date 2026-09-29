/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "logger/kafkatarget.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/log.h"
#include "core/uuid.h"
#include "notify/event.h"

#define STORE_EXT ".kafka.log"
#define STORE_NAME "minio-kafka-audit"

typedef struct item {
  struct item *next;
  char *json;
  size_t n;
} item;

struct buckets_kafka_target {
  char *name, *topic, *store_dir;
  char **brokers;
  buckets_kafka_cfg kcfg;
  char *version, *ca_dir, *cert, *key, *user, *pass, *mech;
  int queue_size;
  buckets_kafka *client;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  pthread_t worker;
  bool stop, started;
  item *head, *tail;
  size_t queued;
  uint64_t total, failed;
  bool online;
};

static char *dup0(const char *s) { return buckets_xstrdup(s ? s : ""); }

/* initKafkaOnce: the client, connected. */
static bool client_ready(buckets_kafka_target *t, char *err, size_t errlen) {
  if (t->client) return true;
  buckets_kafka *c = buckets_kafka_new(&t->kcfg);
  if (!buckets_kafka_connect(c, err, errlen)) {
    buckets_kafka_free(c);
    return false;
  }
  t->client = c;
  t->online = buckets_kafka_has_brokers(c);
  return true;
}

static bool deliver(buckets_kafka_target *t, const char *json, size_t n) {
  char err[512];
  bool ok = client_ready(t, err, sizeof(err));
  if (ok) {
    buckets_kafka_msg m = {NULL, 0, json, n};
    ok = buckets_kafka_send(t->client, t->topic, &m, 1, err, sizeof(err)) == 0;
  }
  pthread_mutex_lock(&t->mu);
  t->total++;
  if (!ok) t->failed++;
  t->online = ok;
  pthread_mutex_unlock(&t->mu);
  if (!ok) buckets_log_warn("%s: %s", t->topic, err); /* LogOnce with the topic */
  return ok;
}

/* ---- the store ------------------------------------------------------------------------ */

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

/* A value re-encoded as Go's json.Marshal writes the map[string]any it
 * was read back into: object keys sorted, strings escaped as Go does,
 * numbers as written. */
static void write_sorted(yyjson_val *v, buckets_buf *out);

static int cmp_key(const void *a, const void *b) {
  return strcmp(yyjson_get_str(*(yyjson_val *const *)a), yyjson_get_str(*(yyjson_val *const *)b));
}

static void write_sorted(yyjson_val *v, buckets_buf *out) {
  if (yyjson_is_obj(v)) {
    size_t n = yyjson_obj_size(v), i = 0, idx, max;
    yyjson_val **keys = buckets_xcalloc(n ? n : 1, sizeof(*keys)), *k, *val;
    yyjson_obj_foreach(v, idx, max, k, val) keys[i++] = k;
    qsort(keys, n, sizeof(*keys), cmp_key);
    buckets_buf_append_char(out, '{');
    for (i = 0; i < n; i++) {
      if (i) buckets_buf_append_char(out, ',');
      const char *ks = yyjson_get_str(keys[i]);
      buckets_json_go_string(out, ks, yyjson_get_len(keys[i]));
      buckets_buf_append_char(out, ':');
      write_sorted(yyjson_obj_getn(v, ks, yyjson_get_len(keys[i])), out);
    }
    buckets_buf_append_char(out, '}');
    free(keys);
  } else if (yyjson_is_arr(v)) {
    buckets_buf_append_char(out, '[');
    size_t idx, max;
    yyjson_val *e;
    yyjson_arr_foreach(v, idx, max, e) {
      if (idx) buckets_buf_append_char(out, ',');
      write_sorted(e, out);
    }
    buckets_buf_append_char(out, ']');
  } else if (yyjson_is_str(v)) {
    buckets_json_go_string(out, yyjson_get_str(v), yyjson_get_len(v));
  } else if (yyjson_is_raw(v)) {
    buckets_buf_append(out, yyjson_get_raw(v), yyjson_get_len(v));
  } else if (yyjson_is_bool(v)) {
    buckets_buf_append_c(out, yyjson_get_bool(v) ? "true" : "false");
  } else {
    buckets_buf_append_c(out, "null");
  }
}

static bool store_put(buckets_kafka_target *t, const char *json, size_t n) {
  if (store_count(t->store_dir) >= (size_t)t->queue_size) return false; /* the store is full */
  char id[40], path[4096], tmp[4200];
  buckets_uuid_v4(id);
  snprintf(path, sizeof(path), "%s/%s" STORE_EXT, t->store_dir, id);
  snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", t->store_dir, id);
  FILE *f = fopen(tmp, "w");
  bool ok = f && fwrite(json, 1, n, f) == n;
  if (f) ok = fclose(f) == 0 && ok;
  if (ok) ok = rename(tmp, path) == 0;
  if (!ok) unlink(tmp);
  return ok;
}

static bool wait_s(buckets_kafka_target *t, int s) {
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += s;
  pthread_mutex_lock(&t->mu);
  if (!t->stop) pthread_cond_timedwait(&t->cv, &t->mu, &until);
  bool stop = t->stop;
  pthread_mutex_unlock(&t->mu);
  return !stop;
}

static void *store_main(void *arg) {
  buckets_kafka_target *t = arg;
  buckets_log_sink_suppress(true);
  for (;;) {
    char name[256];
    if (!store_oldest(t->store_dir, name, sizeof(name))) {
      if (!wait_s(t, 1)) break;
      continue;
    }
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", t->store_dir, name);
    FILE *f = fopen(path, "r");
    buckets_buf raw = BUCKETS_BUF_INIT;
    char chunk[8192];
    size_t k;
    while (f && (k = fread(chunk, 1, sizeof(chunk), f)) > 0) buckets_buf_append(&raw, chunk, k);
    if (f) fclose(f);
    yyjson_doc *doc = yyjson_read(raw.data ? raw.data : "", raw.len, YYJSON_READ_NUMBER_AS_RAW);
    buckets_buf_free(&raw);
    if (!doc) {
      unlink(path);
      continue;
    }
    buckets_buf out = BUCKETS_BUF_INIT;
    write_sorted(yyjson_doc_get_root(doc), &out);
    yyjson_doc_free(doc);
    bool ok = deliver(t, out.data, out.len);
    buckets_buf_free(&out);
    if (ok) unlink(path);
    else if (!wait_s(t, 3)) break; /* kept until it goes through */
  }
  return NULL;
}

static void *memory_main(void *arg) {
  buckets_kafka_target *t = arg;
  buckets_log_sink_suppress(true);
  pthread_mutex_lock(&t->mu);
  for (;;) {
    while (!t->head && !t->stop) pthread_cond_wait(&t->cv, &t->mu);
    if (!t->head) break;
    item *it = t->head;
    t->head = it->next;
    if (!t->head) t->tail = NULL;
    t->queued--;
    pthread_mutex_unlock(&t->mu);
    deliver(t, it->json, it->n);
    free(it->json);
    free(it);
    pthread_mutex_lock(&t->mu);
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
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
    *p = '/';
  }
  return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

buckets_kafka_target *buckets_kafka_target_new(const buckets_kafka_target_cfg *cfg, char *err, size_t errlen) {
  buckets_kafka_target *t = buckets_xcalloc(1, sizeof(*t));
  t->name = dup0(cfg->name), t->topic = dup0(cfg->topic);
  t->queue_size = cfg->queue_size > 0 ? cfg->queue_size : 100000;
  t->kcfg = cfg->kafka;
  t->brokers = buckets_xcalloc(cfg->kafka.nbrokers ? cfg->kafka.nbrokers : 1, sizeof(char *));
  for (size_t i = 0; i < cfg->kafka.nbrokers; i++) t->brokers[i] = buckets_xstrdup(cfg->kafka.brokers[i]);
  t->kcfg.brokers = (const char *const *)t->brokers;
  t->version = dup0(cfg->kafka.version), t->kcfg.version = t->version;
  t->ca_dir = cfg->kafka.ca_dir ? buckets_xstrdup(cfg->kafka.ca_dir) : NULL, t->kcfg.ca_dir = t->ca_dir;
  t->cert = dup0(cfg->kafka.client_cert), t->kcfg.client_cert = t->cert;
  t->key = dup0(cfg->kafka.client_key), t->kcfg.client_key = t->key;
  t->user = dup0(cfg->kafka.sasl_user), t->kcfg.sasl_user = t->user;
  t->pass = dup0(cfg->kafka.sasl_pass), t->kcfg.sasl_pass = t->pass;
  t->mech = dup0(cfg->kafka.sasl_mechanism), t->kcfg.sasl_mechanism = t->mech;
  t->kcfg.compression = "";
  t->kcfg.timeout_ms = 10000;       /* Net.*Timeout, Producer.Timeout */
  t->kcfg.retry_backoff_ms = 10000; /* Producer.Retry.Backoff */
  pthread_mutex_init(&t->mu, NULL);
  pthread_cond_init(&t->cv, NULL);
  /* Init: the client first (its failure fails the target), then the store */
  if (!client_ready(t, err, errlen)) {
    buckets_kafka_target_free(t);
    return NULL;
  }
  if (cfg->queue_dir && *cfg->queue_dir) {
    buckets_buf d = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&d, "%s/" STORE_NAME, cfg->queue_dir);
    t->store_dir = d.data;
    if (!mkdir_p(t->store_dir)) {
      snprintf(err, errlen, "unable to initialize the queue store of %s webhook: %s", t->name, strerror(errno));
      buckets_kafka_target_free(t);
      return NULL;
    }
  }
  t->started = pthread_create(&t->worker, NULL, t->store_dir ? store_main : memory_main, t) == 0;
  return t;
}

void buckets_kafka_target_free(buckets_kafka_target *t) {
  if (!t) return;
  pthread_mutex_lock(&t->mu);
  t->stop = true;
  pthread_cond_broadcast(&t->cv);
  pthread_mutex_unlock(&t->mu);
  if (t->started) pthread_join(t->worker, NULL);
  for (item *it = t->head, *nx; it; it = nx) nx = it->next, free(it->json), free(it);
  buckets_kafka_free(t->client);
  for (size_t i = 0; i < t->kcfg.nbrokers; i++) free(t->brokers[i]);
  free(t->brokers);
  free(t->name), free(t->topic), free(t->store_dir), free(t->version), free(t->ca_dir), free(t->cert), free(t->key);
  free(t->user), free(t->pass), free(t->mech);
  pthread_cond_destroy(&t->cv);
  pthread_mutex_destroy(&t->mu);
  free(t);
}

bool buckets_kafka_target_send(buckets_kafka_target *t, const char *json, size_t n) {
  if (t->store_dir) return store_put(t, json, n);
  pthread_mutex_lock(&t->mu);
  bool ok = t->queued < (size_t)t->queue_size;
  if (ok) {
    item *it = buckets_xcalloc(1, sizeof(*it));
    it->json = buckets_xstrndup(json, n);
    it->n = n;
    if (t->tail) t->tail->next = it;
    else t->head = it;
    t->tail = it;
    t->queued++;
    pthread_cond_signal(&t->cv);
  }
  pthread_mutex_unlock(&t->mu);
  return ok;
}

const char *buckets_kafka_target_name(const buckets_kafka_target *t) { return t->name; }

void buckets_kafka_target_stats_get(buckets_kafka_target *t, buckets_http_target_stats *out) {
  pthread_mutex_lock(&t->mu);
  out->total = t->total;
  out->failed = t->failed;
  out->queued = t->store_dir ? store_count(t->store_dir) : t->queued;
  out->online = t->online;
  pthread_mutex_unlock(&t->mu);
}
