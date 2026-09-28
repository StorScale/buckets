/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "heal/healer.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <yyjson.h>

#include "core/buf.h"
#include "core/log.h"
#include "storage/drive.h"

#define MRF_MAX 100000 /* MinIO's mrfOpsQueueSize */
#define MRF_ATTEMPTS 3
#define TRACKER_EVERY 100 /* objects between tracker saves */

typedef struct mrf {
  char *bucket, *object, *version_id;
  int attempts;
  bool deep;
  struct mrf *next;
} mrf;

struct buckets_healer {
  buckets_objlayer *L;
  pthread_t thread;
  pthread_mutex_t mu;
  pthread_cond_t cv, idle_cv;
  mrf *head, *tail;
  size_t qlen;
  bool stop, busy, drives_pending;
  pthread_t scanner;
  pthread_cond_t scan_cv; /* the scanner's naps; stop wakes it */
  bool scanner_started;
  int scan_interval_s;
  buckets_healer_stats st;
};

static void mrf_free(mrf *e) {
  free(e->bucket);
  free(e->object);
  free(e->version_id);
  free(e);
}

static void on_degraded(void *ud, const char *bucket, const char *object, const char *version_id, bool deep) {
  buckets_healer_enqueue(ud, bucket, object, version_id, deep);
}

void buckets_healer_enqueue(buckets_healer *h, const char *bucket, const char *object, const char *version_id,
                            bool deep) {
  pthread_mutex_lock(&h->mu);
  bool dup = false;
  for (mrf *e = h->head; e && !dup; e = e->next) {
    dup = strcmp(e->bucket, bucket) == 0 && strcmp(e->object, object) == 0 &&
          strcmp(e->version_id, version_id ? version_id : "") == 0;
    if (dup) e->deep |= deep;
  }
  if (dup || h->stop) {
    pthread_mutex_unlock(&h->mu);
    return;
  }
  if (h->qlen >= MRF_MAX) {
    h->st.dropped++;
    pthread_mutex_unlock(&h->mu);
    return;
  }
  mrf *e = buckets_xcalloc(1, sizeof(*e));
  e->bucket = buckets_xstrdup(bucket);
  e->object = buckets_xstrdup(object);
  e->version_id = buckets_xstrdup(version_id ? version_id : "");
  e->deep = deep;
  if (h->tail) h->tail->next = e;
  else h->head = e;
  h->tail = e;
  h->qlen++;
  h->st.queued++;
  pthread_cond_signal(&h->cv);
  pthread_mutex_unlock(&h->mu);
}

/* ---- drive heal tracker ------------------------------------------------------- */

typedef struct {
  char *bucket, *object; /* resume after this point ("" = from the start) */
  uint64_t healed, failed;
} tracker;

static void tracker_free(tracker *t) {
  free(t->bucket);
  free(t->object);
}

static bool tracker_load(buckets_drive *d, tracker *t) {
  memset(t, 0, sizeof(*t));
  buckets_buf raw = BUCKETS_BUF_INIT;
  if (buckets_drive_read_all(d, BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER, &raw) != BUCKETS_DRIVE_OK) return false;
  yyjson_doc *doc = yyjson_read(raw.data, raw.len, 0);
  buckets_buf_free(&raw);
  yyjson_val *root = yyjson_doc_get_root(doc);
  const char *b = yyjson_get_str(yyjson_obj_get(root, "bucket"));
  const char *o = yyjson_get_str(yyjson_obj_get(root, "object"));
  t->bucket = buckets_xstrdup(b ? b : "");
  t->object = buckets_xstrdup(o ? o : "");
  t->healed = yyjson_get_uint(yyjson_obj_get(root, "healed"));
  t->failed = yyjson_get_uint(yyjson_obj_get(root, "failed"));
  yyjson_doc_free(doc);
  return true;
}

static void tracker_save(buckets_drive *d, const tracker *t) {
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_str(doc, root, "drive", d->drive_id);
  yyjson_mut_obj_add_str(doc, root, "bucket", t->bucket ? t->bucket : "");
  yyjson_mut_obj_add_str(doc, root, "object", t->object ? t->object : "");
  yyjson_mut_obj_add_uint(doc, root, "healed", t->healed);
  yyjson_mut_obj_add_uint(doc, root, "failed", t->failed);
  size_t n;
  char *json = yyjson_mut_write(doc, 0, &n);
  buckets_drive_write_all(d, BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER, json, n);
  free(json);
  yyjson_mut_doc_free(doc);
}

static int cmp_str(const void *a, const void *b) {
  return strcmp(((const buckets_bucket_info *)a)->name, ((const buckets_bucket_info *)b)->name);
}

static bool stopping(buckets_healer *h) {
  pthread_mutex_lock(&h->mu);
  bool s = h->stop;
  pthread_mutex_unlock(&h->mu);
  return s;
}

/* Heals every bucket and every object of d's erasure set, resuming from the
 * tracker. Returns true when the drive is complete. */
static bool heal_drive(buckets_healer *h, size_t di) {
  buckets_objlayer *L = h->L;
  buckets_drive *d = L->all[di];
  tracker t;
  if (!tracker_load(d, &t)) return true;
  buckets_drive_place pl;
  buckets_objlayer_place(L, di, &pl);
  buckets_log_info("healing drive %s (resuming after %s/%s)", d->root, t.bucket, t.object);
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(L, &bk, &nb) != BUCKETS_OBJ_OK) {
    tracker_free(&t);
    return false;
  }
  qsort(bk, nb, sizeof(*bk), cmp_str);
  buckets_heal_opts opts = {.remove_dangling = true};
  size_t since_save = 0;
  bool complete = true;
  for (size_t b = 0; b < nb && complete; b++) {
    if (*t.bucket && strcmp(bk[b].name, t.bucket) < 0) continue;
    buckets_obj_heal_bucket(L, bk[b].name);
    /* The bucket's metadata object lives in .minio.sys. */
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&meta, "buckets/%s/.metadata.bin", bk[b].name);
    buckets_obj_heal(L, BUCKETS_META_BUCKET, meta.data, NULL, &opts, NULL);
    buckets_buf_free(&meta);
    char *marker = strcmp(bk[b].name, t.bucket) == 0 && *t.object ? buckets_xstrdup(t.object) : NULL;
    for (;;) {
      if (stopping(h)) {
        complete = false;
        break;
      }
      buckets_obj_listing l;
      if (buckets_obj_list(L, bk[b].name, "", marker, NULL, 1000, &l) != BUCKETS_OBJ_OK) {
        complete = false;
        break;
      }
      for (size_t i = 0; i < l.nobjects; i++) {
        const char *name = l.objects[i].name;
        if (buckets_objlayer_object_set(L, pl.pool, name) != pl.set) continue; /* not this drive's set */
        buckets_heal_result r;
        if (buckets_obj_heal(L, bk[b].name, name, NULL, &opts, &r) == BUCKETS_OBJ_OK) t.healed++;
        else t.failed++;
        pthread_mutex_lock(&h->mu);
        h->st.drive_objects_healed++;
        pthread_mutex_unlock(&h->mu);
        if (++since_save >= TRACKER_EVERY) {
          free(t.bucket);
          free(t.object);
          t.bucket = buckets_xstrdup(bk[b].name);
          t.object = buckets_xstrdup(name);
          tracker_save(d, &t);
          since_save = 0;
        }
      }
      free(marker);
      marker = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
      buckets_obj_list_free(&l);
      if (!marker) break;
    }
    free(marker);
  }
  if (complete) {
    buckets_drive_delete(d, BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER, false, false);
    buckets_log_info("drive %s healed: %llu objects healed, %llu failed", d->root, (unsigned long long)t.healed,
                     (unsigned long long)t.failed);
  }
  buckets_bucket_info_free(bk, nb);
  tracker_free(&t);
  return complete;
}

static void heal_drives(buckets_healer *h) {
  buckets_objlayer *L = h->L;
  size_t pending = 0;
  for (size_t i = 0; i < L->nall; i++) {
    if (L->all[i] && !L->all[i]->remote &&
        buckets_drive_stat(L->all[i], BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER) == 1) {
      pending++;
    }
  }
  pthread_mutex_lock(&h->mu);
  h->st.drives_healing = pending;
  pthread_mutex_unlock(&h->mu);
  for (size_t i = 0; i < L->nall && !stopping(h); i++) {
    if (!L->all[i] || L->all[i]->remote) continue; /* each node heals its own drives */
    if (buckets_drive_stat(L->all[i], BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER) != 1) continue;
    if (heal_drive(h, i)) {
      pthread_mutex_lock(&h->mu);
      h->st.drives_healing--;
      pthread_mutex_unlock(&h->mu);
    }
  }
}

/* ---- scanner ---------------------------------------------------------------------- */

/* Sleeps up to seconds, waking early on stop. Returns false when stopping. */
static bool nap(buckets_healer *h, int seconds) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += seconds;
  pthread_mutex_lock(&h->mu);
  while (!h->stop && pthread_cond_timedwait(&h->scan_cv, &h->mu, &ts) == 0) {
  }
  bool go = !h->stop;
  pthread_mutex_unlock(&h->mu);
  return go;
}

static bool leads(buckets_objlayer *L, const char *object) {
  for (size_t p = 0; p < L->npools; p++) {
    if (buckets_objlayer_set_is_led_here(L, p, buckets_objlayer_object_set(L, p, object))) return true;
  }
  return false;
}

static void scan_object(buckets_healer *h, const char *bucket, const char *object) {
  buckets_heal_opts opts = {.remove_dangling = true};
  buckets_heal_result r;
  if (buckets_obj_heal(h->L, bucket, object, NULL, &opts, &r) == BUCKETS_OBJ_OK && r.healed) {
    buckets_log_info("scanner healed %s/%s on %zu drive%s", bucket, object, r.healed, r.healed == 1 ? "" : "s");
  }
  pthread_mutex_lock(&h->mu);
  h->st.scanned++;
  pthread_mutex_unlock(&h->mu);
}

static void scan_cycle(buckets_healer *h) {
  buckets_objlayer *L = h->L;
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(L, &bk, &nb) != BUCKETS_OBJ_OK) return;
  for (size_t b = 0; b < nb && !stopping(h); b++) {
    buckets_obj_heal_bucket(L, bk[b].name);
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&meta, "buckets/%s/.metadata.bin", bk[b].name);
    if (leads(L, meta.data)) scan_object(h, BUCKETS_META_BUCKET, meta.data);
    buckets_buf_free(&meta);
    char *marker = NULL;
    for (;;) {
      buckets_obj_listing l;
      if (stopping(h) || buckets_obj_list(L, bk[b].name, "", marker, NULL, 1000, &l) != BUCKETS_OBJ_OK) break;
      for (size_t i = 0; i < l.nobjects && !stopping(h); i++) {
        if (leads(L, l.objects[i].name)) scan_object(h, bk[b].name, l.objects[i].name);
      }
      free(marker);
      marker = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
      buckets_obj_list_free(&l);
      if (!marker) break;
    }
    free(marker);
  }
  buckets_bucket_info_free(bk, nb);
  pthread_mutex_lock(&h->mu);
  h->st.scan_cycles++;
  pthread_mutex_unlock(&h->mu);
}

static void *scanner(void *arg) {
  buckets_healer *h = arg;
  while (nap(h, h->scan_interval_s)) scan_cycle(h);
  return NULL;
}

/* ---- the thread ------------------------------------------------------------------ */

static void *run(void *arg) {
  buckets_healer *h = arg;
  pthread_mutex_lock(&h->mu);
  for (;;) {
    if (h->drives_pending && !h->stop) {
      h->drives_pending = false;
      h->busy = true;
      pthread_mutex_unlock(&h->mu);
      heal_drives(h);
      pthread_mutex_lock(&h->mu);
      h->busy = false;
      continue;
    }
    while (!h->head && !h->stop) {
      pthread_cond_broadcast(&h->idle_cv);
      pthread_cond_wait(&h->cv, &h->mu);
    }
    if (h->stop) break;
    mrf *e = h->head;
    h->head = e->next;
    if (!h->head) h->tail = NULL;
    h->qlen--;
    h->busy = true;
    pthread_mutex_unlock(&h->mu);
    buckets_heal_result r;
    buckets_heal_opts opts = {.remove_dangling = true, .deep = e->deep};
    buckets_obj_err err = buckets_obj_heal(h->L, e->bucket, e->object, *e->version_id ? e->version_id : NULL, &opts, &r);
    bool retry = err && err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION &&
                 err != BUCKETS_OBJ_ERR_NO_SUCH_BUCKET && ++e->attempts < MRF_ATTEMPTS;
    if (err && !retry) {
      buckets_log_warn("heal %s/%s: %s", e->bucket, e->object, buckets_obj_strerror(err));
    } else if (!err && r.healed) {
      buckets_log_info("healed %s/%s on %zu drive%s", e->bucket, e->object, r.healed, r.healed == 1 ? "" : "s");
    }
    pthread_mutex_lock(&h->mu);
    h->busy = false;
    if (retry) { /* to the back of the queue */
      e->next = NULL;
      if (h->tail) h->tail->next = e;
      else h->head = e;
      h->tail = e;
      h->qlen++;
    } else {
      if (err) h->st.failed++;
      else h->st.healed++;
      mrf_free(e);
    }
  }
  pthread_cond_broadcast(&h->idle_cv);
  pthread_mutex_unlock(&h->mu);
  return NULL;
}

buckets_healer *buckets_healer_start(buckets_objlayer *L) {
  buckets_healer *h = buckets_xcalloc(1, sizeof(*h));
  h->L = L;
  pthread_mutex_init(&h->mu, NULL);
  pthread_cond_init(&h->cv, NULL);
  pthread_cond_init(&h->idle_cv, NULL);
  pthread_cond_init(&h->scan_cv, NULL);
  /* A drive formatted into an existing pool starts empty: track it. (A whole
   * pool formatted at once is new, not replaced.) */
  for (size_t i = 0; i < L->nall; i++) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, i, &pl);
    bool fresh_pool = true;
    for (size_t j = pl.pool_first; j < pl.pool_first + pl.pool_drives; j++) {
      fresh_pool &= !L->all[j] || L->all[j]->freshly_formatted;
    }
    if (!fresh_pool && L->all[i] && !L->all[i]->remote && L->all[i]->freshly_formatted) {
      tracker t = {0};
      tracker_save(L->all[i], &t);
      buckets_log_info("drive %s was replaced; healing it in the background", L->all[i]->root);
    }
  }
  h->drives_pending = true;
  buckets_objlayer_set_degraded_hook(L, on_degraded, h);
  if (pthread_create(&h->thread, NULL, run, h) != 0) buckets_fatal("start healer thread");
  const char *iv = getenv("BUCKETS_SCANNER_INTERVAL");
  h->scan_interval_s = iv ? atoi(iv) : 60;
  if (h->scan_interval_s > 0) h->scanner_started = pthread_create(&h->scanner, NULL, scanner, h) == 0;
  return h;
}

void buckets_healer_stop(buckets_healer *h) {
  if (!h) return;
  buckets_objlayer_set_degraded_hook(h->L, NULL, NULL);
  pthread_mutex_lock(&h->mu);
  h->stop = true;
  pthread_cond_broadcast(&h->cv);
  pthread_cond_broadcast(&h->scan_cv);
  pthread_mutex_unlock(&h->mu);
  pthread_join(h->thread, NULL);
  if (h->scanner_started) pthread_join(h->scanner, NULL);
  for (mrf *e = h->head, *next; e; e = next) {
    next = e->next;
    mrf_free(e);
  }
  pthread_cond_destroy(&h->idle_cv);
  pthread_cond_destroy(&h->scan_cv);
  pthread_cond_destroy(&h->cv);
  pthread_mutex_destroy(&h->mu);
  free(h);
}

void buckets_healer_stats_get(buckets_healer *h, buckets_healer_stats *out) {
  pthread_mutex_lock(&h->mu);
  *out = h->st;
  pthread_mutex_unlock(&h->mu);
}

void buckets_healer_wait_idle(buckets_healer *h) {
  pthread_mutex_lock(&h->mu);
  while (!h->stop && (h->head || h->busy || h->drives_pending)) pthread_cond_wait(&h->idle_cv, &h->mu);
  pthread_mutex_unlock(&h->mu);
}
