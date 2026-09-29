/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "notify/notifier.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/common.h"
#include "core/log.h"
#include "iam/policy.h"
#include "notify/targets.h"

#define LISTENER_QUEUE 10000

struct buckets_listener {
  buckets_notifier *n;
  struct buckets_listener *next;
  char *bucket; /* NULL: all */
  uint64_t mask;
  char pattern[2200];
  int ping_ms;
  bool empty_records; /* ?ping=N: {"Records":null} rather than a space */
  int64_t next_ping_ns;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  buckets_buf pending; /* lines not yet read */
  size_t pending_pos, queued;
  bool closed;
};

struct buckets_notifier {
  pthread_rwlock_t lock;
  buckets_target **targets;
  size_t ntargets;
  pthread_mutex_t lmu;
  buckets_listener *listeners;
  size_t nlisteners;
};

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

buckets_notifier *buckets_notifier_new(void) {
  buckets_notifier *n = buckets_xcalloc(1, sizeof(*n));
  pthread_rwlock_init(&n->lock, NULL);
  pthread_mutex_init(&n->lmu, NULL);
  return n;
}

static void free_targets(buckets_target **t, size_t k) {
  for (size_t i = 0; i < k; i++) buckets_target_free(t[i]);
  free(t);
}

void buckets_notifier_free(buckets_notifier *n) {
  if (!n) return;
  free_targets(n->targets, n->ntargets);
  pthread_mutex_lock(&n->lmu);
  for (buckets_listener *l = n->listeners; l; l = l->next) {
    pthread_mutex_lock(&l->mu);
    l->closed = true;
    l->n = NULL;
    pthread_cond_broadcast(&l->cv);
    pthread_mutex_unlock(&l->mu);
  }
  pthread_mutex_unlock(&n->lmu);
  pthread_mutex_destroy(&n->lmu);
  pthread_rwlock_destroy(&n->lock);
  free(n);
}

bool buckets_notifier_configure(buckets_notifier *n, const buckets_config *cfg, const char *ca_file, char *err,
                                size_t errlen) {
  buckets_target **t = NULL;
  size_t k = 0;
  if (!buckets_targets_build(cfg, ca_file, &t, &k, err, errlen)) return false;
  pthread_rwlock_wrlock(&n->lock);
  buckets_target **old = n->targets;
  size_t nold = n->ntargets;
  n->targets = t;
  n->ntargets = k;
  pthread_rwlock_unlock(&n->lock);
  free_targets(old, nold);
  for (size_t i = 0; i < k; i++) {
    const buckets_target_id *id = buckets_target_id_of(t[i]);
    buckets_log_info("notify: target %s:%s", id->id, id->type);
  }
  return true;
}

bool buckets_notifier_validate(const buckets_config *cfg, char *err, size_t errlen) {
  return buckets_targets_check(cfg, err, errlen);
}

static buckets_target *find(buckets_notifier *n, const buckets_target_id *id) {
  for (size_t i = 0; i < n->ntargets; i++) {
    const buckets_target_id *t = buckets_target_id_of(n->targets[i]);
    if (strcmp(t->id, id->id) == 0 && strcmp(t->type, id->type) == 0) return n->targets[i];
  }
  return NULL;
}

bool buckets_notifier_exists(void *ud, const buckets_target_id *id) {
  buckets_notifier *n = ud;
  pthread_rwlock_rdlock(&n->lock);
  bool ok = find(n, id) != NULL;
  pthread_rwlock_unlock(&n->lock);
  return ok;
}

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

size_t buckets_notifier_arns(buckets_notifier *n, const char *region, char ***out) {
  pthread_rwlock_rdlock(&n->lock);
  char **arns = buckets_xcalloc(n->ntargets ? n->ntargets : 1, sizeof(char *));
  for (size_t i = 0; i < n->ntargets; i++) {
    const buckets_target_id *id = buckets_target_id_of(n->targets[i]);
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&b, "arn:minio:sqs:%s:%s:%s", region ? region : "", id->id, id->type);
    arns[i] = b.data;
  }
  size_t k = n->ntargets;
  pthread_rwlock_unlock(&n->lock);
  qsort(arns, k, sizeof(char *), str_cmp);
  *out = arns;
  return k;
}

size_t buckets_notifier_target_info_get(buckets_notifier *n, const char *region, buckets_notifier_target_info **out) {
  pthread_rwlock_rdlock(&n->lock);
  buckets_notifier_target_info *v = buckets_xcalloc(n->ntargets ? n->ntargets : 1, sizeof(*v));
  for (size_t i = 0; i < n->ntargets; i++) {
    const buckets_target_id *id = buckets_target_id_of(n->targets[i]);
    snprintf(v[i].arn, sizeof(v[i].arn), "arn:minio:sqs:%s:%s:%s", region ? region : "", id->id, id->type);
    buckets_target_stats_get(n->targets[i], &v[i].st);
  }
  size_t k = n->ntargets;
  pthread_rwlock_unlock(&n->lock);
  *out = v;
  return k;
}

/* ---- listeners ------------------------------------------------------------------------ */

static void listener_pattern(buckets_listener *l, const char *prefix, const char *suffix) {
  /* event.NewPattern, as the listen handler builds it */
  buckets_buf p = BUCKETS_BUF_INIT;
  if (prefix && *prefix) {
    buckets_buf_append_c(&p, prefix);
    if (prefix[strlen(prefix) - 1] != '*') buckets_buf_append_char(&p, '*');
  }
  if (suffix && *suffix) {
    if (*suffix != '*') buckets_buf_append_char(&p, '*');
    buckets_buf_append_c(&p, suffix);
  }
  size_t k = 0;
  for (size_t i = 0; i < p.len && k + 1 < sizeof(l->pattern); i++) {
    if (p.data[i] == '*' && i + 1 < p.len && p.data[i + 1] == '*') continue;
    l->pattern[k++] = p.data[i];
  }
  l->pattern[k] = '\0';
  if (!k) snprintf(l->pattern, sizeof(l->pattern), "*");
  buckets_buf_free(&p);
}

buckets_listener *buckets_notifier_listen(buckets_notifier *n, const char *bucket, uint64_t mask, const char *prefix,
                                          const char *suffix, int ping_ms) {
  buckets_listener *l = buckets_xcalloc(1, sizeof(*l));
  l->n = n;
  l->bucket = bucket && *bucket ? buckets_xstrdup(bucket) : NULL;
  l->mask = mask;
  l->empty_records = ping_ms > 0;
  l->ping_ms = ping_ms > 0 ? ping_ms : 500;
  l->next_ping_ns = now_ns() + (int64_t)l->ping_ms * 1000000LL;
  listener_pattern(l, prefix, suffix);
  pthread_mutex_init(&l->mu, NULL);
  pthread_cond_init(&l->cv, NULL);
  pthread_mutex_lock(&n->lmu);
  l->next = n->listeners;
  n->listeners = l;
  n->nlisteners++;
  pthread_mutex_unlock(&n->lmu);
  return l;
}

long buckets_listener_read(void *ud, char *buf, size_t cap) {
  static const char empty[] = "{\"Records\":null}\n";
  buckets_listener *l = ud;
  pthread_mutex_lock(&l->mu);
  if (l->pending_pos == l->pending.len && !l->closed) {
    struct timespec until = {.tv_sec = (time_t)(l->next_ping_ns / 1000000000LL),
                             .tv_nsec = (long)(l->next_ping_ns % 1000000000LL)};
    pthread_cond_timedwait(&l->cv, &l->mu, &until);
  }
  long k = 0;
  if (l->pending_pos < l->pending.len) {
    size_t avail = l->pending.len - l->pending_pos;
    k = (long)(avail < cap ? avail : cap);
    memcpy(buf, l->pending.data + l->pending_pos, (size_t)k);
    l->pending_pos += (size_t)k;
    if (l->pending_pos == l->pending.len) {
      buckets_buf_reset(&l->pending);
      l->pending_pos = 0;
      l->queued = 0;
    }
  } else if (!l->closed && now_ns() >= l->next_ping_ns) {
    /* keep-alive while idle */
    if (l->empty_records && cap >= sizeof(empty) - 1) {
      memcpy(buf, empty, sizeof(empty) - 1);
      k = (long)sizeof(empty) - 1;
    } else {
      buf[0] = ' ';
      k = 1;
    }
  } else if (!l->closed) {
    pthread_mutex_unlock(&l->mu);
    return buckets_listener_read(ud, buf, cap); /* woken early with nothing to send */
  }
  if (now_ns() >= l->next_ping_ns) l->next_ping_ns = now_ns() + (int64_t)l->ping_ms * 1000000LL;
  pthread_mutex_unlock(&l->mu);
  return k;
}

void buckets_listener_free(void *ud) {
  buckets_listener *l = ud;
  if (!l) return;
  buckets_notifier *n = l->n;
  if (n) {
    pthread_mutex_lock(&n->lmu);
    for (buckets_listener **p = &n->listeners; *p; p = &(*p)->next) {
      if (*p == l) {
        *p = l->next;
        n->nlisteners--;
        break;
      }
    }
    pthread_mutex_unlock(&n->lmu);
  }
  buckets_buf_free(&l->pending);
  pthread_cond_destroy(&l->cv);
  pthread_mutex_destroy(&l->mu);
  free(l->bucket);
  free(l);
}

static void publish(buckets_notifier *n, const buckets_event_args *a, int64_t now) {
  pthread_mutex_lock(&n->lmu);
  if (!n->listeners) {
    pthread_mutex_unlock(&n->lmu);
    return;
  }
  uint64_t bit = buckets_event_name_mask(a->name);
  buckets_buf rec = BUCKETS_BUF_INIT;
  for (buckets_listener *l = n->listeners; l; l = l->next) {
    if (!(l->mask & bit) || (l->bucket && strcmp(l->bucket, a->bucket) != 0)) continue;
    if (!buckets_wildcard_match_simple(l->pattern, a->object ? a->object : "")) continue;
    if (!rec.len) {
      buckets_buf_append_c(&rec, "{\"Records\":[");
      buckets_event_json(a, false, now, &rec);
      buckets_buf_append_c(&rec, "]}\n");
    }
    pthread_mutex_lock(&l->mu);
    if (l->queued < LISTENER_QUEUE) { /* a slow listener loses events rather than slowing writes */
      buckets_buf_append(&l->pending, rec.data, rec.len);
      l->queued++;
      pthread_cond_broadcast(&l->cv);
    }
    pthread_mutex_unlock(&l->mu);
  }
  pthread_mutex_unlock(&n->lmu);
  buckets_buf_free(&rec);
}

bool buckets_notifier_wanted(buckets_notifier *n, const buckets_notify_config *bucket_cfg, buckets_event_name ev) {
  (void)ev;
  pthread_mutex_lock(&n->lmu);
  bool any = n->listeners != NULL;
  pthread_mutex_unlock(&n->lmu);
  return any || (bucket_cfg && bucket_cfg->nqueues);
}

void buckets_notifier_send(buckets_notifier *n, const buckets_notify_config *bucket_cfg, const buckets_event_args *a) {
  int64_t now = now_ns();
  publish(n, a, now);
  if (!bucket_cfg || !bucket_cfg->nqueues) return;
  buckets_target_id ids[64];
  size_t k = buckets_notify_config_match(bucket_cfg, a->name, a->object ? a->object : "", ids, BUCKETS_ARRAY_LEN(ids));
  if (!k) return;
  buckets_buf rec = BUCKETS_BUF_INIT, key = BUCKETS_BUF_INIT;
  buckets_event_json(a, true, now, &rec);
  buckets_buf_appendf(&key, "%s/%s", a->bucket, a->object ? a->object : "");
  pthread_rwlock_rdlock(&n->lock);
  for (size_t i = 0; i < k; i++) {
    buckets_target *t = find(n, &ids[i]);
    if (t) buckets_target_enqueue(t, rec.data, rec.len, buckets_event_name_str(a->name), key.data);
  }
  pthread_rwlock_unlock(&n->lock);
  buckets_buf_free(&rec);
  buckets_buf_free(&key);
}
