/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NOTIFY_TARGET_H
#define BUCKETS_NOTIFY_TARGET_H

#include <stdbool.h>
#include <stdint.h>

#include "bucket/notification.h"

/* A notification target (MinIO's event.Target): events are handed to a
 * worker thread, through a bounded in-memory queue, or through a queue
 * store (queue_dir: one file per event, replayed after restarts and outages)
 * when one is configured. */

typedef enum { BUCKETS_SEND_OK = 0, BUCKETS_SEND_NOT_CONNECTED, BUCKETS_SEND_ERROR } buckets_send_result;

typedef struct {
  const char *type; /* "webhook", "kafka", ... */
  /* Delivers one event: its record (event.Event JSON), name and
   * "bucket/key" (unescaped). */
  buckets_send_result (*send)(void *impl, const char *record, size_t n, const char *event_name, const char *key, char *err,
                              size_t errlen);
  void (*free)(void *impl);
  /* Target.IsActive: a live check (NULL: assumed up); err says why not
   * (Go's error, as config set reports it). */
  bool (*is_active)(void *impl, char *err, size_t errlen);
  /* Called about once a second while the target is idle (keep-alives:
   * NSQ heartbeats, MQTT pings); NULL: none. */
  void (*tick)(void *impl);
  /* A stored batch ("<n>:<uuid>.event") sent at once (Kafka's
   * sendMultiple); NULL: its records one by one. */
  buckets_send_result (*send_batch)(void *impl, const char *const *records, const size_t *lens, const char *const *names,
                                    const char *const *keys, size_t n, char *err, size_t errlen);
  /* Store batching (store.Batch): up to limit events are gathered, then
   * written as one entry, or every commit_ns (0: 30s); NULL or limit <= 1:
   * none. */
  void (*batch_limits)(void *impl, size_t *limit, int64_t *commit_ns);
  /* SendFromStore, where a target's calls differ from Save's (NULL: send). */
  buckets_send_result (*send_from_store)(void *impl, const char *record, size_t n, const char *event_name,
                                         const char *key, char *err, size_t errlen);
} buckets_target_ops;

typedef struct buckets_target buckets_target;

/* queue_dir NULL/"": in memory. The store lives in
 * <queue_dir>/minio-<type>-<id>, one <uuid>.event file per event, as
 * MinIO's QueueStore keeps it. */
buckets_target *buckets_target_new(const char *id, const buckets_target_ops *ops, void *impl, const char *queue_dir,
                                   uint64_t queue_limit, char *err, size_t errlen);
/* Stops the worker (events in a store stay there). */
void buckets_target_free(buckets_target *t);
const buckets_target_id *buckets_target_id_of(const buckets_target *t);
/* Store batching (see buckets_target_ops.batch_limits). */
void buckets_target_set_batch(buckets_target *t, size_t limit, int64_t commit_ns);
/* Queues an event; false when the queue (or store) is full. */
bool buckets_target_enqueue(buckets_target *t, const char *record, size_t n, const char *event_name, const char *key);

typedef struct {
  uint64_t sent, failed, dropped, queued; /* queued: now waiting */
  bool online;
} buckets_target_stats;
void buckets_target_stats_get(buckets_target *t, buckets_target_stats *out);
/* Checks the target now (may block for seconds). */
bool buckets_target_is_active(buckets_target *t);

#endif
