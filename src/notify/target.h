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
/* Queues an event; false when the queue (or store) is full. */
bool buckets_target_enqueue(buckets_target *t, const char *record, size_t n, const char *event_name, const char *key);

typedef struct {
  uint64_t sent, failed, dropped, queued; /* queued: now waiting */
  bool online;
} buckets_target_stats;
void buckets_target_stats_get(buckets_target *t, buckets_target_stats *out);

#endif
