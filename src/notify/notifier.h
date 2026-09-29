/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NOTIFY_NOTIFIER_H
#define BUCKETS_NOTIFY_NOTIFIER_H

#include "bucket/notification.h"
#include "config/config.h"
#include "notify/event.h"
#include "notify/target.h"

/* MinIO's EventNotifier and the HTTP listeners (ListenBucketNotification):
 * the notification targets built from the notify_* sub-systems, and the
 * delivery of events that a bucket's configuration selects. */

typedef struct buckets_notifier buckets_notifier;

buckets_notifier *buckets_notifier_new(void);
void buckets_notifier_free(buckets_notifier *n);

/* (Re)builds the targets from the configuration. On an invalid target the
 * old ones stay and err says why. ca_file: extra trusted CAs (or NULL). */
bool buckets_notifier_configure(buckets_notifier *n, const buckets_config *cfg, const char *ca_file, char *err,
                                size_t errlen);
/* Checks that a configuration would build (config set). */
bool buckets_notifier_validate(const buckets_config *cfg, char *err, size_t errlen);

/* TargetList.Exists, as a buckets_target_exists_fn (ud: the notifier). */
bool buckets_notifier_exists(void *n, const buckets_target_id *id);
/* The targets' ARNs (for server info); caller frees each and the array. */
size_t buckets_notifier_arns(buckets_notifier *n, const char *region, char ***out);

typedef struct {
  char arn[256];
  buckets_target_stats st;
} buckets_notifier_target_info;
size_t buckets_notifier_target_info_get(buckets_notifier *n, const char *region, buckets_notifier_target_info **out);

/* sendEvent: to the listeners, and to the targets bucket_cfg selects (may
 * be NULL: listeners only). */
void buckets_notifier_send(buckets_notifier *n, const buckets_notify_config *bucket_cfg, const buckets_event_args *a);
/* Whether anyone could want this event (skip building it otherwise). */
bool buckets_notifier_wanted(buckets_notifier *n, const buckets_notify_config *bucket_cfg, buckets_event_name ev);

/* ---- ListenBucketNotification ----
 * A subscription to events on bucket (NULL: every bucket) matching mask
 * and the prefix/suffix pattern. Reads yield {"Records":[...]}\n lines;
 * while idle, {"Records":null}\n every ping_ms (?ping=N), or with ping_ms 0
 * a space every 500ms (MinIO's deprecated keep-alive). */
typedef struct buckets_listener buckets_listener;
buckets_listener *buckets_notifier_listen(buckets_notifier *n, const char *bucket, uint64_t mask, const char *prefix,
                                          const char *suffix, int ping_ms);
long buckets_listener_read(void *l, char *buf, size_t cap);
void buckets_listener_free(void *l);

#endif
