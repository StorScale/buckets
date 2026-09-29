/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NOTIFY_EVENT_H
#define BUCKETS_NOTIFY_EVENT_H

#include <stdbool.h>
#include <stdint.h>

#include "bucket/notification.h"
#include "core/buf.h"

/* An S3 event notification record (MinIO's eventArgs.ToEvent and
 * event.Event), serialized as Go's encoding/json does. */

typedef struct {
  const char *key, *value;
} buckets_event_kv;

typedef struct {
  buckets_event_name name;
  const char *bucket;
  const char *object;       /* key ("" for bucket events) */
  int64_t size;             /* plaintext size */
  const char *etag;         /* as clients see it */
  const char *content_type;
  const char *version_id;   /* "" when none */
  const buckets_event_kv *user_meta; /* user-defined metadata, internal keys removed */
  size_t nuser_meta;
  int64_t mod_time_ns;      /* 0: the sequencer uses the event time */
  /* request parameters (extractReqParams) */
  const char *region, *principal, *source_ip, *range;
  /* response elements (extractRespElements) and the server */
  const char *request_id, *host_id, *content_length;
  const char *origin_endpoint, *deployment_id;
  /* source */
  const char *host, *user_agent;
} buckets_event_args;

/* One Event as JSON; escape_key URL-query-escapes the object key (events
 * for targets, as opposed to ListenBucketNotification). now_ns: the event
 * time. */
void buckets_event_json(const buckets_event_args *a, bool escape_key, int64_t now_ns, buckets_buf *out);

/* Go's json string encoding (HTML-safe, invalid UTF-8 as U+FFFD), quoted. */
/* utf8.ValidString */
bool buckets_utf8_valid(const char *s, size_t n);
void buckets_json_go_string(buckets_buf *out, const char *s, size_t n);

/* url.QueryEscape */
void buckets_url_query_escape(buckets_buf *out, const char *s);

#endif
