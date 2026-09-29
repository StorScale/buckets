/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket notifications: ?notification GET/PUT (cmd/bucket-notification-
 * handlers.go) and sendEvent for the object and bucket handlers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "admin/info.h"
#include "bucket/metasys.h"
#include "bucket/notification.h"
#include "notify/notifier.h"
#include "s3/internal.h"
#include "s3/xml.h"

void buckets_s3_get_notification(s3_ctx *c) {
  if (!buckets_s3_require(c, "s3:GetBucketNotification", c->bucket, NULL, NULL)) return;
  buckets_obj_err oe = buckets_obj_stat_bucket(c->s->layer, c->bucket);
  if (oe) {
    buckets_s3_write_error(c, buckets_s3_obj_error(oe));
    return;
  }
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  buckets_notify_config cfg = {0};
  const buckets_buf *raw = &st->meta.config[BUCKETS_BCFG_NOTIFICATION];
  bool have = raw->len && buckets_notify_config_load(raw->data, raw->len, &cfg);
  buckets_bucket_state_release(st);
  /* Queues whose target is gone are left out (MinIO once allowed them). */
  if (have) buckets_notify_config_prune(&cfg, buckets_notifier_exists, c->s->notifier);
  else snprintf(cfg.xmlns, sizeof(cfg.xmlns), "%s", BUCKETS_S3_XMLNS); /* the default config (parseAllConfigs) */
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_notify_config_xml(&cfg, c->s->region, b);
  buckets_notify_config_free(&cfg);
  buckets_s3_write_xml(c, 200);
}

void buckets_s3_put_notification(s3_ctx *c) {
  if (!buckets_s3_require(c, "s3:PutBucketNotification", c->bucket, NULL, NULL)) return;
  buckets_obj_err oe = buckets_obj_stat_bucket(c->s->layer, c->bucket);
  if (oe) {
    buckets_s3_write_error(c, buckets_s3_obj_error(oe));
    return;
  }
  if (c->req->body_len <= 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_MISSING_CONTENT_LENGTH);
    return;
  }
  buckets_s3_error e = buckets_s3_read_doc(c);
  if (e) {
    buckets_s3_write_error(c, e);
    return;
  }
  buckets_notify_config cfg;
  char msg[512];
  if (!buckets_notify_config_parse(c->doc.data ? c->doc.data : "", c->doc.len, c->s->region, buckets_notifier_exists,
                                   c->s->notifier, &cfg, &e, msg, sizeof(msg))) {
    buckets_s3_write_error(c, e);
    return;
  }
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_notify_config_xml(&cfg, c->s->region, &x);
  buckets_notify_config_free(&cfg);
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_NOTIFICATION, x.data, x.len)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
  } else {
    c->resp->status = 200;
  }
  buckets_buf_free(&x);
}

/* The principal of the request: the parent of derived credentials. */
static const char *principal(const s3_ctx *c) {
  if (c->ident && c->ident->parent && *c->ident->parent) return c->ident->parent;
  return c->access_key;
}

/* Not user metadata: the reserved prefix, and what cleanMetadata drops. */
static bool reserved(const char *k, const char *v) {
  static const char *const dropped[] = {"md5Sum", "etag", "expires", "X-Amz-Tagging", "last-modified"};
  if (strncasecmp(k, "x-minio-internal-", 17) == 0) return true;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(dropped); i++)
    if (strcasecmp(k, dropped[i]) == 0) return true;
  return strcasecmp(k, "x-amz-storage-class") == 0 && strcmp(v, "STANDARD") == 0;
}

static void send_event(s3_ctx *c, int event_name, const char *bucket, const char *object, const buckets_object_info *oi,
                       const char *version_id, bool written, const char *internal_ua) {
  buckets_notifier *n = c->s->notifier;
  if (!n || !c->s->meta) return;
  /* no events for replica writes (sendEvent) */
  if (c->req && buckets_http_header_get(c->req, "X-Minio-Source-Replication-Request").p) return;
  /* a bucket just created or removed has no rules: only listeners hear it */
  bool bucket_ev = event_name == BUCKETS_EV_BUCKET_CREATED || event_name == BUCKETS_EV_BUCKET_REMOVED;
  buckets_bucket_state *st = bucket_ev ? NULL : buckets_metasys_get(c->s->meta, bucket);
  const buckets_notify_config *cfg = st && st->has_notify ? &st->notify : NULL;
  if (!buckets_notifier_wanted(n, cfg, (buckets_event_name)event_name)) {
    buckets_bucket_state_release(st);
    return;
  }
  char ip[128] = "";
  char *range_s = NULL, *ua_s = NULL;
  if (c->req) {
    buckets_s3_source_ip(c->req, ip, sizeof(ip));
    buckets_str range = buckets_http_header_get(c->req, "Range"), ua = buckets_http_header_get(c->req, "User-Agent");
    range_s = range.p ? buckets_str_dup(range) : NULL;
    ua_s = ua.p ? buckets_str_dup(ua) : NULL;
  }
  buckets_event_kv *meta = NULL;
  size_t nmeta = 0;
  char etag[128] = "", vid[64] = "", clen[32] = "";
  const char *ctype = "";
  int64_t size = 0, mod = 0;
  if (oi) {
    meta = buckets_xcalloc(oi->nmeta ? oi->nmeta : 1, sizeof(*meta));
    for (size_t i = 0; i < oi->nmeta; i++) {
      if (reserved(oi->meta[i].key, (const char *)oi->meta[i].value)) continue;
      meta[nmeta++] = (buckets_event_kv){oi->meta[i].key, (const char *)oi->meta[i].value};
    }
    const char *ct = buckets_object_meta(oi, "content-type");
    ctype = ct ? ct : "";
    snprintf(etag, sizeof(etag), "%s", oi->etag);
    size = oi->size;
    mod = oi->mod_time_ns;
    if (strcmp(oi->version_id, "null") != 0) snprintf(vid, sizeof(vid), "%s", oi->version_id);
  }
  if (version_id && *version_id && strcmp(version_id, "null") != 0) snprintf(vid, sizeof(vid), "%s", version_id);
  /* the Content-Length written (writeResponse sets "0" on empty bodies) */
  if (written && c->resp)
    snprintf(clen, sizeof(clen), "%lld",
             c->resp->content_length >= 0 ? (long long)c->resp->content_length : (long long)c->resp->body.len);
  buckets_objlayer *L = c->s->layer;
  buckets_event_args a = {
      .name = (buckets_event_name)event_name,
      .bucket = bucket,
      .object = object ? object : "",
      .size = size,
      .etag = etag,
      .content_type = ctype,
      .version_id = vid,
      .user_meta = meta,
      .nuser_meta = nmeta,
      .mod_time_ns = mod,
      .no_request = internal_ua != NULL,
      .region = internal_ua ? "" : c->s->region,
      .principal = internal_ua ? "" : principal(c),
      .source_ip = ip,
      .range = range_s,
      .request_id = c->request_id,
      .host_id = internal_ua ? "" : c->s->host_id,
      .content_length = clen,
      .origin_endpoint = c->s->endpoint,
      .deployment_id = L ? L->deployment_id_str : "",
      /* internal events: globalLocalNodeName */
      .host = internal_ua ? (c->s->cluster && c->s->cluster->self ? c->s->cluster->self : "") : ip,
      .user_agent = internal_ua ? internal_ua : ua_s ? ua_s : "",
  };
  buckets_notifier_send(n, cfg, &a);
  buckets_bucket_state_release(st);
  free(meta);
  free(range_s);
  free(ua_s);
}

void buckets_s3_send_event(s3_ctx *c, int event_name, const char *bucket, const char *object, const buckets_object_info *oi,
                           const char *version_id) {
  send_event(c, event_name, bucket, object, oi, version_id, true, NULL);
}

void buckets_s3_send_event_early(s3_ctx *c, int event_name, const char *bucket, const char *object,
                                 const buckets_object_info *oi, const char *version_id) {
  send_event(c, event_name, bucket, object, oi, version_id, false, NULL);
}

/* event.ValidateFilterRuleValue */
static bool filter_value_ok(const char *v) {
  size_t n = strlen(v);
  if (n > 1024 || strchr(v, '\\') || !buckets_utf8_valid(v, n)) return false;
  for (const char *p = v;;) {
    const char *slash = strchr(p, '/');
    size_t len = slash ? (size_t)(slash - p) : strlen(p);
    if ((len == 1 && p[0] == '.') || (len == 2 && p[0] == '.' && p[1] == '.')) return false;
    if (!slash) break;
    p = slash + 1;
  }
  return true;
}

/* The single value of key: NULL when absent; *many when repeated. */
static const char *query_one(const buckets_query *q, const char *key, bool *many) {
  const char *v = NULL;
  size_t k = 0;
  for (size_t i = 0; i < q->n; i++) {
    if (strcmp(q->items[i].key, key) != 0) continue;
    if (!k++) v = q->items[i].value;
  }
  *many = k > 1;
  return v;
}

/* ListenNotificationHandler: GET /?events=... (every bucket) or
 * GET /bucket?events=...; a stream of {"Records":[...]} lines. */
void buckets_s3_listen_notification(s3_ctx *c) {
  bool all = !c->bucket || !*c->bucket;
  if (!buckets_s3_require(c, all ? "s3:ListenNotification" : "s3:ListenBucketNotification", all ? "" : c->bucket, NULL,
                          NULL))
    return;
  if (!c->s->notifier) {
    buckets_s3_write_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
    return;
  }
  bool many;
  const char *prefix = query_one(&c->q, "prefix", &many);
  if (many) {
    buckets_s3_write_error(c, BUCKETS_ERR_FILTER_NAME_PREFIX);
    return;
  }
  if (prefix && !filter_value_ok(prefix)) {
    buckets_s3_write_error(c, BUCKETS_ERR_FILTER_VALUE_INVALID);
    return;
  }
  const char *suffix = query_one(&c->q, "suffix", &many);
  if (many) {
    buckets_s3_write_error(c, BUCKETS_ERR_FILTER_NAME_SUFFIX);
    return;
  }
  if (suffix && !filter_value_ok(suffix)) {
    buckets_s3_write_error(c, BUCKETS_ERR_FILTER_VALUE_INVALID);
    return;
  }
  uint64_t mask = 0;
  for (size_t i = 0; i < c->q.n; i++) {
    if (strcmp(c->q.items[i].key, "events") != 0) continue;
    buckets_event_name ev = buckets_event_name_parse(c->q.items[i].value);
    if (!ev) {
      buckets_s3_write_error(c, BUCKETS_ERR_EVENT_NOTIFICATION);
      return;
    }
    mask |= buckets_event_name_mask(ev);
  }
  if (!all) {
    buckets_obj_err oe = buckets_obj_stat_bucket(c->s->layer, c->bucket);
    if (oe) {
      buckets_s3_write_error(c, buckets_s3_obj_error(oe));
      return;
    }
  }
  int ping_ms = 0;
  const char *ping = buckets_query_get(&c->q, "ping");
  if (ping) {
    char *end;
    long v = strtol(ping, &end, 10);
    if (!*ping || *end || v < 1 || v > 86400) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_QUERY_PARAMS);
      return;
    }
    ping_ms = (int)v * 1000;
  }
  buckets_listener *l = buckets_notifier_listen(c->s->notifier, all ? NULL : c->bucket, mask, prefix, suffix, ping_ms);
  buckets_http_resp_header(c->resp, "Content-Type", "text/event-stream");
  buckets_http_resp_header(c->resp, "Cache-Control", "no-cache");
  buckets_http_resp_header(c->resp, "X-Accel-Buffering", "no");
  c->resp->status = 200;
  c->resp->chunked = true;
  c->resp->stream = buckets_listener_read;
  c->resp->stream_ud = l;
  c->resp->stream_free = buckets_listener_free;
}

void buckets_s3_send_internal_event(buckets_s3_server *s, int event_name, const char *bucket, const char *object,
                                    const buckets_object_info *oi, const char *version_id, const char *user_agent) {
  s3_ctx c = {.s = s};
  send_event(&c, event_name, bucket, object, oi, version_id, false, user_agent);
}
