/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "notify/event.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/common.h"

/* Length of the UTF-8 sequence at s (n bytes left), or 0 when invalid. */
static size_t utf8_len(const unsigned char *s, size_t n, uint32_t *cp) {
  unsigned char c = s[0];
  size_t len;
  uint32_t v;
  if (c < 0x80) {
    *cp = c;
    return 1;
  } else if ((c & 0xe0) == 0xc0) {
    len = 2, v = c & 0x1f;
  } else if ((c & 0xf0) == 0xe0) {
    len = 3, v = c & 0x0f;
  } else if ((c & 0xf8) == 0xf0) {
    len = 4, v = c & 0x07;
  } else {
    return 0;
  }
  if (len > n) return 0;
  for (size_t i = 1; i < len; i++) {
    if ((s[i] & 0xc0) != 0x80) return 0;
    v = (v << 6) | (s[i] & 0x3f);
  }
  if ((len == 2 && v < 0x80) || (len == 3 && v < 0x800) || (len == 4 && (v < 0x10000 || v > 0x10ffff)) ||
      (v >= 0xd800 && v <= 0xdfff))
    return 0;
  *cp = v;
  return len;
}

bool buckets_utf8_valid(const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s;
  for (size_t i = 0; i < n;) {
    uint32_t cp;
    size_t len = utf8_len(p + i, n - i, &cp);
    if (!len) return false;
    i += len;
  }
  return true;
}

void buckets_json_go_string(buckets_buf *out, const char *s, size_t n) {
  static const char hex[] = "0123456789abcdef";
  const unsigned char *p = (const unsigned char *)s;
  buckets_buf_append_char(out, '"');
  for (size_t i = 0; i < n;) {
    unsigned char c = p[i];
    if (c < 0x80) {
      switch (c) {
      case '"': buckets_buf_append_c(out, "\\\""); break;
      case '\\': buckets_buf_append_c(out, "\\\\"); break;
      case '\n': buckets_buf_append_c(out, "\\n"); break;
      case '\r': buckets_buf_append_c(out, "\\r"); break;
      case '\t': buckets_buf_append_c(out, "\\t"); break;
      case '<':
      case '>':
      case '&':
        buckets_buf_appendf(out, "\\u00%c%c", hex[c >> 4], hex[c & 15]);
        break;
      default:
        if (c < 0x20) buckets_buf_appendf(out, "\\u00%c%c", hex[c >> 4], hex[c & 15]);
        else buckets_buf_append_char(out, (char)c);
      }
      i++;
      continue;
    }
    uint32_t cp;
    size_t len = utf8_len(p + i, n - i, &cp);
    if (!len) {
      /* encoding/json: the replacement character itself (U+FFFD) */
      buckets_buf_append_c(out, "\xef\xbf\xbd");
      i++;
      continue;
    }
    if (cp == 0x2028 || cp == 0x2029) buckets_buf_appendf(out, "\\u%04x", (unsigned)cp);
    else buckets_buf_append(out, (const char *)p + i, len);
    i += len;
  }
  buckets_buf_append_char(out, '"');
}

static void jstr(buckets_buf *out, const char *s) { buckets_json_go_string(out, s ? s : "", s ? strlen(s) : 0); }

void buckets_url_query_escape(buckets_buf *out, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
        *p == '.' || *p == '~')
      buckets_buf_append_char(out, (char)*p);
    else if (*p == ' ') buckets_buf_append_char(out, '+');
    else buckets_buf_appendf(out, "%%%c%c", hex[*p >> 4], hex[*p & 15]);
  }
}

static int kv_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_event_kv *)a)->key, ((const buckets_event_kv *)b)->key);
}

/* A JSON object of string pairs, sorted by key (Go marshals maps so). */
static void jmap(buckets_buf *out, buckets_event_kv *kv, size_t n) {
  qsort(kv, n, sizeof(*kv), kv_cmp);
  buckets_buf_append_char(out, '{');
  for (size_t i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(out, ',');
    jstr(out, kv[i].key);
    buckets_buf_append_char(out, ':');
    jstr(out, kv[i].value);
  }
  buckets_buf_append_char(out, '}');
}

void buckets_event_json(const buckets_event_args *a, bool escape_key, int64_t now_ns, buckets_buf *out) {
  time_t secs = (time_t)(now_ns / 1000000000LL);
  struct tm tm;
  gmtime_r(&secs, &tm);
  char when[40];
  snprintf(when, sizeof(when), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, (int)((now_ns / 1000000LL) % 1000));
  char seq[32];
  snprintf(seq, sizeof(seq), "%llX", (unsigned long long)(a->mod_time_ns ? a->mod_time_ns : now_ns));

  buckets_buf_append_c(out, "{\"eventVersion\":\"2.0\",\"eventSource\":\"minio:s3\",\"awsRegion\":");
  jstr(out, a->region);
  buckets_buf_append_c(out, ",\"eventTime\":");
  jstr(out, when);
  buckets_buf_append_c(out, ",\"eventName\":");
  jstr(out, buckets_event_name_str(a->name));
  buckets_buf_append_c(out, ",\"userIdentity\":{\"principalId\":");
  jstr(out, a->principal);
  buckets_buf_append_c(out, "},\"requestParameters\":");
  if (a->no_request) {
    buckets_buf_append_c(out, "null");
  } else {
    buckets_event_kv req[4];
    size_t nreq = 0;
    req[nreq++] = (buckets_event_kv){"principalId", a->principal ? a->principal : ""};
    req[nreq++] = (buckets_event_kv){"region", a->region ? a->region : ""};
    req[nreq++] = (buckets_event_kv){"sourceIPAddress", a->source_ip ? a->source_ip : ""};
    if (a->range && *a->range) req[nreq++] = (buckets_event_kv){"range", a->range};
    jmap(out, req, nreq);
  }
  buckets_buf_append_c(out, ",\"responseElements\":");
  buckets_event_kv resp[5];
  size_t nresp = 0;
  resp[nresp++] = (buckets_event_kv){"x-amz-request-id", a->request_id ? a->request_id : ""};
  resp[nresp++] = (buckets_event_kv){"x-amz-id-2", a->host_id ? a->host_id : ""};
  resp[nresp++] = (buckets_event_kv){"x-minio-origin-endpoint", a->origin_endpoint ? a->origin_endpoint : ""};
  resp[nresp++] = (buckets_event_kv){"x-minio-deployment-id", a->deployment_id ? a->deployment_id : ""};
  if (a->content_length && *a->content_length) resp[nresp++] = (buckets_event_kv){"content-length", a->content_length};
  jmap(out, resp, nresp);

  buckets_buf_append_c(out, ",\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"Config\",\"bucket\":{\"name\":");
  jstr(out, a->bucket);
  buckets_buf_append_c(out, ",\"ownerIdentity\":{\"principalId\":");
  jstr(out, a->principal);
  buckets_buf_append_c(out, "},\"arn\":");
  buckets_buf arn = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&arn, "arn:aws:s3:::%s", a->bucket ? a->bucket : "");
  jstr(out, arn.data);
  buckets_buf_free(&arn);
  buckets_buf_append_c(out, "},\"object\":{\"key\":");
  if (escape_key) {
    buckets_buf k = BUCKETS_BUF_INIT;
    buckets_url_query_escape(&k, a->object ? a->object : "");
    jstr(out, k.data ? k.data : "");
    buckets_buf_free(&k);
  } else {
    jstr(out, a->object);
  }
  bool removed = a->name == BUCKETS_EV_OBJECT_REMOVED_DELETE || a->name == BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED ||
                 a->name == BUCKETS_EV_OBJECT_REMOVED_NOOP;
  if (!removed) {
    if (a->size) buckets_buf_appendf(out, ",\"size\":%lld", (long long)a->size);
    if (a->etag && *a->etag) {
      buckets_buf_append_c(out, ",\"eTag\":");
      jstr(out, a->etag);
    }
    if (a->content_type && *a->content_type) {
      buckets_buf_append_c(out, ",\"contentType\":");
      jstr(out, a->content_type);
    }
    if (a->nuser_meta) {
      buckets_buf_append_c(out, ",\"userMetadata\":");
      buckets_event_kv *um = buckets_xcalloc(a->nuser_meta, sizeof(*um));
      memcpy(um, a->user_meta, a->nuser_meta * sizeof(*um));
      jmap(out, um, a->nuser_meta);
      free(um);
    }
  }
  if (a->version_id && *a->version_id) {
    buckets_buf_append_c(out, ",\"versionId\":");
    jstr(out, a->version_id);
  }
  buckets_buf_append_c(out, ",\"sequencer\":");
  jstr(out, seq);
  buckets_buf_append_c(out, "}},\"source\":{\"host\":");
  jstr(out, a->host);
  buckets_buf_append_c(out, ",\"port\":\"\",\"userAgent\":");
  jstr(out, a->user_agent);
  buckets_buf_append_c(out, "}}");
}
