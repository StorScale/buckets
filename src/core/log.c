/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/log.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/buf.h"
#include "core/timefmt.h"

static buckets_log_level g_level = BUCKETS_LOG_INFO;
static const char *const level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};

void buckets_log_set_level(buckets_log_level level) { g_level = level; }

bool buckets_log_parse_level(const char *s, buckets_log_level *out) {
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(level_names); i++) {
    if (strcasecmp(s, level_names[i]) == 0) {
      *out = (buckets_log_level)i;
      return true;
    }
  }
  return false;
}

static void json_escape(buckets_buf *out, const char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
      case '"': buckets_buf_append(out, "\\\"", 2); break;
      case '\\': buckets_buf_append(out, "\\\\", 2); break;
      case '\n': buckets_buf_append(out, "\\n", 2); break;
      case '\r': buckets_buf_append(out, "\\r", 2); break;
      case '\t': buckets_buf_append(out, "\\t", 2); break;
      default:
        if (c < 0x20) {
          buckets_buf_appendf(out, "\\u%04x", c);
        } else {
          buckets_buf_append_char(out, (char)c);
        }
    }
  }
}

static _Atomic uint64_t g_problems;
static buckets_log_sink_fn g_sink;
static void *g_sink_ud;
static _Thread_local bool g_sink_off;

void buckets_log_set_sink(buckets_log_sink_fn fn, void *ud) {
  g_sink_ud = ud;
  g_sink = fn;
}

void buckets_log_sink_suppress(bool on) { g_sink_off = on; }

uint64_t buckets_log_problems(void) { return atomic_load(&g_problems); }

void buckets_log(buckets_log_level level, const char *fmt, ...) {
  if (level >= BUCKETS_LOG_WARN) atomic_fetch_add(&g_problems, 1);
  buckets_log_sink_fn sink = level >= BUCKETS_LOG_WARN && !g_sink_off ? g_sink : NULL;
  if (level < g_level && !sink) return;

  buckets_buf msg = BUCKETS_BUF_INIT;
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n > 0) {
    buckets_buf_reserve(&msg, (size_t)n);
    vsnprintf(msg.data, (size_t)n + 1, fmt, ap2);
    msg.len = (size_t)n;
  }
  va_end(ap2);

  char ts[BUCKETS_TIME_ISO8601_LEN + 1];
  buckets_time_iso8601(time(NULL), ts);

  if (level >= g_level) {
    buckets_buf line = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&line, "{\"level\":\"%s\",\"time\":\"%s\",\"msg\":\"", level_names[level], ts);
    json_escape(&line, msg.data ? msg.data : "", msg.len);
    buckets_buf_append(&line, "\"}\n", 3);
    fwrite(line.data, 1, line.len, stderr);
    buckets_buf_free(&line);
  }
  if (sink) {
    g_sink_off = true; /* whatever the sink logs is not fed back to it */
    sink(g_sink_ud, level, msg.data ? msg.data : "", msg.len);
    g_sink_off = false;
  }
  buckets_buf_free(&msg);
}
