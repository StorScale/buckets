/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/timefmt.h"

#include <stdio.h>
#include <string.h>

static const char *const k_days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char *const k_months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

void buckets_time_amz(time_t t, char *out) {
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, BUCKETS_TIME_AMZ_LEN + 1, "%Y%m%dT%H%M%SZ", &tm);
}

void buckets_time_iso8601(time_t t, char *out) {
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, BUCKETS_TIME_ISO8601_LEN + 1, "%Y-%m-%dT%H:%M:%S.000Z", &tm);
}

void buckets_time_http(time_t t, char *out) {
  struct tm tm;
  gmtime_r(&t, &tm);
  /* Avoid strftime %a/%b: they are locale-dependent. */
  snprintf(out, BUCKETS_TIME_HTTP_LEN + 1, "%s, %02d %s %04d %02d:%02d:%02d GMT", k_days[tm.tm_wday],
           tm.tm_mday, k_months[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static bool parse_digits(const char *p, int n, int *out) {
  int v = 0;
  for (int i = 0; i < n; i++) {
    if (p[i] < '0' || p[i] > '9') return false;
    v = v * 10 + (p[i] - '0');
  }
  *out = v;
  return true;
}

static bool tm_in_range(const struct tm *tm) {
  return tm->tm_mon >= 0 && tm->tm_mon <= 11 && tm->tm_mday >= 1 && tm->tm_mday <= 31 &&
         tm->tm_hour <= 23 && tm->tm_min <= 59 && tm->tm_sec <= 60;
}

bool buckets_time_parse_amz(buckets_str s, time_t *out) {
  if (s.n != BUCKETS_TIME_AMZ_LEN || s.p[8] != 'T' || s.p[15] != 'Z') return false;
  struct tm tm = {0};
  int y, mo, d, h, mi, se;
  if (!parse_digits(s.p, 4, &y) || !parse_digits(s.p + 4, 2, &mo) || !parse_digits(s.p + 6, 2, &d) ||
      !parse_digits(s.p + 9, 2, &h) || !parse_digits(s.p + 11, 2, &mi) ||
      !parse_digits(s.p + 13, 2, &se)) {
    return false;
  }
  tm.tm_year = y - 1900;
  tm.tm_mon = mo - 1;
  tm.tm_mday = d;
  tm.tm_hour = h;
  tm.tm_min = mi;
  tm.tm_sec = se;
  if (!tm_in_range(&tm)) return false;
  *out = timegm(&tm);
  return true;
}

bool buckets_time_parse_http(buckets_str s, time_t *out) {
  /* RFC 1123 only: "Sun, 30 Aug 2015 12:36:00 GMT" */
  if (s.n != BUCKETS_TIME_HTTP_LEN || s.p[3] != ',' || memcmp(s.p + 26, "GMT", 3) != 0) return false;
  struct tm tm = {0};
  int d, y, h, mi, se;
  if (!parse_digits(s.p + 5, 2, &d) || !parse_digits(s.p + 12, 4, &y) ||
      !parse_digits(s.p + 17, 2, &h) || !parse_digits(s.p + 20, 2, &mi) ||
      !parse_digits(s.p + 23, 2, &se)) {
    return false;
  }
  tm.tm_mon = -1;
  for (int i = 0; i < 12; i++) {
    if (memcmp(s.p + 8, k_months[i], 3) == 0) tm.tm_mon = i;
  }
  tm.tm_year = y - 1900;
  tm.tm_mday = d;
  tm.tm_hour = h;
  tm.tm_min = mi;
  tm.tm_sec = se;
  if (!tm_in_range(&tm)) return false;
  *out = timegm(&tm);
  return true;
}
