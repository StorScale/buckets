/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/timefmt.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

long long buckets_days_from_civil(int y, int m, int d) {
  /* Howard Hinnant's algorithm: valid for any proleptic Gregorian date,
   * unlike timegm(), which some libcs reject before 1900. */
  y -= m <= 2;
  long long era = (y >= 0 ? y : y - 399) / 400;
  long long yoe = y - era * 400;
  long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

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

void buckets_time_iso8601_ns(int64_t ns, char *out) {
  time_t t = (time_t)(ns / 1000000000LL);
  long ms = (long)((ns % 1000000000LL) / 1000000LL);
  if (ns < 0 && ns % 1000000000LL) {
    t--;
    ms = (long)((ns % 1000000000LL + 1000000000LL) / 1000000LL);
  }
  struct tm tm;
  gmtime_r(&t, &tm);
  char base[24];
  strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(out, BUCKETS_TIME_ISO8601_LEN + 1, "%s.%03ldZ", base, ms);
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

/* time.Parse(time.RFC3339, s), to UTC seconds + nanoseconds. */
bool buckets_time_parse_rfc3339(const char *s, long long *sec, long *nsec) {
  int Y, M, D, h, m, sc, n = 0;
  if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &Y, &M, &D, &h, &m, &sc, &n) != 6 || n != 19) return false;
  if (M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || sc > 59) return false;
  const char *p = s + 19;
  long frac = 0;
  if (*p == '.') {
    p++;
    int digits = 0;
    while (isdigit((unsigned char)*p)) {
      if (digits < 9) frac = frac * 10 + (*p - '0');
      digits++;
      p++;
    }
    if (!digits) return false;
    for (; digits < 9; digits++) frac *= 10;
  }
  long off = 0;
  if (*p == 'Z') {
    p++;
  } else if (*p == '+' || *p == '-') {
    int oh, om, k = 0;
    if (sscanf(p + 1, "%2d:%2d%n", &oh, &om, &k) != 2 || k != 5) return false;
    off = (oh * 3600L + om * 60L) * (*p == '-' ? -1 : 1);
    p += 6;
  } else {
    return false;
  }
  if (*p) return false;
  static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  bool leap = (Y % 4 == 0 && Y % 100 != 0) || Y % 400 == 0;
  if (D > mdays[M - 1] + (M == 2 && leap)) return false;
  *sec = buckets_days_from_civil(Y, M, D) * 86400LL + h * 3600LL + m * 60LL + sc - off;
  *nsec = frac;
  return true;
}

void buckets_time_rfc3339_nano(long long sec, long nsec, char *out) {
  time_t t = (time_t)sec;
  struct tm tm;
  gmtime_r(&t, &tm);
  int n = snprintf(out, BUCKETS_TIME_RFC3339_NANO_LEN + 1, "%04d-%02d-%02dT%02d:%02d:%02d", tm.tm_year + 1900,
                   tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  if (nsec > 0) {
    char frac[11];
    snprintf(frac, sizeof(frac), ".%09ld", nsec);
    size_t k = strlen(frac);
    while (frac[k - 1] == '0') frac[--k] = '\0';
    memcpy(out + n, frac, k);
    n += (int)k;
  }
  out[n++] = 'Z';
  out[n] = '\0';
}

bool buckets_go_duration_parse(const char *s, int64_t *ns) {
  static const struct {
    const char *unit;
    double ns;
  } units[] = {{"ns", 1}, {"us", 1e3}, {"\xc2\xb5s", 1e3}, {"\xce\xbcs", 1e3}, {"ms", 1e6},
               {"s", 1e9}, {"m", 60e9}, {"h", 3600e9}};
  if (!s || !*s) return false;
  bool neg = false;
  if (*s == '-' || *s == '+') neg = *s++ == '-';
  if (strcmp(s, "0") == 0) {
    *ns = 0;
    return true;
  }
  double total = 0;
  if (!*s) return false;
  while (*s) {
    char *end;
    if (!((*s >= '0' && *s <= '9') || *s == '.')) return false;
    double v = strtod(s, &end);
    if (end == s) return false;
    s = end;
    size_t best = 0;
    double mult = 0;
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
      size_t n = strlen(units[i].unit);
      if (n > best && strncmp(s, units[i].unit, n) == 0) best = n, mult = units[i].ns;
    }
    if (!best) return false; /* a unit is required */
    s += best;
    total += v * mult;
  }
  if (total > 9.2e18) return false;
  *ns = (int64_t)(neg ? -total : total);
  return true;
}
