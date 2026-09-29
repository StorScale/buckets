/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_TIMEFMT_H
#define BUCKETS_CORE_TIMEFMT_H

#include <time.h>

#include "core/str.h"

/* 20150830T123600Z */
#define BUCKETS_TIME_AMZ_LEN 16
/* 2015-08-30T12:36:00.000Z (S3 XML timestamps) */
#define BUCKETS_TIME_ISO8601_LEN 24
/* Sun, 30 Aug 2015 12:36:00 GMT */
#define BUCKETS_TIME_HTTP_LEN 29

/* Output buffers must hold LEN + 1 bytes. All times are UTC. */
void buckets_time_amz(time_t t, char *out);
void buckets_time_iso8601(time_t t, char *out);
/* amztime.ISO8601Format: milliseconds from a unix-nanosecond time. */
void buckets_time_iso8601_ns(int64_t ns, char *out);
void buckets_time_http(time_t t, char *out);

bool buckets_time_parse_amz(buckets_str s, time_t *out);
bool buckets_time_parse_http(buckets_str s, time_t *out);

/* Go's time.RFC3339Nano in UTC ("2006-01-02T15:04:05.999999999Z", trailing
 * fraction zeros trimmed), as encoding/json writes time.Time. */
#define BUCKETS_TIME_RFC3339_NANO_LEN 30
void buckets_time_rfc3339_nano(long long sec, long nsec, char *out);
/* time.Parse(time.RFC3339, s) (fraction and offset accepted), to UTC. */
bool buckets_time_parse_rfc3339(const char *s, long long *sec, long *nsec);
/* Days since 1970-01-01 of a proleptic Gregorian date. */
long long buckets_days_from_civil(int y, int m, int d);

/* time.ParseDuration: a signed sequence of decimal numbers with units
 * (ns, us, µs, ms, s, m, h), e.g. "300ms", "-1.5h", "2h45m". */
bool buckets_go_duration_parse(const char *s, int64_t *ns);

#endif
