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
void buckets_time_http(time_t t, char *out);

bool buckets_time_parse_amz(buckets_str s, time_t *out);
bool buckets_time_parse_http(buckets_str s, time_t *out);

#endif
