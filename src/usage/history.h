/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_USAGE_HISTORY_H
#define BUCKETS_USAGE_HISTORY_H

/* Usage history for the usage and chargeback reports (docs/design/usage-reports.md), in daily records under
 * .minio.sys/buckets/usage/<YYYY-MM-DD>/, apart from MinIO's own data usage:
 *   storage.json          the leader's samples at each scanner cycle:
 *                         {"buckets": {"<name>": {"avg", "count", "peak", "last"}}}
 *   traffic-<server>.json what each server counted, added every few minutes:
 *                         {"buckets": {"<name>": {"in", "out", "read", "write", "delete"}}}
 * The record parts are pure (JSON in, JSON out) and unit tested; reading and writing the files is the caller's. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <yyjson.h>

#include "core/buf.h"

#define BUCKETS_USAGE_DIR "buckets/usage/"
#define BUCKETS_USAGE_RATES_PATH "buckets/usage-rates.json"

/* ---- days ------------------------------------------------------------------------------------- */

/* "YYYY-MM-DD" (UTC) of a unix time. */
void buckets_usage_day(int64_t unix_s, char out[11]);
/* The unix time of a day's midnight (UTC); false when it is not a day. */
bool buckets_usage_day_parse(const char *day, int64_t *unix_s);
/* The days in the month a day is in. */
int buckets_usage_days_in_month(const char *day);
/* The first day kept when keeping `keep` days up to today (13 months: 396), into out; older days are
 * removed. Days compare as strings. */
void buckets_usage_keep_from(const char *today, int keep, char out[11]);
/* Days kept: BUCKETS_USAGE_HISTORY_DAYS when set (1 or more), else 396 (13 months). */
int buckets_usage_history_days(void);
/* Today, as the server records it: BUCKETS_USAGE_TEST_DAY when set (tests), else from the clock. */
void buckets_usage_today(char out[11]);

/* ---- what is counted -------------------------------------------------------------------------- */

typedef enum { BUCKETS_USAGE_READ = 0, BUCKETS_USAGE_WRITE, BUCKETS_USAGE_DELETE } buckets_usage_kind;
/* An S3 API, by its lowercase metrics name ("getobject"), as a read, a write or a delete. */
buckets_usage_kind buckets_usage_kind_of(const char *api);

typedef struct {
  uint64_t in, out, read, write, del;
} buckets_usage_traffic;

typedef struct {
  const char *bucket;
  buckets_usage_traffic t;
} buckets_usage_traffic_add;

/* A traffic record (or "" for none) with t added for each bucket, written to out. */
void buckets_usage_traffic_merge(const char *json, size_t len, const buckets_usage_traffic_add *add, size_t n,
                                 buckets_buf *out);

typedef struct {
  const char *bucket;
  uint64_t bytes;
} buckets_usage_sample;

/* A storage record (or "" for none) with one more sample of each bucket, written to out: the day's running
 * average, its peak and the latest. */
void buckets_usage_storage_merge(const char *json, size_t len, const buckets_usage_sample *s, size_t n,
                                 buckets_buf *out);

/* ---- teams ------------------------------------------------------------------------------------- */

/* The team a bucket is charged to, among teams as buckets_teams_from_policies gives them (sorted by name):
 * the first team naming it, else the team whose prefix matches it longest; NULL when none. *named_twice is
 * set when more than one team names it. */
const char *buckets_usage_team_of(yyjson_val *teams, const char *bucket, bool *named_twice);

/* ---- a period ---------------------------------------------------------------------------------- */

/* Where a period's records come from. storage: the day's storage record into out (false when none). traffic:
 * each server's record for the day, appended to out as separate documents (their count). */
typedef struct {
  bool (*storage)(void *ud, const char *day, buckets_buf *out);
  size_t (*traffic)(void *ud, const char *day, buckets_buf **out);
  void *ud;
} buckets_usage_source;

/* The report for from..to (inclusive days, at most 400), as JSON (docs/design/usage-reports.md):
 * {"from", "to", "days", "buckets": [...], "teams": [...], "missingDays": [...]}. teams: as for
 * buckets_usage_team_of (may be NULL); rates: the stored rates document or NULL, copied into the report.
 * False (and why) for a bad period. A day without a storage record carries the last known sizes forward,
 * looking back up to 31 days before from; a day with nothing to carry is missing. */
bool buckets_usage_report(const buckets_usage_source *src, const char *from, const char *to,
                          yyjson_val *teams, yyjson_val *rates, buckets_buf *out, char *err, size_t errlen);

/* Checks a rates document {"currency", "storageGbMonth", "outGb", "inGb", "per10kRead", "per10kWrite",
 * "per10kDelete"}: numbers from 0, a currency of 1 to 8 characters. */
bool buckets_usage_rates_check(yyjson_val *rates, char *err, size_t errlen);

#endif
