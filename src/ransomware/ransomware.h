/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_RANSOMWARE_H
#define BUCKETS_RANSOMWARE_H

/* Ransomware alerts (docs/design/ransomware-alerts.md): every server counts deletes, destroyed versions and
 * overwrites per bucket and credential, in one-minute slots for the last hour, and the protection changes made;
 * the leader sums every server's recent counts, finds bursts against each bucket's usual rate, and keeps the
 * incidents (s3/ransomguard.c). The counting, the snapshot a server gives the leader, the detection rule and the
 * incidents' records are here, apart from the server, and unit tested. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <yyjson.h>

#include "core/buf.h"

#define BUCKETS_RW_INCIDENTS_PATH "buckets/incidents.json"

typedef enum {
  BUCKETS_RW_DELETED = 0,
  BUCKETS_RW_DESTROYED,
  BUCKETS_RW_OVERWRITTEN,
  BUCKETS_RW_NKINDS
} buckets_rw_kind;

/* The protection changes reported every time. */
typedef enum {
  BUCKETS_RW_VERSIONING_SUSPENDED = 0,
  BUCKETS_RW_NONCURRENT_EXPIRY,
  BUCKETS_RW_RETENTION_BYPASSED,
  BUCKETS_RW_BUCKET_DELETED,
  BUCKETS_RW_PUBLIC_WRITE,
  BUCKETS_RW_NCHANGES
} buckets_rw_change;
const char *buckets_rw_change_name(buckets_rw_change c); /* "versioning-suspended", ... */

/* ---- counting (each server) ------------------------------------------------------------------------- */

/* n objects of a kind, by a credential (its access key, the person behind it, and "user", "access-key", "sts"
 * or "root"), at now (unix seconds). */
void buckets_rw_note(const char *bucket, const char *access_key, const char *user, const char *cred_type,
                     buckets_rw_kind kind, uint64_t n, int64_t now);
/* A protection change, queued for the leader. detail: what changed, in words. */
void buckets_rw_protection(const char *bucket, const char *access_key, const char *user,
                           const char *cred_type, buckets_rw_change change, const char *detail, int64_t now);

typedef struct {
  char *bucket;
  uint64_t n[BUCKETS_RW_NKINDS];
  uint64_t changes[BUCKETS_RW_NCHANGES];
} buckets_rw_total;
/* Each bucket's counts since the server started (the metrics, and the usage history's deltas). */
size_t buckets_rw_totals(buckets_rw_total **out);
void buckets_rw_totals_free(buckets_rw_total *t, size_t n);

/* This server's counts for the window minutes up to now, per bucket and credential, and the protection changes
 * queued after since (a sequence number), as JSON for the leader:
 *   {"node", "seq", "rows": [{"b", "k", "u", "t", "n": [deleted, destroyed, overwritten]}],
 *    "changes": [{"seq", "b", "k", "u", "t", "change", "detail", "at"}]} */
void buckets_rw_snapshot(const char *node, int window_min, uint64_t since, int64_t now, buckets_buf *out);
/* Forgets everything (tests). */
void buckets_rw_reset(void);

/* ---- detection (the leader) ------------------------------------------------------------------------- */

/* One bucket and credential's counts over the window, summed over the servers. */
typedef struct {
  char *bucket, *access_key, *user, *cred_type;
  uint64_t n[BUCKETS_RW_NKINDS];
} buckets_rw_row;

/* Adds a snapshot's rows to rows (same bucket and credential added together). */
void buckets_rw_rows_add(buckets_rw_row **rows, size_t *n, yyjson_val *snapshot);
void buckets_rw_rows_free(buckets_rw_row *rows, size_t n);

typedef struct {
  uint64_t floor; /* at least this many objects in the window (BUCKETS_RANSOMWARE_FLOOR, 1000) */
  double factor;  /* and this many times the usual rate (BUCKETS_RANSOMWARE_FACTOR, 10) */
  int window_min; /* BUCKETS_RANSOMWARE_WINDOW, in minutes (5) */
} buckets_rw_rule;
/* The rule from the environment, its defaults otherwise. */
void buckets_rw_rule_from_env(buckets_rw_rule *r);
/* Whether bucket is left out (BUCKETS_RANSOMWARE_EXCLUDE: a comma-separated list). */
bool buckets_rw_excluded(const char *bucket);

typedef enum {
  BUCKETS_RW_MASS_DELETE = 0,
  BUCKETS_RW_MASS_OVERWRITE,
  BUCKETS_RW_PROTECTION_REMOVED
} buckets_rw_incident_kind;
const char *buckets_rw_kind_name(buckets_rw_incident_kind k); /* "mass-delete", ... */

/* A burst found: a bucket's (bucket set), or a credential's over several buckets (bucket NULL). The credentials
 * are the biggest contributors, largest first (up to 3). */
typedef struct {
  buckets_rw_incident_kind kind;
  const char *bucket;
  uint64_t count, usual;
  const buckets_rw_row *who[3];
  uint64_t who_n[3];
  size_t nwho;
} buckets_rw_burst;

/* The usual count over the window, for a bucket and a kind (deletes or overwrites): from its history; 0 when it
 * has none. */
typedef uint64_t (*buckets_rw_usual_fn)(void *ud, const char *bucket, buckets_rw_incident_kind kind);

/* The bursts in rows: per bucket, at least floor objects and more than factor times the usual count; per
 * credential over several buckets, the same against the sum of their usual counts, when no bucket's burst names
 * it already. Excluded buckets are skipped. *out is malloc'd. */
size_t buckets_rw_detect(const buckets_rw_row *rows, size_t n, const buckets_rw_rule *rule,
                         buckets_rw_usual_fn usual, void *ud, buckets_rw_burst **out);

/* A bucket's usual count over window minutes, from the usage history's traffic records (usage/history.h: each
 * bucket's "dh" and "oh", deletes and overwrites per UTC hour), summed over the servers: the median of the 14 days'
 * busiest hours, scaled to the window. records[i] is one server's record of day[i] (0 to 13 days before
 * yesterday, so today, which an attack under way is already part of, counts not). */
uint64_t buckets_rw_usual_from_history(const buckets_buf *records, const int *day, size_t n,
                                       const char *bucket, buckets_rw_incident_kind kind, int window_min);

/* ---- incidents --------------------------------------------------------------------------------------- */

/* The stored incidents (incidents.json), as a mutable document {"incidents": [...]}:
 *   {"id", "kind", "bucket" (or null: several), "change" (protection), "detail",
 *    "credentials": [{"accessKey", "user", "type", "count"}], "opened", "lastSeen", "closed" (0: open),
 *    "counts": {"deleted", "destroyed", "overwritten"}, "usual", "action": "disabled" | "revoked" | "none" | null,
 *    "undone", "falseAlarm", "source": a protection change's "node/seq"} */
yyjson_mut_doc *buckets_rw_incidents_parse(const char *json, size_t len);
/* The open incident of kind for bucket (NULL: a credential's) and, for a credential's, access_key; NULL if none. */
yyjson_mut_val *buckets_rw_incident_open(yyjson_mut_doc *d, buckets_rw_incident_kind kind, const char *bucket,
                                         const char *access_key);
/* Records a burst: a new incident (id given), or the open one updated. Returns it; *opened when it is new. */
yyjson_mut_val *buckets_rw_incident_record(yyjson_mut_doc *d, const buckets_rw_burst *b, const char *id,
                                           int64_t now, bool *opened);
/* Closes open incidents not seen for quiet seconds, and drops closed ones older than keep seconds. */
void buckets_rw_incidents_age(yyjson_mut_doc *d, int64_t now, int64_t quiet, int64_t keep);
/* Whether an incident with this source (a protection change) is already recorded. */
bool buckets_rw_incident_has_source(yyjson_mut_doc *d, const char *source);

#endif
