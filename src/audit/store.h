/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_AUDIT_STORE_H
#define BUCKETS_AUDIT_STORE_H

/* The audit log's local copy (docs/design/audit-log.md): each server keeps the audit entries of what it served,
 * on its own first drive, outside the erasure-coded data:
 *   <drive>/.buckets-audit/<YYYY-MM-DD>/<HH>-<seq>.jsonl     the segment being written (one entry per line)
 *   <drive>/.buckets-audit/<YYYY-MM-DD>/<HH>-<seq>.jsonl.gz  closed segments, gzip
 * A segment closes at the end of its hour or at 64 MiB. Entries are handed to a writer thread, which appends and
 * flushes every second; when its queue is full they are dropped and counted, never waited for. Kept for
 * BUCKETS_AUDIT_LOCAL_DAYS (30) and BUCKETS_AUDIT_LOCAL_MAX bytes (10 GiB), oldest first. A name starting with a dot
 * is no bucket, so neither Buckets nor MinIO takes the directory for one.
 *
 *   BUCKETS_AUDIT_LOCAL         off: no local copy (on by default)
 *   BUCKETS_AUDIT_LOCAL_READS   off: leave reads (GET, HEAD, LIST, Select) out */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <yyjson.h>

#include "core/buf.h"

#define BUCKETS_AUDIT_DIR ".buckets-audit"

bool buckets_audit_local_enabled(void);
bool buckets_audit_local_reads(void);

typedef struct buckets_audit_store buckets_audit_store;
/* A store under root (<drive>/.buckets-audit), its writer started. */
buckets_audit_store *buckets_audit_store_new(const char *root);
/* Stops the writer (what is queued is written first) and frees the store. */
void buckets_audit_store_free(buckets_audit_store *s);
/* Queues an entry (MinIO's audit JSON, one line) for writing; false when it was dropped. */
bool buckets_audit_store_put(buckets_audit_store *s, const char *json, size_t n);
/* Writes what is queued now (tests). */
void buckets_audit_store_flush(buckets_audit_store *s);

/* What a query selects. Empty strings and zeros match everything. */
typedef struct {
  int64_t from_ns, to_ns; /* the entries' "time" in [from, to] (to 0: now) */
  int64_t before_ns;      /* the cursor: older than this only (0: none) */
  const char *user;       /* the person: parentUser (accessKey without one), or an OpenID token's
                           * preferred_username, upn or email */
  const char *access_key;
  const char *bucket;
  const char *prefix; /* of the object's key */
  const char *api;    /* the API's name, e.g. "PutObject", "ServerInfo" */
  const char *kind;   /* "read", "write", "delete" or "admin" */
  const char *status; /* "ok" (below 400), "denied" (401, 403) or "failed" (other errors) */
  const char *ip;     /* remotehost */
  size_t limit;       /* at most this many (0: 100), newest first */
} buckets_audit_query;

/* Whether one entry matches (unit tested). */
bool buckets_audit_match(yyjson_val *entry, const buckets_audit_query *q);
/* An entry's time ("time", RFC 3339) in unix nanoseconds; 0 when it has none. */
int64_t buckets_audit_time_ns(yyjson_val *entry);
/* An API's kind, by its name: "admin" when the request path is the admin API's, else read, write or delete. */
const char *buckets_audit_kind(yyjson_val *entry);

/* The entries under root matching q, newest first, as a JSON array appended to out; *oldest_ns: the oldest entry
 * kept (0: none). Reads the segments of the hours in range only. */
size_t buckets_audit_query_dir(const char *root, const buckets_audit_query *q, buckets_buf *out,
                               int64_t *oldest_ns);

/* Entries dropped since start, because the writer's queue was full or the drive refused them. */
uint64_t buckets_audit_store_dropped(buckets_audit_store *s);
/* Bytes of segments on the drive: at the last retention pass (every 5 minutes), plus what was written since. */
uint64_t buckets_audit_store_kept(buckets_audit_store *s);
/* The store's root. */
const char *buckets_audit_store_root(const buckets_audit_store *s);

/* Removes segments beyond the limits (days back from now, total bytes), oldest first; the bytes kept. */
uint64_t buckets_audit_retain(const char *root, int days, uint64_t max_bytes, int64_t now);

#endif
