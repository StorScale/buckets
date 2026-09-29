/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_TRACE_TRACE_H
#define BUCKETS_TRACE_TRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Server tracing (mc admin trace): madmin.TraceInfo records, as JSON, to
 * the subscribers that want their type (MinIO's globalTrace pubsub). */

/* madmin.TraceType bits */
enum {
  BUCKETS_TRACE_OS = 1u << 0,
  BUCKETS_TRACE_STORAGE = 1u << 1,
  BUCKETS_TRACE_S3 = 1u << 2,
  BUCKETS_TRACE_INTERNAL = 1u << 3,
  BUCKETS_TRACE_SCANNER = 1u << 4,
  BUCKETS_TRACE_DECOMMISSION = 1u << 5,
  BUCKETS_TRACE_HEALING = 1u << 6,
  BUCKETS_TRACE_BATCH_REPLICATION = 1u << 7,
  BUCKETS_TRACE_BATCH_KEYROTATION = 1u << 8,
  BUCKETS_TRACE_BATCH_EXPIRE = 1u << 9,
  BUCKETS_TRACE_REBALANCE = 1u << 10,
  BUCKETS_TRACE_REPLICATION_RESYNC = 1u << 11,
  BUCKETS_TRACE_BOOTSTRAP = 1u << 12,
  BUCKETS_TRACE_FTP = 1u << 13,
  BUCKETS_TRACE_ILM = 1u << 14,
  BUCKETS_TRACE_KMS = 1u << 15,
  BUCKETS_TRACE_FORMATTING = 1u << 16,
  BUCKETS_TRACE_ADMIN = 1u << 17,
  BUCKETS_TRACE_OBJECT = 1u << 18,
};

/* madmin.ServiceTraceOpts, as parsed from the request */
typedef struct {
  uint64_t types;
  bool only_errors, internal;
  int64_t threshold_ns;
} buckets_trace_opts;

/* This node's name in records (host:port). */
void buckets_trace_set_node(const char *node);
const char *buckets_trace_node(void);

/* Whether any subscriber wants a type (skip building records otherwise). */
bool buckets_trace_wanted(uint64_t types);

/* A record: its type, duration, and for HTTP records the path and status
 * (the filter's inputs; http false for others). json: one TraceInfo, no
 * trailing newline. */
typedef struct {
  uint64_t type;
  int64_t dur_ns;
  bool http;
  const char *path;
  int status;
} buckets_trace_meta;
void buckets_trace_publish(const buckets_trace_meta *m, const char *json, size_t n);

typedef struct buckets_trace_sub buckets_trace_sub;
buckets_trace_sub *buckets_trace_subscribe(const buckets_trace_opts *o);
/* Stream reads: records as JSON lines, or " " each idle second. */
long buckets_trace_sub_read(void *sub, char *buf, size_t cap);
void buckets_trace_sub_free(void *sub);

#endif
