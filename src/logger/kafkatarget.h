/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_LOGGER_KAFKATARGET_H
#define BUCKETS_LOGGER_KAFKATARGET_H

#include <stdbool.h>
#include <stddef.h>

#include "logger/httptarget.h"
#include "net/kafka.h"

/* MinIO's Kafka audit target (internal/logger/target/kafka, audit_kafka):
 * each entry as an unkeyed message (a random partition) to the topic, with
 * sarama's settings there (10s timeouts, retries 10s apart). Entries wait in
 * memory (queue_size), or with a queue_dir in MinIO's queue store
 * (<queue_dir>/minio-kafka-audit/<uuid>.kafka.log, the entry's JSON), sent
 * from there with their keys sorted as MinIO's replay re-encodes them. */
typedef struct {
  const char *name; /* "audit-kafka-<target>" */
  buckets_kafka_cfg kafka;
  const char *topic;
  int queue_size;
  const char *queue_dir;
} buckets_kafka_target_cfg;

typedef struct buckets_kafka_target buckets_kafka_target;

buckets_kafka_target *buckets_kafka_target_new(const buckets_kafka_target_cfg *cfg, char *err, size_t errlen);
void buckets_kafka_target_free(buckets_kafka_target *t);
bool buckets_kafka_target_send(buckets_kafka_target *t, const char *json, size_t n);
const char *buckets_kafka_target_name(const buckets_kafka_target *t);
void buckets_kafka_target_stats_get(buckets_kafka_target *t, buckets_http_target_stats *out);

#endif
