/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_KAFKA_H
#define BUCKETS_NET_KAFKA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A Kafka producer that behaves as IBM/sarama's SyncProducer does with the
 * settings MinIO gives it (the notification and audit targets): the brokers'
 * metadata first (all topics, refreshed every 15 minutes, and a topic's own
 * when it is not known yet), then one Produce per message to the partition
 * leader (acks 1, a 5s timeout, sarama's FNV-1a hash partitioning of the
 * key), in record batches (Kafka 0.11 and later) with CRC32C, optionally
 * compressed (gzip, snappy). SASL PLAIN and SCRAM-SHA-256/512 (a v1
 * handshake then SaslAuthenticate) and TLS. The protocol versions follow the
 * configured Kafka version (default 2.1.0): Metadata v4-v10, Produce v3-v7,
 * ApiVersions v3 from 2.4. */

typedef struct buckets_kafka buckets_kafka;

typedef struct {
  const char *const *brokers; /* host:port */
  size_t nbrokers;
  const char *version; /* "" = 2.1.0 */
  bool tls, tls_skip_verify;
  const char *ca_dir, *client_cert, *client_key;
  bool sasl;
  const char *sasl_user, *sasl_pass, *sasl_mechanism; /* "", "plain", "sha256", "sha512" */
  const char *compression;                           /* "", "none", "gzip", "snappy", "lz4", "zstd" */
  int compression_level;
  int timeout_ms;       /* network and produce timeouts (0: 5s, the notification target's) */
  int retry_backoff_ms; /* between produce retries (0: 1s) */
} buckets_kafka_cfg;

/* sarama.ParseKafkaVersion: "x.y.z" (1.0 and later) or "0.x.y.z". */
bool buckets_kafka_parse_version(const char *s, int v[4], char *err, size_t errlen);

buckets_kafka *buckets_kafka_new(const buckets_kafka_cfg *cfg);
void buckets_kafka_free(buckets_kafka *k);
/* sarama.NewClient: the seed brokers' metadata; false with sarama's error. */
bool buckets_kafka_connect(buckets_kafka *k, char *err, size_t errlen);
/* Whether the client knows any broker (MinIO's isActive). */
bool buckets_kafka_has_brokers(buckets_kafka *k);

typedef struct {
  const char *key; /* NULL: no key (a random partition) */
  size_t klen;
  const char *value;
  size_t vlen;
} buckets_kafka_msg;

/* SendMessage(s): n messages to topic, each partition's in one batch; 0,
 * or 1 when the brokers could not be reached, 2 on a broker error. */
int buckets_kafka_send(buckets_kafka *k, const char *topic, const buckets_kafka_msg *msgs, size_t n, char *err,
                       size_t errlen);
/* The periodic metadata refresh (call now and then while idle). */
void buckets_kafka_tick(buckets_kafka *k);

#endif
