/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_CONN_H
#define BUCKETS_NET_CONN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"
#include "net/tls.h"

/* A client stream connection (TCP, optionally TLS) with buffered reads, for
 * the notification targets' protocols (Redis, NATS, NSQ, MQTT, Kafka, AMQP,
 * PostgreSQL, MySQL). Blocking, with a timeout on every socket operation. */

typedef struct buckets_conn buckets_conn;

/* tls NULL: plain TCP. On failure err gets Go's form, "dial tcp HOST:PORT:
 * connect: connection refused" and the like. */
buckets_conn *buckets_conn_dial(const char *host, int port, buckets_tls_client *tls, int timeout_ms, char *err,
                                size_t errlen);
void buckets_conn_close(buckets_conn *c);
/* Upgrades a connected plain stream to TLS (STARTTLS-style protocols). */
bool buckets_conn_start_tls(buckets_conn *c, buckets_tls_client *tls, const char *host);

bool buckets_conn_write(buckets_conn *c, const void *data, size_t n);
/* Exactly n bytes; false on EOF, error or timeout. */
bool buckets_conn_read_full(buckets_conn *c, void *out, size_t n);
/* A line ending in "\r\n" (or "\n"), without it; false on EOF/error/timeout. */
bool buckets_conn_read_line(buckets_conn *c, buckets_buf *line);
/* Bytes already buffered (reads that will not block). */
size_t buckets_conn_buffered(const buckets_conn *c);
/* Whether a read would not block (data buffered or arriving) within
 * timeout_ms: 1 yes, 0 no, -1 the connection failed. */
int buckets_conn_readable(buckets_conn *c, int timeout_ms);
/* Whether the peer closed or errored (a non-blocking check). */
bool buckets_conn_broken(buckets_conn *c);
void buckets_conn_set_timeout(buckets_conn *c, int timeout_ms);

#endif
