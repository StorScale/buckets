/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_CLIENT_H
#define BUCKETS_NET_CLIENT_H

#include "core/buf.h"
#include "net/tls.h"

/* A blocking HTTP/1.1 client for one peer, with a pool of keep-alive
 * connections shared by all threads. Used for internode RPC and by the
 * operator for the Kubernetes API; responses are Content-Length delimited or
 * chunked. */
typedef struct buckets_http_client buckets_http_client;

typedef struct {
  const char *name, *value;
} buckets_http_kv;

typedef struct {
  int status;
  buckets_buf headers; /* raw "Name: value\r\n" lines */
  buckets_buf body;
} buckets_http_result;

/* tls NULL: plain TCP. timeout_ms bounds connect and each socket read/write. */
buckets_http_client *buckets_http_client_new(const char *host, int port, buckets_tls_client *tls, int timeout_ms);
void buckets_http_client_free(buckets_http_client *c);
const char *buckets_http_client_host(const buckets_http_client *c);
int buckets_http_client_port(const buckets_http_client *c);
/* The last failed connection attempt in Go's words ("dial tcp HOST:PORT:
 * connect: connection refused"), or "". */
const char *buckets_http_client_dial_error(const buckets_http_client *c);

/* Sends one request and reads the whole response. Returns false on a
 * transport failure (connect, send, receive, or a malformed response). A
 * request that fails on a reused keep-alive connection before any response
 * byte arrived is retried once on a new connection. */
bool buckets_http_client_do(buckets_http_client *c, const char *method, const char *target, const buckets_http_kv *hdrs,
                            size_t nhdrs, const void *body, size_t body_len, buckets_http_result *res);
/* Case-insensitive; NULL if absent. The value is not NUL-terminated. */
const char *buckets_http_result_header(const buckets_http_result *r, const char *name, size_t *len);
void buckets_http_result_free(buckets_http_result *r);
/* ---- streaming ----
 * A request whose body is pulled from rd (body_len bytes; 0 with rd NULL for
 * none) and whose response body is read incrementally. Returns NULL on a
 * transport failure before the response headers arrived; otherwise the
 * status and raw header lines are filled in and the body is read with
 * buckets_http_stream_read (Content-Length or chunked). Freeing a stream
 * that was read to its end returns the connection to the pool. */
typedef struct buckets_http_stream buckets_http_stream;
typedef long (*buckets_http_read_fn)(void *ud, void *buf, size_t n);
buckets_http_stream *buckets_http_client_open(buckets_http_client *c, const char *method, const char *target,
                                              const buckets_http_kv *hdrs, size_t nhdrs, buckets_http_read_fn rd,
                                              void *rd_ud, int64_t body_len, int *status, buckets_buf *headers);
/* The response's Content-Length, or -1 (chunked, or read to close). */
int64_t buckets_http_stream_length(const buckets_http_stream *s);
/* Bytes read, 0 at the end of the body, -1 on failure. */
long buckets_http_stream_read(void *s, void *buf, size_t n);
void buckets_http_stream_free(void *s);

/* Case-insensitive lookup in raw "Name: value\r\n" lines; NULL if absent. */
const char *buckets_http_headers_get(const buckets_buf *headers, const char *name, size_t *len);

/* Drops idle connections (e.g. after the peer restarted). */
void buckets_http_client_reset(buckets_http_client *c);

/* Traffic through a client (the internode metrics): bytes, failed
 * requests, and connection attempts with their total time. */
typedef struct {
  uint64_t sent, received, errors, dials, dial_errors, dial_ns;
} buckets_http_client_stats;
void buckets_http_client_stats_get(buckets_http_client *c, buckets_http_client_stats *out);

#endif
