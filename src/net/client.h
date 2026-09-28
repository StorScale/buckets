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

/* Sends one request and reads the whole response. Returns false on a
 * transport failure (connect, send, receive, or a malformed response). A
 * request that fails on a reused keep-alive connection before any response
 * byte arrived is retried once on a new connection. */
bool buckets_http_client_do(buckets_http_client *c, const char *method, const char *target, const buckets_http_kv *hdrs,
                            size_t nhdrs, const void *body, size_t body_len, buckets_http_result *res);
/* Case-insensitive; NULL if absent. The value is not NUL-terminated. */
const char *buckets_http_result_header(const buckets_http_result *r, const char *name, size_t *len);
void buckets_http_result_free(buckets_http_result *r);
/* Drops idle connections (e.g. after the peer restarted). */
void buckets_http_client_reset(buckets_http_client *c);

#endif
