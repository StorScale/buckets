/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_FETCH_H
#define BUCKETS_NET_FETCH_H

#include "net/client.h"

/* One request to an http(s):// URL (identity providers, webhooks), trusting
 * the system roots plus ca_file when given. Returns false on a malformed URL
 * or transport failure (err says which); otherwise *out holds the response. */
bool buckets_fetch(const char *method, const char *url, const char *ca_file, const buckets_http_kv *hdrs, size_t nhdrs,
                   const void *body, size_t len, int timeout_ms, buckets_http_result *out, char *err, size_t errlen);

/* The same, with the response body read as it arrives: NULL (err set)
 * before the response headers; then *status and *headers are filled in and
 * the body is read with buckets_fetch_read (0 at its end, -1 on failure).
 * body must stay valid until buckets_fetch_open returns. */
typedef struct buckets_fetch_stream buckets_fetch_stream;
buckets_fetch_stream *buckets_fetch_open(const char *method, const char *url, const char *ca_file,
                                         const buckets_http_kv *hdrs, size_t nhdrs, const void *body, size_t len,
                                         int timeout_ms, int *status, buckets_buf *headers, char *err, size_t errlen);
long buckets_fetch_read(void *s, void *buf, size_t n);
void buckets_fetch_close(void *s);

#endif
