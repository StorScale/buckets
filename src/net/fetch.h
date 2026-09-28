/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_FETCH_H
#define BUCKETS_NET_FETCH_H

#include "net/client.h"

/* One request to an http(s):// URL (identity providers, webhooks), trusting
 * the system roots plus ca_file when given. Returns false on a malformed URL
 * or transport failure (err says which); otherwise *out holds the response. */
bool buckets_fetch(const char *method, const char *url, const char *ca_file, const buckets_http_kv *hdrs, size_t nhdrs,
                   const void *body, size_t len, int timeout_ms, buckets_http_result *out, char *err, size_t errlen);

#endif
