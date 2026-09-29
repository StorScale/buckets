/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_TIER_INTERNAL_H
#define BUCKETS_TIER_INTERNAL_H

#include <stdatomic.h>

#include "tier/tier.h"

/* A warm backend: its operations, and what they share. */
typedef struct {
  buckets_warm_err (*put)(buckets_warm *w, const char *object, buckets_http_read_fn rd, void *rd_ud, int64_t length,
                          const char *orig_name, char *rv, size_t rvcap, char *err, size_t errlen);
  buckets_warm_err (*get)(buckets_warm *w, const char *object, const char *rv, int64_t off, int64_t len,
                          buckets_warm_stream **out, char *err, size_t errlen);
  buckets_warm_err (*remove)(buckets_warm *w, const char *object, const char *rv, char *err, size_t errlen);
  buckets_warm_err (*in_use)(buckets_warm *w, bool *in_use, char *err, size_t errlen);
  void (*destroy)(buckets_warm *w);
} buckets_warm_ops;

struct buckets_warm {
  const buckets_warm_ops *ops;
  _Atomic int refs;
  char *tier;
};

/* A remote object being read: the HTTP body (and what owns its connection). */
struct buckets_warm_stream {
  buckets_http_stream *body;
  int64_t remaining; /* -1: to the end of the body */
  void *ud;
  void (*free_ud)(void *ud);
};

buckets_warm *buckets_warm_s3_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen);
buckets_warm *buckets_warm_azure_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen);
buckets_warm *buckets_warm_gcs_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen);

/* <prefix>/<object> (getDest) */
void buckets_warm_dest(const char *prefix, const char *object, buckets_buf *out);
bool buckets_warm_endpoint(const char *url, char *host, size_t cap, bool *secure);

#endif
