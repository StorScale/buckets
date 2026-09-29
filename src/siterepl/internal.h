/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SITEREPL_INTERNAL_H
#define BUCKETS_SITEREPL_INTERNAL_H

#include <pthread.h>
#include <yyjson.h>

#include "core/common.h"
#include "s3/errors_gen.h"
#include "siterepl/siterepl.h"

struct buckets_s3_server;

struct buckets_sr {
  struct buckets_s3_server *s;
  pthread_rwlock_t lock; /* guards the state */
  bool enabled;
  char *name;
  buckets_sr_peer *peers; /* sorted by name */
  size_t npeers;
  char *svc_ak;
  buckets_sr_time updated;
  /* the heal routine */
  pthread_mutex_t mu;
  pthread_cond_t cv;
  bool stop, started;
  pthread_t heal_thread;
};

/* ---- shared helpers (siterepl.c) ---- */

void sr_time_str(buckets_sr_time t, char *out /* >= 40 */);
bool sr_time_parse(const char *s, buckets_sr_time *out);
buckets_sr_time sr_now(void);
bool sr_time_after(buckets_sr_time a, buckets_sr_time b);
bool sr_time_is_zero(buckets_sr_time t);
buckets_sr_time sr_zero_time(void);
void sr_add_time(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, buckets_sr_time t);
buckets_sr_time sr_get_time(yyjson_val *o, const char *key);

const char *sr_self_id(buckets_sr *sr);
void sr_err(buckets_sr_err *e, buckets_s3_error code, const char *fmt, ...) BUCKETS_PRINTF(3, 4);

/* A copy of the peers (under the read lock). */
typedef struct {
  char *name, *svc_ak;
  buckets_sr_peer *peers;
  size_t npeers;
  buckets_sr_time updated;
  bool enabled;
} sr_snapshot;
void sr_snapshot_take(buckets_sr *sr, sr_snapshot *out);
void sr_snapshot_free(sr_snapshot *s);
const buckets_sr_peer *sr_snapshot_peer(const sr_snapshot *s, const char *dep_id);

/* An admin API call to a peer with the service account, path after
 * /minio/admin/v3. out gets the response body. err: the peer's message. */
bool sr_peer_call(buckets_sr *sr, const char *dep_id, const char *method, const char *path, const char *query,
                  const void *body, size_t n, buckets_buf *out, char *err, size_t errlen);
bool sr_endpoint_call(buckets_sr *sr, const char *endpoint, const char *ak, const char *sk, const char *method, const char *path,
                      const char *query, const void *body, size_t n, buckets_buf *out, char *err, size_t errlen);

/* The peer operations of the local site (used by the handlers and heal). */
bool sr_make_with_versioning(buckets_sr *sr, const char *bucket, bool lock_enabled, buckets_sr_time created,
                             char *err, size_t errlen);
bool sr_configure_repl(buckets_sr *sr, const char *bucket, char *err, size_t errlen);
bool sr_local_delete_bucket(buckets_sr *sr, const char *bucket, bool force, char *err, size_t errlen);
void sr_purge_deleted_bucket(buckets_sr *sr, const char *bucket);
bool sr_bucket_op_to_peer(buckets_sr *sr, const char *dep_id, const char *bucket, const char *op,
                          const char *extra_query, char *err, size_t errlen);
bool sr_apply_iam_item(buckets_sr *sr, yyjson_val *item, char *err, size_t errlen);
bool sr_apply_bucket_meta(buckets_sr *sr, yyjson_val *item, char *err, size_t errlen);
void sr_send_bucket_meta(buckets_sr *sr, const char *dep_id, const char *json, size_t n);
void sr_send_iam_item(buckets_sr *sr, const char *dep_id, const char *json, size_t n);

/* srstatus.c */
void sr_heal_once(buckets_sr *sr);

#endif
