/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SITEREPL_SITEREPL_H
#define BUCKETS_SITEREPL_SITEREPL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* Site replication (MinIO's SiteReplicationSys, cmd/site-replication.go):
 * a group of deployments that keep buckets, bucket metadata and IAM in
 * sync, with bucket replication rules between every pair. Wire compatible
 * with MinIO, so MinIO and Buckets sites can share a group:
 *
 *  - the state is .minio.sys/config/site-replication/state.json
 *    ({"version":1,"srState":{name, peers, serviceAccountAccessKey, updatedAt}});
 *  - sites talk through the admin API (/minio/admin/v3/site-replication/...)
 *    signed with the shared service account site-replicator-0;
 *  - changes made on this site are pushed to the peers by the hooks below,
 *    and a periodic heal (on the cluster leader) repairs what was missed. */

struct buckets_s3_server;
typedef struct buckets_sr buckets_sr;

#define BUCKETS_SR_SVC_ACCOUNT "site-replicator-0"

/* A Go time.Time (sec may be BUCKETS_GO_ZERO_TIME_SEC). */
typedef struct {
  long long sec;
  long nsec;
} buckets_sr_time;

/* madmin.PeerInfo */
typedef struct {
  char *endpoint, *name, *deployment_id;
  char sync[8];      /* "", "enable", "disable" */
  uint64_t bw_limit; /* defaultbandwidth.bandwidthLimitPerBucket */
  bool bw_set;
  buckets_sr_time bw_updated;
  bool replicate_ilm_expiry;
} buckets_sr_peer;

buckets_sr *buckets_sr_new(struct buckets_s3_server *s);
void buckets_sr_free(buckets_sr *sr);
/* Loads the state (once the object layer and IAM are up) and starts the
 * heal routine. */
void buckets_sr_start(buckets_sr *sr);
void buckets_sr_stop(buckets_sr *sr);
/* Re-reads the state (another node of this deployment changed it). */
void buckets_sr_reload(buckets_sr *sr);

bool buckets_sr_enabled(buckets_sr *sr);
/* The key STS session tokens are signed with while site replication is on
 * (the service account's secret, the same on every site), copied into out;
 * false when disabled. */
bool buckets_sr_token_key(buckets_sr *sr, char *out, size_t cap);

/* ---- hooks: a local change to push to the peers (no-ops when disabled) ---- */

/* MakeBucketHook: creates the bucket (versioned) on every peer and sets up
 * replication rules between every pair. Returns false with err on failure. */
bool buckets_sr_make_bucket_hook(buckets_sr *sr, const char *bucket, bool lock_enabled, bool force_create,
                                 char *err, size_t errlen);
bool buckets_sr_delete_bucket_hook(buckets_sr *sr, const char *bucket, bool force, char *err, size_t errlen);
/* BucketMetaHook for one configuration of the bucket ("policy", "tags",
 * "version-config", "object-lock-config", "sse-config", "quota-config"),
 * sent as it now is (absent means deleted). */
void buckets_sr_bucket_meta_hook(buckets_sr *sr, const char *bucket, const char *type);

/* IAMChangeHook: item is a madmin.SRIAMItem (JSON), sent as is. */
void buckets_sr_iam_hook(buckets_sr *sr, const char *item_json, size_t len);
/* Builders for the common items. */
void buckets_sr_iam_policy(buckets_sr *sr, const char *name, const char *policy_json /* NULL: deleted */);
void buckets_sr_iam_user(buckets_sr *sr, const char *access_key, bool deleted, const char *secret_key,
                         const char *status);
void buckets_sr_iam_group(buckets_sr *sr, const char *group, const char *const *members, size_t n,
                          const char *status, bool is_remove);
/* user_type: MinIO's IAMUserType (0 regular, 1 STS, 2 service account, -1 unknown). */
void buckets_sr_iam_mapping(buckets_sr *sr, const char *name, int user_type, bool is_group, const char *policies);
void buckets_sr_iam_svc_create(buckets_sr *sr, const char *access_key);
void buckets_sr_iam_svc_update(buckets_sr *sr, const char *access_key, const char *secret_key, const char *status,
                               const char *name, const char *description, const char *session_policy,
                               bool has_expiration, long long exp_sec);
void buckets_sr_iam_svc_delete(buckets_sr *sr, const char *access_key);
void buckets_sr_iam_sts(buckets_sr *sr, const char *access_key, const char *parent_policy_mapping);

/* ---- the admin API (admin/siterepl.c) ---- */

/* The JSON bodies of the responses, or false with an error: code is the
 * admin API error (a buckets_s3_error), message its description. */
typedef struct {
  int code;
  char message[4096];
} buckets_sr_err;

bool buckets_sr_add(buckets_sr *sr, const char *requester_ak, const char *sites_json, size_t n, bool ilm_expiry,
                    buckets_buf *out, buckets_sr_err *e);
bool buckets_sr_peer_join(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e);
void buckets_sr_info_json(buckets_sr *sr, buckets_buf *out);
void buckets_sr_idp_settings_json(buckets_sr *sr, buckets_buf *out);
/* SRPeerBucketOps; query values as MinIO's (createdAt, lockEnabled, ...). */
bool buckets_sr_peer_bucket_op(buckets_sr *sr, const char *bucket, const char *op, const char *created_at,
                               bool lock_enabled, bool versioning_enabled, bool force_create, buckets_sr_err *e);
bool buckets_sr_peer_iam_item(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e);
bool buckets_sr_peer_bucket_meta(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e);

/* madmin.SRStatusOptions */
typedef struct {
  bool buckets, policies, users, groups, metrics, ilm_expiry_rules, peer_state, show_deleted;
  int entity; /* madmin.SREntityType: 1 bucket, 2 policy, 3 user, 4 group, 5 ilm-expiry-rule */
  const char *entity_value;
} buckets_sr_status_opts;

bool buckets_sr_metainfo_json(buckets_sr *sr, const buckets_sr_status_opts *o, buckets_buf *out, buckets_sr_err *e);
bool buckets_sr_status_json(buckets_sr *sr, const buckets_sr_status_opts *o, buckets_buf *out, buckets_sr_err *e);
bool buckets_sr_remove(buckets_sr *sr, const char *json, size_t n, buckets_buf *out, buckets_sr_err *e);
bool buckets_sr_peer_remove(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e);
bool buckets_sr_edit(buckets_sr *sr, const char *json, size_t n, bool disable_ilm, bool enable_ilm,
                     buckets_buf *out, buckets_sr_err *e);
bool buckets_sr_peer_edit(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e);
bool buckets_sr_state_edit(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e);
bool buckets_sr_resync_op(buckets_sr *sr, const char *json, size_t n, const char *op, buckets_buf *out,
                          buckets_sr_err *e);

#endif
