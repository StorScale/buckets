/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_ADMIN_ADMIN_H
#define BUCKETS_ADMIN_ADMIN_H

#include "s3/internal.h"

/* The madmin-compatible admin API under /minio/admin/v3. The request has
 * already been authenticated (c->ident); handlers authorize their own
 * admin: actions and answer with JSON (madmin-encrypted where MinIO does). */
bool buckets_admin_is_admin_path(buckets_str path);
void buckets_admin_handle(s3_ctx *c);
/* A JSON error response as MinIO's writeErrorResponseJSON writes it. */
void buckets_admin_json_error(s3_ctx *c, int status, const char *code, const char *message, const char *key,
                              const char *bucket);

/* ServerInfo (info.c). */
void buckets_admin_server_info(s3_ctx *c);
void buckets_admin_storage_info(s3_ctx *c);
void buckets_admin_background_heal_status(s3_ctx *c);
/* mc admin heal (heal.c); the peer side of a status request forwarded to
 * the node running a sequence; stopping every sequence at shutdown. */
void buckets_admin_heal(s3_ctx *c);
void buckets_admin_heal_peer(buckets_s3_server *s, const buckets_query *q, int *status, buckets_buf *out);
void buckets_admin_heal_shutdown(void);
/* mc admin cluster bucket export|import (bucketmeta.c). */
void buckets_admin_export_bucket_metadata(s3_ctx *c);
void buckets_admin_import_bucket_metadata(s3_ctx *c);
/* mc support inspect (inspect.c). */
void buckets_admin_inspect_data(s3_ctx *c);
/* mc admin top locks, mc admin unlock (locks.c; distributed setups only). */
void buckets_admin_top_locks(s3_ctx *c);
void buckets_admin_force_unlock(s3_ctx *c);
/* mc admin speedtest, mc support perf object|drive (perf.c); the peer side. */
void buckets_admin_object_speedtest(s3_ctx *c);
void buckets_admin_drive_speedtest(s3_ctx *c);
bool buckets_admin_perf_peer(buckets_s3_server *s, const char *op, const buckets_query *q, buckets_http_response *resp);
/* mc support perf client|net|site-replication (netperf.c). */
void buckets_admin_client_devnull(s3_ctx *c);
void buckets_admin_client_devnull_extratime(s3_ctx *c);
void buckets_admin_netperf(s3_ctx *c);
void buckets_admin_sr_devnull(s3_ctx *c);
void buckets_admin_sr_netperf(s3_ctx *c);
void buckets_admin_site_perf(s3_ctx *c);
bool buckets_admin_netperf_peer(buckets_s3_server *s, const char *op, const buckets_http_request *req,
                                const buckets_query *q, buckets_http_response *resp);
/* BUCKETS_INTERNODE_PREFIX "perf/devnull": a peer's netperf stream. */
void buckets_admin_internode_devnull(const buckets_http_request *req, buckets_http_response *resp, void *ud);
/* The site-replication perf endpoints MinIO calls unsigned (served so only
 * while site replication is on). */
bool buckets_admin_site_perf_unsigned(buckets_s3_server *s, buckets_str path);
/* Admin work a peer asks of this node (peer/admin?op=...): heal sequence
 * status, speedtests. */
void buckets_admin_peer(buckets_s3_server *s, const buckets_http_request *req, const buckets_query *q,
                        buckets_http_response *resp);
/* The answer to an admin API this setup does not serve (XMinioAdminVersionMismatch). */
void buckets_admin_unsupported(s3_ctx *c);

/* mc admin config (config.c). */
void buckets_admin_config_get_kv(s3_ctx *c);
void buckets_admin_config_set_kv(s3_ctx *c);
void buckets_admin_config_del_kv(s3_ctx *c);
void buckets_admin_config_help(s3_ctx *c);
void buckets_admin_config_history_list(s3_ctx *c);
void buckets_admin_config_history_clear(s3_ctx *c);
void buckets_admin_config_history_restore(s3_ctx *c);
void buckets_admin_config_export(s3_ctx *c);
void buckets_admin_config_import(s3_ctx *c);
/* mc idp openid|ldap: /idp-config/{type}[/{name}] (config.c). */
bool buckets_admin_is_idp_config(buckets_str path);
void buckets_admin_idp_config(s3_ctx *c);

/* mc admin cluster iam export|import (iamxfer.c). */
void buckets_admin_export_iam(s3_ctx *c);
void buckets_admin_import_iam(s3_ctx *c);
void buckets_admin_import_iam_v2(s3_ctx *c);

/* mc quota set|info|clear (bucket.c). */
void buckets_admin_set_bucket_quota(s3_ctx *c);
void buckets_admin_get_bucket_quota(s3_ctx *c);
/* mc admin info's usage: the scanner's stored data usage (bucket.c). */
void buckets_admin_data_usage_info(s3_ctx *c);

/* mc admin bucket remote add|ls|rm (replicate.c). */
void buckets_admin_set_remote_target(s3_ctx *c);
void buckets_admin_list_remote_targets(s3_ctx *c);
void buckets_admin_remove_remote_target(s3_ctx *c);
void buckets_admin_replication_diff(s3_ctx *c);
void buckets_admin_replication_mrf(s3_ctx *c);
/* remote tiers (tier.c) */
void buckets_admin_tier_add(s3_ctx *c);
void buckets_admin_tier_edit(s3_ctx *c);
void buckets_admin_tier_list(s3_ctx *c);
void buckets_admin_tier_remove(s3_ctx *c);
void buckets_admin_tier_verify(s3_ctx *c);
void buckets_admin_tier_stats(s3_ctx *c);
/* batch jobs and the realtime metrics stream (batch.c) */
void buckets_admin_batch_start(s3_ctx *c);
void buckets_admin_batch_list(s3_ctx *c);
void buckets_admin_batch_status(s3_ctx *c);
void buckets_admin_batch_describe(s3_ctx *c);
void buckets_admin_batch_cancel(s3_ctx *c);
void buckets_admin_metrics(s3_ctx *c);
/* pool decommission and rebalance (pools.c) */
void buckets_admin_pools_list(s3_ctx *c);
void buckets_admin_pools_status(s3_ctx *c);
void buckets_admin_decommission(s3_ctx *c);
void buckets_admin_decommission_cancel(s3_ctx *c);
void buckets_admin_rebalance_start(s3_ctx *c);
void buckets_admin_rebalance_status(s3_ctx *c);
void buckets_admin_rebalance_stop(s3_ctx *c);
/* site replication (siterepl.c) */
void buckets_admin_sr_add(s3_ctx *c);
void buckets_admin_sr_remove(s3_ctx *c);
void buckets_admin_sr_info(s3_ctx *c);
void buckets_admin_sr_metainfo(s3_ctx *c);
void buckets_admin_sr_status(s3_ctx *c);
void buckets_admin_sr_peer_join(s3_ctx *c);
void buckets_admin_sr_peer_bucket_ops(s3_ctx *c);
void buckets_admin_sr_peer_iam_item(s3_ctx *c);
void buckets_admin_sr_peer_bucket_meta(s3_ctx *c);
void buckets_admin_sr_peer_idp_settings(s3_ctx *c);
void buckets_admin_sr_edit(s3_ctx *c);
void buckets_admin_sr_peer_edit(s3_ctx *c);
void buckets_admin_sr_peer_remove(s3_ctx *c);
void buckets_admin_sr_resync_op(s3_ctx *c);
void buckets_admin_sr_state_edit(s3_ctx *c);

/* KMS APIs (kms.c): /minio/kms/v1/..., and the admin v3 /kms/... routes. */
bool buckets_admin_is_kms_path(buckets_str path);
void buckets_admin_kms_handle(s3_ctx *c);
void buckets_admin_kms_status_v3(s3_ctx *c);
void buckets_admin_kms_key_status_v3(s3_ctx *c);
void buckets_admin_kms_create_key_v3(s3_ctx *c);

/* Shared helpers (admin.c): validateAdminReq for one action (answers the
 * request itself when it fails), custom-coded errors, IAM store errors. */
bool buckets_admin_authorize(s3_ctx *c, const char *action);
/* The first allowed of several actions (validateAdminReq with many). */
bool buckets_admin_authorize_any(s3_ctx *c, const char *const *actions, size_t n);
void buckets_admin_custom_error(s3_ctx *c, int status, const char *code, const char *message);
void buckets_admin_iam_error(s3_ctx *c, buckets_iam_err e, const char *detail);

/* A JSON error body (writeErrorResponseJSON). */
void buckets_admin_error(s3_ctx *c, buckets_s3_error e);
void buckets_admin_error_msg(s3_ctx *c, buckets_s3_error e, const char *message);

#endif
