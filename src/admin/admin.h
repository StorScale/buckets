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
void buckets_admin_custom_error(s3_ctx *c, int status, const char *code, const char *message);
void buckets_admin_iam_error(s3_ctx *c, buckets_iam_err e, const char *detail);

/* A JSON error body (writeErrorResponseJSON). */
void buckets_admin_error(s3_ctx *c, buckets_s3_error e);
void buckets_admin_error_msg(s3_ctx *c, buckets_s3_error e, const char *message);

#endif
