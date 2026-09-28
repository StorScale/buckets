/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONFIG_CONFIG_H
#define BUCKETS_CONFIG_CONFIG_H

#include "core/buf.h"

/* The server configuration (MinIO's internal/config): sub-systems such as
 * identity_openid, api or notify_webhook, each with targets ("_" is the
 * default one) of key=value pairs. Every sub-system, key, default and help
 * text comes from MinIO's own registry (tools/configgen). Values resolve as
 * environment (MINIO_<SUBSYS>_<KEY>[_<TARGET>], or the BUCKETS_ spelling),
 * then the stored config, then the default. */

#define BUCKETS_CONFIG_DEFAULT_TARGET "_"

typedef struct buckets_config buckets_config;

/* Every sub-system with its default target set to the defaults. */
buckets_config *buckets_config_new(void);
void buckets_config_free(buckets_config *c);
buckets_config *buckets_config_clone(const buckets_config *c);

/* config.json: {"subsys":{"target":[{"key":..,"value":..}]}}, merged with the
 * defaults (Config.Merge). */
buckets_config *buckets_config_from_json(const char *json, size_t len, char *err, size_t errlen);
char *buckets_config_to_json(const buckets_config *c);

/* mc admin config set / import (ReadConfig): one "subsys[:target] k=v ..."
 * per line; '#' lines are ignored. *dynamic_only says whether every line was
 * for a dynamic sub-system. */
bool buckets_config_set_text(buckets_config *c, const char *text, bool *dynamic_only, char *err, size_t errlen);
/* mc admin config reset (DelFrom): "subsys[:target] [key ...]" per line. */
bool buckets_config_del_text(buckets_config *c, const char *text, char *err, size_t errlen);
/* The sub-system of a "subsys[:target] ..." line (GetSubSys). */
bool buckets_config_subsys_of(const char *line, char *subsys, size_t cap, char *err, size_t errlen);
/* Rejects stored keys and MINIO_ variables the sub-system does not know. */
bool buckets_config_check_valid_keys(const buckets_config *c, const char *subsys, char *err, size_t errlen);

/* mc admin config get (GetSubsysInfo + WriteTo): target NULL for all of
 * them; secrets are left out when redact. */
bool buckets_config_get_text(const buckets_config *c, const char *subsys, const char *target, bool redact,
                             buckets_buf *out, char *err, size_t errlen);
/* mc admin config export: every sub-system, disabled ones commented out. */
void buckets_config_export(const buckets_config *c, buckets_buf *out);
/* The help-config-kv JSON (madmin.Help). */
char *buckets_config_help_json(const char *subsys, const char *key, bool env_only, char *err, size_t errlen);

/* The resolved value (env, config, default); caller frees. NULL when the
 * sub-system or key is unknown. */
char *buckets_config_get(const buckets_config *c, const char *subsys, const char *target, const char *key);
/* Targets with any configuration, from the config or the environment;
 * the default one first. Caller frees each and the array. */
size_t buckets_config_targets(const buckets_config *c, const char *subsys, char ***out);
bool buckets_config_is_dynamic(const char *subsys);
bool buckets_config_known(const char *subsys);

/* validateConfig: known keys (and environment variables) for subsys (all
 * sub-systems when "" or NULL), then any validator registered for it. */
typedef bool (*buckets_config_validator)(const buckets_config *c, char *err, size_t errlen);
void buckets_config_register_validator(const char *subsys, buckets_config_validator fn);
bool buckets_config_validate(const buckets_config *c, const char *subsys, char *err, size_t errlen);

/* GetResolvedConfigParams: every key of subsys with its resolved value and
 * where it came from, plus the comment when set. With redact, secret keys
 * are left out. */
typedef enum { BUCKETS_CFG_SRC_DEF = 1, BUCKETS_CFG_SRC_ENV, BUCKETS_CFG_SRC_CFG } buckets_config_src;
typedef struct {
  char *key, *value;
  buckets_config_src src;
} buckets_config_kvsrc;
size_t buckets_config_resolved(const buckets_config *c, const char *subsys, const char *target, bool redact,
                               buckets_config_kvsrc **out);
void buckets_config_kvsrc_free(buckets_config_kvsrc *v, size_t n);

/* config.ParseBool: 1, 0, or -1 when s is not a boolean. */
int buckets_config_parse_bool(const char *s);

/* getenv, preferring BUCKETS_<rest> over MINIO_<rest> for MINIO_ names. */
const char *buckets_config_getenv(const char *minio_name);

#endif
