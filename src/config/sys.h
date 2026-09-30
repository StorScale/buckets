/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONFIG_SYS_H
#define BUCKETS_CONFIG_SYS_H

#include "config/config.h"
#include "object/object.h"

/* The live server configuration and its storage, as MinIO keeps it:
 * .minio.sys/config/config.json (plaintext JSON; madmin-encrypted with the
 * root credentials by older releases) and one .minio.sys/config/history/
 * <uuid>.kv per change. */
typedef struct buckets_config_sys buckets_config_sys;

buckets_config_sys *buckets_config_sys_new(const char *root_access_key, const char *root_secret_key);
void buckets_config_sys_free(buckets_config_sys *s);

/* Reads config.json (defaults when absent). */
bool buckets_config_sys_load(buckets_config_sys *s, buckets_objlayer *layer, char *err, size_t errlen);
/* A snapshot of the current config; caller frees. */
buckets_config *buckets_config_sys_snapshot(buckets_config_sys *s);
/* The resolved value of one key (env, config, default); caller frees. */
char *buckets_config_sys_value(buckets_config_sys *s, const char *subsys, const char *target, const char *key);

/* Saves cfg as the new config (and history_kv, when given, as a history
 * entry), then publishes it and calls the change hook for subsys ("" for
 * all). Takes ownership of cfg. */
bool buckets_config_sys_update(buckets_config_sys *s, buckets_config *cfg, const char *history_kv, const char *subsys,
                               char *err, size_t errlen);
/* Re-reads config.json (a peer changed it). */
bool buckets_config_sys_reload(buckets_config_sys *s);

/* local: the change was made here (tell peers); else it came from a peer. */
typedef void (*buckets_config_changed_fn)(void *ud, const char *subsys, bool local);
void buckets_config_sys_set_hook(buckets_config_sys *s, buckets_config_changed_fn fn, void *ud);
/* With a KMS, the configuration is written sealed by it (and read either way). */
struct buckets_kms;
void buckets_config_sys_set_kms(buckets_config_sys *s, struct buckets_kms *k);

/* History (mc admin config history / restore). */
typedef struct {
  char *restore_id;
  long long create_ns;
  char *data;
} buckets_config_history;
size_t buckets_config_sys_history(buckets_config_sys *s, int count, bool with_data, buckets_config_history **out);
void buckets_config_history_free(buckets_config_history *h, size_t n);
bool buckets_config_sys_history_read(buckets_config_sys *s, const char *restore_id, buckets_buf *out);
bool buckets_config_sys_history_delete(buckets_config_sys *s, const char *restore_id);

#endif
