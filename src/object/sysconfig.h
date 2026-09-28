/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OBJECT_SYSCONFIG_H
#define BUCKETS_OBJECT_SYSCONFIG_H

#include "core/buf.h"
#include "object/object.h"

/* Small configuration objects under .minio.sys (MinIO's readConfig /
 * saveConfig / deleteConfig / listIAMConfigItems). */

/* NO_SUCH_KEY when absent or empty. mod_time_ns may be NULL. */
buckets_obj_err buckets_sysconfig_read(buckets_objlayer *L, const char *path, buckets_buf *out, int64_t *mod_time_ns);
buckets_obj_err buckets_sysconfig_write(buckets_objlayer *L, const char *path, const void *data, size_t n);
buckets_obj_err buckets_sysconfig_delete(buckets_objlayer *L, const char *path);

/* Lists the entries under prefix (which ends in '/'): with dirs, the first
 * path component of every key ("alice" for "alice/identity.json"); without,
 * every object key relative to prefix. Sorted. */
buckets_obj_err buckets_sysconfig_list(buckets_objlayer *L, const char *prefix, bool dirs, char ***names, size_t *n);
void buckets_sysconfig_names_free(char **names, size_t n);

#endif
