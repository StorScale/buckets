/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_ADMIN_ADMIN_H
#define BUCKETS_ADMIN_ADMIN_H

#include "s3/internal.h"

/* The madmin-compatible admin API under /minio/admin/v3. The request has
 * already been authenticated (c->ident); handlers authorize their own
 * admin: actions and answer with JSON (madmin-encrypted where MinIO does). */
bool buckets_admin_is_admin_path(buckets_str path);
void buckets_admin_handle(s3_ctx *c);

/* A JSON error body (writeErrorResponseJSON). */
void buckets_admin_error(s3_ctx *c, buckets_s3_error e);
void buckets_admin_error_msg(s3_ctx *c, buckets_s3_error e, const char *message);

#endif
