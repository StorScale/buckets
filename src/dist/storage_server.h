/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_STORAGE_SERVER_H
#define BUCKETS_DIST_STORAGE_SERVER_H

#include "net/http.h"
#include "storage/drive.h"

/* Serves this node's local drives to its peers: the other end of
 * storage/remote.c. Replaces MinIO's cmd/storage-rest-server.go. */
typedef struct buckets_storage_server buckets_storage_server;

/* drives: this node's local drives (borrowed; NULL entries are skipped). */
buckets_storage_server *buckets_storage_server_new(buckets_drive *const *drives, size_t n);
void buckets_storage_server_free(buckets_storage_server *s);
/* Handler for BUCKETS_INTERNODE_PREFIX "storage/". */
void buckets_storage_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

#endif
