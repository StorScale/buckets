/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_SERVER_H
#define BUCKETS_S3_SERVER_H

#include "net/http.h"
#include "storage/drive.h"

/* The S3 API front end: health probes, request authentication and routing.
 * Replaces MinIO's cmd/api-router.go + generic-handlers.go + auth-handler.go. */
typedef struct {
  buckets_drive *drive;
  const char *root_user;
  const char *root_password;
  const char *region; /* "" accepts any region in signatures */
  char host_id[65];   /* x-amz-id-2 */
  uint64_t request_seq;
} buckets_s3_server;

void buckets_s3_server_init(buckets_s3_server *s, buckets_drive *drive, const char *root_user,
                            const char *root_password, const char *region);
void buckets_s3_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

#endif
