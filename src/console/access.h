/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONSOLE_ACCESS_H
#define BUCKETS_CONSOLE_ACCESS_H

/* The console's access review (iam/access.h): the facts gathered with admin
 * API calls made as the signed-in person, then analysed. Facts the person may
 * not read are named in "missing" rather than failing the review.
 *
 *   GET  /api/v1/access/bucket/<bucket>?level=read|write|delete|manage|any
 *        -> the review (buckets_access_bucket), with "at" (Unix seconds)
 *   POST /api/v1/access/check  {"who", "action", "bucket", "object"?, "conds"?}
 *        -> the decision (buckets_access_check)
 *   GET  /api/v1/access/principals
 *        -> {"principals": [{"kind", "name", "owner"?, "status"?}], "openid", "ldap", "missing"}
 *   GET  /api/v1/access/local-users
 *        -> {"provider": "OpenID" | "LDAP" | null, "users": [{"name", "status", "policies", "groups", "keys"}],
 *            "missing"} */

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"
#include "net/http.h"

typedef struct {
  /* An admin API call as the signed-in person (as buckets_console_teams_session's). */
  int (*admin)(void *ud, const char *method, const char *api, const char *query, const void *body, size_t n,
               bool encrypt, bool decrypt, buckets_buf *out);
  /* An S3 GET as the signed-in person (path "/<bucket>", query encoded): the HTTP status, 0 if no answer. */
  int (*s3_get)(void *ud, const char *path, const char *query, buckets_buf *out);
  void *ud;
} buckets_console_access_session;

/* sub: the path after /api/v1/access. */
void buckets_console_access_handle(const buckets_http_request *req, const char *sub,
                                   const buckets_console_access_session *sess, buckets_http_response *resp);

#endif
