/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONSOLE_TEAMS_H
#define BUCKETS_CONSOLE_TEAMS_H

/* The console's Teams page (iam/teams.h): teams are their policies, so every
 * endpoint is admin API calls made as the signed-in person, and the servers
 * decide what they may do.
 *
 *   GET    /api/v1/teams          -> {"teams": [{"name", "buckets", "prefixes", "levels", "edited",
 *                                     "members": {"<level>": {"users": [...], "groups": [...]}}}],
 *                                     "ldap": LDAP sign-in is on}
 *   PUT    /api/v1/teams/<name>   {"team", "overwrite"?} -> the team: its levels' policies written, and the
 *                                 policies of levels it no longer has removed (their members detached first).
 *                                 409 {"code": "Edited", "edited"} when a policy was changed outside the
 *                                 page and overwrite is not set; 409 "Overlap" when a prefix overlaps
 *                                 another team's.
 *   DELETE /api/v1/teams/<name>   members detached, policies removed
 *   POST   /api/v1/teams/<name>/members  {"level", "user" | "group", "remove"?}: attached to (or detached
 *                                 from) the level's policy; a DN while LDAP sign-in is on is an LDAP entity,
 *                                 anything else a local user or group. */

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"
#include "net/http.h"

typedef struct {
  /* An admin API call as the signed-in person (api: "list-canned-policies"; query encoded or NULL): the
   * body sent encrypted with the session's secret key when encrypt, the reply decrypted when decrypt; the
   * HTTP status, 0 if the servers did not answer. */
  int (*admin)(void *ud, const char *method, const char *api, const char *query, const void *body, size_t n,
               bool encrypt, bool decrypt, buckets_buf *out);
  void *ud;
} buckets_console_teams_session;

/* sub: the path after /api/v1/teams ("" or "/<name>[/members]"). */
void buckets_console_teams_handle(const buckets_http_request *req, const char *sub,
                                  const buckets_console_teams_session *sess, buckets_http_response *resp);

#endif
