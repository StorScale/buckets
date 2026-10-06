/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONSOLE_IDPCONFIG_H
#define BUCKETS_CONSOLE_IDPCONFIG_H

/* The console's Identity page, where buckets-operator runs the cluster: the
 * sign-in settings (iam/idpsettings.h) live in Secret <cluster>-identity, and
 * the operator applies them to the servers and to the console; the page edits
 * Secret <cluster>-identity-candidate, tests it, and copies it over.
 *
 *   GET  /api/v1/identity-config            -> {"managed", "cluster", "namespace", "settings", "candidate"
 *                                               (secrets left out), "candidateHash", "test", "status",
 *                                               "redirectUri" (this console's /oauth_callback)}
 *   PUT  /api/v1/identity-config/candidate  {"settings"} -> {"candidate", "candidateHash"}: checked and saved
 *   POST /api/v1/identity-config/ldap-test  {"username", "password"?} -> the user's DN, groups and policies
 *   POST /api/v1/identity-config/removal-test {"user"} -> {"passed", "state", "id", "displayName",
 *                                               "userPrincipalName"} or {"passed": false, "error"}: one person
 *                                               looked up in Microsoft Graph, Keycloak or Okta, for removing
 *                                               people who leave
 *   POST /api/v1/identity-config/apply      {"candidateHash"}: the candidate goes live, once tested
 *
 * The OpenID test is a sign-in in a popup: GET /api/v1/login/oidc?test=1 on
 * the console (console.c) signs in with the candidate, checks the ID token
 * with buckets_console_idp_check_token, and records the outcome with
 * buckets_console_idp_record_test (in the candidate Secret, so any console
 * replica can apply it).
 *
 * Secret fields left empty keep their saved values. Outside Kubernetes (no
 * BUCKETS_CONSOLE_CLUSTER), GET says {"managed": false}. */

#include <stdbool.h>
#include <yyjson.h>

#include "core/buf.h"
#include "net/http.h"

typedef struct buckets_console_idp buckets_console_idp;

/* What the endpoints need from the signed-in session: an admin API GET as
 * that person (api: "list-canned-policies"; query encoded or NULL), the
 * reply's body into out, decrypted with the session's secret key when
 * decrypt; the HTTP status, 0 if the servers did not answer. */
typedef struct {
  int (*admin_get)(void *ud, const char *api, const char *query, bool decrypt, buckets_buf *out);
  void *ud;
  const char *region;  /* for the OpenID library */
  const char *ca_file; /* to trust the provider's or the directory's certificate (NULL: the system's) */
  const char *callback; /* this console's /oauth_callback, as the browser reaches it */
} buckets_console_idp_session;

/* From BUCKETS_CONSOLE_CLUSTER and BUCKETS_CONSOLE_NAMESPACE, and the pod's
 * service account; NULL when not set. */
buckets_console_idp *buckets_console_idp_new(void);
void buckets_console_idp_free(buckets_console_idp *m);

/* sub: the path after /api/v1/identity-config. The caller has checked that
 * the session may change the servers' configuration. */
void buckets_console_idp_handle(buckets_console_idp *m, const buckets_http_request *req, const char *sub,
                                const buckets_console_idp_session *sess, buckets_http_response *resp);

/* The candidate settings (secrets included) and their hash; NULL when there
 * is no candidate. */
yyjson_doc *buckets_console_idp_candidate(buckets_console_idp *m, char hash[17]);

/* An OpenID test sign-in's ID token (and access token, for UserInfo) checked
 * against settings as the servers will check it, and its roles matched to
 * the policies that exist: {"passed", "error"?, "user", "claimName", "roles",
 * "policies" (matched), "unmatched", "claims"}. */
yyjson_mut_doc *buckets_console_idp_check_token(yyjson_val *settings, const char *id_token, const char *access_token,
                                                const buckets_console_idp_session *sess);

/* Saves a test's outcome (part: "openid" or "ldap") with the candidate it tested (hash): apply
 * accepts only a candidate whose tests of every part it sets passed. */
void buckets_console_idp_record_test(buckets_console_idp *m, const char *hash, const char *part, yyjson_mut_doc *result);

#endif
