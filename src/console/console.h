/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONSOLE_CONSOLE_H
#define BUCKETS_CONSOLE_CONSOLE_H

#include <stdbool.h>
#include <stdint.h>

#include "net/client.h"
#include "net/http.h"

/* consoled: the web console's backend-for-frontend. It serves the SPA,
 * logs users in by exchanging their keys for STS credentials at bucketsd,
 * keeps those in an encrypted cookie, and proxies the SPA's S3 and admin
 * calls to bucketsd, signing them with the session's credentials. It holds
 * no state beyond the cookie key.
 *
 *   GET  /api/v1/login-methods                        -> {"ldap","share","oidc","localUsers": bool, "oidcName"}
 *   GET  /api/v1/login/oidc                           -> 302 to the identity provider
 *   GET  /oauth_callback?code=&state=                 -> session cookie, 302 to /
 *   POST /api/v1/login   {"accessKey","secretKey"[,"method":"ldap"]} -> session cookie
 *   GET  /api/v1/share?bucket=&key=[&versionId=][&expires=]  -> {"url","expiresAt"}
 *   POST /api/v1/logout
 *   GET  /api/v1/session                              -> {"accessKey","expiresAt"}
 *   *    /api/v1/s3/<bucket>/<key>?...                -> bucketsd /<bucket>/<key>?...
 *   *    /api/v1/admin/<api>?...                      -> bucketsd /minio/admin/v3/<api>?...
 *        (X-Console-Encrypt: 1 madmin-encrypts the body with the session's
 *        secret key, X-Console-Decrypt: 1 decrypts a reply that is encrypted)
 *   GET  /healthz
 *   GET  anything else                                -> the SPA (index.html fallback)
 *
 * Requests other than GET/HEAD to /api must carry X-Console-Request: 1,
 * which a cross-site page cannot send without a CORS preflight. */

typedef struct {
  const char *upstream_host; /* bucketsd */
  int upstream_port;
  buckets_tls_client *upstream_tls; /* NULL: plain HTTP */
  const char *web_dir;              /* the built SPA; NULL serves none */
  const char *passphrase, *salt;    /* derive the cookie key (PBKDF2-SHA256) */
  int sts_duration;                 /* session length in seconds */
  bool secure_cookie;               /* the console is served over TLS */
  const char *region;
  const char *s3_url; /* bucketsd as browsers reach it, for share links (NULL: none) */
  bool ldap;          /* offer LDAP sign-in (AssumeRoleWithLDAPIdentity) */
  /* OpenID sign-in (authorization code flow, then AssumeRoleWithWebIdentity):
   * enabled with a configuration URL and client ID. */
  const char *oidc_config_url, *oidc_client_id, *oidc_client_secret;
  const char *oidc_scopes;       /* NULL: "openid profile email" */
  const char *oidc_redirect_uri; /* NULL: <scheme>://<Host>/oauth_callback */
  const char *oidc_display_name; /* the sign-in button's label */
  const char *oidc_ca_file;
  bool local_users; /* the Users page offers Create user (off by default while OpenID sign-in is on) */
} buckets_console_config;

typedef struct buckets_console buckets_console;

buckets_console *buckets_console_new(const buckets_console_config *cfg);
void buckets_console_free(buckets_console *c);
void buckets_console_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud);

/* Session cookies (exposed for tests): seal the credentials, open them. */
typedef struct {
  char access_key[256], secret_key[256], session_token[4096];
  char user[256];
  int64_t expires; /* unix seconds */
} buckets_console_session;

bool buckets_console_seal(const buckets_console *c, const buckets_console_session *s, buckets_buf *cookie);
bool buckets_console_open(const buckets_console *c, const char *cookie, size_t n, buckets_console_session *s);

#endif
