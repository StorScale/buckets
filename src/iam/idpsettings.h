/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_IDPSETTINGS_H
#define BUCKETS_IAM_IDPSETTINGS_H

/* The identity-provider settings people fill in on the console's Identity
 * page, for the operator (which applies them to the servers) and the console
 * (which signs people in with them): checked, turned into bucketsd's
 * identity_openid and identity_ldap configuration, and into the console's own
 * view of them.
 *
 * As JSON:
 *   {"openid": {"provider": "entra" | "okta" | "keycloak" | "generic",
 *               "displayName",                       the sign-in button's label
 *               "tenantId",                          entra
 *               "domain", "authServer",              okta (authServer default "default")
 *               "url", "realm",                      keycloak (url: the server's base URL)
 *               "configUrl",                         generic (the discovery document)
 *               "clientId", "clientSecret",
 *               "claimName",                         the claim naming policies (default per provider)
 *               "scopes",                            space or comma separated (default per provider)
 *               "redirectUri",                       the console's /oauth_callback, if not derived
 *               "rolePolicy",                        policies for everyone signing in, instead of a claim
 *               "claimUserinfo",                     true: claims from the UserInfo endpoint too
               "removal": {"enabled",               people who leave lose their access (entra only, for now;
                           "deleteAfterDays",        iam/idsync.h), with the sign-in app's credentials: their
                           "maxPerSync"}},           keys off at once, deleted after deleteAfterDays (30)
 *    "ldap":   {"preset": "ad" | "openldap" | "custom",
 *               "serverAddr",                        host[:port]
 *               "tls": "ldaps" | "starttls" | "plain",
 *               "skipVerify",                        true: trust any certificate (testing only)
 *               "lookupBindDn", "lookupBindPassword",
 *               "userSearchBase", "userSearchFilter",
 *               "groupSearchBase", "groupSearchFilter"}}
 * Either part may be absent (that kind of sign-in off). */

#include <stdbool.h>
#include <stddef.h>
#include <yyjson.h>

#include "core/buf.h"

/* The settings' secret fields, as "part.field": shown to nobody once saved.
 * NULL-terminated. */
extern const char *const buckets_idp_secret_fields[];

/* Checks settings. On error, false and why, in words for the person who
 * filled them in. */
bool buckets_idp_check(yyjson_val *settings, char *err, size_t errlen);

/* The OpenID discovery URL the settings name ("" if none). */
void buckets_idp_config_url(yyjson_val *settings, char *out, size_t cap);

/* bucketsd's configuration for the settings, as `mc admin config set` lines
 * ("identity_openid key=\"value\" ..."): one line per part that is set, and for
 * a part that is not, its "enable=off" line. Appended to out. False (and why)
 * if the settings do not check. */
bool buckets_idp_server_config(yyjson_val *settings, buckets_buf *out, char *err, size_t errlen);

/* The identity sync's settings when removal is on (false when off). client_secret points into settings. */
typedef struct {
  const char *tenant, *client_id, *client_secret;
  long delete_after_days, max_per_sync;
} buckets_idp_removal;
bool buckets_idp_removal_of(yyjson_val *settings, buckets_idp_removal *out);

/* What the console needs to sign people in, written into d as an object:
 *   {"oidc": {"configUrl", "clientId", "clientSecret", "scopes", "displayName", "redirectUri"} | null,
 *    "ldap": {"displayName"} | null}
 * scopes space separated, as OAuth sends them. */
yyjson_mut_val *buckets_idp_console_view(yyjson_mut_doc *d, yyjson_val *settings);

/* A copy of settings with each secret field set replaced by "" and listed in
 * "secretsSet". */
yyjson_mut_val *buckets_idp_settings_redacted(yyjson_mut_doc *d, yyjson_val *settings);
/* In settings (mutable), each secret field left empty takes its value from
 * saved, when saved has the same kind of provider: editing keeps secrets
 * nobody retyped. */
void buckets_idp_settings_keep_secrets(yyjson_mut_doc *d, yyjson_mut_val *settings, yyjson_val *saved);

/* A one-line summary ("Microsoft Entra ID (tenant ...); LDAP at ...", or
 * "not configured"). */
void buckets_idp_settings_describe(yyjson_val *settings, char *out, size_t cap);

#endif
