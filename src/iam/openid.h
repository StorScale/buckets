/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_OPENID_H
#define BUCKETS_IAM_OPENID_H

#include <yyjson.h>

#include "config/config.h"

/* OpenID Connect identity providers (MinIO's internal/config/identity/
 * openid): the identity_openid targets, each with its discovery document
 * and JWKS, keyed by role ARN (claim-based providers share the dummy one).
 * Reference counted: a config change builds a new one. */
typedef struct buckets_openid buckets_openid;

/* LookupConfig. NULL (err set) when the config is invalid or a provider
 * cannot be reached; an object with no providers when none is configured. */
buckets_openid *buckets_openid_build(const buckets_config *cfg, const char *region, char *err, size_t errlen);
buckets_openid *buckets_openid_ref(buckets_openid *o);
void buckets_openid_release(buckets_openid *o);

bool buckets_openid_enabled(const buckets_openid *o);
/* The JWT policy claim (claim_prefix + claim_name) of the claim-based
 * provider, "" when there is none. */
const char *buckets_openid_claim_name(const buckets_openid *o);
/* The policies of a role ARN (role_policy), or NULL. */
const char *buckets_openid_role_policy(const buckets_openid *o, const char *arn);

/* Whether a provider was configured from the target name; *role_arn gets
 * its role ARN when it has a role policy (else NULL). */
bool buckets_openid_target(const buckets_openid *o, const char *name, const char **role_arn);

/* The role-policy provider with this role ARN: its target name, user
 * readable claim ("" if unset) and user ID claim ("sub" if unset). */
bool buckets_openid_by_arn(const buckets_openid *o, const char *arn, const char **name, const char **readable_claim,
                           const char **id_claim);

typedef enum {
  BUCKETS_OIDC_OK = 0,
  BUCKETS_OIDC_EXPIRED,
  BUCKETS_OIDC_INVALID_DURATION,
  BUCKETS_OIDC_ERROR,
} buckets_oidc_status;

/* Config.Validate: verifies the token for the role (NULL: the claim-based
 * provider), applies DurationSeconds to exp, merges UserInfo claims, and
 * checks aud/azp against the client id. *claims gets the claims. */
buckets_oidc_status buckets_openid_validate(buckets_openid *o, const char *role_arn, const char *token,
                                            const char *access_token, const char *duration_seconds,
                                            yyjson_mut_doc **claims, char *err, size_t errlen);

/* openid.GetDefaultExpiration: seconds, or -1 when invalid. */
long long buckets_sts_expiry_seconds(const char *duration_seconds);

/* madmin.OpenIDProviderSettings of each provider (OpenIDConfig.GetSettings):
 * pointers into o; the array is the caller's to free. */
typedef struct {
  const char *arn;
  bool claim_provider; /* the claim-based provider (no role ARN) */
  bool claim_userinfo;
  const char *role_policy, *client_id;
  char hashed_secret[48]; /* base64url(sha256(client secret)), unpadded */
} buckets_openid_setting;
size_t buckets_openid_settings(const buckets_openid *o, buckets_openid_setting **out);

#endif
