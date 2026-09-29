/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_LDAPIDP_H
#define BUCKETS_IAM_LDAPIDP_H

#include "core/buf.h"

#include "config/config.h"
#include "net/ldap.h"

/* Active Directory / LDAP as the identity provider (MinIO's
 * internal/config/identity/ldap on minio/pkg/ldap): the identity_ldap
 * config, validated against the server, and the lookups built on it.
 * Reference counted. Every operation opens its own connection. */
typedef struct buckets_ldapidp buckets_ldapidp;

/* Lookup + Validate. NULL (err set, as "<Result>: <Detail>") when the
 * config is invalid or the server cannot be used; a disabled object when
 * identity_ldap is not configured. ca is a CA file or directory (or NULL)
 * trusted besides the system roots. */
buckets_ldapidp *buckets_ldapidp_build(const buckets_config *cfg, const char *ca, char *err, size_t errlen);
buckets_ldapidp *buckets_ldapidp_ref(buckets_ldapidp *p);
void buckets_ldapidp_release(buckets_ldapidp *p);
bool buckets_ldapidp_enabled(const buckets_ldapidp *p);

/* A DN found in the directory: normalized, as the server sent it, and the
 * requested attributes. */
typedef struct {
  char *norm_dn, *actual_dn;
  buckets_ldap_attr *attrs;
  size_t nattrs;
} buckets_ldap_dnres;
void buckets_ldap_dnres_free(buckets_ldap_dnres *r);

/* Config.Bind: finds the user's DN, binds as the user, and looks up the
 * user's groups (normalized DNs). */
bool buckets_ldapidp_bind(buckets_ldapidp *p, const char *username, const char *password, buckets_ldap_dnres *out,
                          char ***groups, size_t *ngroups, char *err, size_t errlen);

/* LookupUserDN: the user (a login name) and its groups: 1 found, 0 not
 * found (err "Unable to find user DN: User DN not found for: ..."), -1 error. */
int buckets_ldapidp_lookup_user(buckets_ldapidp *p, const char *username, buckets_ldap_dnres *out, char ***groups,
                                size_t *ngroups, char *err, size_t errlen);
/* ParsesAsDN */
bool buckets_ldapidp_parses_as_dn(const char *s);
/* GetValidatedDNForUsername: 1 found, 0 not found, -1 error. */
int buckets_ldapidp_validated_user(buckets_ldapidp *p, const char *username, buckets_ldap_dnres *out, char *err,
                                   size_t errlen);
/* GetValidatedGroupDN: 1 found (*under_base says whether it is under a
 * group base DN), 0 not found, -1 error. */
int buckets_ldapidp_validated_group(buckets_ldapidp *p, const char *dn, buckets_ldap_dnres *out, bool *under_base,
                                    char *err, size_t errlen);
/* GetValidatedDNWithGroups: 1 found, 0 not found, -1 error. */
int buckets_ldapidp_validated_user_groups(buckets_ldapidp *p, const char *username, buckets_ldap_dnres *out,
                                          char ***groups, size_t *ngroups, char *err, size_t errlen);

/* IsLDAPUserDN / IsLDAPGroupDN: under a configured base DN. */
bool buckets_ldapidp_is_user_dn(const buckets_ldapidp *p, const char *dn);
bool buckets_ldapidp_is_group_dn(const buckets_ldapidp *p, const char *dn);

/* GetExpiryDuration: seconds (dsecs "" is the default hour), -1 invalid. */
long long buckets_ldapidp_expiry(const buckets_ldapidp *p, const char *dsecs);

/* QuickNormalizeDN / DecodeDN: the input (a copy) when it does not parse. */
char *buckets_ldapidp_quick_normalize(const char *dn);
char *buckets_ldapidp_decode(const char *dn);

/* GetNonEligibleUserDistNames: the (normalized) DNs among dns that no
 * longer exist or match the user filter. false on error. */
bool buckets_ldapidp_non_eligible(buckets_ldapidp *p, char *const *dns, size_t n, char ***out, size_t *nout,
                                  char *err, size_t errlen);
/* LookupGroupMemberships for one user DN (with its login name, may be ""). */
bool buckets_ldapidp_user_groups(buckets_ldapidp *p, const char *username, const char *dn, char ***groups,
                                 size_t *ngroups, char *err, size_t errlen);

/* Frees a vector of strings. */
void buckets_ldap_strv_free(char **v, size_t n);

/* madmin.LDAPSettings (site replication checks that peers agree): the user
 * and group search bases as configured (";"-joined) and the filters. */
void buckets_ldapidp_settings(const buckets_ldapidp *p, buckets_buf *user_base, const char **user_filter,
                              buckets_buf *group_base, const char **group_filter);

#endif
