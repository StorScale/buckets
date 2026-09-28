/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_IAM_H
#define BUCKETS_IAM_IAM_H

#include <stdatomic.h>
#include <yyjson.h>

#include "core/buf.h"
#include "iam/policy.h"
#include "object/object.h"

/* The IAM store: users, groups, policies, policy mappings, service accounts
 * and STS credentials, cached in memory and persisted in the object layer
 * exactly as MinIO does (cmd/iam-store.go, cmd/iam-object-store.go):
 *
 *   .minio.sys/config/iam/format.json
 *   .minio.sys/config/iam/{users,service-accounts,sts}/<key>/identity.json
 *   .minio.sys/config/iam/groups/<group>/members.json
 *   .minio.sys/config/iam/policies/<name>/policy.json
 *   .minio.sys/config/iam/policydb/{users,sts-users,service-accounts,groups}/<name>.json
 *
 * so drives written by MinIO carry their IAM state over. */

typedef enum { BUCKETS_IAM_REG = 0, BUCKETS_IAM_SVC, BUCKETS_IAM_STS, BUCKETS_IAM_ROOT } buckets_iam_utype;

/* A Go time.Time in UTC. */
typedef struct {
  long long sec;
  long nsec;
} buckets_iam_time;

/* One credential (MinIO's UserIdentity). Immutable once published and
 * reference counted, so request threads can hold one without a lock. */
typedef struct {
  _Atomic int refs;
  buckets_iam_utype type; /* where it is stored */
  char *access_key, *secret_key, *session_token;
  char *parent, *name, *description;
  char **groups;
  size_t ngroups;
  char status[4]; /* "on", "off" or "" */
  buckets_iam_time expiration, updated;
  char *claims_field; /* credentials.claims, raw JSON (round-tripped), or NULL */
  yyjson_doc *claims; /* verified claims of session_token, or NULL */
  /* The decoded "sessionPolicy" claim: present, and parsed (NULL when it
   * does not parse, which denies everything). */
  bool has_session_policy;
  char *session_policy_json;
  buckets_policy *session_policy;
} buckets_iam_ident;

void buckets_iam_ident_release(buckets_iam_ident *id);
/* Credentials.IsTemp / IsServiceAccount / IsExpired / IsValid. */
bool buckets_iam_ident_is_temp(const buckets_iam_ident *id);
bool buckets_iam_ident_is_svc(const buckets_iam_ident *id);
bool buckets_iam_ident_is_expired(const buckets_iam_ident *id);
bool buckets_iam_ident_is_valid(const buckets_iam_ident *id);
/* A string claim, or NULL. */
const char *buckets_iam_ident_claim(const buckets_iam_ident *id, const char *key);

bool buckets_iam_time_is_set(buckets_iam_time t); /* neither zero nor 1970 */

typedef enum {
  BUCKETS_IAM_OK = 0,
  BUCKETS_IAM_ERR_INVALID_ARGUMENT,
  BUCKETS_IAM_ERR_NO_SUCH_USER,
  BUCKETS_IAM_ERR_NO_SUCH_GROUP,
  BUCKETS_IAM_ERR_NO_SUCH_POLICY,
  BUCKETS_IAM_ERR_NO_SUCH_SVC,
  BUCKETS_IAM_ERR_POLICY_IN_USE,
  BUCKETS_IAM_ERR_GROUP_NOT_EMPTY,
  BUCKETS_IAM_ERR_GROUP_DISABLED,
  BUCKETS_IAM_ERR_NOT_ALLOWED,     /* errIAMActionNotAllowed */
  BUCKETS_IAM_ERR_SVC_NOT_ALLOWED, /* errIAMServiceAccountNotAllowed */
  BUCKETS_IAM_ERR_NO_POLICY_CHANGE,
  BUCKETS_IAM_ERR_INVALID_ACCESS_KEY,
  BUCKETS_IAM_ERR_INVALID_SECRET_KEY,
  BUCKETS_IAM_ERR_SESSION_POLICY_TOO_LARGE,
  BUCKETS_IAM_ERR_INVALID_EXPIRATION,
  BUCKETS_IAM_ERR_MALFORMED_POLICY,
  BUCKETS_IAM_ERR_STORAGE,
  BUCKETS_IAM_ERR_NOT_INITIALIZED,
} buckets_iam_err;

const char *buckets_iam_strerror(buckets_iam_err e);

typedef struct buckets_iam buckets_iam;

buckets_iam *buckets_iam_new(const char *root_access_key, const char *root_secret_key);
void buckets_iam_free(buckets_iam *iam);

/* Attaches the object layer, writes format.json if needed and loads
 * everything. Until this succeeds, lookups of non-root keys fail with
 * BUCKETS_IAM_ERR_NOT_INITIALIZED. */
bool buckets_iam_start(buckets_iam *iam, buckets_objlayer *layer);
bool buckets_iam_ready(const buckets_iam *iam);
/* Reloads everything from storage (the periodic refresh). */
bool buckets_iam_reload(buckets_iam *iam);
/* Starts a thread that reloads every interval_sec seconds. */
void buckets_iam_start_refresh(buckets_iam *iam, int interval_sec);

/* Called after every change with what changed, for peer notification.
 * kind: "user", "svc", "sts", "group", "policy", "policydb-user",
 * "policydb-sts", "policydb-group". */
typedef void (*buckets_iam_notify_fn)(void *ud, const char *kind, const char *name);
void buckets_iam_set_notify(buckets_iam *iam, buckets_iam_notify_fn fn, void *ud);
/* Applies a peer's notification: reloads that item from storage. */
void buckets_iam_on_notify(buckets_iam *iam, const char *kind, const char *name);

const char *buckets_iam_root_access_key(const buckets_iam *iam);
const char *buckets_iam_root_secret_key(const buckets_iam *iam);

/* OpenID hooks: the JWT policy claim name (claim_prefix + claim_name) and
 * the policies of a role ARN (role_policy). Both return malloc'd strings
 * (NULL: none). */
typedef struct {
  char *(*claim_name)(void *ud);
  char *(*role_policy)(void *ud, const char *arn);
  void *ud;
} buckets_iam_openid_hooks;
void buckets_iam_set_openid_hooks(buckets_iam *iam, const buckets_iam_openid_hooks *hooks);

/* LDAPUsersSysType (set before start when identity_ldap is enabled): users
 * are LDAP DNs whose policies are mapped in policydb/sts-users, groups are
 * LDAP group DNs, and built-in user/group changes are not allowed. */
void buckets_iam_set_ldap_mode(buckets_iam *iam, bool on);
bool buckets_iam_ldap_mode(buckets_iam *iam);

/* An authorization plugin (policy_plugin): when it returns true, *allowed
 * is the decision and IAM policies are not consulted at all. */
typedef bool (*buckets_iam_authz_fn)(void *ud, const buckets_iam_ident *id, bool owner,
                                     const buckets_policy_args *args, bool *allowed);
void buckets_iam_set_authz(buckets_iam *iam, buckets_iam_authz_fn fn, void *ud);

/* ---- authentication ------------------------------------------------------- */

typedef enum {
  BUCKETS_IAM_KEY_OK = 0,
  BUCKETS_IAM_KEY_UNKNOWN,
  BUCKETS_IAM_KEY_DISABLED,
  BUCKETS_IAM_KEY_NOT_READY,
} buckets_iam_key_status;

/* checkKeyValid's lookup: the root credential, or a stored identity that is
 * valid (enabled, not expired). *out is a reference to release. */
buckets_iam_key_status buckets_iam_get_key(buckets_iam *iam, const char *access_key, buckets_iam_ident **out);

typedef enum {
  BUCKETS_IAM_TOKEN_OK = 0,
  BUCKETS_IAM_TOKEN_NO_ACCESS_KEY, /* a token on an anonymous request */
  BUCKETS_IAM_TOKEN_INVALID,
  BUCKETS_IAM_TOKEN_EXPIRED,
} buckets_iam_token_status;

/* checkClaimsFromToken: validates the request's x-amz-security-token (or
 * NULL) against the credential, and says whether the caller acts as the
 * owner (root, or root-derived without a session policy). */
buckets_iam_token_status buckets_iam_check_token(const buckets_iam *iam, const buckets_iam_ident *id,
                                                 const char *token, bool *owner);

/* ---- authorization --------------------------------------------------------- */

/* IAMSys.IsAllowed for an authenticated credential. */
bool buckets_iam_is_allowed(buckets_iam *iam, const buckets_iam_ident *id, bool owner,
                            const buckets_policy_args *args);

/* The user name conditions see: the parent for derived credentials. */
const char *buckets_iam_condition_user(const buckets_iam_ident *id);

/* ---- users ------------------------------------------------------------------ */

typedef struct {
  char *name;
  char *policy; /* comma-separated mapped policies, "" if none */
  char **member_of;
  size_t nmember_of;
  bool enabled;
  buckets_iam_time updated; /* of the policy mapping, as MinIO reports */
} buckets_iam_user_info;

void buckets_iam_user_info_free(buckets_iam_user_info *u, size_t n);

/* AddUser: creates or replaces a regular user; status is "enabled"/"on" or
 * anything else for disabled. */
buckets_iam_err buckets_iam_add_user(buckets_iam *iam, const char *access_key, const char *secret_key,
                                     const char *status);
buckets_iam_err buckets_iam_set_user_status(buckets_iam *iam, const char *access_key, bool enabled);
buckets_iam_err buckets_iam_set_user_secret(buckets_iam *iam, const char *access_key, const char *secret_key);
/* DeleteUser for a regular user: leaves its groups and removes its service
 * accounts and STS credentials. */
buckets_iam_err buckets_iam_delete_user(buckets_iam *iam, const char *access_key);
buckets_iam_err buckets_iam_get_user_info(buckets_iam *iam, const char *name, buckets_iam_user_info *out);
/* Regular users only (no service accounts or STS). */
void buckets_iam_list_users(buckets_iam *iam, buckets_iam_user_info **out, size_t *n);
/* The stored identity for a key (any type), not checking validity. */
buckets_iam_ident *buckets_iam_get_ident(buckets_iam *iam, const char *access_key);

/* ---- groups ----------------------------------------------------------------- */

typedef struct {
  char *name;
  char *status; /* "enabled" / "disabled" */
  char **members;
  size_t nmembers;
  char *policy;
  buckets_iam_time updated;
} buckets_iam_group_desc;

void buckets_iam_group_desc_free(buckets_iam_group_desc *g);
buckets_iam_err buckets_iam_group_add_members(buckets_iam *iam, const char *group, const char *const *members,
                                              size_t n);
/* With n == 0, deletes the group, which must be empty. */
buckets_iam_err buckets_iam_group_remove_members(buckets_iam *iam, const char *group, const char *const *members,
                                                 size_t n);
buckets_iam_err buckets_iam_group_set_status(buckets_iam *iam, const char *group, bool enabled);
buckets_iam_err buckets_iam_group_describe(buckets_iam *iam, const char *group, buckets_iam_group_desc *out);
void buckets_iam_list_groups(buckets_iam *iam, char ***out, size_t *n);

/* ---- policies ------------------------------------------------------------------ */

typedef struct {
  char *name;
  char *json; /* the policy document */
  buckets_iam_time created, updated;
} buckets_iam_policy_doc;

void buckets_iam_policy_doc_free(buckets_iam_policy_doc *d, size_t n);
buckets_iam_err buckets_iam_set_policy(buckets_iam *iam, const char *name, const char *json, size_t len,
                                       char *err, size_t errlen);
buckets_iam_err buckets_iam_delete_policy(buckets_iam *iam, const char *name);
buckets_iam_err buckets_iam_get_policy(buckets_iam *iam, const char *name, buckets_iam_policy_doc *out);
void buckets_iam_list_policies(buckets_iam *iam, buckets_iam_policy_doc **out, size_t *n);

/* PolicyDBSet: replaces the mapping (policies "" removes it). */
buckets_iam_err buckets_iam_policy_set(buckets_iam *iam, const char *name, bool is_group, buckets_iam_utype type,
                                       const char *policies);
/* PolicyDBUpdate: attaches or detaches; *effective (may be NULL) gets the
 * resulting mapping, *changed the policies actually added/removed. */
buckets_iam_err buckets_iam_policy_update(buckets_iam *iam, const char *name, bool is_group, bool attach,
                                          const char *const *policies, size_t n, char **changed, char **effective);
/* The same for the STS mapping of a user (an LDAP DN) or a group, which
 * need not exist in the store. */
buckets_iam_err buckets_iam_policy_update_sts(buckets_iam *iam, const char *name, bool is_group, bool attach,
                                              const char *const *policies, size_t n, char **changed,
                                              char **effective);
/* CurrentPolicies: the names in csv that exist, comma-separated ("" if none). */
char *buckets_iam_existing_policies(buckets_iam *iam, const char *csv);
/* doesPolicyAllow: the named policies (comma-separated) evaluated together. */
bool buckets_iam_policies_allow(buckets_iam *iam, const char *csv, const buckets_policy_args *args);
/* The policies a credential's claims name: its role ARN's (*from_role), or
 * the OpenID policy claim's (*from_claim); "" when neither applies. */
char *buckets_iam_ident_policies(buckets_iam *iam, const buckets_iam_ident *id, bool *from_role, bool *from_claim);
/* PolicyDBGet(name, groups...): comma-separated ("" if none). */
char *buckets_iam_policy_db_get(buckets_iam *iam, const char *name, char *const *groups, size_t ngroups);
/* The mapped policies of a user (with its groups) or a group, comma-separated. */
char *buckets_iam_mapped_policies(buckets_iam *iam, const char *name, bool is_group);

/* QueryPolicyEntities: madmin.PolicyEntitiesResult as JSON. With no users, groups or policies it
 * lists every policy's users and groups. */
char *buckets_iam_policy_entities_json(buckets_iam *iam, const char *const *users, size_t nu,
                                       const char *const *groups, size_t ng, const char *const *policies, size_t np);

/* QueryLDAPPolicyEntities: like buckets_iam_policy_entities_json for LDAP,
 * where each queried user comes with the groups found for it, entities
 * are filtered by the predicates (IsLDAPUserDN / IsLDAPGroupDN) and names
 * are reported decoded (DecodeDN). */
typedef bool (*buckets_iam_name_pred)(void *ud, const char *name);
typedef struct {
  const char *user;
  char *const *groups;
  size_t ngroups;
} buckets_iam_entity_user;
char *buckets_iam_ldap_policy_entities_json(buckets_iam *iam, const buckets_iam_entity_user *users, size_t nu,
                                            const char *const *groups, size_t ng, const char *const *policies,
                                            size_t np, buckets_iam_name_pred is_user, buckets_iam_name_pred is_group,
                                            void *ud);
/* GetAllSTSUserMappings: the STS-mapped users matching pred and their
 * policies (both arrays and strings to free). */
size_t buckets_iam_sts_user_mappings(buckets_iam *iam, buckets_iam_name_pred pred, void *ud, char ***names,
                                     char ***policies);

/* ---- service accounts ---------------------------------------------------------- */

typedef struct {
  const char *parent;
  const char *const *groups;
  size_t ngroups;
  const char *access_key; /* NULL: generate */
  const char *secret_key;
  const char *session_policy; /* JSON, NULL/"" inherits the parent's policies */
  const char *name, *description;
  const buckets_iam_time *expiration;
  const char *claims_json; /* extra claims (a JSON object) for the token, or NULL */
} buckets_iam_svc_opts;

/* Creates a service account; *out is a reference to the new credential. */
buckets_iam_err buckets_iam_add_svc(buckets_iam *iam, const buckets_iam_svc_opts *o, buckets_iam_ident **out,
                                    char *err, size_t errlen);

typedef struct {
  const char *secret_key;
  const char *status; /* "", "on", "off", "enabled", "disabled" */
  const char *name, *description;
  const buckets_iam_time *expiration;
  bool set_policy;
  const char *session_policy; /* with set_policy: JSON; blank removes it */
} buckets_iam_svc_update;

buckets_iam_err buckets_iam_update_svc(buckets_iam *iam, const char *access_key, const buckets_iam_svc_update *u,
                                       char *err, size_t errlen);
buckets_iam_err buckets_iam_delete_svc(buckets_iam *iam, const char *access_key);
/* Service accounts (type SVC) or STS credentials (type STS) whose parent is
 * parent; references to release. */
void buckets_iam_list_derived(buckets_iam *iam, const char *parent, buckets_iam_utype type,
                              buckets_iam_ident ***out, size_t *n);

/* ---- STS -------------------------------------------------------------------------- */

/* SetTempUser: stores a temporary credential. claims_json is the token's
 * claims (without accessKey); the token is signed with the root secret. If
 * policy is set, it is mapped to the parent user (sts-users). */
buckets_iam_err buckets_iam_set_temp_user(buckets_iam *iam, const char *access_key, const char *secret_key,
                                          const char *parent, const char *const *groups, size_t ngroups,
                                          buckets_iam_time expiration, const char *claims_json,
                                          const char *policy, buckets_iam_ident **out);

/* RevokeTokens: deletes the STS credentials of parent, only those whose
 * tokenRevokeType claim is type when type is set. */
buckets_iam_err buckets_iam_revoke_tokens(buckets_iam *iam, const char *parent, const char *type);

/* Random credentials as auth.GenerateCredentials: a 20-character access
 * key (A-Z0-9) and a 40-character secret. */
void buckets_iam_generate_credentials(char ak[21], char sk[41]);

#endif
