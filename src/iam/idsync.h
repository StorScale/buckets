/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_IDSYNC_H
#define BUCKETS_IAM_IDSYNC_H

/* Identity sync (docs/design/identity-sync.md): people signed in through an
 * OpenID provider keep access keys after they leave, so the provider is asked
 * about each one. Gone or disabled: their temporary credentials go at once,
 * their access keys are turned off at once and deleted after a grace period;
 * back within it, the keys come back on. LDAP has its own sync (s3/server.c).
 *
 * Settings (environment):
 *   BUCKETS_OPENID_SYNC_PROVIDER     entra, keycloak, okta or scim (SCIM only: no provider API); unset: off
 *   scim:     BUCKETS_OPENID_SYNC_TENANT_ID (Entra: people by tid and oid) or _ISSUER (by iss and sub)
 *   BUCKETS_SCIM                     on: SCIM's records answer for the people they name, beside the API
 *   BUCKETS_OPENID_SYNC_ROLES        on: also keep each person's roles current (_ROLES_FROM, _APP_ID below)
 *   entra:    BUCKETS_OPENID_SYNC_TENANT_ID, _CLIENT_ID, _CLIENT_SECRET (an app with Graph's User.Read.All);
 *             people by the token's tid and oid
 *   keycloak: BUCKETS_OPENID_SYNC_URL (Keycloak's base URL), _REALM, _CLIENT_ID, _CLIENT_SECRET (a client
 *             whose service account has realm-management's view-users); _ISSUER (default URL/realms/REALM)
 *   okta:     BUCKETS_OPENID_SYNC_URL (https://<domain>), _API_TOKEN (read-only), _ISSUER (the
 *             authorization server's); Keycloak and Okta people by the token's iss and sub
 *   BUCKETS_OPENID_SYNC_INTERVAL     seconds between syncs (3600)
 *   BUCKETS_OPENID_REMOVE_AFTER      grace period: days, or a Go duration such as 10s (30 days)
 *   BUCKETS_OPENID_REMOVE_MAX        more people than this gone in one sync: none removed (10)
 *   BUCKETS_OPENID_SYNC_LOGIN_URL, _GRAPH_URL   Microsoft's endpoints (tests point them elsewhere)
 *
 * The planning is pure, so tested without a provider; the client is the
 * only part that talks to one. */

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* ---- settings --------------------------------------------------------------------------- */

typedef struct {
  char provider[16]; /* "entra", "keycloak", "okta"; "" off */
  char url[512], realm[128], issuer[700], api_token[256];
  char tenant[64], client_id[128], client_secret[256];
  char login_url[256], graph_url[256];
  long interval_s;
  long long remove_after_s;
  long remove_max;
  bool scim; /* SCIM's records (iam/scim.h) answer for the people they name: BUCKETS_SCIM=on, or provider scim */
  /* roles kept current (docs/design/roles-current.md): BUCKETS_OPENID_SYNC_ROLES=on; where the token's policy
   * claim comes from (BUCKETS_OPENID_SYNC_ROLES_FROM: app-roles or groups for Entra; realm-roles, client-roles or
   * groups for Keycloak; groups for Okta and SCIM); the sign-in app or client whose roles count
   * (BUCKETS_OPENID_SYNC_APP_ID; the sync's own client ID by default) */
  bool roles;
  char roles_from[16];
  char app_id[128];
} buckets_idsync_settings;

/* From the environment; false and why when set but not usable. Off (provider "") is fine. */
bool buckets_idsync_settings_from_env(buckets_idsync_settings *s, char *err, size_t errlen);

/* ---- what the provider says ----------------------------------------------------------------- */

typedef enum {
  BUCKETS_IDSYNC_UNKNOWN = 0, /* not asked, or the answer could not be used: nothing is done */
  BUCKETS_IDSYNC_ACTIVE,
  BUCKETS_IDSYNC_DISABLED,
  BUCKETS_IDSYNC_GONE,
} buckets_idsync_state;

const char *buckets_idsync_state_name(buckets_idsync_state st);

/* Microsoft Graph's reply to GET /v1.0/users/{id}?$select=id,accountEnabled. */
buckets_idsync_state buckets_idsync_graph_state(int status, const char *body, size_t len);
/* Keycloak's reply to GET /admin/realms/{realm}/users/{id}. */
buckets_idsync_state buckets_idsync_keycloak_state(int status, const char *body, size_t len);
/* Okta's reply to GET /api/v1/users/{id}: SUSPENDED and DEPROVISIONED are disabled. */
buckets_idsync_state buckets_idsync_okta_state(int status, const char *body, size_t len);

/* Whose credential this is, by its token's claims: the person's ID with this provider, or NULL when the
 * credential is not from it. */
const char *buckets_idsync_person_of(const buckets_idsync_settings *s, const char *tid, const char *oid,
                                     const char *iss, const char *sub);

/* ---- planning ------------------------------------------------------------------------------- */

/* A credential of one of the provider's people. */
typedef struct {
  const char *access_key;
  const char *person; /* the provider's ID for its owner (Entra: oid; Keycloak, Okta: sub) */
  bool sts;           /* temporary; else an access key (service account) */
  bool enabled;       /* an access key's status */
} buckets_idsync_cred;

/* An access key the sync turned off: who owned it, and when (unix seconds). */
typedef struct buckets_idsync_held_s {
  char *access_key, *person;
  long long since;
} buckets_idsync_held;

typedef enum {
  BUCKETS_IDSYNC_REVOKE,  /* a temporary credential: delete */
  BUCKETS_IDSYNC_DISABLE, /* an access key: turn off, and remember */
  BUCKETS_IDSYNC_ENABLE,  /* an access key the sync turned off: its owner is back */
  BUCKETS_IDSYNC_DELETE,  /* an access key off for the whole grace period */
  BUCKETS_IDSYNC_FORGET,  /* remembered, but the key is gone */
} buckets_idsync_action_kind;

typedef struct {
  buckets_idsync_action_kind kind;
  const char *access_key, *person;
} buckets_idsync_action;

typedef struct {
  buckets_idsync_action *actions;
  size_t n;
  size_t people_leaving; /* gone or disabled, with something still to remove */
  bool held;             /* more than remove_max: no new removals this time */
} buckets_idsync_plan;

/* The person's state: states[i] for people[i]. */
typedef struct {
  const char *const *people;
  const buckets_idsync_state *states;
  size_t n;
} buckets_idsync_answers;

/* What to do now, given the credentials, what the provider said and what the sync turned off before.
 * Pointers in the plan point into creds and held. */
void buckets_idsync_plan_make(const buckets_idsync_cred *creds, size_t ncreds,
                              const buckets_idsync_answers *ans, const buckets_idsync_held *held,
                              size_t nheld, long long now, long long remove_after_s, long remove_max,
                              buckets_idsync_plan *out);
void buckets_idsync_plan_free(buckets_idsync_plan *p);
const char *buckets_idsync_action_name(buckets_idsync_action_kind k);

/* ---- what the sync turned off, kept across restarts ------------------------------------------ */

/* {"held": [{"accessKey", "person", "since"}]}; an empty or missing document is no keys. */
bool buckets_idsync_held_parse(const char *json, size_t len, buckets_idsync_held **out, size_t *n);
void buckets_idsync_held_json(const buckets_idsync_held *h, size_t n, buckets_buf *out);
void buckets_idsync_held_free(buckets_idsync_held *h, size_t n);

/* ---- the provider's API ------------------------------------------------------------------------- */

typedef struct buckets_idsync_client buckets_idsync_client;
buckets_idsync_client *buckets_idsync_client_new(const buckets_idsync_settings *s);
void buckets_idsync_client_free(buckets_idsync_client *c);
/* What Graph, Keycloak or Okta says about a person besides their state. */
typedef struct {
  char id[64], display_name[256], upn[256];
} buckets_idsync_person;
/* One person by their ID (for the console's check also a sign-in name: Entra's user principal name, a Keycloak
 * user name or an Okta login); UNKNOWN (and err) when the provider could not answer. who, when not NULL, gets
 * their ID and names. */
buckets_idsync_state buckets_idsync_client_lookup(buckets_idsync_client *c, const char *id,
                                                  buckets_idsync_person *who, char *err, size_t errlen);
/* Roles kept current: the person's values for the token's policy claim now, from settings.roles_from (Entra's app
 * roles: their own and their direct groups', or group IDs; Okta's group names; Keycloak's realm or client roles,
 * or group paths), sorted. false (and err) when the provider couldn't answer: nothing is changed then. */
bool buckets_idsync_client_values(buckets_idsync_client *c, const char *id, char ***values, size_t *n, char *err,
                                  size_t errlen);
void buckets_idsync_values_free(char **v, size_t n);
/* A sync run starts: what is cached for values (who holds which Entra app role) is asked again. */
void buckets_idsync_client_begin(buckets_idsync_client *c);

/* One person's roles: the policies their sign-ins map to now and what the provider says now (comma-separated). */
typedef struct {
  const char *person, *parent;
  const char *old_csv, *new_csv;
  bool removes; /* set: something of old_csv isn't in new_csv */
  bool apply;   /* set: the change goes ahead */
} buckets_idsync_role_change;
/* Which changes go ahead: every one that changes something, unless more than remove_max people would lose a role;
 * then only those that add without removing. Returns whether some were held. */
bool buckets_idsync_roles_decide(buckets_idsync_role_change *ch, size_t n, long remove_max);
/* Two comma-separated lists with the same values, in any order. */
bool buckets_idsync_csv_same(const char *a, const char *b);

#endif
