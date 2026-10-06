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
 *   BUCKETS_OPENID_SYNC_PROVIDER     entra (the only one yet); unset: off
 *   BUCKETS_OPENID_SYNC_TENANT_ID, _CLIENT_ID, _CLIENT_SECRET
 *   BUCKETS_OPENID_SYNC_INTERVAL     seconds between syncs (3600)
 *   BUCKETS_OPENID_REMOVE_AFTER      grace period: days, or a Go duration such as 10s (30 days)
 *   BUCKETS_OPENID_REMOVE_MAX        more people than this gone in one sync: none removed (10)
 *   BUCKETS_OPENID_SYNC_LOGIN_URL, _GRAPH_URL   Microsoft's endpoints (tests point them elsewhere)
 *
 * The planning is pure, so tested without a provider; the Entra client is
 * the only part that talks to one. */

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* ---- settings --------------------------------------------------------------------------- */

typedef struct {
  char provider[16]; /* "entra"; "" off */
  char tenant[64], client_id[128], client_secret[256];
  char login_url[256], graph_url[256];
  long interval_s;
  long long remove_after_s;
  long remove_max;
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

/* ---- planning ------------------------------------------------------------------------------- */

/* A credential of one of the provider's people. */
typedef struct {
  const char *access_key;
  const char *person; /* the provider's ID for its owner (Entra: oid) */
  bool sts;           /* temporary; else an access key (service account) */
  bool enabled;       /* an access key's status */
} buckets_idsync_cred;

/* An access key the sync turned off: who owned it, and when (unix seconds). */
typedef struct {
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

/* ---- Entra ------------------------------------------------------------------------------------- */

typedef struct buckets_idsync_entra buckets_idsync_entra;
buckets_idsync_entra *buckets_idsync_entra_new(const buckets_idsync_settings *s);
void buckets_idsync_entra_free(buckets_idsync_entra *e);
/* What Graph says about a person besides their state. */
typedef struct {
  char id[64], display_name[256], upn[256];
} buckets_idsync_person;
/* One person by object ID (or, for the console's check, user principal name); UNKNOWN (and err) when Graph
 * could not answer. who, when not NULL, gets their ID and names. */
buckets_idsync_state buckets_idsync_entra_lookup(buckets_idsync_entra *e, const char *oid,
                                                 buckets_idsync_person *who, char *err, size_t errlen);

#endif
