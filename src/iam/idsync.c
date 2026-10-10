/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/idsync.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "net/fetch.h"

/* ---- settings --------------------------------------------------------------------------- */

static const char *env(const char *name) {
  const char *v = getenv(name);
  return v && *v ? v : NULL;
}

static bool copy(char *dst, size_t cap, const char *v, const char *name, char *err, size_t errlen) {
  if (!v) {
    snprintf(err, errlen, "%s is not set", name);
    return false;
  }
  if (strlen(v) >= cap) {
    snprintf(err, errlen, "%s is too long", name);
    return false;
  }
  snprintf(dst, cap, "%s", v);
  return true;
}

static bool provider_is(const buckets_idsync_settings *s, const char *name) {
  return strcmp(s->provider, name) == 0;
}

bool buckets_idsync_settings_from_env(buckets_idsync_settings *s, char *err, size_t errlen) {
  memset(s, 0, sizeof(*s));
  const char *p = env("BUCKETS_OPENID_SYNC_PROVIDER");
  if (!p) return true;
  if (strcmp(p, "entra") != 0 && strcmp(p, "keycloak") != 0 && strcmp(p, "okta") != 0 && strcmp(p, "scim") != 0) {
    snprintf(err, errlen, "BUCKETS_OPENID_SYNC_PROVIDER %s: entra, keycloak, okta or scim", p);
    return false;
  }
  snprintf(s->provider, sizeof(s->provider), "%s", p);
  const char *sc = env("BUCKETS_SCIM");
  s->scim = provider_is(s, "scim") || (sc && (!strcmp(sc, "on") || !strcmp(sc, "true") || !strcmp(sc, "1")));
#define NEED(field, name) copy(s->field, sizeof(s->field), env(name), name, err, errlen)
  const char *u = env("BUCKETS_OPENID_SYNC_URL");
  if (u && strlen(u) < sizeof(s->url)) { /* without trailing slashes, for building URLs and the issuer */
    snprintf(s->url, sizeof(s->url), "%s", u);
    for (size_t n = strlen(s->url); n && s->url[n - 1] == '/';) s->url[--n] = '\0';
  }
  if (provider_is(s, "scim")) { /* nothing to ask: whose tokens SCIM's externalIds are */
    const char *t = env("BUCKETS_OPENID_SYNC_TENANT_ID");
    if (t ? !NEED(tenant, "BUCKETS_OPENID_SYNC_TENANT_ID") : !NEED(issuer, "BUCKETS_OPENID_SYNC_ISSUER")) {
      snprintf(err, errlen, "BUCKETS_OPENID_SYNC_PROVIDER scim needs BUCKETS_OPENID_SYNC_TENANT_ID (Entra ID) or "
                            "BUCKETS_OPENID_SYNC_ISSUER (the tokens' issuer, such as Okta's)");
      return false;
    }
  } else if (provider_is(s, "entra")) {
    if (!NEED(tenant, "BUCKETS_OPENID_SYNC_TENANT_ID") || !NEED(client_id, "BUCKETS_OPENID_SYNC_CLIENT_ID") ||
        !NEED(client_secret, "BUCKETS_OPENID_SYNC_CLIENT_SECRET"))
      return false;
    const char *login = env("BUCKETS_OPENID_SYNC_LOGIN_URL"), *graph = env("BUCKETS_OPENID_SYNC_GRAPH_URL");
    if (!copy(s->login_url, sizeof(s->login_url), login ? login : "https://login.microsoftonline.com",
              "BUCKETS_OPENID_SYNC_LOGIN_URL", err, errlen) ||
        !copy(s->graph_url, sizeof(s->graph_url), graph ? graph : "https://graph.microsoft.com",
              "BUCKETS_OPENID_SYNC_GRAPH_URL", err, errlen))
      return false;
  } else if (provider_is(s, "keycloak")) {
    if (!*s->url) { /* unset or too long: copy says which */
      copy(s->url, sizeof(s->url), u, "BUCKETS_OPENID_SYNC_URL", err, errlen);
      return false;
    }
    if (!NEED(realm, "BUCKETS_OPENID_SYNC_REALM") || !NEED(client_id, "BUCKETS_OPENID_SYNC_CLIENT_ID") ||
        !NEED(client_secret, "BUCKETS_OPENID_SYNC_CLIENT_SECRET"))
      return false;
    const char *iss = env("BUCKETS_OPENID_SYNC_ISSUER");
    if (iss) {
      if (!NEED(issuer, "BUCKETS_OPENID_SYNC_ISSUER")) return false;
    } else {
      snprintf(s->issuer, sizeof(s->issuer), "%s/realms/%s", s->url, s->realm);
    }
  } else {          /* okta */
    if (!*s->url) { /* unset or too long: copy says which */
      copy(s->url, sizeof(s->url), u, "BUCKETS_OPENID_SYNC_URL", err, errlen);
      return false;
    }
    if (!NEED(api_token, "BUCKETS_OPENID_SYNC_API_TOKEN") || !NEED(issuer, "BUCKETS_OPENID_SYNC_ISSUER"))
      return false;
  }
#undef NEED
  const char *iv = env("BUCKETS_OPENID_SYNC_INTERVAL");
  s->interval_s = iv ? atol(iv) : 3600;
  if (s->interval_s <= 0) {
    snprintf(err, errlen, "BUCKETS_OPENID_SYNC_INTERVAL %s: seconds, more than 0", iv);
    return false;
  }
  const char *ra = env("BUCKETS_OPENID_REMOVE_AFTER");
  s->remove_after_s = 30LL * 86400;
  if (ra) {
    bool digits = true;
    for (const char *c = ra; *c; c++) digits &= isdigit((unsigned char)*c) != 0;
    int64_t ns;
    if (digits)
      s->remove_after_s = atoll(ra) * 86400;
    else if (buckets_go_duration_parse(ra, &ns) && ns >= 0)
      s->remove_after_s = ns / 1000000000LL;
    else {
      snprintf(err, errlen, "BUCKETS_OPENID_REMOVE_AFTER %s: days, or a duration such as 720h", ra);
      return false;
    }
  }
  const char *rm = env("BUCKETS_OPENID_REMOVE_MAX");
  s->remove_max = rm ? atol(rm) : 10;
  if (s->remove_max < 0) {
    snprintf(err, errlen, "BUCKETS_OPENID_REMOVE_MAX %s: a count", rm);
    return false;
  }
  /* roles kept current (docs/design/roles-current.md) */
  const char *ro = env("BUCKETS_OPENID_SYNC_ROLES");
  s->roles = ro && (!strcmp(ro, "on") || !strcmp(ro, "true") || !strcmp(ro, "1"));
  const char *from = env("BUCKETS_OPENID_SYNC_ROLES_FROM");
  const char *dflt = provider_is(s, "entra") ? "app-roles" : provider_is(s, "keycloak") ? "realm-roles" : "groups";
  snprintf(s->roles_from, sizeof(s->roles_from), "%s", from ? from : dflt);
  static const char *const ok_from[][2] = {{"entra", "app-roles"}, {"entra", "groups"},        {"keycloak", "realm-roles"},
                                           {"keycloak", "client-roles"}, {"keycloak", "groups"}, {"okta", "groups"},
                                           {"scim", "groups"}};
  bool known = false;
  for (size_t i = 0; i < sizeof(ok_from) / sizeof(ok_from[0]); i++)
    known |= provider_is(s, ok_from[i][0]) && !strcmp(s->roles_from, ok_from[i][1]);
  if (s->roles && !known) {
    snprintf(err, errlen, "BUCKETS_OPENID_SYNC_ROLES_FROM %s: not a source of roles for %s", s->roles_from, s->provider);
    return false;
  }
  const char *app = env("BUCKETS_OPENID_SYNC_APP_ID"); /* the sign-in app (Entra) or client (Keycloak) */
  snprintf(s->app_id, sizeof(s->app_id), "%s", app ? app : s->client_id);
  return true;
}

const char *buckets_idsync_person_of(const buckets_idsync_settings *s, const char *tid, const char *oid,
                                     const char *iss, const char *sub) {
  if (provider_is(s, "entra") || (provider_is(s, "scim") && *s->tenant))
    return tid && oid && *oid && strcmp(tid, s->tenant) == 0 ? oid : NULL;
  if (!*s->provider) return NULL;
  /* Keycloak and Okta: the token's subject, from this issuer (a trailing slash aside) */
  if (!iss || !sub || !*sub) return NULL;
  size_t a = strlen(iss), b = strlen(s->issuer);
  while (a && iss[a - 1] == '/') a--;
  while (b && s->issuer[b - 1] == '/') b--;
  return a == b && strncmp(iss, s->issuer, a) == 0 ? sub : NULL;
}

/* ---- what the provider says ----------------------------------------------------------------- */

const char *buckets_idsync_state_name(buckets_idsync_state st) {
  switch (st) {
    case BUCKETS_IDSYNC_ACTIVE: return "active";
    case BUCKETS_IDSYNC_DISABLED: return "disabled";
    case BUCKETS_IDSYNC_GONE: return "gone";
    default: return "unknown";
  }
}

buckets_idsync_state buckets_idsync_graph_state(int status, const char *body, size_t len) {
  yyjson_doc *d = body && len ? yyjson_read(body, len, 0) : NULL;
  yyjson_val *root = yyjson_doc_get_root(d);
  buckets_idsync_state st = BUCKETS_IDSYNC_UNKNOWN;
  if (status == 200) {
    yyjson_val *en = yyjson_obj_get(root, "accountEnabled");
    if (yyjson_is_bool(en)) st = yyjson_get_bool(en) ? BUCKETS_IDSYNC_ACTIVE : BUCKETS_IDSYNC_DISABLED;
  } else if (status == 404) {
    /* only Graph's own "no such user", not a 404 from a wrong URL or a proxy */
    const char *code = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(root, "error"), "code"));
    if (code && strcmp(code, "Request_ResourceNotFound") == 0) st = BUCKETS_IDSYNC_GONE;
  }
  yyjson_doc_free(d);
  return st;
}

buckets_idsync_state buckets_idsync_keycloak_state(int status, const char *body, size_t len) {
  yyjson_doc *d = body && len ? yyjson_read(body, len, 0) : NULL;
  yyjson_val *root = yyjson_doc_get_root(d);
  buckets_idsync_state st = BUCKETS_IDSYNC_UNKNOWN;
  if (status == 200) {
    yyjson_val *en = yyjson_obj_get(root, "enabled");
    if (yyjson_is_bool(en)) st = yyjson_get_bool(en) ? BUCKETS_IDSYNC_ACTIVE : BUCKETS_IDSYNC_DISABLED;
  } else if (status == 404) {
    /* only "User not found", not a realm that is not there */
    const char *e = yyjson_get_str(yyjson_obj_get(root, "error"));
    if (e && strcmp(e, "User not found") == 0) st = BUCKETS_IDSYNC_GONE;
  }
  yyjson_doc_free(d);
  return st;
}

buckets_idsync_state buckets_idsync_okta_state(int status, const char *body, size_t len) {
  yyjson_doc *d = body && len ? yyjson_read(body, len, 0) : NULL;
  yyjson_val *root = yyjson_doc_get_root(d);
  buckets_idsync_state st = BUCKETS_IDSYNC_UNKNOWN;
  if (status == 200) {
    /* Okta's user lifecycle: only these two take sign-in away for good */
    const char *s = yyjson_get_str(yyjson_obj_get(root, "status"));
    if (s)
      st = strcmp(s, "SUSPENDED") == 0 || strcmp(s, "DEPROVISIONED") == 0 ? BUCKETS_IDSYNC_DISABLED
                                                                          : BUCKETS_IDSYNC_ACTIVE;
  } else if (status == 404) {
    const char *code = yyjson_get_str(yyjson_obj_get(root, "errorCode"));
    const char *sum = yyjson_get_str(yyjson_obj_get(root, "errorSummary"));
    if (code && strcmp(code, "E0000007") == 0 && sum && strstr(sum, "(User)")) st = BUCKETS_IDSYNC_GONE;
  }
  yyjson_doc_free(d);
  return st;
}

/* ---- planning ------------------------------------------------------------------------------- */

const char *buckets_idsync_action_name(buckets_idsync_action_kind k) {
  switch (k) {
    case BUCKETS_IDSYNC_REVOKE: return "revoke";
    case BUCKETS_IDSYNC_DISABLE: return "disable";
    case BUCKETS_IDSYNC_ENABLE: return "enable";
    case BUCKETS_IDSYNC_DELETE: return "delete";
    default: return "forget";
  }
}

static buckets_idsync_state state_of(const buckets_idsync_answers *a, const char *person) {
  for (size_t i = 0; a && i < a->n; i++)
    if (strcmp(a->people[i], person) == 0) return a->states[i];
  return BUCKETS_IDSYNC_UNKNOWN;
}

static const buckets_idsync_held *held_of(const buckets_idsync_held *h, size_t n, const char *access_key) {
  for (size_t i = 0; i < n; i++)
    if (strcmp(h[i].access_key, access_key) == 0) return &h[i];
  return NULL;
}

static bool leaving(buckets_idsync_state st) {
  return st == BUCKETS_IDSYNC_GONE || st == BUCKETS_IDSYNC_DISABLED;
}

static void add(buckets_idsync_plan *p, buckets_idsync_action_kind k, const char *access_key,
                const char *person) {
  p->actions = buckets_xrealloc(p->actions, (p->n + 1) * sizeof(*p->actions));
  p->actions[p->n++] = (buckets_idsync_action){k, access_key, person};
}

void buckets_idsync_plan_make(const buckets_idsync_cred *creds, size_t ncreds,
                              const buckets_idsync_answers *ans, const buckets_idsync_held *held,
                              size_t nheld, long long now, long long remove_after_s, long remove_max,
                              buckets_idsync_plan *out) {
  memset(out, 0, sizeof(*out));
  /* the people leaving with something still to take away: a temporary credential, or a key still on */
  const char **counted = buckets_xcalloc(ncreds + 1, sizeof(char *));
  for (size_t i = 0; i < ncreds; i++) {
    const buckets_idsync_cred *c = &creds[i];
    if (!leaving(state_of(ans, c->person))) continue;
    if (!c->sts && (!c->enabled || held_of(held, nheld, c->access_key))) continue;
    bool seen = false;
    for (size_t k = 0; k < out->people_leaving && !seen; k++) seen = strcmp(counted[k], c->person) == 0;
    if (!seen) counted[out->people_leaving++] = c->person;
  }
  free(counted);
  out->held = out->people_leaving > (size_t)remove_max;

  for (size_t i = 0; i < ncreds; i++) {
    const buckets_idsync_cred *c = &creds[i];
    buckets_idsync_state st = state_of(ans, c->person);
    const buckets_idsync_held *h = c->sts ? NULL : held_of(held, nheld, c->access_key);
    if (leaving(st)) {
      if (c->sts) {
        if (!out->held) add(out, BUCKETS_IDSYNC_REVOKE, c->access_key, c->person);
      } else if (h) {
        if (now - h->since >= remove_after_s) add(out, BUCKETS_IDSYNC_DELETE, c->access_key, c->person);
      } else if (c->enabled && !out->held) {
        add(out, BUCKETS_IDSYNC_DISABLE, c->access_key, c->person);
      }
    } else if (st == BUCKETS_IDSYNC_ACTIVE && h) {
      add(out, BUCKETS_IDSYNC_ENABLE, c->access_key, c->person);
    }
  }
  for (size_t k = 0; k < nheld; k++) {
    bool present = false;
    for (size_t i = 0; i < ncreds && !present; i++)
      present = !creds[i].sts && strcmp(creds[i].access_key, held[k].access_key) == 0;
    if (!present) add(out, BUCKETS_IDSYNC_FORGET, held[k].access_key, held[k].person);
  }
}

void buckets_idsync_plan_free(buckets_idsync_plan *p) {
  free(p->actions);
  memset(p, 0, sizeof(*p));
}

/* ---- what the sync turned off ------------------------------------------------------------------ */

bool buckets_idsync_held_parse(const char *json, size_t len, buckets_idsync_held **out, size_t *n) {
  *out = NULL;
  *n = 0;
  if (!json || !len) return true;
  yyjson_doc *d = yyjson_read(json, len, 0);
  yyjson_val *arr = yyjson_obj_get(yyjson_doc_get_root(d), "held");
  if (!d || (arr && !yyjson_is_arr(arr))) {
    yyjson_doc_free(d);
    return false;
  }
  size_t i, max;
  yyjson_val *v;
  *out = buckets_xcalloc(yyjson_arr_size(arr) + 1, sizeof(**out));
  yyjson_arr_foreach(arr, i, max, v) {
    const char *ak = yyjson_get_str(yyjson_obj_get(v, "accessKey")),
               *pe = yyjson_get_str(yyjson_obj_get(v, "person"));
    if (!ak || !pe) continue;
    (*out)[*n].access_key = buckets_xstrdup(ak);
    (*out)[*n].person = buckets_xstrdup(pe);
    (*out)[*n].since = yyjson_get_sint(yyjson_obj_get(v, "since"));
    (*n)++;
  }
  yyjson_doc_free(d);
  return true;
}

void buckets_idsync_held_json(const buckets_idsync_held *h, size_t n, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *arr = yyjson_mut_obj_add_arr(d, root, "held");
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "accessKey", h[i].access_key);
    yyjson_mut_obj_add_strcpy(d, o, "person", h[i].person);
    yyjson_mut_obj_add_sint(d, o, "since", h[i].since);
  }
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  if (j) buckets_buf_append(out, j, len);
  free(j);
  yyjson_mut_doc_free(d);
}

void buckets_idsync_held_free(buckets_idsync_held *h, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(h[i].access_key);
    free(h[i].person);
  }
  free(h);
}

/* ---- the provider's API ------------------------------------------------------------------------- */

typedef struct {
  char *principal, *value;
} role_grant;

struct buckets_idsync_client {
  buckets_idsync_settings s;
  pthread_mutex_t mu;
  char *token;
  long long token_until;
  /* Entra app roles: who holds which of the sign-in app's roles (users and groups), for a minute */
  role_grant *grants;
  size_t ngrants;
  bool group_grants;
  long long grants_until;
  char *kc_client; /* Keycloak: the sign-in client's ID (UUID), for its roles */
};

buckets_idsync_client *buckets_idsync_client_new(const buckets_idsync_settings *s) {
  buckets_idsync_client *c = buckets_xcalloc(1, sizeof(*c));
  c->s = *s;
  pthread_mutex_init(&c->mu, NULL);
  return c;
}

void buckets_idsync_client_free(buckets_idsync_client *c) {
  if (!c) return;
  memset(c->s.client_secret, 0, sizeof(c->s.client_secret));
  memset(c->s.api_token, 0, sizeof(c->s.api_token));
  free(c->token);
  for (size_t i = 0; i < c->ngrants; i++) {
    free(c->grants[i].principal);
    free(c->grants[i].value);
  }
  free(c->grants);
  free(c->kc_client);
  pthread_mutex_destroy(&c->mu);
  free(c);
}

static const char *provider_title(const buckets_idsync_settings *s) {
  return provider_is(s, "entra") ? "Microsoft Graph" : provider_is(s, "keycloak") ? "Keycloak" : "Okta";
}

/* An app-only token (client credentials): Entra's for Graph, or the Keycloak client's service account. Cached
 * until a minute before it expires. Okta's API token needs none. */
static bool client_token(buckets_idsync_client *c, bool fresh, char *err, size_t errlen) {
  if (provider_is(&c->s, "okta")) return true;
  long long now = (long long)time(NULL);
  if (!fresh && c->token && now < c->token_until) return true;
  buckets_buf url = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  if (provider_is(&c->s, "entra")) {
    buckets_buf_appendf(&url, "%s/", c->s.login_url);
    buckets_url_encode(&url, c->s.tenant, false);
    buckets_buf_append_c(&url, "/oauth2/v2.0/token");
    buckets_buf_append_c(&body,
                         "grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default");
  } else {
    buckets_buf_appendf(&url, "%s/realms/", c->s.url);
    buckets_url_encode(&url, c->s.realm, false);
    buckets_buf_append_c(&url, "/protocol/openid-connect/token");
    buckets_buf_append_c(&body, "grant_type=client_credentials");
  }
  buckets_buf_append_c(&body, "&client_id=");
  buckets_url_encode(&body, c->s.client_id, false);
  buckets_buf_append_c(&body, "&client_secret=");
  buckets_url_encode(&body, c->s.client_secret, false);
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result r;
  bool ok = buckets_fetch("POST", url.data, NULL, h, 1, body.data, body.len, 15000, &r, err, errlen);
  memset(body.data, 0, body.len);
  buckets_buf_free(&body);
  buckets_buf_free(&url);
  if (!ok) return false;
  yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
  yyjson_val *root = yyjson_doc_get_root(d);
  const char *tok = r.status == 200 ? yyjson_get_str(yyjson_obj_get(root, "access_token")) : NULL;
  long long exp = yyjson_get_sint(yyjson_obj_get(root, "expires_in"));
  if (tok) {
    free(c->token);
    c->token = buckets_xstrdup(tok);
    c->token_until = now + (exp > 120 ? exp - 60 : 60);
  } else {
    const char *why = yyjson_get_str(yyjson_obj_get(root, "error_description"));
    if (!why) why = yyjson_get_str(yyjson_obj_get(root, "error"));
    snprintf(err, errlen, "%s sign-in for the sync refused (%d): %.300s",
             provider_is(&c->s, "entra") ? "Microsoft" : "Keycloak", r.status, why ? why : "no access token");
  }
  yyjson_doc_free(d);
  buckets_http_result_free(&r);
  return tok != NULL;
}

static void fill_person(const buckets_idsync_settings *s, yyjson_val *u, buckets_idsync_person *who) {
  const char *id = yyjson_get_str(yyjson_obj_get(u, "id")), *name = NULL, *login = NULL;
  char full[256] = "";
  if (provider_is(s, "entra")) {
    name = yyjson_get_str(yyjson_obj_get(u, "displayName"));
    login = yyjson_get_str(yyjson_obj_get(u, "userPrincipalName"));
  } else {
    yyjson_val *src = provider_is(s, "okta") ? yyjson_obj_get(u, "profile") : u;
    const char *first = yyjson_get_str(yyjson_obj_get(src, "firstName")),
               *last = yyjson_get_str(yyjson_obj_get(src, "lastName"));
    snprintf(full, sizeof(full), "%s%s%s", first ? first : "", first && last ? " " : "", last ? last : "");
    name = full;
    login = yyjson_get_str(yyjson_obj_get(src, provider_is(s, "okta") ? "login" : "username"));
  }
  snprintf(who->id, sizeof(who->id), "%s", id ? id : "");
  snprintf(who->display_name, sizeof(who->display_name), "%s", name ? name : "");
  snprintf(who->upn, sizeof(who->upn), "%s", login ? login : "");
}

/* One GET of the provider's API as the sync; the status (0 when it cannot be reached) and the body in r. */
static bool client_get(buckets_idsync_client *c, const char *path_and_query, buckets_http_result *r,
                       char *err, size_t errlen) {
  buckets_buf url = BUCKETS_BUF_INIT, auth = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&url, "%s%s", provider_is(&c->s, "entra") ? c->s.graph_url : c->s.url, path_and_query);
  if (provider_is(&c->s, "okta"))
    buckets_buf_appendf(&auth, "SSWS %s", c->s.api_token);
  else
    buckets_buf_appendf(&auth, "Bearer %s", c->token);
  buckets_http_kv h[] = {{"Authorization", auth.data}, {"Accept", "application/json"}};
  bool ok = buckets_fetch("GET", url.data, NULL, h, 2, NULL, 0, 15000, r, err, errlen);
  memset(auth.data, 0, auth.len);
  buckets_buf_free(&url);
  buckets_buf_free(&auth);
  return ok;
}

static buckets_idsync_state state_from(const buckets_idsync_settings *s, int status, const char *body,
                                       size_t len) {
  if (provider_is(s, "entra")) return buckets_idsync_graph_state(status, body, len);
  if (provider_is(s, "keycloak")) return buckets_idsync_keycloak_state(status, body, len);
  return buckets_idsync_okta_state(status, body, len);
}

buckets_idsync_state buckets_idsync_client_lookup(buckets_idsync_client *c, const char *id,
                                                  buckets_idsync_person *who, char *err, size_t errlen) {
  if (who) memset(who, 0, sizeof(*who));
  buckets_idsync_state st = BUCKETS_IDSYNC_UNKNOWN;
  pthread_mutex_lock(&c->mu);
  for (int attempt = 0; attempt < 2; attempt++) {
    if (!client_token(c, attempt > 0, err, errlen)) break;
    buckets_buf path = BUCKETS_BUF_INIT;
    if (provider_is(&c->s, "entra")) {
      buckets_buf_append_c(&path, "/v1.0/users/");
      buckets_url_encode(&path, id, false);
      buckets_buf_append_c(&path, who ? "?$select=id,accountEnabled,displayName,userPrincipalName"
                                      : "?$select=id,accountEnabled");
    } else if (provider_is(&c->s, "keycloak")) {
      buckets_buf_append_c(&path, "/admin/realms/");
      buckets_url_encode(&path, c->s.realm, false);
      buckets_buf_append_c(&path, "/users/");
      buckets_url_encode(&path, id, false);
    } else {
      buckets_buf_append_c(&path, "/api/v1/users/"); /* an ID, or a login (the console's lookup) */
      buckets_url_encode(&path, id, false);
    }
    buckets_http_result r;
    bool ok = client_get(c, path.data, &r, err, errlen);
    buckets_buf_free(&path);
    if (!ok) break;
    int status = r.status;
    st = state_from(&c->s, status, r.body.data, r.body.len);
    yyjson_doc *d = status == 200 && who ? yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0) : NULL;
    if (d) fill_person(&c->s, yyjson_doc_get_root(d), who);
    yyjson_doc_free(d);
    if (st == BUCKETS_IDSYNC_GONE && who && provider_is(&c->s, "keycloak")) {
      /* the console's lookup may give a user name: Keycloak finds those by search */
      buckets_buf q = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&q, "/admin/realms/");
      buckets_url_encode(&q, c->s.realm, false);
      buckets_buf_append_c(&q, "/users?exact=true&username=");
      buckets_url_encode(&q, id, false);
      buckets_http_result sr;
      if (client_get(c, q.data, &sr, err, errlen)) {
        yyjson_doc *sd =
            sr.status == 200 ? yyjson_read(sr.body.data ? sr.body.data : "", sr.body.len, 0) : NULL;
        yyjson_val *u = yyjson_arr_get(yyjson_doc_get_root(sd), 0);
        if (u) {
          yyjson_val *en = yyjson_obj_get(u, "enabled");
          st = yyjson_get_bool(en) ? BUCKETS_IDSYNC_ACTIVE : BUCKETS_IDSYNC_DISABLED;
          fill_person(&c->s, u, who);
        }
        yyjson_doc_free(sd);
        buckets_http_result_free(&sr);
      }
      buckets_buf_free(&q);
    }
    if (st == BUCKETS_IDSYNC_UNKNOWN)
      snprintf(err, errlen, "%s answered %d for user %s: %.200s", provider_title(&c->s), status, id,
               r.body.data ? r.body.data : "");
    buckets_http_result_free(&r);
    if (status != 401 || provider_is(&c->s, "okta")) break; /* 401: the token went stale; once more */
  }
  pthread_mutex_unlock(&c->mu);
  return st;
}

/* ---- roles kept current (docs/design/roles-current.md) ----------------------------------------- */

typedef struct {
  char **v;
  size_t n;
} strs;

static void strs_add(strs *a, const char *v) {
  if (!v || !*v) return;
  for (size_t i = 0; i < a->n; i++)
    if (!strcmp(a->v[i], v)) return;
  a->v = buckets_xrealloc(a->v, (a->n + 1) * sizeof(*a->v));
  a->v[a->n++] = buckets_xstrdup(v);
}

static void strs_free(strs *a) {
  for (size_t i = 0; i < a->n; i++) free(a->v[i]);
  free(a->v);
  memset(a, 0, sizeof(*a));
}

void buckets_idsync_values_free(char **v, size_t n) {
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
}

/* Every page of a GET (Graph's @odata.nextLink followed); each page's root to fn. false (and err) on an error. */
static bool get_pages(buckets_idsync_client *c, const char *first, bool (*fn)(void *ud, yyjson_val *root), void *ud,
                      int *status, char *err, size_t errlen) {
  char *path = buckets_xstrdup(first);
  bool ok = true;
  for (int pages = 0; path && pages < 1000; pages++) {
    buckets_http_result r;
    if (!client_get(c, path, &r, err, errlen)) {
      ok = false;
      break;
    }
    *status = r.status;
    yyjson_doc *d = r.status == 200 ? yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0) : NULL;
    if (!d) {
      snprintf(err, errlen, "%s answered %d for %s: %.200s", provider_title(&c->s), r.status, path,
               r.body.data ? r.body.data : "");
      buckets_http_result_free(&r);
      ok = false;
      break;
    }
    ok = fn(ud, yyjson_doc_get_root(d));
    const char *next = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "@odata.nextLink"));
    free(path);
    path = NULL;
    size_t gl = strlen(c->s.graph_url);
    if (ok && next && provider_is(&c->s, "entra") && !strncmp(next, c->s.graph_url, gl)) path = buckets_xstrdup(next + gl);
    else if (ok && next && provider_is(&c->s, "entra") && !strncmp(next, "https://graph.microsoft.com", 27))
      path = buckets_xstrdup(next + 27);
    yyjson_doc_free(d);
    buckets_http_result_free(&r);
    if (!ok) break;
  }
  free(path);
  return ok;
}

typedef struct {
  strs *out;
  const char *key;      /* a field of each element ("id", "name", "path"), or NULL for Okta's profile.name */
  const char *odata;    /* only elements of this @odata.type, or NULL */
  role_grant **grants;  /* app role assignments: principal and role ID */
  size_t *ngrants;
  bool *groups;
} collect_ctx;

static yyjson_val *items_of(yyjson_val *root) { return yyjson_is_arr(root) ? root : yyjson_obj_get(root, "value"); }

static bool collect(void *ud, yyjson_val *root) {
  collect_ctx *x = ud;
  size_t i, n;
  yyjson_val *e;
  yyjson_arr_foreach(items_of(root), i, n, e) {
    if (x->odata && strcmp(yyjson_get_str(yyjson_obj_get(e, "@odata.type")) ? yyjson_get_str(yyjson_obj_get(e, "@odata.type")) : "", x->odata))
      continue;
    if (x->grants) { /* appRoleAssignedTo: principalId, principalType, appRoleId */
      const char *pid = yyjson_get_str(yyjson_obj_get(e, "principalId")), *rid = yyjson_get_str(yyjson_obj_get(e, "appRoleId"));
      const char *pt = yyjson_get_str(yyjson_obj_get(e, "principalType"));
      if (!pid || !rid) continue;
      *x->grants = buckets_xrealloc(*x->grants, (*x->ngrants + 1) * sizeof(**x->grants));
      (*x->grants)[(*x->ngrants)++] = (role_grant){buckets_xstrdup(pid), buckets_xstrdup(rid)};
      if (pt && !strcmp(pt, "Group")) *x->groups = true;
      continue;
    }
    const char *v = x->key ? yyjson_get_str(yyjson_obj_get(e, x->key))
                           : yyjson_get_str(yyjson_obj_get(yyjson_obj_get(e, "profile"), "name"));
    strs_add(x->out, v);
  }
  return true;
}

/* Entra: the sign-in app's roles and who holds them, refreshed after a minute. */
static bool entra_grants(buckets_idsync_client *c, int *status, char *err, size_t errlen) {
  long long now = (long long)time(NULL);
  if (c->grants_until > now) return true;
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&p, "/v1.0/servicePrincipals(appId='");
  buckets_url_encode(&p, c->s.app_id, false);
  buckets_buf_append_c(&p, "')?$select=id,appRoles");
  buckets_http_result r;
  bool ok = client_get(c, p.data, &r, err, errlen);
  buckets_buf_free(&p);
  if (!ok) return false;
  *status = r.status;
  yyjson_doc *d = r.status == 200 ? yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0) : NULL;
  if (!d) {
    snprintf(err, errlen, "Microsoft Graph answered %d for the sign-in app %s (needs Application.Read.All): %.200s", r.status,
             c->s.app_id, r.body.data ? r.body.data : "");
    buckets_http_result_free(&r);
    return false;
  }
  yyjson_val *sp = yyjson_doc_get_root(d);
  char spid[64];
  snprintf(spid, sizeof(spid), "%s", yyjson_get_str(yyjson_obj_get(sp, "id")) ? yyjson_get_str(yyjson_obj_get(sp, "id")) : "");
  /* role IDs to values */
  strs ids = {0}, vals = {0};
  size_t i, n;
  yyjson_val *ar;
  yyjson_arr_foreach(yyjson_obj_get(sp, "appRoles"), i, n, ar) {
    const char *id = yyjson_get_str(yyjson_obj_get(ar, "id")), *v = yyjson_get_str(yyjson_obj_get(ar, "value"));
    if (!id || !v || !*v || !yyjson_get_bool(yyjson_obj_get(ar, "isEnabled"))) continue;
    ids.v = buckets_xrealloc(ids.v, (ids.n + 1) * sizeof(char *));
    ids.v[ids.n++] = buckets_xstrdup(id);
    vals.v = buckets_xrealloc(vals.v, (vals.n + 1) * sizeof(char *));
    vals.v[vals.n++] = buckets_xstrdup(v);
  }
  yyjson_doc_free(d);
  buckets_http_result_free(&r);
  role_grant *g = NULL;
  size_t ng = 0;
  bool groups = false;
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&q, "/v1.0/servicePrincipals/");
  buckets_url_encode(&q, spid, false);
  buckets_buf_append_c(&q, "/appRoleAssignedTo?$select=principalId,principalType,appRoleId&$top=999");
  collect_ctx x = {.grants = &g, .ngrants = &ng, .groups = &groups};
  ok = get_pages(c, q.data, collect, &x, status, err, errlen);
  buckets_buf_free(&q);
  if (ok) { /* role IDs become their values; the default access (no value) drops out */
    size_t k = 0;
    for (size_t j = 0; j < ng; j++) {
      const char *val = NULL;
      for (size_t m = 0; m < ids.n && !val; m++)
        if (!strcmp(ids.v[m], g[j].value)) val = vals.v[m];
      if (!val) {
        free(g[j].principal);
        free(g[j].value);
        continue;
      }
      free(g[j].value);
      g[k] = (role_grant){g[j].principal, buckets_xstrdup(val)};
      k++;
    }
    ng = k;
    for (size_t j = 0; j < c->ngrants; j++) {
      free(c->grants[j].principal);
      free(c->grants[j].value);
    }
    free(c->grants);
    c->grants = g;
    c->ngrants = ng;
    c->group_grants = groups;
    c->grants_until = now + 60;
  } else {
    for (size_t j = 0; j < ng; j++) {
      free(g[j].principal);
      free(g[j].value);
    }
    free(g);
  }
  strs_free(&ids);
  strs_free(&vals);
  return ok;
}

static bool values_once(buckets_idsync_client *c, const char *id, strs *out, int *status, char *err, size_t errlen) {
  buckets_buf p = BUCKETS_BUF_INIT;
  collect_ctx x = {.out = out};
  bool ok = false;
  const char *from = c->s.roles_from;
  if (provider_is(&c->s, "entra") && !strcmp(from, "groups")) {
    buckets_buf_append_c(&p, "/v1.0/users/");
    buckets_url_encode(&p, id, false);
    buckets_buf_append_c(&p, "/transitiveMemberOf?$select=id&$top=999");
    x.key = "id";
    x.odata = "#microsoft.graph.group";
    ok = get_pages(c, p.data, collect, &x, status, err, errlen);
  } else if (provider_is(&c->s, "entra")) { /* app roles: their own, and their direct groups' */
    ok = entra_grants(c, status, err, errlen);
    for (size_t i = 0; ok && i < c->ngrants; i++)
      if (!strcmp(c->grants[i].principal, id)) strs_add(out, c->grants[i].value);
    if (ok && c->group_grants) {
      strs groups = {0};
      buckets_buf_append_c(&p, "/v1.0/users/");
      buckets_url_encode(&p, id, false);
      buckets_buf_append_c(&p, "/memberOf?$select=id&$top=999");
      collect_ctx gx = {.out = &groups, .key = "id", .odata = "#microsoft.graph.group"};
      ok = get_pages(c, p.data, collect, &gx, status, err, errlen);
      for (size_t g = 0; ok && g < groups.n; g++)
        for (size_t i = 0; i < c->ngrants; i++)
          if (!strcmp(c->grants[i].principal, groups.v[g])) strs_add(out, c->grants[i].value);
      strs_free(&groups);
    }
  } else if (provider_is(&c->s, "okta")) {
    buckets_buf_append_c(&p, "/api/v1/users/");
    buckets_url_encode(&p, id, false);
    buckets_buf_append_c(&p, "/groups");
    ok = get_pages(c, p.data, collect, &x, status, err, errlen);
  } else if (provider_is(&c->s, "keycloak")) {
    buckets_buf base = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&base, "/admin/realms/");
    buckets_url_encode(&base, c->s.realm, false);
    buckets_buf_append_c(&base, "/users/");
    buckets_url_encode(&base, id, false);
    if (!strcmp(from, "groups")) {
      buckets_buf_appendf(&p, "%s/groups?briefRepresentation=true", base.data);
      x.key = "path"; /* the group membership mapper's "full group path", Keycloak's default */
      ok = get_pages(c, p.data, collect, &x, status, err, errlen);
    } else if (!strcmp(from, "client-roles")) {
      if (!c->kc_client) { /* the sign-in client's ID (UUID) */
        buckets_buf q = BUCKETS_BUF_INIT;
        buckets_buf_append_c(&q, "/admin/realms/");
        buckets_url_encode(&q, c->s.realm, false);
        buckets_buf_append_c(&q, "/clients?clientId=");
        buckets_url_encode(&q, c->s.app_id, false);
        strs uuid = {0};
        collect_ctx ux = {.out = &uuid, .key = "id"};
        ok = get_pages(c, q.data, collect, &ux, status, err, errlen);
        if (ok && uuid.n) c->kc_client = buckets_xstrdup(uuid.v[0]);
        else if (ok) {
          snprintf(err, errlen, "Keycloak has no client %s in realm %s", c->s.app_id, c->s.realm);
          ok = false;
        }
        strs_free(&uuid);
        buckets_buf_free(&q);
        if (!ok) {
          buckets_buf_free(&base);
          buckets_buf_free(&p);
          return false;
        }
      }
      buckets_buf_appendf(&p, "%s/role-mappings/clients/", base.data);
      buckets_url_encode(&p, c->kc_client, false);
      buckets_buf_append_c(&p, "/composite");
      x.key = "name";
      ok = get_pages(c, p.data, collect, &x, status, err, errlen);
    } else {
      buckets_buf_appendf(&p, "%s/role-mappings/realm/composite", base.data);
      x.key = "name";
      ok = get_pages(c, p.data, collect, &x, status, err, errlen);
    }
    buckets_buf_free(&base);
  } else {
    snprintf(err, errlen, "no roles to ask %s for", c->s.provider);
  }
  buckets_buf_free(&p);
  return ok;
}

static int cmp_strp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

void buckets_idsync_client_begin(buckets_idsync_client *c) {
  pthread_mutex_lock(&c->mu);
  c->grants_until = 0;
  pthread_mutex_unlock(&c->mu);
}

bool buckets_idsync_client_values(buckets_idsync_client *c, const char *id, char ***values, size_t *n, char *err,
                                  size_t errlen) {
  *values = NULL;
  *n = 0;
  strs out = {0};
  bool ok = false;
  pthread_mutex_lock(&c->mu);
  for (int attempt = 0; attempt < 2; attempt++) {
    strs_free(&out);
    int status = 0;
    if (!client_token(c, attempt > 0, err, errlen)) break;
    ok = values_once(c, id, &out, &status, err, errlen);
    if (ok || status != 401 || provider_is(&c->s, "okta")) break; /* 401: a stale token; once more */
    c->grants_until = 0;
  }
  pthread_mutex_unlock(&c->mu);
  if (!ok) {
    strs_free(&out);
    return false;
  }
  if (out.n) qsort(out.v, out.n, sizeof(char *), cmp_strp);
  *values = out.v;
  *n = out.n;
  return true;
}

/* ---- which role changes go ahead --------------------------------------------------------------- */

static bool csv_has(const char *csv, const char *v, size_t vl) {
  for (const char *p = csv; p && *p;) {
    const char *e = strchr(p, ',');
    size_t l = e ? (size_t)(e - p) : strlen(p);
    if (l == vl && !strncmp(p, v, vl)) return true;
    p = e ? e + 1 : NULL;
  }
  return false;
}

/* Whether every value of a is in b. */
static bool csv_within(const char *a, const char *b) {
  for (const char *p = a; p && *p;) {
    const char *e = strchr(p, ',');
    size_t l = e ? (size_t)(e - p) : strlen(p);
    if (l && !csv_has(b, p, l)) return false;
    p = e ? e + 1 : NULL;
  }
  return true;
}

bool buckets_idsync_csv_same(const char *a, const char *b) { return csv_within(a, b) && csv_within(b, a); }

bool buckets_idsync_roles_decide(buckets_idsync_role_change *ch, size_t n, long remove_max) {
  size_t removing = 0;
  for (size_t i = 0; i < n; i++) {
    ch[i].removes = !csv_within(ch[i].old_csv, ch[i].new_csv);
    ch[i].apply = !buckets_idsync_csv_same(ch[i].old_csv, ch[i].new_csv);
    if (ch[i].apply && ch[i].removes) removing++;
  }
  bool held = removing > (size_t)remove_max;
  for (size_t i = 0; held && i < n; i++)
    if (ch[i].removes) ch[i].apply = false; /* additions still go ahead */
  return held;
}
