/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/idpsettings.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static bool is_hex64(const char *v) {
  size_t n = 0;
  for (; v[n]; n++)
    if (!((v[n] >= '0' && v[n] <= '9') || (v[n] >= 'a' && v[n] <= 'f'))) return false;
  return n == 64;
}

const char *const buckets_idp_secret_fields[] = {"openid.clientSecret", "openid.removal.apiToken",
                                                 "ldap.lookupBindPassword", NULL};

/* settings["a.b"], or NULL */
static yyjson_val *at(yyjson_val *o, const char *path) {
  char key[64];
  while (o && *path) {
    const char *dot = strchr(path, '.');
    size_t n = dot ? (size_t)(dot - path) : strlen(path);
    snprintf(key, sizeof(key), "%.*s", (int)n, path);
    o = yyjson_obj_get(o, key);
    path = dot ? dot + 1 : path + n;
  }
  return o;
}

static const char *str(yyjson_val *o, const char *path) {
  const char *s = yyjson_get_str(at(o, path));
  return s ? s : "";
}

static bool flag(yyjson_val *o, const char *path) { return yyjson_get_bool(at(o, path)); }

static bool fail(char *err, size_t errlen, const char *msg) {
  snprintf(err, errlen, "%s", msg);
  return false;
}

static bool is_url(const char *s) { return strncmp(s, "https://", 8) == 0 || strncmp(s, "http://", 7) == 0; }

static bool has_space(const char *s) {
  for (; *s; s++)
    if (isspace((unsigned char)*s)) return true;
  return false;
}

/* ---- providers -------------------------------------------------------------------- */

typedef struct {
  const char *name, *label, *claim, *scopes;
} provider_def;

static const provider_def k_providers[] = {
    {"entra", "Microsoft Entra ID", "roles", "openid profile email"},
    {"okta", "Okta", "groups", "openid profile email groups"},
    {"keycloak", "Keycloak", "roles", "openid profile email"},
    {"generic", "OpenID", "policy", "openid profile email"},
};

static const provider_def *provider_of(yyjson_val *s) {
  const char *p = str(s, "openid.provider");
  for (size_t i = 0; i < sizeof(k_providers) / sizeof(k_providers[0]); i++)
    if (strcmp(p, k_providers[i].name) == 0) return &k_providers[i];
  return NULL;
}

/* "https://example.okta.com/" -> "example.okta.com" */
static void host_only(const char *in, char *out, size_t cap) {
  if (strncmp(in, "https://", 8) == 0) in += 8;
  else if (strncmp(in, "http://", 7) == 0) in += 7;
  snprintf(out, cap, "%s", in);
  size_t n = strlen(out);
  while (n && out[n - 1] == '/') out[--n] = '\0';
}

void buckets_idp_config_url(yyjson_val *s, char *out, size_t cap) {
  *out = '\0';
  const provider_def *p = provider_of(s);
  if (!p) return;
  if (strcmp(p->name, "entra") == 0) {
    snprintf(out, cap, "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", str(s, "openid.tenantId"));
  } else if (strcmp(p->name, "okta") == 0) {
    char host[256];
    host_only(str(s, "openid.domain"), host, sizeof(host));
    const char *as = str(s, "openid.authServer");
    snprintf(out, cap, "https://%s/oauth2/%s/.well-known/openid-configuration", host, *as ? as : "default");
  } else if (strcmp(p->name, "keycloak") == 0) {
    char base[512];
    snprintf(base, sizeof(base), "%s", str(s, "openid.url"));
    size_t n = strlen(base);
    while (n && base[n - 1] == '/') base[--n] = '\0';
    snprintf(out, cap, "%s/realms/%s/.well-known/openid-configuration", base, str(s, "openid.realm"));
  } else {
    snprintf(out, cap, "%s", str(s, "openid.configUrl"));
  }
}

static const char *claim_of(yyjson_val *s, const provider_def *p) {
  const char *c = str(s, "openid.claimName");
  return *c ? c : p->claim;
}

/* scopes as given (space or comma separated), else the provider's, joined by sep */
static void scopes_of(yyjson_val *s, const provider_def *p, char sep, char *out, size_t cap) {
  const char *in = str(s, "openid.scopes");
  if (!*in) in = p->scopes;
  size_t o = 0;
  bool need_sep = false;
  for (const char *c = in; *c && o + 2 < cap; c++) {
    if (*c == ',' || isspace((unsigned char)*c)) {
      need_sep = o > 0;
      continue;
    }
    if (need_sep) out[o++] = sep, need_sep = false;
    out[o++] = *c;
  }
  out[o] = '\0';
}

static const char *label_of(yyjson_val *s, const provider_def *p) {
  const char *l = str(s, "openid.displayName");
  return *l ? l : p->label;
}

/* ---- LDAP presets ------------------------------------------------------------------ */

typedef struct {
  const char *name, *label, *user_filter, *group_filter;
} ldap_preset;

static const ldap_preset k_ldap[] = {
    {"ad", "Active Directory", "(&(objectCategory=user)(sAMAccountName=%s))", "(&(objectClass=group)(member=%d))"},
    {"openldap", "LDAP", "(&(objectClass=inetOrgPerson)(uid=%s))", "(&(objectClass=groupOfNames)(member=%d))"},
    {"custom", "LDAP", "", ""},
};

static const ldap_preset *ldap_preset_of(yyjson_val *s) {
  const char *p = str(s, "ldap.preset");
  for (size_t i = 0; i < sizeof(k_ldap) / sizeof(k_ldap[0]); i++)
    if (strcmp(p, k_ldap[i].name) == 0) return &k_ldap[i];
  return &k_ldap[2];
}

static const char *ldap_user_filter(yyjson_val *s) {
  const char *f = str(s, "ldap.userSearchFilter");
  return *f ? f : ldap_preset_of(s)->user_filter;
}

/* The group filter applies only with a group search base. */
static const char *ldap_group_filter(yyjson_val *s) {
  if (!*str(s, "ldap.groupSearchBase")) return "";
  const char *f = str(s, "ldap.groupSearchFilter");
  return *f ? f : ldap_preset_of(s)->group_filter;
}

static const char *ldap_tls(yyjson_val *s) {
  const char *t = str(s, "ldap.tls");
  return *t ? t : "ldaps";
}

/* ---- checks ------------------------------------------------------------------------- */

static bool check_openid(yyjson_val *s, char *err, size_t errlen) {
  const provider_def *p = provider_of(s);
  if (!p) return fail(err, errlen, "Choose an identity provider: Microsoft Entra ID, Okta, Keycloak or another OpenID provider.");
  if (strcmp(p->name, "entra") == 0) {
    const char *t = str(s, "openid.tenantId");
    if (!*t || strchr(t, '/') || has_space(t))
      return fail(err, errlen, "Enter the directory (tenant) ID from the app registration's Overview page.");
  } else if (strcmp(p->name, "okta") == 0) {
    char host[256];
    host_only(str(s, "openid.domain"), host, sizeof(host));
    if (!*host || strchr(host, '/') || has_space(host))
      return fail(err, errlen, "Enter your Okta domain, for example example.okta.com.");
    const char *as = str(s, "openid.authServer");
    if (strchr(as, '/') || has_space(as))
      return fail(err, errlen, "The authorization server is an ID such as \"default\", not a URL.");
  } else if (strcmp(p->name, "keycloak") == 0) {
    const char *u = str(s, "openid.url"), *r = str(s, "openid.realm");
    if (!is_url(u)) return fail(err, errlen, "Enter Keycloak's base URL, for example https://keycloak.example.com.");
    if (!*r || strchr(r, '/') || has_space(r)) return fail(err, errlen, "Enter the Keycloak realm's name.");
  } else if (!is_url(str(s, "openid.configUrl"))) {
    return fail(err, errlen,
                "Enter the provider's discovery URL (it ends in /.well-known/openid-configuration).");
  }
  if (!*str(s, "openid.clientId")) return fail(err, errlen, "Enter the application's client ID.");
  if (!*str(s, "openid.clientSecret"))
    return fail(err, errlen, "Enter the application's client secret: the console signs people in as a confidential client.");
  const char *rp = str(s, "openid.rolePolicy");
  if (!*rp && has_space(claim_of(s, p))) return fail(err, errlen, "The claim name cannot contain spaces.");
  if (flag(s, "openid.removal.enabled")) {
    if (strcmp(p->name, "generic") == 0)
      return fail(err, errlen, "Removing people who leave works with Entra ID, Okta and Keycloak.");
    const char *method = str(s, "openid.removal.method");
    if (*method && strcmp(method, "api") && strcmp(method, "scim") && strcmp(method, "both"))
      return fail(err, errlen, "Learn who left by asking the provider, by SCIM, or both.");
    bool scim = !strcmp(method, "scim") || !strcmp(method, "both"), api = strcmp(method, "scim") != 0;
    if (scim && strcmp(p->name, "keycloak") == 0)
      return fail(err, errlen, "Keycloak has no SCIM client: ask Keycloak who has left instead.");
    if (scim && !is_hex64(str(s, "openid.removal.scimTokenSha256")))
      return fail(err, errlen, "Make a SCIM token first.");
    if (*str(s, "openid.removal.scimPreviousSha256") && !is_hex64(str(s, "openid.removal.scimPreviousSha256")))
      return fail(err, errlen, "The previous SCIM token's hash is not a SHA-256.");
    if (api && strcmp(p->name, "okta") == 0 && !*str(s, "openid.removal.apiToken"))
      return fail(err, errlen, "Enter an Okta API token for checking who has left.");
    yyjson_val *days = at(s, "openid.removal.deleteAfterDays"), *max = at(s, "openid.removal.maxPerSync");
    if (days && (!yyjson_is_int(days) || yyjson_get_sint(days) < 1 || yyjson_get_sint(days) > 3650))
      return fail(err, errlen, "Delete the access keys of people who left after 1 to 3650 days.");
    if (max && (!yyjson_is_int(max) || yyjson_get_sint(max) < 1 || yyjson_get_sint(max) > 100000))
      return fail(err, errlen, "The most people removed in one sync is a number from 1.");
    yyjson_val *every = at(s, "openid.removal.intervalMinutes");
    if (every && (!yyjson_is_int(every) || yyjson_get_sint(every) < 1 || yyjson_get_sint(every) > 1440))
      return fail(err, errlen, "Check every 1 to 1440 minutes.");
    const char *from = str(s, "openid.removal.rolesFrom");
    if (flag(s, "openid.removal.roles") && *rp)
      return fail(err, errlen, "Roles are kept current from the provider's claim, and a role policy gives no claim.");
    static const char *const ok_from[][2] = {{"entra", "app-roles"},       {"entra", "groups"},
                                             {"keycloak", "realm-roles"},  {"keycloak", "client-roles"},
                                             {"keycloak", "groups"},       {"okta", "groups"}};
    bool known = !*from || (scim && !api && strcmp(from, "groups") == 0);
    for (size_t i = 0; i < sizeof(ok_from) / sizeof(ok_from[0]); i++)
      known |= strcmp(p->name, ok_from[i][0]) == 0 && strcmp(from, ok_from[i][1]) == 0;
    if (!known) return fail(err, errlen, "Roles come from app roles or groups (Entra ID), groups (Okta), or realm roles, client roles or groups (Keycloak).");
  }
  const char *ru = str(s, "openid.redirectUri");
  if (*ru) {
    size_t n = strlen(ru), m = strlen("/oauth_callback");
    if (!is_url(ru) || n < m || strcmp(ru + n - m, "/oauth_callback") != 0)
      return fail(err, errlen, "The redirect URI is the console's address followed by /oauth_callback.");
  }
  return true;
}

static bool check_ldap(yyjson_val *s, char *err, size_t errlen) {
  const char *a = str(s, "ldap.serverAddr");
  if (!*a || strstr(a, "://") || has_space(a))
    return fail(err, errlen, "Enter the directory server as host or host:port, for example ldap.example.com:636.");
  const char *t = ldap_tls(s);
  if (strcmp(t, "ldaps") != 0 && strcmp(t, "starttls") != 0 && strcmp(t, "plain") != 0)
    return fail(err, errlen, "Choose how to connect: LDAPS, StartTLS or plain LDAP.");
  if (!*str(s, "ldap.lookupBindDn") || !*str(s, "ldap.lookupBindPassword"))
    return fail(err, errlen, "Enter the read-only service account's DN and password, used to look up users and groups.");
  if (!*str(s, "ldap.userSearchBase")) return fail(err, errlen, "Enter the base DN to search for users.");
  const char *uf = ldap_user_filter(s);
  if (!strstr(uf, "%s")) return fail(err, errlen, "The user search filter must contain %s, where the user name goes.");
  if (*str(s, "ldap.groupSearchBase")) {
    const char *gf = ldap_group_filter(s);
    if (!strstr(gf, "%d") && !strstr(gf, "%s"))
      return fail(err, errlen, "The group search filter must contain %d (the user's DN) or %s (the user name).");
  }
  return true;
}

/* A value goes into `config set` text in double quotes. */
static bool quotable(yyjson_val *s, char *err, size_t errlen) {
  static const char *const fields[] = {"openid.displayName", "openid.clientId", "openid.clientSecret", "openid.claimName",
                                       "openid.scopes", "openid.rolePolicy", "openid.configUrl", "openid.tenantId",
                                       "openid.domain", "openid.url", "openid.realm", "ldap.serverAddr", "ldap.lookupBindDn",
                                       "ldap.lookupBindPassword", "ldap.userSearchBase", "ldap.userSearchFilter",
                                       "ldap.groupSearchBase", "ldap.groupSearchFilter", NULL};
  for (const char *const *f = fields; *f; f++) {
    const char *v = str(s, *f);
    if (strchr(v, '"') || strchr(v, '\n') || strchr(v, '\r')) {
      snprintf(err, errlen, "%s cannot contain double quotes or line breaks.", strchr(*f, '.') + 1);
      return false;
    }
  }
  return true;
}

bool buckets_idp_check(yyjson_val *s, char *err, size_t errlen) {
  if (!yyjson_is_obj(s)) return fail(err, errlen, "The settings are not a JSON object.");
  yyjson_val *o = yyjson_obj_get(s, "openid"), *l = yyjson_obj_get(s, "ldap");
  if (o && !yyjson_is_null(o) && !check_openid(s, err, errlen)) return false;
  if (l && !yyjson_is_null(l) && !check_ldap(s, err, errlen)) return false;
  return quotable(s, err, errlen);
}

static bool has(yyjson_val *s, const char *part) {
  yyjson_val *v = yyjson_obj_get(s, part);
  return v && yyjson_is_obj(v);
}

/* ---- renderings --------------------------------------------------------------------- */

static void kv(buckets_buf *b, const char *k, const char *v) { buckets_buf_appendf(b, " %s=\"%s\"", k, v); }

bool buckets_idp_server_config(yyjson_val *s, buckets_buf *out, char *err, size_t errlen) {
  if (!buckets_idp_check(s, err, errlen)) return false;
  if (has(s, "openid")) {
    const provider_def *p = provider_of(s);
    char url[1024], scopes[512];
    buckets_idp_config_url(s, url, sizeof(url));
    scopes_of(s, p, ',', scopes, sizeof(scopes));
    buckets_buf_append_c(out, "identity_openid");
    kv(out, "enable", "on");
    kv(out, "display_name", label_of(s, p));
    kv(out, "config_url", url);
    kv(out, "client_id", str(s, "openid.clientId"));
    kv(out, "client_secret", str(s, "openid.clientSecret"));
    if (*str(s, "openid.rolePolicy")) kv(out, "role_policy", str(s, "openid.rolePolicy"));
    else kv(out, "claim_name", claim_of(s, p));
    kv(out, "scopes", scopes);
    if (flag(s, "openid.claimUserinfo")) kv(out, "claim_userinfo", "on");
    buckets_buf_append_char(out, '\n');
  } else {
    buckets_buf_append_c(out, "identity_openid enable=\"off\"\n");
  }
  if (has(s, "ldap")) {
    const char *t = ldap_tls(s);
    buckets_buf_append_c(out, "identity_ldap");
    kv(out, "enable", "on");
    kv(out, "server_addr", str(s, "ldap.serverAddr"));
    kv(out, "lookup_bind_dn", str(s, "ldap.lookupBindDn"));
    kv(out, "lookup_bind_password", str(s, "ldap.lookupBindPassword"));
    kv(out, "user_dn_search_base_dn", str(s, "ldap.userSearchBase"));
    kv(out, "user_dn_search_filter", ldap_user_filter(s));
    if (*str(s, "ldap.groupSearchBase")) {
      kv(out, "group_search_base_dn", str(s, "ldap.groupSearchBase"));
      kv(out, "group_search_filter", ldap_group_filter(s));
    }
    kv(out, "server_starttls", strcmp(t, "starttls") == 0 ? "on" : "off");
    kv(out, "server_insecure", strcmp(t, "plain") == 0 ? "on" : "off");
    kv(out, "tls_skip_verify", flag(s, "ldap.skipVerify") ? "on" : "off");
    buckets_buf_append_char(out, '\n');
  } else {
    buckets_buf_append_c(out, "identity_ldap enable=\"off\"\n");
  }
  return true;
}

yyjson_mut_val *buckets_idp_console_view(yyjson_mut_doc *d, yyjson_val *s) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  const provider_def *p = provider_of(s);
  if (has(s, "openid") && p) {
    char url[1024], scopes[512];
    buckets_idp_config_url(s, url, sizeof(url));
    scopes_of(s, p, ' ', scopes, sizeof(scopes));
    yyjson_mut_val *c = yyjson_mut_obj_add_obj(d, o, "oidc");
    yyjson_mut_obj_add_strcpy(d, c, "configUrl", url);
    yyjson_mut_obj_add_strcpy(d, c, "clientId", str(s, "openid.clientId"));
    yyjson_mut_obj_add_strcpy(d, c, "clientSecret", str(s, "openid.clientSecret"));
    yyjson_mut_obj_add_strcpy(d, c, "scopes", scopes);
    yyjson_mut_obj_add_strcpy(d, c, "displayName", label_of(s, p));
    yyjson_mut_obj_add_strcpy(d, c, "redirectUri", str(s, "openid.redirectUri"));
  } else {
    yyjson_mut_obj_add_null(d, o, "oidc");
  }
  if (has(s, "ldap")) {
    yyjson_mut_val *l = yyjson_mut_obj_add_obj(d, o, "ldap");
    yyjson_mut_obj_add_str(d, l, "displayName", ldap_preset_of(s)->label);
  } else {
    yyjson_mut_obj_add_null(d, o, "ldap");
  }
  return o;
}

/* ---- secrets ------------------------------------------------------------------------ */

/* The object holding a field ("openid.removal.apiToken": settings.openid.removal), and its last key. */
static yyjson_mut_val *mut_part(yyjson_mut_val *o, const char *field, const char **leaf) {
  const char *last = strrchr(field, '.');
  *leaf = last + 1;
  for (const char *p = field; o && p < last;) {
    const char *dot = strchr(p, '.');
    char key[32];
    snprintf(key, sizeof(key), "%.*s", (int)(dot - p), p);
    o = yyjson_mut_obj_get(o, key);
    p = dot + 1;
  }
  return yyjson_mut_is_obj(o) ? o : NULL;
}

yyjson_mut_val *buckets_idp_settings_redacted(yyjson_mut_doc *d, yyjson_val *settings) {
  yyjson_mut_val *c = yyjson_val_mut_copy(d, settings);
  if (!yyjson_mut_is_obj(c)) c = yyjson_mut_obj(d);
  yyjson_mut_val *set = yyjson_mut_arr(d);
  for (const char *const *f = buckets_idp_secret_fields; *f; f++) {
    const char *leaf;
    yyjson_mut_val *part = mut_part(c, *f, &leaf);
    if (!part) continue;
    const char *v = yyjson_mut_get_str(yyjson_mut_obj_get(part, leaf));
    if (!v || !*v) continue;
    yyjson_mut_obj_remove_key(part, leaf);
    yyjson_mut_obj_add_str(d, part, leaf, "");
    yyjson_mut_arr_add_str(d, set, *f);
  }
  yyjson_mut_obj_remove_key(c, "secretsSet");
  yyjson_mut_obj_add_val(d, c, "secretsSet", set);
  return c;
}

/* The same provider (openid) or the same directory server (ldap): a secret
 * saved for one is never handed to another. */
static bool same_source(yyjson_mut_val *now, yyjson_val *saved, const char *field) {
  bool ldap = strncmp(field, "ldap.", 5) == 0;
  const char *k = ldap ? "serverAddr" : "provider";
  yyjson_mut_val *np = yyjson_mut_obj_get(now, ldap ? "ldap" : "openid");
  const char *a = yyjson_mut_get_str(yyjson_mut_obj_get(np, k));
  const char *b = str(saved, ldap ? "ldap.serverAddr" : "openid.provider");
  return a && *a && strcmp(a, b) == 0;
}

void buckets_idp_settings_keep_secrets(yyjson_mut_doc *d, yyjson_mut_val *settings, yyjson_val *saved) {
  for (const char *const *f = buckets_idp_secret_fields; *f; f++) {
    const char *old = str(saved, *f);
    if (!*old || !same_source(settings, saved, *f)) continue;
    const char *leaf;
    yyjson_mut_val *part = mut_part(settings, *f, &leaf);
    if (!part) continue;
    const char *now = yyjson_mut_get_str(yyjson_mut_obj_get(part, leaf));
    if (now && *now) continue;
    yyjson_mut_obj_remove_key(part, leaf);
    yyjson_mut_obj_add_strcpy(d, part, leaf, old);
  }
  yyjson_mut_obj_remove_key(settings, "secretsSet");
}

bool buckets_idp_removal_of(yyjson_val *s, buckets_idp_removal *out) {
  memset(out, 0, sizeof(*out));
  const provider_def *p = provider_of(s);
  if (!has(s, "openid") || !p || strcmp(p->name, "generic") == 0 || !flag(s, "openid.removal.enabled")) return false;
  out->provider = p->name;
  out->tenant = str(s, "openid.tenantId");
  out->client_id = str(s, "openid.clientId");
  out->client_secret = str(s, "openid.clientSecret");
  out->api_token = str(s, "openid.removal.apiToken");
  const char *method = str(s, "openid.removal.method");
  out->scim = !strcmp(method, "scim") || !strcmp(method, "both");
  out->api = strcmp(method, "scim") != 0;
  snprintf(out->scim_sha256, sizeof(out->scim_sha256), "%s", str(s, "openid.removal.scimTokenSha256"));
  snprintf(out->scim_previous, sizeof(out->scim_previous), "%s", str(s, "openid.removal.scimPreviousSha256"));
  out->realm = str(s, "openid.realm");
  /* the issuer the tokens carry: the discovery URL without its /.well-known part */
  char cfg[600];
  buckets_idp_config_url(s, cfg, sizeof(cfg));
  char *wk = strstr(cfg, "/.well-known/");
  if (wk) *wk = '\0';
  if (strcmp(p->name, "keycloak") == 0) {
    snprintf(out->url, sizeof(out->url), "%s", str(s, "openid.url"));
    size_t n = strlen(out->url);
    while (n && out->url[n - 1] == '/') out->url[--n] = '\0';
  } else if (strcmp(p->name, "okta") == 0) {
    char host[256];
    host_only(str(s, "openid.domain"), host, sizeof(host));
    snprintf(out->url, sizeof(out->url), "https://%s", host);
  }
  if (strcmp(p->name, "entra") != 0) snprintf(out->issuer, sizeof(out->issuer), "%s", cfg);
  yyjson_val *days = at(s, "openid.removal.deleteAfterDays"), *max = at(s, "openid.removal.maxPerSync");
  out->delete_after_days = yyjson_is_int(days) ? (long)yyjson_get_sint(days) : 30;
  out->max_per_sync = yyjson_is_int(max) ? (long)yyjson_get_sint(max) : 10;
  yyjson_val *every = at(s, "openid.removal.intervalMinutes");
  out->interval_minutes = yyjson_is_int(every) ? (long)yyjson_get_sint(every) : 60;
  /* roles kept current: off unless set, so settings saved before keep what they did; read as the claim is */
  out->roles = flag(s, "openid.removal.roles");
  const char *from = str(s, "openid.removal.rolesFrom");
  if (!*from) {
    const char *claim = claim_of(s, p);
    if (strcmp(p->name, "entra") == 0) from = strcmp(claim, "groups") == 0 ? "groups" : "app-roles";
    else if (strcmp(p->name, "keycloak") == 0) from = strcmp(claim, "groups") == 0 ? "groups" : "realm-roles";
    else from = "groups";
  }
  if (out->scim && !out->api) from = "groups"; /* SCIM alone: the groups it pushes */
  snprintf(out->roles_from, sizeof(out->roles_from), "%s", from);
  return true;
}

void buckets_idp_settings_describe(yyjson_val *s, char *out, size_t cap) {
  char a[512] = "", b[512] = "";
  const provider_def *p = provider_of(s);
  if (has(s, "openid") && p) {
    if (strcmp(p->name, "entra") == 0) snprintf(a, sizeof(a), "Microsoft Entra ID (tenant %s)", str(s, "openid.tenantId"));
    else if (strcmp(p->name, "okta") == 0) snprintf(a, sizeof(a), "Okta at %s", str(s, "openid.domain"));
    else if (strcmp(p->name, "keycloak") == 0)
      snprintf(a, sizeof(a), "Keycloak realm %s at %s", str(s, "openid.realm"), str(s, "openid.url"));
    else snprintf(a, sizeof(a), "OpenID provider %s", str(s, "openid.configUrl"));
  }
  buckets_idp_removal rm;
  if (*a && buckets_idp_removal_of(s, &rm)) {
    size_t n = strlen(a);
    snprintf(a + n, sizeof(a) - n, ", people who leave removed (keys deleted after %ld days)", rm.delete_after_days);
  }
  if (has(s, "ldap")) snprintf(b, sizeof(b), "%s at %s", ldap_preset_of(s)->label, str(s, "ldap.serverAddr"));
  if (*a && *b) snprintf(out, cap, "%s; %s", a, b);
  else if (*a || *b) snprintf(out, cap, "%s%s", a, b);
  else snprintf(out, cap, "not configured");
}
