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

bool buckets_idsync_settings_from_env(buckets_idsync_settings *s, char *err, size_t errlen) {
  memset(s, 0, sizeof(*s));
  const char *p = env("BUCKETS_OPENID_SYNC_PROVIDER");
  if (!p) return true;
  if (strcmp(p, "entra") != 0) {
    snprintf(err, errlen, "BUCKETS_OPENID_SYNC_PROVIDER %s: only entra is supported", p);
    return false;
  }
  snprintf(s->provider, sizeof(s->provider), "%s", p);
  if (!copy(s->tenant, sizeof(s->tenant), env("BUCKETS_OPENID_SYNC_TENANT_ID"),
            "BUCKETS_OPENID_SYNC_TENANT_ID", err, errlen) ||
      !copy(s->client_id, sizeof(s->client_id), env("BUCKETS_OPENID_SYNC_CLIENT_ID"),
            "BUCKETS_OPENID_SYNC_CLIENT_ID", err, errlen) ||
      !copy(s->client_secret, sizeof(s->client_secret), env("BUCKETS_OPENID_SYNC_CLIENT_SECRET"),
            "BUCKETS_OPENID_SYNC_CLIENT_SECRET", err, errlen))
    return false;
  const char *login = env("BUCKETS_OPENID_SYNC_LOGIN_URL"), *graph = env("BUCKETS_OPENID_SYNC_GRAPH_URL");
  if (!copy(s->login_url, sizeof(s->login_url), login ? login : "https://login.microsoftonline.com",
            "BUCKETS_OPENID_SYNC_LOGIN_URL", err, errlen) ||
      !copy(s->graph_url, sizeof(s->graph_url), graph ? graph : "https://graph.microsoft.com",
            "BUCKETS_OPENID_SYNC_GRAPH_URL", err, errlen))
    return false;
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
  return true;
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

/* ---- Entra ------------------------------------------------------------------------------------- */

struct buckets_idsync_entra {
  buckets_idsync_settings s;
  pthread_mutex_t mu;
  char *token;
  long long token_until;
};

buckets_idsync_entra *buckets_idsync_entra_new(const buckets_idsync_settings *s) {
  buckets_idsync_entra *e = buckets_xcalloc(1, sizeof(*e));
  e->s = *s;
  pthread_mutex_init(&e->mu, NULL);
  return e;
}

void buckets_idsync_entra_free(buckets_idsync_entra *e) {
  if (!e) return;
  memset(e->s.client_secret, 0, sizeof(e->s.client_secret));
  free(e->token);
  pthread_mutex_destroy(&e->mu);
  free(e);
}

/* An app-only token for Graph (client credentials), cached until a minute before it expires. */
static bool entra_token(buckets_idsync_entra *e, bool fresh, char *err, size_t errlen) {
  long long now = (long long)time(NULL);
  if (!fresh && e->token && now < e->token_until) return true;
  buckets_buf url = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&url, "%s/", e->s.login_url);
  buckets_url_encode(&url, e->s.tenant, false);
  buckets_buf_append_c(&url, "/oauth2/v2.0/token");
  buckets_buf_append_c(
      &body, "grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_id=");
  buckets_url_encode(&body, e->s.client_id, false);
  buckets_buf_append_c(&body, "&client_secret=");
  buckets_url_encode(&body, e->s.client_secret, false);
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result r;
  bool ok = buckets_fetch("POST", url.data, NULL, h, 1, body.data, body.len, 15000, &r, err, errlen);
  memset(body.data, 0, body.len);
  buckets_buf_free(&body);
  buckets_buf_free(&url);
  if (!ok) return false;
  yyjson_doc *d = r.status == 200 ? yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0) : NULL;
  const char *tok = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "access_token"));
  long long exp = yyjson_get_sint(yyjson_obj_get(yyjson_doc_get_root(d), "expires_in"));
  if (tok) {
    free(e->token);
    e->token = buckets_xstrdup(tok);
    e->token_until = now + (exp > 120 ? exp - 60 : 60);
  } else {
    yyjson_doc *ed = d ? NULL : yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    const char *why = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ed), "error_description"));
    snprintf(err, errlen, "Microsoft sign-in for the sync refused (%d): %.300s", r.status,
             why ? why : "no access token");
    yyjson_doc_free(ed);
  }
  yyjson_doc_free(d);
  buckets_http_result_free(&r);
  return tok != NULL;
}

buckets_idsync_state buckets_idsync_entra_lookup(buckets_idsync_entra *e, const char *oid,
                                                 buckets_idsync_person *who, char *err, size_t errlen) {
  if (who) memset(who, 0, sizeof(*who));
  buckets_idsync_state st = BUCKETS_IDSYNC_UNKNOWN;
  pthread_mutex_lock(&e->mu);
  for (int attempt = 0; attempt < 2; attempt++) {
    if (!entra_token(e, attempt > 0, err, errlen)) break;
    buckets_buf url = BUCKETS_BUF_INIT, auth = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&url, "%s/v1.0/users/", e->s.graph_url);
    buckets_url_encode(&url, oid, false);
    buckets_buf_append_c(&url, who ? "?$select=id,accountEnabled,displayName,userPrincipalName"
                                   : "?$select=id,accountEnabled");
    buckets_buf_appendf(&auth, "Bearer %s", e->token);
    buckets_http_kv h[] = {{"Authorization", auth.data}, {"Accept", "application/json"}};
    buckets_http_result r;
    bool ok = buckets_fetch("GET", url.data, NULL, h, 2, NULL, 0, 15000, &r, err, errlen);
    buckets_buf_free(&url);
    buckets_buf_free(&auth);
    if (!ok) break;
    int status = r.status;
    st = buckets_idsync_graph_state(status, r.body.data, r.body.len);
    if (who && status == 200) {
      yyjson_doc *d = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
      yyjson_val *root = yyjson_doc_get_root(d);
      const char *id = yyjson_get_str(yyjson_obj_get(root, "id")),
                 *dn = yyjson_get_str(yyjson_obj_get(root, "displayName")),
                 *upn = yyjson_get_str(yyjson_obj_get(root, "userPrincipalName"));
      snprintf(who->id, sizeof(who->id), "%s", id ? id : "");
      snprintf(who->display_name, sizeof(who->display_name), "%s", dn ? dn : "");
      snprintf(who->upn, sizeof(who->upn), "%s", upn ? upn : "");
      yyjson_doc_free(d);
    }
    if (st == BUCKETS_IDSYNC_UNKNOWN)
      snprintf(err, errlen, "Microsoft Graph answered %d for user %s: %.200s", status, oid,
               r.body.data ? r.body.data : "");
    buckets_http_result_free(&r);
    if (status != 401) break; /* 401: the token went stale; once more with a new one */
  }
  pthread_mutex_unlock(&e->mu);
  return st;
}
