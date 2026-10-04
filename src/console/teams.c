/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "console/teams.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yyjson.h>

#include "iam/teams.h"

#define MAX_BODY (64 * 1024)
#define MAX_POLICY (20 * 1024) /* what add-canned-policy takes */

static void reply(buckets_http_response *resp, int status, yyjson_mut_doc *d) {
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

static void fail(buckets_http_response *resp, int status, const char *code, const char *message) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "code", code);
  yyjson_mut_obj_add_strcpy(d, o, "message", message);
  reply(resp, status, d);
}

/* An admin API refusal passed on: its status, code and message. */
static void fail_admin(buckets_http_response *resp, int status, const buckets_buf *body, const char *doing) {
  yyjson_doc *e = status ? yyjson_read(body->data ? body->data : "", body->len, 0) : NULL;
  const char *code = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(e), "Code"));
  const char *msg = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(e), "Message"));
  char m[512];
  snprintf(m, sizeof(m), "%s: %s", doing, msg ? msg : status ? "the servers refused" : "the servers did not answer");
  fail(resp, status ? status : 502, code ? code : "ServerError", m);
  yyjson_doc_free(e);
}

typedef struct {
  const buckets_console_teams_session *sess;
  int status;
  buckets_buf body;
} call;

static bool admin(call *c, const char *method, const char *api, const char *query, const void *body, size_t n,
                  bool encrypt, bool decrypt) {
  buckets_buf_reset(&c->body);
  c->status = c->sess->admin(c->sess->ud, method, api, query, body, n, encrypt, decrypt, &c->body);
  return c->status >= 200 && c->status < 300;
}

/* ---- members ---------------------------------------------------------------------------- */

/* "policy=team-x-ro&policy=team-x-rw..." for a team's levels */
static void level_query(const char *team, yyjson_val *levels, buckets_buf *q) {
  size_t i, max;
  yyjson_val *l;
  yyjson_arr_foreach(levels, i, max, l) {
    char pn[128];
    buckets_team_policy_name(team, yyjson_get_str(l), pn, sizeof(pn));
    buckets_buf_appendf(q, "%spolicy=", q->len ? "&" : "");
    buckets_url_encode(q, pn, false);
  }
}

static bool is_dn(const char *s) { return strchr(s, '=') != NULL; }

/* The members of each level, from the servers' policy mappings: {"<level>": {"users", "groups"}}. Members are
 * what someone attached: local users and groups from the built-in listing, and LDAP users and groups (DNs) from
 * the LDAP one when LDAP sign-in is on (*ldap). The built-in listing also names the hashed parents of OpenID
 * sessions that signed in with a role; those are not members, so a user counts only if it is a local user. */
static yyjson_mut_val *members(call *c, yyjson_mut_doc *d, const char *team, yyjson_val *levels, bool *ldap) {
  yyjson_mut_val *out = yyjson_mut_obj(d);
  buckets_buf q = BUCKETS_BUF_INIT;
  level_query(team, levels, &q);
  size_t i, max;
  yyjson_val *l;
  yyjson_arr_foreach(levels, i, max, l) {
    yyjson_mut_val *m = yyjson_mut_obj(d); /* the key copied: levels may not outlive d */
    yyjson_mut_obj_add(out, yyjson_mut_strcpy(d, yyjson_get_str(l)), m);
    yyjson_mut_obj_add_arr(d, m, "users");
    yyjson_mut_obj_add_arr(d, m, "groups");
  }
  yyjson_doc *local = NULL; /* list-users, fetched when a built-in mapping names a user */
  static const char *const apis[] = {"idp/builtin/policy-entities", "idp/ldap/policy-entities"};
  for (int k = 0; k < 2; k++) {
    bool ok = q.len && admin(c, "GET", apis[k], q.data, NULL, 0, false, true);
    if (k == 1) *ldap = ok;
    if (!ok) continue;
    yyjson_doc *r = yyjson_read(c->body.data ? c->body.data : "", c->body.len, 0);
    size_t j, jm;
    yyjson_val *pm;
    yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(r), "policyMappings"), j, jm, pm) {
      const char *pol = yyjson_get_str(yyjson_obj_get(pm, "policy"));
      yyjson_arr_foreach(levels, i, max, l) {
        char pn[128];
        buckets_team_policy_name(team, yyjson_get_str(l), pn, sizeof(pn));
        if (!pol || strcmp(pol, pn) != 0) continue;
        yyjson_mut_val *m = yyjson_mut_obj_get(out, yyjson_get_str(l));
        static const char *const kinds[] = {"users", "groups"};
        for (int t = 0; t < 2; t++) {
          yyjson_mut_val *dst = yyjson_mut_obj_get(m, kinds[t]);
          size_t x, xm;
          yyjson_val *who;
          yyjson_arr_foreach(yyjson_obj_get(pm, kinds[t]), x, xm, who) {
            const char *w = yyjson_get_str(who);
            if (!w) continue;
            if (k == 1 && !is_dn(w)) continue;
            if (k == 0 && t == 0 && !is_dn(w)) {
              if (!local) {
                call lu = {c->sess, 0, BUCKETS_BUF_INIT};
                local = admin(&lu, "GET", "list-users", NULL, NULL, 0, false, true)
                            ? yyjson_read(lu.body.data ? lu.body.data : "", lu.body.len, 0)
                            : yyjson_read("{}", 2, 0);
                buckets_buf_free(&lu.body);
              }
              if (!yyjson_obj_get(yyjson_doc_get_root(local), w)) continue;
            }
            if (k == 0 && is_dn(w)) continue; /* LDAP's, from its own listing */
            bool dup = false;
            size_t y, ym;
            yyjson_mut_val *have;
            yyjson_mut_arr_foreach(dst, y, ym, have) dup = dup || strcmp(yyjson_mut_get_str(have), w) == 0;
            if (!dup) yyjson_mut_arr_add_strcpy(d, dst, w);
          }
        }
      }
    }
    yyjson_doc_free(r);
  }
  yyjson_doc_free(local);
  buckets_buf_free(&q);
  return out;
}

/* Attaches or detaches a policy for a user or group; false with the refusal in c. */
static bool attach(call *c, const char *policy, const char *user, const char *group, bool ldap, bool remove) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_arr_add_strcpy(d, yyjson_mut_obj_add_arr(d, o, "policies"), policy);
  if (user) yyjson_mut_obj_add_strcpy(d, o, "user", user);
  else yyjson_mut_obj_add_strcpy(d, o, "group", group);
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  char api[64];
  snprintf(api, sizeof(api), "idp/%s/policy/%s", ldap && is_dn(user ? user : group) ? "ldap" : "builtin",
           remove ? "detach" : "attach");
  bool ok = admin(c, "POST", api, NULL, js, n, true, false);
  free(js);
  return ok;
}

/* Detaches every member of a level; false (refusal in c) on the first failure. */
static bool detach_all(call *c, yyjson_mut_val *m, const char *policy, bool ldap) {
  static const char *const kinds[] = {"users", "groups"};
  for (int t = 0; t < 2; t++) {
    size_t i, max;
    yyjson_mut_val *w;
    yyjson_mut_arr_foreach(yyjson_mut_obj_get(m, kinds[t]), i, max, w) {
      const char *who = yyjson_mut_get_str(w);
      if (!attach(c, policy, t ? NULL : who, t ? who : NULL, ldap, true)) return false;
    }
  }
  return true;
}

/* ---- the endpoints -------------------------------------------------------------------------- */

/* The teams in the servers' policies, as buckets_teams_from_policies gives them; NULL (refusal in c) when the
 * policies cannot be listed. */
static yyjson_mut_val *list_teams(call *c, yyjson_mut_doc *d) {
  if (!admin(c, "GET", "list-canned-policies", NULL, NULL, 0, false, false)) return NULL;
  yyjson_doc *p = yyjson_read(c->body.data ? c->body.data : "", c->body.len, 0);
  yyjson_mut_val *teams = buckets_teams_from_policies(d, yyjson_doc_get_root(p));
  yyjson_doc_free(p);
  return teams;
}

static yyjson_mut_val *find_team(yyjson_mut_val *teams, const char *name) {
  size_t i, max;
  yyjson_mut_val *t;
  yyjson_mut_arr_foreach(teams, i, max, t) {
    if (strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(t, "name")), name) == 0) return t;
  }
  return NULL;
}

static void handle_list(call *c, buckets_http_response *resp) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *teams = list_teams(c, d);
  if (!teams) {
    yyjson_mut_doc_free(d);
    fail_admin(resp, c->status, &c->body, "Listing policies");
    return;
  }
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_val(d, o, "teams", teams);
  bool ldap = false;
  size_t i, max;
  yyjson_mut_val *t;
  yyjson_mut_arr_foreach(teams, i, max, t) {
    yyjson_doc *levels = yyjson_mut_val_imut_copy(yyjson_mut_obj_get(t, "levels"), NULL);
    yyjson_mut_obj_add_val(d, t, "members",
                           members(c, d, yyjson_mut_get_str(yyjson_mut_obj_get(t, "name")), yyjson_doc_get_root(levels), &ldap));
    yyjson_doc_free(levels);
  }
  if (!yyjson_mut_arr_size(teams)) { /* is LDAP on? ask with a policy nobody has */
    call probe = {c->sess, 0, BUCKETS_BUF_INIT};
    ldap = admin(&probe, "GET", "idp/ldap/policy-entities", "policy=team-", NULL, 0, false, true);
    buckets_buf_free(&probe.body);
  }
  yyjson_mut_obj_add_bool(d, o, "ldap", ldap);
  reply(resp, 200, d);
}

static bool str_in_mut(yyjson_mut_val *arr, const char *s) {
  size_t i, max;
  yyjson_mut_val *v;
  yyjson_mut_arr_foreach(arr, i, max, v) if (strcmp(yyjson_mut_get_str(v), s) == 0) return true;
  return false;
}

static bool str_in(yyjson_val *arr, const char *s) {
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(arr, i, max, v) if (strcmp(yyjson_get_str(v), s) == 0) return true;
  return false;
}

/* Removes the policies of an existing team's levels that keep (NULL: none) does not list, detaching their members
 * first. False with the response written on failure. */
static bool remove_levels(call *c, yyjson_mut_val *existing, yyjson_val *keep, buckets_http_response *resp) {
  const char *name = yyjson_mut_get_str(yyjson_mut_obj_get(existing, "name"));
  yyjson_mut_val *levels = yyjson_mut_obj_get(existing, "levels");
  yyjson_doc *lv = yyjson_mut_val_imut_copy(levels, NULL);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  bool ldap = false, ok = true;
  yyjson_mut_val *mem = members(c, d, name, yyjson_doc_get_root(lv), &ldap);
  size_t i, max;
  yyjson_mut_val *l;
  yyjson_mut_arr_foreach(levels, i, max, l) {
    const char *level = yyjson_mut_get_str(l);
    if (keep && str_in(keep, level)) continue;
    char pn[128], q[160];
    buckets_team_policy_name(name, level, pn, sizeof(pn));
    if (!detach_all(c, yyjson_mut_obj_get(mem, level), pn, ldap)) {
      fail_admin(resp, c->status, &c->body, "Removing the level's members");
      ok = false;
      break;
    }
    snprintf(q, sizeof(q), "name=%s", pn); /* team names need no escaping */
    if (!admin(c, "DELETE", "remove-canned-policy", q, NULL, 0, false, false)) {
      fail_admin(resp, c->status, &c->body, "Removing the level's policy");
      ok = false;
      break;
    }
  }
  yyjson_mut_doc_free(d);
  yyjson_doc_free(lv);
  return ok;
}

static void handle_put(call *c, const char *name, yyjson_val *body, buckets_http_response *resp) {
  yyjson_val *team = yyjson_obj_get(body, "team");
  char err[512];
  if (!buckets_team_check(team, err, sizeof(err))) {
    fail(resp, 400, "InvalidTeam", err);
    return;
  }
  if (strcmp(yyjson_get_str(yyjson_obj_get(team, "name")), name) != 0) {
    fail(resp, 400, "InvalidTeam", "The team's name does not match the address");
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *teams = list_teams(c, d);
  if (!teams) {
    yyjson_mut_doc_free(d);
    fail_admin(resp, c->status, &c->body, "Listing policies");
    return;
  }
  yyjson_doc *ti = yyjson_mut_val_imut_copy(teams, NULL);
  bool overlap = buckets_team_overlaps(team, yyjson_doc_get_root(ti), err, sizeof(err));
  yyjson_doc_free(ti);
  if (overlap) {
    yyjson_mut_doc_free(d);
    fail(resp, 409, "Overlap", err);
    return;
  }
  yyjson_mut_val *existing = find_team(teams, name);
  yyjson_mut_val *edited = existing ? yyjson_mut_obj_get(existing, "edited") : NULL;
  if (edited && yyjson_mut_arr_size(edited) && !yyjson_get_bool(yyjson_obj_get(body, "overwrite"))) {
    yyjson_mut_doc *e = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *o = yyjson_mut_obj(e);
    yyjson_mut_doc_set_root(e, o);
    yyjson_mut_obj_add_str(e, o, "code", "Edited");
    yyjson_mut_obj_add_str(e, o, "message",
                           "Some of this team's policies were changed outside the Teams page: saving replaces those "
                           "changes.");
    yyjson_mut_obj_add_val(e, o, "edited", yyjson_mut_val_mut_copy(e, edited));
    yyjson_mut_doc_free(d);
    reply(resp, 409, e);
    return;
  }
  /* every level's policy first, so a refusal leaves the team as it was or with more, never with less */
  size_t i, max;
  yyjson_val *l;
  yyjson_arr_foreach(yyjson_obj_get(team, "levels"), i, max, l) {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_team_policy(team, yyjson_get_str(l), &p);
    if (p.len > MAX_POLICY) {
      buckets_buf_free(&p);
      yyjson_mut_doc_free(d);
      fail(resp, 400, "TooManyBuckets",
           "The team names too many buckets for one policy (20 KiB): name them by a prefix instead");
      return;
    }
    char pn[128], q[160];
    buckets_team_policy_name(name, yyjson_get_str(l), pn, sizeof(pn));
    snprintf(q, sizeof(q), "name=%s", pn);
    bool ok = admin(c, "PUT", "add-canned-policy", q, p.data, p.len, false, false);
    buckets_buf_free(&p);
    if (!ok) {
      yyjson_mut_doc_free(d);
      fail_admin(resp, c->status, &c->body, "Writing the team's policy");
      return;
    }
  }
  if (existing && !remove_levels(c, existing, yyjson_obj_get(team, "levels"), resp)) {
    yyjson_mut_doc_free(d);
    return;
  }
  yyjson_mut_doc_free(d);
  d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, yyjson_val_mut_copy(d, team));
  reply(resp, 200, d);
}

static void handle_delete(call *c, const char *name, buckets_http_response *resp) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *teams = list_teams(c, d);
  if (!teams) {
    yyjson_mut_doc_free(d);
    fail_admin(resp, c->status, &c->body, "Listing policies");
    return;
  }
  yyjson_mut_val *existing = find_team(teams, name);
  if (!existing) {
    yyjson_mut_doc_free(d);
    fail(resp, 404, "NoSuchTeam", "There is no such team");
    return;
  }
  if (remove_levels(c, existing, NULL, resp)) {
    resp->status = 204;
    buckets_buf_reset(&resp->body);
  }
  yyjson_mut_doc_free(d);
}

static void handle_members(call *c, const char *name, yyjson_val *body, buckets_http_response *resp) {
  const char *level = yyjson_get_str(yyjson_obj_get(body, "level"));
  const char *user = yyjson_get_str(yyjson_obj_get(body, "user")), *group = yyjson_get_str(yyjson_obj_get(body, "group"));
  bool remove = yyjson_get_bool(yyjson_obj_get(body, "remove"));
  if (user && !*user) user = NULL;
  if (group && !*group) group = NULL;
  if (!level || !user == !group) {
    fail(resp, 400, "InvalidRequest", "Give a level and either a user or a group");
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *teams = list_teams(c, d);
  yyjson_mut_val *t = teams ? find_team(teams, name) : NULL;
  bool found = t && str_in_mut(yyjson_mut_obj_get(t, "levels"), level);
  if (!teams) fail_admin(resp, c->status, &c->body, "Listing policies");
  else if (!found) fail(resp, 404, "NoSuchTeam", "The team has no such level");
  yyjson_mut_doc_free(d);
  if (!found) return;
  /* is LDAP on? */
  char pn[128], q[160];
  buckets_team_policy_name(name, level, pn, sizeof(pn));
  snprintf(q, sizeof(q), "policy=%s", pn);
  call probe = {c->sess, 0, BUCKETS_BUF_INIT};
  bool ldap = admin(&probe, "GET", "idp/ldap/policy-entities", q, NULL, 0, false, true);
  buckets_buf_free(&probe.body);
  if (!attach(c, pn, user, group, ldap, remove)) {
    fail_admin(resp, c->status, &c->body, remove ? "Removing the member" : "Adding the member");
    return;
  }
  resp->status = 204;
  buckets_buf_reset(&resp->body);
}

void buckets_console_teams_handle(const buckets_http_request *req, const char *sub,
                                  const buckets_console_teams_session *sess, buckets_http_response *resp) {
  call c = {sess, 0, BUCKETS_BUF_INIT};
  bool get = buckets_str_eq_c(req->method, "GET"), put = buckets_str_eq_c(req->method, "PUT"),
       del = buckets_str_eq_c(req->method, "DELETE"), post = buckets_str_eq_c(req->method, "POST");
  char name[BUCKETS_TEAM_NAME_MAX + 1] = "";
  const char *rest = "";
  if (*sub == '/') {
    const char *slash = strchr(sub + 1, '/');
    size_t n = slash ? (size_t)(slash - sub - 1) : strlen(sub + 1);
    if (n == 0 || n > BUCKETS_TEAM_NAME_MAX) {
      fail(resp, 404, "NotFound", "unknown API");
      return;
    }
    snprintf(name, sizeof(name), "%.*s", (int)n, sub + 1);
    rest = slash ? slash : "";
  } else if (*sub) {
    fail(resp, 404, "NotFound", "unknown API");
    return;
  }
  yyjson_doc *bd = NULL;
  if (put || post) {
    if (req->body_len > MAX_BODY || req->body_fd >= 0 || req->pipe) {
      fail(resp, 413, "TooLarge", "request too large");
      return;
    }
    bd = yyjson_read(req->body.p ? req->body.p : "", req->body.n, 0);
    if (!yyjson_is_obj(yyjson_doc_get_root(bd))) {
      yyjson_doc_free(bd);
      fail(resp, 400, "InvalidRequest", "expected a JSON object");
      return;
    }
  }
  yyjson_val *body = yyjson_doc_get_root(bd);
  if (get && !*name) handle_list(&c, resp);
  else if (put && *name && !*rest) handle_put(&c, name, body, resp);
  else if (del && *name && !*rest) handle_delete(&c, name, resp);
  else if (post && *name && strcmp(rest, "/members") == 0) handle_members(&c, name, body, resp);
  else fail(resp, 404, "NotFound", "unknown API");
  yyjson_doc_free(bd);
  buckets_buf_free(&c.body);
}
