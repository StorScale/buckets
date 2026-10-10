/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/scim.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "core/uuid.h"

#define SCHEMA_USER "urn:ietf:params:scim:schemas:core:2.0:User"
#define SCHEMA_ERROR "urn:ietf:params:scim:api:messages:2.0:Error"

static char *dup_or_null(const char *s) { return s ? buckets_xstrdup(s) : NULL; }
static void set_str(char **dst, const char *v) {
  free(*dst);
  *dst = dup_or_null(v);
}

void buckets_scim_user_free(buckets_scim_user *u) {
  if (!u) return;
  free(u->external_id);
  free(u->user_name);
  free(u->display_name);
  memset(u, 0, sizeof(*u));
}

void buckets_scim_group_free(buckets_scim_group *g) {
  if (!g) return;
  free(g->display_name);
  free(g->external_id);
  for (size_t i = 0; i < g->nmembers; i++) free(g->members[i]);
  free(g->members);
  memset(g, 0, sizeof(*g));
}

void buckets_scim_store_free(buckets_scim_store *s) {
  for (size_t i = 0; i < s->n; i++) buckets_scim_user_free(&s->u[i]);
  for (size_t i = 0; i < s->ng; i++) buckets_scim_group_free(&s->g[i]);
  free(s->g);
  free(s->u);
  memset(s, 0, sizeof(*s));
}

bool buckets_scim_store_parse(const char *json, size_t len, buckets_scim_store *out) {
  memset(out, 0, sizeof(*out));
  if (!json || !len) return true;
  yyjson_doc *d = yyjson_read(json, len, 0);
  yyjson_val *root = yyjson_doc_get_root(d);
  if (!yyjson_is_obj(root)) {
    yyjson_doc_free(d);
    return false;
  }
  out->rev = yyjson_get_sint(yyjson_obj_get(root, "rev"));
  yyjson_val *arr = yyjson_obj_get(root, "users");
  size_t i, n;
  yyjson_val *v;
  out->u = buckets_xcalloc(yyjson_arr_size(arr) + 1, sizeof(*out->u));
  yyjson_arr_foreach(arr, i, n, v) {
    buckets_scim_user *u = &out->u[out->n++];
    const char *id = yyjson_get_str(yyjson_obj_get(v, "id"));
    snprintf(u->id, sizeof(u->id), "%s", id ? id : "");
    u->external_id = dup_or_null(yyjson_get_str(yyjson_obj_get(v, "externalId")));
    u->user_name = dup_or_null(yyjson_get_str(yyjson_obj_get(v, "userName")));
    u->display_name = dup_or_null(yyjson_get_str(yyjson_obj_get(v, "displayName")));
    u->active = yyjson_get_bool(yyjson_obj_get(v, "active"));
    u->deleted = yyjson_get_bool(yyjson_obj_get(v, "deleted"));
    u->created = yyjson_get_sint(yyjson_obj_get(v, "created"));
    u->modified = yyjson_get_sint(yyjson_obj_get(v, "modified"));
  }
  yyjson_val *ga = yyjson_obj_get(root, "groups");
  out->g = buckets_xcalloc(yyjson_arr_size(ga) + 1, sizeof(*out->g));
  yyjson_arr_foreach(ga, i, n, v) {
    buckets_scim_group *g = &out->g[out->ng++];
    const char *id = yyjson_get_str(yyjson_obj_get(v, "id"));
    snprintf(g->id, sizeof(g->id), "%s", id ? id : "");
    g->display_name = dup_or_null(yyjson_get_str(yyjson_obj_get(v, "displayName")));
    g->external_id = dup_or_null(yyjson_get_str(yyjson_obj_get(v, "externalId")));
    yyjson_val *ms = yyjson_obj_get(v, "members");
    g->members = buckets_xcalloc(yyjson_arr_size(ms) + 1, sizeof(char *));
    size_t j, jm;
    yyjson_val *m;
    yyjson_arr_foreach(ms, j, jm, m) if (yyjson_get_str(m)) g->members[g->nmembers++] = buckets_xstrdup(yyjson_get_str(m));
    g->created = yyjson_get_sint(yyjson_obj_get(v, "created"));
    g->modified = yyjson_get_sint(yyjson_obj_get(v, "modified"));
  }
  yyjson_doc_free(d);
  return true;
}

static void write_doc(yyjson_mut_doc *d, buckets_buf *out) {
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  if (j) buckets_buf_append(out, j, len);
  free(j);
  yyjson_mut_doc_free(d);
}

void buckets_scim_store_json(const buckets_scim_store *s, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *arr = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_int(d, root, "rev", s->rev);
  for (size_t i = 0; i < s->n; i++) {
    const buckets_scim_user *u = &s->u[i];
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "id", u->id);
    if (u->external_id) yyjson_mut_obj_add_strcpy(d, o, "externalId", u->external_id);
    if (u->user_name) yyjson_mut_obj_add_strcpy(d, o, "userName", u->user_name);
    if (u->display_name) yyjson_mut_obj_add_strcpy(d, o, "displayName", u->display_name);
    yyjson_mut_obj_add_bool(d, o, "active", u->active);
    if (u->deleted) yyjson_mut_obj_add_bool(d, o, "deleted", true);
    yyjson_mut_obj_add_int(d, o, "created", u->created);
    yyjson_mut_obj_add_int(d, o, "modified", u->modified);
  }
  yyjson_mut_obj_add_val(d, root, "users", arr);
  yyjson_mut_val *ga = yyjson_mut_obj_add_arr(d, root, "groups");
  for (size_t i = 0; i < s->ng; i++) {
    const buckets_scim_group *g = &s->g[i];
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, ga);
    yyjson_mut_obj_add_strcpy(d, o, "id", g->id);
    if (g->display_name) yyjson_mut_obj_add_strcpy(d, o, "displayName", g->display_name);
    if (g->external_id) yyjson_mut_obj_add_strcpy(d, o, "externalId", g->external_id);
    yyjson_mut_val *ms = yyjson_mut_obj_add_arr(d, o, "members");
    for (size_t j = 0; j < g->nmembers; j++) yyjson_mut_arr_add_strcpy(d, ms, g->members[j]);
    yyjson_mut_obj_add_int(d, o, "created", g->created);
    yyjson_mut_obj_add_int(d, o, "modified", g->modified);
  }
  write_doc(d, out);
}

void buckets_scim_store_prune(buckets_scim_store *s, long long now, long long keep_s) {
  size_t k = 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->u[i].deleted && now - s->u[i].modified > keep_s) {
      buckets_scim_user_free(&s->u[i]);
      continue;
    }
    s->u[k++] = s->u[i];
  }
  s->n = k;
}

buckets_scim_user *buckets_scim_find_id(buckets_scim_store *s, const char *id) {
  for (size_t i = 0; i < s->n; i++)
    if (!s->u[i].deleted && !strcmp(s->u[i].id, id)) return &s->u[i];
  return NULL;
}

buckets_scim_user *buckets_scim_find_external(buckets_scim_store *s, const char *external_id) {
  for (size_t i = 0; i < s->n; i++)
    if (!s->u[i].deleted && s->u[i].external_id && !strcmp(s->u[i].external_id, external_id)) return &s->u[i];
  return NULL;
}

buckets_scim_user *buckets_scim_find_user_name(buckets_scim_store *s, const char *user_name) {
  for (size_t i = 0; i < s->n; i++)
    if (!s->u[i].deleted && s->u[i].user_name && !strcasecmp(s->u[i].user_name, user_name)) return &s->u[i];
  return NULL;
}

buckets_idsync_state buckets_scim_state_of(const buckets_scim_store *s, const char *person) {
  /* the newest record for the ID wins: a person deleted and assigned again is active */
  const buckets_scim_user *best = NULL;
  for (size_t i = 0; i < s->n; i++) {
    const buckets_scim_user *u = &s->u[i];
    if (!u->external_id || strcmp(u->external_id, person) != 0) continue;
    if (!best || (best->deleted && !u->deleted) ||
        (best->deleted == u->deleted && u->modified >= best->modified))
      best = u;
  }
  if (!best) return BUCKETS_IDSYNC_UNKNOWN;
  return best->deleted ? BUCKETS_IDSYNC_GONE : best->active ? BUCKETS_IDSYNC_ACTIVE : BUCKETS_IDSYNC_DISABLED;
}

static bool fail(int *status, int code, char *err, size_t errlen, const char *msg) {
  *status = code;
  snprintf(err, errlen, "%s", msg);
  return false;
}

/* A boolean as JSON, or as Entra's "True"/"False". */
static bool get_bool(yyjson_val *v, bool *out) {
  if (yyjson_is_bool(v)) {
    *out = yyjson_get_bool(v);
    return true;
  }
  const char *s = yyjson_get_str(v);
  if (s && (!strcasecmp(s, "true") || !strcasecmp(s, "false"))) {
    *out = !strcasecmp(s, "true");
    return true;
  }
  return false;
}

/* The attributes kept, from an object: POST and PUT bodies, and patches without a path. */
static bool apply_attrs(buckets_scim_user *u, yyjson_val *o, bool replace_all, int *status, char *err,
                        size_t errlen) {
  size_t i, n;
  yyjson_val *k, *v;
  if (replace_all) u->active = true; /* SCIM: active defaults to true */
  yyjson_obj_foreach(o, i, n, k, v) {
    const char *key = yyjson_get_str(k);
    if (!strcasecmp(key, "userName")) {
      if (!yyjson_is_str(v) || !*yyjson_get_str(v))
        return fail(status, 400, err, errlen, "userName must be a string");
      set_str(&u->user_name, yyjson_get_str(v));
    } else if (!strcasecmp(key, "externalId")) {
      set_str(&u->external_id, yyjson_is_str(v) && *yyjson_get_str(v) ? yyjson_get_str(v) : NULL);
    } else if (!strcasecmp(key, "displayName")) {
      set_str(&u->display_name, yyjson_get_str(v));
    } else if (!strcasecmp(key, "active")) {
      bool b;
      if (!get_bool(v, &b)) return fail(status, 400, err, errlen, "active must be a boolean");
      u->active = b;
    }
    /* everything else (name, emails, the enterprise extension, ...) is accepted and not kept */
  }
  return true;
}

bool buckets_scim_user_from_json(yyjson_val *body, buckets_scim_user *out, int *status, char *err,
                                 size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (!yyjson_is_obj(body)) return fail(status, 400, err, errlen, "The body must be a JSON object");
  if (!apply_attrs(out, body, true, status, err, errlen)) {
    buckets_scim_user_free(out);
    return false;
  }
  if (!out->user_name) {
    buckets_scim_user_free(out);
    return fail(status, 400, err, errlen, "userName is required");
  }
  return true;
}

bool buckets_scim_patch(buckets_scim_user *u, yyjson_val *body, int *status, char *err, size_t errlen) {
  yyjson_val *ops = yyjson_obj_get(body, "Operations");
  if (!ops) ops = yyjson_obj_get(body, "operations");
  if (!yyjson_is_arr(ops)) return fail(status, 400, err, errlen, "A PatchOp needs Operations");
  size_t i, n;
  yyjson_val *op;
  yyjson_arr_foreach(ops, i, n, op) {
    const char *kind = yyjson_get_str(yyjson_obj_get(op, "op"));
    const char *path = yyjson_get_str(yyjson_obj_get(op, "path"));
    yyjson_val *value = yyjson_obj_get(op, "value");
    if (!kind) return fail(status, 400, err, errlen, "An operation needs op");
    bool remove = !strcasecmp(kind, "remove");
    if (!remove && strcasecmp(kind, "add") && strcasecmp(kind, "replace"))
      return fail(status, 400, err, errlen, "op is add, replace or remove");
    if (!path || !*path) { /* the value is an object of attributes */
      if (remove) return fail(status, 400, err, errlen, "remove needs a path");
      if (!yyjson_is_obj(value))
        return fail(status, 400, err, errlen, "Without a path, the value must be an object");
      if (!apply_attrs(u, value, false, status, err, errlen)) return false;
      continue;
    }
    if (!strcasecmp(path, "active")) {
      bool b = false;
      if (remove) return fail(status, 400, err, errlen, "active can't be removed");
      if (!get_bool(value, &b)) return fail(status, 400, err, errlen, "active must be a boolean");
      u->active = b;
    } else if (!strcasecmp(path, "userName")) {
      if (remove || !yyjson_is_str(value) || !*yyjson_get_str(value))
        return fail(status, 400, err, errlen, "userName must be a string");
      set_str(&u->user_name, yyjson_get_str(value));
    } else if (!strcasecmp(path, "externalId")) {
      set_str(&u->external_id,
              remove || !yyjson_is_str(value) || !*yyjson_get_str(value) ? NULL : yyjson_get_str(value));
    } else if (!strcasecmp(path, "displayName")) {
      set_str(&u->display_name, remove ? NULL : yyjson_get_str(value));
    }
    /* other paths (name.givenName, emails[type eq "work"].value, ...) aren't kept */
  }
  return true;
}

bool buckets_scim_filter_parse(const char *s, buckets_scim_filter *out) {
  memset(out, 0, sizeof(*out));
  if (!s) return true;
  while (isspace((unsigned char)*s)) s++;
  if (!*s) return true;
  const char *a = s;
  while (*s && !isspace((unsigned char)*s)) s++;
  size_t al = (size_t)(s - a);
  if (al == 8 && !strncasecmp(a, "userName", 8))
    snprintf(out->attr, sizeof(out->attr), "userName");
  else if (al == 10 && !strncasecmp(a, "externalId", 10))
    snprintf(out->attr, sizeof(out->attr), "externalId");
  else if (al == 11 && !strncasecmp(a, "displayName", 11))
    snprintf(out->attr, sizeof(out->attr), "displayName");
  else
    return false;
  while (isspace((unsigned char)*s)) s++;
  if (strncasecmp(s, "eq", 2) != 0 || !isspace((unsigned char)s[2])) return false;
  s += 2;
  while (isspace((unsigned char)*s)) s++;
  if (*s != '"') return false;
  s++;
  size_t k = 0;
  for (; *s && *s != '"'; s++) {
    if (*s == '\\' && s[1]) s++;
    if (k + 1 >= sizeof(out->value)) return false;
    out->value[k++] = *s;
  }
  if (*s != '"') return false;
  out->value[k] = '\0';
  s++;
  while (isspace((unsigned char)*s)) s++;
  return *s == '\0'; /* and, or, other operators: not supported */
}

bool buckets_scim_filter_match(const buckets_scim_filter *f, const buckets_scim_user *u) {
  if (u->deleted) return false;
  if (!*f->attr) return true;
  if (!strcmp(f->attr, "userName"))
    return u->user_name && !strcasecmp(u->user_name, f->value); /* caseExact false */
  return u->external_id && !strcmp(u->external_id, f->value);
}

static void iso(long long t, char *out) { buckets_time_iso8601((time_t)t, out); }

void buckets_scim_user_json(const buckets_scim_user *u, const char *base, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_arr_add_str(d, yyjson_mut_obj_add_arr(d, o, "schemas"), SCHEMA_USER);
  yyjson_mut_obj_add_strcpy(d, o, "id", u->id);
  if (u->external_id) yyjson_mut_obj_add_strcpy(d, o, "externalId", u->external_id);
  yyjson_mut_obj_add_strcpy(d, o, "userName", u->user_name ? u->user_name : "");
  if (u->display_name) yyjson_mut_obj_add_strcpy(d, o, "displayName", u->display_name);
  yyjson_mut_obj_add_bool(d, o, "active", u->active);
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, o, "meta");
  char t[40];
  yyjson_mut_obj_add_str(d, m, "resourceType", "User");
  iso(u->created, t);
  yyjson_mut_obj_add_strcpy(d, m, "created", t);
  iso(u->modified, t);
  yyjson_mut_obj_add_strcpy(d, m, "lastModified", t);
  if (base && *base) {
    char loc[1024];
    snprintf(loc, sizeof(loc), "%s/Users/%s", base, u->id);
    yyjson_mut_obj_add_strcpy(d, m, "location", loc);
  }
  write_doc(d, out);
}

void buckets_scim_error_json(int status, const char *scim_type, const char *detail, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_arr_add_str(d, yyjson_mut_obj_add_arr(d, o, "schemas"), SCHEMA_ERROR);
  char st[8];
  snprintf(st, sizeof(st), "%d", status);
  yyjson_mut_obj_add_strcpy(d, o, "status", st);
  if (scim_type && *scim_type) yyjson_mut_obj_add_strcpy(d, o, "scimType", scim_type);
  yyjson_mut_obj_add_strcpy(d, o, "detail", detail ? detail : "");
  write_doc(d, out);
}

void buckets_scim_service_provider_config(buckets_buf *out) {
  buckets_buf_append_c(
      out,
      "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig\"],"
      "\"documentationUri\":\"https://github.com/StorScale/buckets/blob/main/docs/identity.md\","
      "\"patch\":{\"supported\":true},\"bulk\":{\"supported\":false,\"maxOperations\":0,\"maxPayloadSize\":0}"
      ","
      "\"filter\":{\"supported\":true,\"maxResults\":1000},\"changePassword\":{\"supported\":false},"
      "\"sort\":{\"supported\":false},\"etag\":{\"supported\":false},"
      "\"authenticationSchemes\":[{\"type\":\"oauthbearertoken\",\"name\":\"Bearer token\","
      "\"description\":\"The token made in the console (Identity, Sign-in, People who "
      "leave)\",\"primary\":true}],"
      "\"meta\":{\"resourceType\":\"ServiceProviderConfig\"}}");
}

void buckets_scim_resource_types(const char *base, buckets_buf *out) {
  const char *b = base ? base : "";
  buckets_buf_appendf(out,
                      "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],\"totalResults\":2,"
                      "\"Resources\":[{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ResourceType\"],"
                      "\"id\":\"User\",\"name\":\"User\",\"endpoint\":\"/Users\",\"schema\":\"" SCHEMA_USER "\","
                      "\"meta\":{\"resourceType\":\"ResourceType\",\"location\":\"%s/ResourceTypes/User\"}},"
                      "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ResourceType\"],\"id\":\"Group\","
                      "\"name\":\"Group\",\"endpoint\":\"/Groups\",\"schema\":\"urn:ietf:params:scim:schemas:core:2.0:Group\","
                      "\"meta\":{\"resourceType\":\"ResourceType\",\"location\":\"%s/ResourceTypes/Group\"}}]}",
                      b, b);
}

void buckets_scim_schemas(buckets_buf *out) {
  buckets_buf_append_c(out,
                       "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],"
                       "\"totalResults\":1,\"Resources\":[{"
                       "\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Schema\"],\"id\":\"" SCHEMA_USER
                       "\",\"name\":\"User\","
                       "\"attributes\":["
                       "{\"name\":\"userName\",\"type\":\"string\",\"multiValued\":false,\"required\":true,"
                       "\"caseExact\":false,"
                       "\"mutability\":\"readWrite\",\"returned\":\"default\",\"uniqueness\":\"server\"},"
                       "{\"name\":\"externalId\",\"type\":\"string\",\"multiValued\":false,\"required\":"
                       "false,\"caseExact\":true,"
                       "\"mutability\":\"readWrite\",\"returned\":\"default\",\"uniqueness\":\"none\"},"
                       "{\"name\":\"displayName\",\"type\":\"string\",\"multiValued\":false,\"required\":"
                       "false,\"caseExact\":false,"
                       "\"mutability\":\"readWrite\",\"returned\":\"default\",\"uniqueness\":\"none\"},"
                       "{\"name\":\"active\",\"type\":\"boolean\",\"multiValued\":false,\"required\":false,"
                       "\"mutability\":\"readWrite\",\"returned\":\"default\"}],"
                       "\"meta\":{\"resourceType\":\"Schema\"}}]}");
}

/* ---- groups (roles kept current, docs/design/roles-current.md) --------------------------------- */

buckets_scim_group *buckets_scim_find_group(buckets_scim_store *s, const char *id) {
  for (size_t i = 0; i < s->ng; i++)
    if (!strcmp(s->g[i].id, id)) return &s->g[i];
  return NULL;
}

bool buckets_scim_group_filter_match(const buckets_scim_filter *f, const buckets_scim_group *g) {
  if (!*f->attr) return true;
  if (!strcmp(f->attr, "displayName")) return g->display_name && !strcasecmp(g->display_name, f->value);
  if (!strcmp(f->attr, "externalId")) return g->external_id && !strcmp(g->external_id, f->value);
  return false;
}

static void member_add(buckets_scim_group *g, const char *id) {
  if (!id || !*id) return;
  for (size_t i = 0; i < g->nmembers; i++)
    if (!strcmp(g->members[i], id)) return;
  g->members = buckets_xrealloc(g->members, (g->nmembers + 1) * sizeof(char *));
  g->members[g->nmembers++] = buckets_xstrdup(id);
}

static void member_remove(buckets_scim_group *g, const char *id) {
  for (size_t i = 0; i < g->nmembers; i++) {
    if (strcmp(g->members[i], id) != 0) continue;
    free(g->members[i]);
    g->members[i] = g->members[--g->nmembers];
    return;
  }
}

static void members_clear(buckets_scim_group *g) {
  for (size_t i = 0; i < g->nmembers; i++) free(g->members[i]);
  g->nmembers = 0;
}

/* members: [{"value": id}, ...] (or bare strings) */
static void members_from(buckets_scim_group *g, yyjson_val *arr, bool add) {
  if (yyjson_is_obj(arr)) { /* a single member, as some providers send it */
    const char *id = yyjson_get_str(yyjson_obj_get(arr, "value"));
    if (add) member_add(g, id);
    else if (id) member_remove(g, id);
    return;
  }
  size_t i, n;
  yyjson_val *m;
  yyjson_arr_foreach(arr, i, n, m) {
    const char *id = yyjson_is_str(m) ? yyjson_get_str(m) : yyjson_get_str(yyjson_obj_get(m, "value"));
    if (add) member_add(g, id);
    else if (id) member_remove(g, id);
  }
}

static void set_opt(char **dst, yyjson_val *v) {
  free(*dst);
  *dst = yyjson_is_str(v) && *yyjson_get_str(v) ? buckets_xstrdup(yyjson_get_str(v)) : NULL;
}

bool buckets_scim_group_from_json(yyjson_val *body, buckets_scim_group *out, int *status, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (!yyjson_is_obj(body)) return fail(status, 400, err, errlen, "The body must be a JSON object");
  set_opt(&out->display_name, yyjson_obj_get(body, "displayName"));
  set_opt(&out->external_id, yyjson_obj_get(body, "externalId"));
  if (!out->display_name) {
    buckets_scim_group_free(out);
    return fail(status, 400, err, errlen, "displayName is required");
  }
  members_from(out, yyjson_obj_get(body, "members"), true);
  return true;
}

/* members[value eq "id"]: the id; NULL when the path is something else. */
static char *member_filter(const char *path) {
  const char *b = strchr(path, '[');
  if (!b || strncasecmp(path, "members", 7) != 0) return NULL;
  buckets_scim_filter f;
  char inner[600];
  snprintf(inner, sizeof(inner), "%.*s", (int)strcspn(b + 1, "]"), b + 1);
  /* reuse the user filter's parsing: "value eq ..." becomes "userName eq ..." to pass its attribute check */
  if (strncasecmp(inner, "value", 5) != 0) return NULL;
  char tmp[640];
  snprintf(tmp, sizeof(tmp), "userName%s", inner + 5);
  if (!buckets_scim_filter_parse(tmp, &f)) return NULL;
  return buckets_xstrdup(f.value);
}

bool buckets_scim_group_patch(buckets_scim_group *g, yyjson_val *body, int *status, char *err, size_t errlen) {
  yyjson_val *ops = yyjson_obj_get(body, "Operations");
  if (!ops) ops = yyjson_obj_get(body, "operations");
  if (!yyjson_is_arr(ops)) return fail(status, 400, err, errlen, "A PatchOp needs Operations");
  size_t i, n;
  yyjson_val *op;
  yyjson_arr_foreach(ops, i, n, op) {
    const char *kind = yyjson_get_str(yyjson_obj_get(op, "op"));
    const char *path = yyjson_get_str(yyjson_obj_get(op, "path"));
    yyjson_val *value = yyjson_obj_get(op, "value");
    if (!kind) return fail(status, 400, err, errlen, "An operation needs op");
    bool add = !strcasecmp(kind, "add"), rem = !strcasecmp(kind, "remove"), repl = !strcasecmp(kind, "replace");
    if (!add && !rem && !repl) return fail(status, 400, err, errlen, "op is add, replace or remove");
    if (!path || !*path) { /* a value object: displayName, externalId, members */
      if (!yyjson_is_obj(value)) return fail(status, 400, err, errlen, "Without a path, the value must be an object");
      yyjson_val *dn = yyjson_obj_get(value, "displayName"), *ex = yyjson_obj_get(value, "externalId");
      if (dn) set_opt(&g->display_name, dn);
      if (ex) set_opt(&g->external_id, ex);
      yyjson_val *ms = yyjson_obj_get(value, "members");
      if (ms) {
        if (repl) members_clear(g);
        members_from(g, ms, !rem);
      }
      continue;
    }
    char *mid = member_filter(path);
    if (mid) { /* members[value eq "id"] */
      if (rem) member_remove(g, mid);
      free(mid);
      continue;
    }
    if (!strcasecmp(path, "members")) {
      if (repl || (rem && !value)) members_clear(g);
      if (value) members_from(g, value, !rem);
    } else if (!strcasecmp(path, "displayName")) {
      if (rem) return fail(status, 400, err, errlen, "displayName can't be removed");
      set_opt(&g->display_name, value);
    } else if (!strcasecmp(path, "externalId")) {
      if (rem) set_opt(&g->external_id, NULL);
      else set_opt(&g->external_id, value);
    }
  }
  if (!g->display_name) return fail(status, 400, err, errlen, "displayName is required");
  return true;
}

void buckets_scim_group_json(const buckets_scim_group *g, const char *base, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_arr_add_str(d, yyjson_mut_obj_add_arr(d, o, "schemas"), "urn:ietf:params:scim:schemas:core:2.0:Group");
  yyjson_mut_obj_add_strcpy(d, o, "id", g->id);
  if (g->external_id) yyjson_mut_obj_add_strcpy(d, o, "externalId", g->external_id);
  yyjson_mut_obj_add_strcpy(d, o, "displayName", g->display_name ? g->display_name : "");
  yyjson_mut_val *ms = yyjson_mut_obj_add_arr(d, o, "members");
  for (size_t i = 0; i < g->nmembers; i++) {
    yyjson_mut_val *m = yyjson_mut_arr_add_obj(d, ms);
    yyjson_mut_obj_add_strcpy(d, m, "value", g->members[i]);
  }
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, o, "meta");
  char t[40];
  yyjson_mut_obj_add_str(d, m, "resourceType", "Group");
  iso(g->created, t);
  yyjson_mut_obj_add_strcpy(d, m, "created", t);
  iso(g->modified, t);
  yyjson_mut_obj_add_strcpy(d, m, "lastModified", t);
  if (base && *base) {
    char loc[1024];
    snprintf(loc, sizeof(loc), "%s/Groups/%s", base, g->id);
    yyjson_mut_obj_add_strcpy(d, m, "location", loc);
  }
  write_doc(d, out);
}

static int cmp_sp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

size_t buckets_scim_values_of(const buckets_scim_store *s, const char *person, bool by_external, char ***out) {
  *out = NULL;
  size_t n = 0;
  for (size_t u = 0; u < s->n; u++) {
    const buckets_scim_user *usr = &s->u[u];
    if (usr->deleted || !usr->external_id || strcmp(usr->external_id, person) != 0) continue;
    for (size_t g = 0; g < s->ng; g++) {
      bool member = false;
      for (size_t m = 0; m < s->g[g].nmembers && !member; m++) member = !strcmp(s->g[g].members[m], usr->id);
      const char *v = by_external ? s->g[g].external_id : s->g[g].display_name;
      if (!member || !v || !*v) continue;
      bool seen = false;
      for (size_t k = 0; k < n && !seen; k++) seen = !strcmp((*out)[k], v);
      if (seen) continue;
      *out = buckets_xrealloc(*out, (n + 1) * sizeof(char *));
      (*out)[n++] = buckets_xstrdup(v);
    }
  }
  if (n) qsort(*out, n, sizeof(char *), cmp_sp);
  return n;
}

void buckets_scim_values_free(char **v, size_t n) {
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
}
