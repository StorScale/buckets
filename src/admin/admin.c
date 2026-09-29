/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The madmin-compatible admin API (/minio/admin/v3): IAM users, groups,
 * canned policies, policy mappings and service accounts.
 * Replaces MinIO's cmd/admin-handlers-users.go. */
#include "admin/admin.h"
#include "siterepl/siterepl.h"
#include "notify/event.h"
#include "core/timefmt.h"
#include "logger/console.h"
#include "trace/trace.h"
#include "dist/peerstream.h"
#include "dist/peer.h"
#include "dist/internode.h"
#include <strings.h>
#include "admin/info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "core/log.h"
#include "core/timefmt.h"
#include "config/sys.h"
#include "crypto/madmin.h"
#include "iam/ldapidp.h"
#include "iam/openid.h"
#include "iam/plugins.h"

#define ADMIN_PREFIX "/minio/admin/v3"
#define MAX_ECONFIG_JSON (262272) /* maxEConfigJSONSize */

/* ---- responses -------------------------------------------------------------------- */

/* writeErrorResponseJSON: APIErrorResponse as json.Encoder writes it (Go's
 * escaping, a trailing newline), the deployment as its HostId. */
void buckets_admin_json_error(s3_ctx *c, int status, const char *code, const char *message, const char *key,
                              const char *bucket) {
  buckets_buf b = BUCKETS_BUF_INIT;
  const char *host = c->s->layer ? c->s->layer->deployment_id_str : "";
  const char *res = c->path ? c->path : "/";
  buckets_buf_append_c(&b, "{\"Code\":");
  buckets_json_go_string(&b, code, strlen(code));
  buckets_buf_append_c(&b, ",\"Message\":");
  buckets_json_go_string(&b, message, strlen(message));
  if (key && *key) { /* omitempty */
    buckets_buf_append_c(&b, ",\"Key\":");
    buckets_json_go_string(&b, key, strlen(key));
  }
  if (bucket && *bucket) {
    buckets_buf_append_c(&b, ",\"BucketName\":");
    buckets_json_go_string(&b, bucket, strlen(bucket));
  }
  buckets_buf_append_c(&b, ",\"Resource\":");
  buckets_json_go_string(&b, res, strlen(res));
  buckets_buf_append_c(&b, ",\"RequestId\":");
  buckets_json_go_string(&b, c->request_id, strlen(c->request_id));
  buckets_buf_append_c(&b, ",\"HostId\":");
  buckets_json_go_string(&b, host, strlen(host));
  buckets_buf_append_c(&b, "}\n");
  c->resp->status = status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, b.data, b.len);
  buckets_buf_free(&b);
}

void buckets_admin_error_msg(s3_ctx *c, buckets_s3_error e, const char *message) {
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  /* reqInfo's bucket and key, when a handler named them (APIErrorResponse omitempty) */
  buckets_admin_json_error(c, info->status, info->code, message ? message : info->message, c->err_object, c->err_bucket);
}

void buckets_admin_error(s3_ctx *c, buckets_s3_error e) { buckets_admin_error_msg(c, e, NULL); }

/* A custom-coded admin error (AdminError / APIError literals in MinIO). */
static void custom_error(s3_ctx *c, int status, const char *code, const char *message) {
  buckets_admin_json_error(c, status, code, message, NULL, NULL);
}

/* toAdminAPIErr for IAM store errors. */
static void iam_error(s3_ctx *c, buckets_iam_err e, const char *detail) {
  buckets_s3_error code;
  switch (e) {
    case BUCKETS_IAM_ERR_INVALID_ARGUMENT: code = BUCKETS_ERR_ADMIN_INVALID_ARGUMENT; break;
    case BUCKETS_IAM_ERR_NO_SUCH_USER: code = BUCKETS_ERR_ADMIN_NO_SUCH_USER; break;
    case BUCKETS_IAM_ERR_NO_SUCH_GROUP: code = BUCKETS_ERR_ADMIN_NO_SUCH_GROUP; break;
    case BUCKETS_IAM_ERR_NO_SUCH_POLICY: code = BUCKETS_ERR_ADMIN_NO_SUCH_POLICY; break;
    case BUCKETS_IAM_ERR_NO_SUCH_SVC: code = BUCKETS_ERR_ADMIN_SERVICE_ACCOUNT_NOT_FOUND; break;
    case BUCKETS_IAM_ERR_GROUP_NOT_EMPTY: code = BUCKETS_ERR_ADMIN_GROUP_NOT_EMPTY; break;
    case BUCKETS_IAM_ERR_GROUP_DISABLED: code = BUCKETS_ERR_ADMIN_GROUP_DISABLED; break;
    case BUCKETS_IAM_ERR_NO_POLICY_CHANGE: code = BUCKETS_ERR_ADMIN_POLICY_CHANGE_ALREADY_APPLIED; break;
    case BUCKETS_IAM_ERR_INVALID_ACCESS_KEY: code = BUCKETS_ERR_ADMIN_INVALID_ACCESS_KEY; break;
    case BUCKETS_IAM_ERR_INVALID_SECRET_KEY: code = BUCKETS_ERR_ADMIN_INVALID_SECRET_KEY; break;
    case BUCKETS_IAM_ERR_NOT_INITIALIZED: code = BUCKETS_ERR_IAM_NOT_INITIALIZED; break;
    case BUCKETS_IAM_ERR_INVALID_EXPIRATION: code = BUCKETS_ERR_ADMIN_INVALID_ARGUMENT; break;
    case BUCKETS_IAM_ERR_NOT_ALLOWED:
      custom_error(c, 403, "XMinioIAMActionNotAllowed", "Specified IAM action is not allowed");
      return;
    default: code = BUCKETS_ERR_INTERNAL_ERROR; break;
  }
  buckets_admin_error_msg(c, code, detail);
}

static void write_json(s3_ctx *c, yyjson_mut_doc *d, bool encrypt) {
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  if (encrypt) {
    if (!buckets_madmin_encrypt(c->ident->secret_key, json, len, &c->resp->body)) {
      free(json);
      buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
      return;
    }
  } else {
    buckets_buf_append(&c->resp->body, json, len);
  }
  free(json);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

static void time_str(buckets_iam_time t, char out[BUCKETS_TIME_RFC3339_NANO_LEN + 1]) {
  buckets_time_rfc3339_nano(t.sec, t.nsec, out);
}

static void add_time(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, buckets_iam_time t) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  time_str(t, ts);
  yyjson_mut_obj_add_strcpy(d, o, key, ts);
}

static bool parse_time(yyjson_val *v, buckets_iam_time *out) {
  const char *s = yyjson_get_str(v);
  return s && buckets_time_parse_rfc3339(s, &out->sec, &out->nsec);
}

/* ---- authorization ------------------------------------------------------------------ */

static const char *requestor(const s3_ctx *c) { return c->ident ? c->ident->access_key : ""; }
static const char *requestor_parent(const s3_ctx *c) {
  if (c->ident && c->ident->parent && *c->ident->parent) return c->ident->parent;
  return requestor(c);
}

/* validateAdminSignature: a SigV4 header-signed request carrying X-Amz-Content-Sha256. */
static bool admin_signed(s3_ctx *c) {
  if (!c->ident || c->auth != BUCKETS_AUTH_SIGV4_HEADER ||
      !buckets_http_header_get(c->req, "X-Amz-Content-Sha256").p) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return false;
  }
  return true;
}

static bool allowed(s3_ctx *c, const char *action, bool deny_only) {
  return buckets_s3_allowed(c, action, NULL, NULL, deny_only);
}

/* validateAdminReq: the first allowed of the given actions. */
static bool admin_req(s3_ctx *c, const char *const *actions, size_t n) {
  if (!admin_signed(c)) return false;
  for (size_t i = 0; i < n; i++) {
    if (allowed(c, actions[i], false)) return true;
  }
  buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
  return false;
}

static bool admin_req1(s3_ctx *c, const char *action) { return admin_req(c, &action, 1); }

/* Reads and madmin-decrypts the body with the requestor's secret key. */
static yyjson_doc *read_encrypted(s3_ctx *c) {
  if (c->req->body_len > MAX_ECONFIG_JSON) {
    custom_error(c, 400, "XMinioAdminConfigTooLarge",
                 "Configuration data provided exceeds the allowed maximum of 262272 bytes");
    return NULL;
  }
  buckets_s3_error e = buckets_s3_read_doc(c);
  if (e) {
    buckets_admin_error(c, e);
    return NULL;
  }
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (!buckets_madmin_decrypt(c->ident->secret_key, c->doc.data, c->doc.len, &plain)) {
    buckets_buf_free(&plain);
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON);
    return NULL;
  }
  yyjson_doc *d = yyjson_read(plain.data ? plain.data : "", plain.len, 0);
  buckets_buf_free(&plain);
  if (!d) buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON);
  return d;
}

static yyjson_doc *read_plain(s3_ctx *c) {
  buckets_s3_error e = buckets_s3_read_doc(c);
  if (e) {
    buckets_admin_error(c, e);
    return NULL;
  }
  yyjson_doc *d = yyjson_read(c->doc.data ? c->doc.data : "", c->doc.len, 0);
  if (!d) buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
  return d;
}

static const char *qget(s3_ctx *c, const char *key) {
  const char *v = buckets_query_get(&c->q, key);
  return v ? v : "";
}

/* hasSpaceBE: leading or trailing whitespace. */
static bool has_space_be(const char *s) {
  size_t n = strlen(s);
  return n && (s[0] == ' ' || s[0] == '\t' || s[n - 1] == ' ' || s[n - 1] == '\t' || s[0] == '\n' ||
               s[n - 1] == '\n');
}

static bool utf8_ok(const char *s) {
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {
    size_t k = *p < 0x80 ? 1 : (*p >> 5) == 6 ? 2 : (*p >> 4) == 14 ? 3 : (*p >> 3) == 30 ? 4 : 0;
    if (!k) return false;
    for (size_t j = 1; j < k; j++) {
      if ((p[j] & 0xC0) != 0x80) return false;
    }
    p += k;
  }
  return true;
}

/* ---- users --------------------------------------------------------------------------- */

static void add_user_info(yyjson_mut_doc *d, yyjson_mut_val *o, const buckets_iam_user_info *u) {
  if (*u->policy) yyjson_mut_obj_add_strcpy(d, o, "policyName", u->policy);
  yyjson_mut_obj_add_str(d, o, "status", u->enabled ? "enabled" : "disabled");
  if (u->nmember_of) {
    yyjson_mut_val *m = yyjson_mut_obj_add_arr(d, o, "memberOf");
    for (size_t i = 0; i < u->nmember_of; i++) yyjson_mut_arr_add_strcpy(d, m, u->member_of[i]);
  }
  add_time(d, o, "updatedAt", u->updated);
}

static void h_add_user(s3_ctx *c) {
  const char *ak = qget(c, "accessKey");
  if (!admin_signed(c)) return;
  buckets_iam *iam = c->s->iam;
  if (strcmp(ak, buckets_iam_root_access_key(iam)) == 0) {
    buckets_admin_error(c, BUCKETS_ERR_ADD_USER_INVALID_ARGUMENT);
    return;
  }
  buckets_iam_ident *cur = buckets_iam_get_ident(iam, ak);
  bool exists = cur != NULL;
  bool derived = cur && (buckets_iam_ident_is_temp(cur) || buckets_iam_ident_is_svc(cur));
  buckets_iam_ident_release(cur);
  bool self_derived = (buckets_iam_ident_is_temp(c->ident) || buckets_iam_ident_is_svc(c->ident)) &&
                      c->ident->parent && strcmp(c->ident->parent, ak) == 0;
  if (derived || self_derived) {
    buckets_admin_error(c, BUCKETS_ERR_ADD_USER_INVALID_ARGUMENT);
    return;
  }
  if (!exists && has_space_be(ak)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT);
    return;
  }
  if (!utf8_ok(ak)) {
    buckets_admin_error(c, BUCKETS_ERR_ADD_USER_VALID_UTF);
    return;
  }
  if (!allowed(c, "admin:CreateUser", strcmp(ak, requestor(c)) == 0)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  yyjson_doc *req = read_encrypted(c);
  if (!req) return;
  yyjson_val *root = yyjson_doc_get_root(req);
  const char *sk = yyjson_get_str(yyjson_obj_get(root, "secretKey"));
  const char *status = yyjson_get_str(yyjson_obj_get(root, "status"));
  buckets_iam_err e = buckets_iam_add_user(iam, ak, sk ? sk : "", status ? status : "");
  if (e) {
    iam_error(c, e, NULL);
  } else {
    c->resp->status = 200;
    buckets_sr_iam_user(c->s->sr, ak, false, sk, status);
  }
  yyjson_doc_free(req);
}

static void h_remove_user(s3_ctx *c) {
  if (!admin_req1(c, "admin:DeleteUser")) return;
  const char *ak = qget(c, "accessKey");
  buckets_iam *iam = c->s->iam;
  buckets_iam_ident *cur = buckets_iam_get_ident(iam, ak);
  bool derived = cur && (buckets_iam_ident_is_temp(cur) || buckets_iam_ident_is_svc(cur));
  buckets_iam_ident_release(cur);
  if (derived || strcmp(ak, buckets_iam_root_access_key(iam)) == 0 || strcmp(ak, requestor(c)) == 0) {
    iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
    return;
  }
  buckets_iam_err e = buckets_iam_delete_user(iam, ak);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  c->resp->status = 200;
  buckets_sr_iam_user(c->s->sr, ak, true, NULL, NULL);
}

static void h_list_users(s3_ctx *c) {
  if (!admin_req1(c, "admin:ListUsers")) return;
  buckets_iam_user_info *users;
  size_t n;
  buckets_iam_list_users(c->s->iam, &users, &n);
  const char *bucket = buckets_query_get(&c->q, "bucket");
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < n; i++) {
    (void)bucket; /* ListBucketUsers: filtering by bucket access lands with bucket policies */
    yyjson_mut_val *o = yyjson_mut_obj(d);
    add_user_info(d, o, &users[i]);
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, users[i].name), o);
  }
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
  buckets_iam_user_info_free(users, n);
  free(users);
}

static void h_user_info(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *name = qget(c, "accessKey");
  if (!allowed(c, "admin:GetUser", strcmp(name, requestor(c)) == 0)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  buckets_iam_user_info u;
  buckets_iam_err e = buckets_iam_get_user_info(c->s->iam, name, &u);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  add_user_info(d, root, &u);
  write_json(c, d, false);
  yyjson_mut_doc_free(d);
  buckets_iam_user_info_free(&u, 1);
}

static void h_set_user_status(s3_ctx *c) {
  if (!admin_req1(c, "admin:EnableUser")) return;
  const char *ak = qget(c, "accessKey"), *status = qget(c, "status");
  if (strcmp(ak, requestor(c)) == 0 || (strcmp(status, "enabled") != 0 && strcmp(status, "disabled") != 0)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT);
    return;
  }
  buckets_iam_err e = buckets_iam_set_user_status(c->s->iam, ak, strcmp(status, "enabled") == 0);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  c->resp->status = 200;
  buckets_sr_iam_user(c->s->sr, ak, false, NULL, status);
}

/* ---- groups ----------------------------------------------------------------------------- */

static void h_update_group_members(s3_ctx *c) {
  if (!admin_req1(c, "admin:AddUserToGroup")) return;
  yyjson_doc *req = read_plain(c);
  if (!req) return;
  yyjson_val *root = yyjson_doc_get_root(req);
  const char *group = yyjson_get_str(yyjson_obj_get(root, "group"));
  bool is_remove = yyjson_get_bool(yyjson_obj_get(root, "isRemove"));
  yyjson_val *mv = yyjson_obj_get(root, "members");
  size_t n = yyjson_is_arr(mv) ? yyjson_arr_size(mv) : 0;
  const char **members = buckets_xcalloc(n ? n : 1, sizeof(char *));
  size_t m = 0;
  size_t i, max;
  yyjson_val *v;
  buckets_iam *iam = c->s->iam;
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (n) {
    yyjson_arr_foreach(mv, i, max, v) {
      const char *name = yyjson_get_str(v);
      if (!name) continue;
      buckets_iam_ident *cur = buckets_iam_get_ident(iam, name);
      bool temp = cur && buckets_iam_ident_is_temp(cur);
      buckets_iam_ident_release(cur);
      if (temp || strcmp(name, buckets_iam_root_access_key(iam)) == 0) e = BUCKETS_IAM_ERR_NOT_ALLOWED;
      members[m++] = name;
    }
  }
  if (!e && !group) e = BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  if (!e && is_remove) {
    e = buckets_iam_group_remove_members(iam, group, members, m);
  } else if (!e) {
    buckets_iam_group_desc gd;
    bool exists = buckets_iam_group_describe(iam, group, &gd) == BUCKETS_IAM_OK;
    if (exists) buckets_iam_group_desc_free(&gd);
    if (!exists && has_space_be(group)) {
      buckets_admin_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT);
      goto out;
    }
    e = buckets_iam_group_add_members(iam, group, members, m);
  }
  if (e) {
    iam_error(c, e, NULL);
  } else {
    c->resp->status = 200;
    const char *gs = yyjson_get_str(yyjson_obj_get(root, "groupStatus"));
    buckets_sr_iam_group(c->s->sr, group, members, m, gs, is_remove);
  }
out:
  free(members);
  yyjson_doc_free(req);
}

static void h_get_group(s3_ctx *c) {
  if (!admin_req1(c, "admin:GetGroup")) return;
  buckets_iam_group_desc gd;
  buckets_iam_err e = buckets_iam_group_describe(c->s->iam, qget(c, "group"), &gd);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "name", gd.name);
  yyjson_mut_obj_add_strcpy(d, root, "status", gd.status);
  yyjson_mut_val *m = yyjson_mut_obj_add_arr(d, root, "members");
  for (size_t i = 0; i < gd.nmembers; i++) yyjson_mut_arr_add_strcpy(d, m, gd.members[i]);
  yyjson_mut_obj_add_strcpy(d, root, "policy", gd.policy);
  add_time(d, root, "updatedAt", gd.updated);
  write_json(c, d, false);
  yyjson_mut_doc_free(d);
  buckets_iam_group_desc_free(&gd);
}

static void h_list_groups(s3_ctx *c) {
  if (!admin_req1(c, "admin:ListGroups")) return;
  char **groups;
  size_t n;
  buckets_iam_list_groups(c->s->iam, &groups, &n);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < n; i++) yyjson_mut_arr_add_strcpy(d, root, groups[i]);
  write_json(c, d, false);
  yyjson_mut_doc_free(d);
  for (size_t i = 0; i < n; i++) free(groups[i]);
  free(groups);
}

static void h_set_group_status(s3_ctx *c) {
  if (!admin_req1(c, "admin:EnableGroup")) return;
  const char *status = qget(c, "status");
  buckets_iam_err e;
  if (strcmp(status, "enabled") == 0) e = buckets_iam_group_set_status(c->s->iam, qget(c, "group"), true);
  else if (strcmp(status, "disabled") == 0) e = buckets_iam_group_set_status(c->s->iam, qget(c, "group"), false);
  else e = BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  c->resp->status = 200;
  buckets_sr_iam_group(c->s->sr, qget(c, "group"), NULL, 0, status, false);
}

/* ---- canned policies --------------------------------------------------------------------- */

static void h_list_policies(s3_ctx *c) {
  if (!admin_req1(c, "admin:ListUserPolicies")) return;
  buckets_iam_policy_doc *docs;
  size_t n;
  buckets_iam_list_policies(c->s->iam, &docs, &n);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_doc **parsed = buckets_xcalloc(n ? n : 1, sizeof(*parsed));
  for (size_t i = 0; i < n; i++) {
    parsed[i] = yyjson_read(docs[i].json, strlen(docs[i].json), 0);
    if (!parsed[i]) continue;
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, docs[i].name), yyjson_val_mut_copy(d, yyjson_doc_get_root(parsed[i])));
  }
  write_json(c, d, false);
  buckets_buf_append_c(&c->resp->body, "\n"); /* json.Encoder */
  yyjson_mut_doc_free(d);
  for (size_t i = 0; i < n; i++) yyjson_doc_free(parsed[i]);
  free(parsed);
  buckets_iam_policy_doc_free(docs, n);
  free(docs);
}

static void h_info_policy(s3_ctx *c) {
  if (!admin_req1(c, "admin:GetPolicy")) return;
  const char *name = qget(c, "name");
  if (!*name || strchr(name, ',')) {
    custom_error(c, 400, "XMinioAdminInvalidRequest", "only a single policy is allowed here");
    return;
  }
  const char *v = qget(c, "v");
  if (*v && strcmp(v, "2") != 0) {
    buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, "invalid version parameter 'v' supplied");
    return;
  }
  buckets_iam_policy_doc pd;
  buckets_iam_err e = buckets_iam_get_policy(c->s->iam, name, &pd);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  yyjson_doc *pol = yyjson_read(pd.json, strlen(pd.json), 0);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  if (*v) {
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_strcpy(d, root, "PolicyName", name);
    yyjson_mut_obj_add_val(d, root, "Policy", yyjson_val_mut_copy(d, yyjson_doc_get_root(pol)));
    if (buckets_iam_time_is_set(pd.created) || buckets_iam_time_is_set(pd.updated)) {
      add_time(d, root, "CreateDate", pd.created);
      add_time(d, root, "UpdateDate", pd.updated);
    }
  } else {
    yyjson_mut_doc_set_root(d, yyjson_val_mut_copy(d, yyjson_doc_get_root(pol)));
  }
  size_t len;
  char *json = yyjson_mut_write(d, YYJSON_WRITE_PRETTY, &len);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, json, len);
  free(json);
  c->resp->status = 200;
  yyjson_mut_doc_free(d);
  yyjson_doc_free(pol);
  buckets_iam_policy_doc_free(&pd, 1);
}

static void h_add_policy(s3_ctx *c) {
  if (!admin_req1(c, "admin:CreatePolicy")) return;
  const char *name = qget(c, "name");
  if (has_space_be(name)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT);
    return;
  }
  if (strchr(name, ',')) {
    buckets_admin_error(c, BUCKETS_ERR_POLICY_INVALID_NAME);
    return;
  }
  if (c->req->body_len <= 0) {
    buckets_admin_error(c, BUCKETS_ERR_MISSING_CONTENT_LENGTH);
    return;
  }
  if (c->req->body_len > 20 * 1024) { /* maxBucketPolicySize */
    buckets_admin_error(c, BUCKETS_ERR_ENTITY_TOO_LARGE);
    return;
  }
  buckets_s3_error re = buckets_s3_read_doc(c);
  if (re) {
    buckets_admin_error(c, re);
    return;
  }
  char err[512];
  buckets_policy *p;
  if (!buckets_policy_parse(c->doc.data, c->doc.len, &p, err, sizeof(err))) {
    custom_error(c, 400, "XMinioMalformedIAMPolicy", err);
    return;
  }
  bool no_version = !*buckets_policy_version(p);
  buckets_policy_free(p);
  if (no_version) {
    buckets_admin_error(c, BUCKETS_ERR_POLICY_INVALID_VERSION);
    return;
  }
  buckets_iam_err e = buckets_iam_set_policy(c->s->iam, name, c->doc.data, c->doc.len, err, sizeof(err));
  if (e == BUCKETS_IAM_ERR_MALFORMED_POLICY) {
    custom_error(c, 400, "XMinioMalformedIAMPolicy", err);
  } else if (e) {
    iam_error(c, e, NULL);
  } else {
    c->resp->status = 200;
    buckets_sr_iam_policy(c->s->sr, name, c->doc.data);
  }
}

static void h_remove_policy(s3_ctx *c) {
  if (!admin_req1(c, "admin:DeletePolicy")) return;
  buckets_iam_err e = buckets_iam_delete_policy(c->s->iam, qget(c, "name"));
  if (e == BUCKETS_IAM_ERR_POLICY_IN_USE) {
    custom_error(c, 400, "XMinioIAMPolicyInUse", "The policy cannot be removed, as it is in use");
  } else if (e) {
    iam_error(c, e, NULL);
  } else {
    c->resp->status = 200;
    buckets_sr_iam_policy(c->s->sr, qget(c, "name"), NULL);
  }
}

/* SetPolicyForUserOrGroup (the legacy mc admin policy set). */
static void h_set_user_or_group_policy(s3_ctx *c) {
  if (!admin_req1(c, "admin:AttachUserOrGroupPolicy")) return;
  const char *policy = qget(c, "policyName"), *entity = qget(c, "userOrGroup");
  bool is_group = strcmp(qget(c, "isGroup"), "true") == 0;
  buckets_iam *iam = c->s->iam;
  bool ldap = buckets_iam_ldap_mode(iam);
  if (!is_group) {
    buckets_iam_ident *cur = buckets_iam_get_ident(iam, entity);
    bool temp = cur && buckets_iam_ident_is_temp(cur);
    bool exists = cur && cur->type == BUCKETS_IAM_REG;
    buckets_iam_ident_release(cur);
    if (temp || strcmp(entity, buckets_iam_root_access_key(iam)) == 0) {
      iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
      return;
    }
    if (!exists && !ldap) {
      iam_error(c, BUCKETS_IAM_ERR_NO_SUCH_USER, NULL);
      return;
    }
  } else {
    buckets_iam_group_desc gd;
    buckets_iam_err ge = buckets_iam_group_describe(iam, entity, &gd);
    if (ge) {
      iam_error(c, ge, NULL);
      return;
    }
    buckets_iam_group_desc_free(&gd);
  }
  if (ldap) {
    /* The user or group must be in the directory; map its normalized DN. */
    buckets_ldapidp *lp = buckets_s3_ldap(c->s);
    buckets_ldap_dnres res;
    char err[1024];
    bool under = true;
    int r = is_group ? buckets_ldapidp_validated_group(lp, entity, &res, &under, err, sizeof(err))
                     : buckets_ldapidp_validated_user(lp, entity, &res, err, sizeof(err));
    buckets_ldapidp_release(lp);
    if (r < 0) {
      buckets_log_warn("ldap: %s", err);
      buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
      return;
    }
    if (r == 0 || !under) {
      if (r > 0) buckets_ldap_dnres_free(&res);
      iam_error(c, is_group ? BUCKETS_IAM_ERR_NO_SUCH_GROUP : BUCKETS_IAM_ERR_NO_SUCH_USER, NULL);
      return;
    }
    buckets_iam_err e = buckets_iam_policy_set(iam, res.norm_dn, is_group, BUCKETS_IAM_STS, policy);
    if (e) {
      iam_error(c, e, NULL);
    } else {
      c->resp->status = 200;
      buckets_sr_iam_mapping(c->s->sr, res.norm_dn, 1, is_group, policy);
    }
    buckets_ldap_dnres_free(&res);
    return;
  }
  buckets_iam_err e = buckets_iam_policy_set(iam, entity, is_group, BUCKETS_IAM_REG, policy);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  c->resp->status = 200;
  buckets_sr_iam_mapping(c->s->sr, entity, 0, is_group, policy);
}

static void add_csv_array(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, const char *csv) {
  if (!csv || !*csv) return;
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, key);
  const char *p = csv;
  while (*p) {
    const char *e = strchr(p, ',');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    yyjson_mut_arr_add_strncpy(d, a, p, n);
    p = e ? e + 1 : p + n;
  }
}

/* AttachDetachPolicyBuiltin, and AttachDetachPolicyLDAP (PolicyDBUpdateLDAP). */
static void attach_detach(s3_ctx *c, bool attach, bool ldap) {
  static const char *const actions[] = {"admin:UpdatePolicyAssociation", "admin:AttachUserOrGroupPolicy"};
  if (!admin_req(c, actions, ldap ? 1 : 2)) return;
  buckets_ldapidp *lp = NULL;
  if (ldap) {
    lp = buckets_s3_ldap(c->s);
    bool on = buckets_ldapidp_enabled(lp);
    if (!on) {
      buckets_ldapidp_release(lp);
      buckets_admin_error(c, BUCKETS_ERR_ADMIN_LDAP_NOT_ENABLED);
      return;
    }
  }
  yyjson_doc *req = NULL;
  const char **policies = NULL;
  char *changed = NULL, *dn = NULL, *effective = NULL;
  buckets_ldap_dnres res = {0};
  if (c->req->body_len > MAX_ECONFIG_JSON) {
    custom_error(c, 400, "XMinioAdminConfigTooLarge",
                 "Configuration data provided exceeds the allowed maximum of 262272 bytes");
    goto out;
  }
  buckets_str ct = buckets_http_header_get(c->req, "Content-Type");
  if (!ct.p || !buckets_str_eq_c(ct, "application/octet-stream")) {
    buckets_admin_error(c, BUCKETS_ERR_BAD_REQUEST);
    goto out;
  }
  if (!(req = read_encrypted(c))) goto out;
  yyjson_val *root = yyjson_doc_get_root(req);
  const char *user = yyjson_get_str(yyjson_obj_get(root, "user"));
  const char *group = yyjson_get_str(yyjson_obj_get(root, "group"));
  yyjson_val *pv = yyjson_obj_get(root, "policies");
  size_t np = yyjson_is_arr(pv) ? yyjson_arr_size(pv) : 0;
  bool has_user = user && *user, has_group = group && *group;
  buckets_iam *iam = c->s->iam;
  buckets_iam_err e = BUCKETS_IAM_OK;
  /* PolicyAssociationReq.IsValid */
  if (!np || has_user == has_group) {
    custom_error(c, 400, "XMinioAdminInvalidArgument",
                 !np ? "no policy names were given" : "exactly one of user or group must be specified");
    goto out;
  }
  policies = buckets_xcalloc(np, sizeof(char *));
  size_t k = 0, i, max;
  yyjson_val *v;
  yyjson_arr_foreach(pv, i, max, v) {
    if (yyjson_is_str(v)) policies[k++] = yyjson_get_str(v);
  }
  if (ldap) {
    /* The entity must be in the directory (a detach may name a DN that is gone). */
    const char *raw = has_user ? user : group;
    char err[1024];
    bool under = true;
    int r = has_user ? buckets_ldapidp_validated_user(lp, user, &res, err, sizeof(err))
                     : buckets_ldapidp_validated_group(lp, group, &res, &under, err, sizeof(err));
    if (r < 0) {
      buckets_log_warn("ldap: %s", err);
      buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
      goto out;
    }
    if (r > 0 && under) {
      dn = buckets_xstrdup(res.norm_dn);
    } else if (!attach && (has_group || buckets_ldapidp_is_user_dn(lp, user))) {
      dn = buckets_ldapidp_quick_normalize(raw);
    } else {
      iam_error(c, has_user ? BUCKETS_IAM_ERR_NO_SUCH_USER : BUCKETS_IAM_ERR_NO_SUCH_GROUP, NULL);
      goto out;
    }
    /* Backward compatibility: detach from a non-normalized DN too. */
    if (!attach && strcmp(raw, dn) != 0)
      buckets_iam_policy_update_sts(iam, raw, has_group, false, policies, k, NULL, NULL);
    e = buckets_iam_policy_update_sts(iam, dn, has_group, attach, policies, k, &changed, &effective);
  } else {
    if (has_user) {
      buckets_iam_ident *cur = buckets_iam_get_ident(iam, user);
      if (cur && buckets_iam_ident_is_temp(cur)) e = BUCKETS_IAM_ERR_NOT_ALLOWED;
      else if (strcmp(user, buckets_iam_root_access_key(iam)) == 0) e = BUCKETS_IAM_ERR_NOT_ALLOWED;
      else if (!cur || !buckets_iam_ident_is_valid(cur)) e = BUCKETS_IAM_ERR_NO_SUCH_USER;
      buckets_iam_ident_release(cur);
    } else {
      buckets_iam_group_desc gd;
      e = buckets_iam_group_describe(iam, group, &gd);
      if (!e) buckets_iam_group_desc_free(&gd);
    }
    if (!e) e = buckets_iam_policy_update(iam, has_user ? user : group, has_group, attach, policies, k, &changed, &effective);
  }
  if (e) {
    iam_error(c, e, NULL);
    goto out;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *out = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, out);
  add_csv_array(d, out, attach ? "policiesAttached" : "policiesDetached", changed);
  buckets_sr_iam_mapping(c->s->sr, ldap ? dn : has_user ? user : group, ldap ? 1 : 0, has_group,
                         effective ? effective : "");
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  add_time(d, out, "updatedAt", (buckets_iam_time){ts.tv_sec, ts.tv_nsec});
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
out:
  free(changed);
  free(effective);
  free(dn);
  free(policies);
  buckets_ldap_dnres_free(&res);
  buckets_ldapidp_release(lp);
  yyjson_doc_free(req);
}

/* ---- service accounts -------------------------------------------------------------------- */

/* claims of the request sender, less "exp", as a JSON object (NULL: none). */
static char *sender_claims(s3_ctx *c) {
  if (!c->ident->claims) return NULL;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_val_mut_copy(d, yyjson_doc_get_root(c->ident->claims));
  yyjson_mut_doc_set_root(d, root);
  if (yyjson_mut_is_obj(root)) yyjson_mut_obj_remove_key(root, "exp");
  char *json = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  return json;
}

static void add_ldap_attr_claims(yyjson_mut_doc *d, yyjson_mut_val *root, const buckets_ldap_dnres *dn) {
  for (size_t a = 0; a < dn->nattrs; a++) {
    char key[256];
    snprintf(key, sizeof(key), "ldapAttrib_%s", dn->attrs[a].name);
    yyjson_mut_val *arr = yyjson_mut_arr(d);
    for (size_t v = 0; v < dn->attrs[a].nvalues; v++) yyjson_mut_arr_add_strcpy(d, arr, dn->attrs[a].values[v]);
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, key), arr);
  }
}

static void join_groups(buckets_buf *b, char *const *groups, size_t n) {
  buckets_buf_append_c(b, "");
  for (size_t i = 0; i < n; i++) buckets_buf_appendf(b, "%s%s", i ? "`,`" : "", groups[i]);
}

/* AddServiceAccount (ldap false) and AddServiceAccountLDAP (ldap true). */
static void add_svc(s3_ctx *c, bool ldap) {
  if (!admin_signed(c)) return;
  yyjson_doc *req = read_encrypted(c);
  if (!req) return;
  yyjson_val *root = yyjson_doc_get_root(req);
  const char *ak = yyjson_get_str(yyjson_obj_get(root, "accessKey"));
  const char *sk = yyjson_get_str(yyjson_obj_get(root, "secretKey"));
  const char *target = yyjson_get_str(yyjson_obj_get(root, "targetUser"));
  const char *name = yyjson_get_str(yyjson_obj_get(root, "name"));
  const char *desc = yyjson_get_str(yyjson_obj_get(root, "description"));
  if (!desc || !*desc) desc = yyjson_get_str(yyjson_obj_get(root, "comment"));
  yyjson_val *pol = yyjson_obj_get(root, "policy");
  buckets_iam_time exp_t;
  bool has_exp = parse_time(yyjson_obj_get(root, "expiration"), &exp_t) && buckets_iam_time_is_set(exp_t);
  if (has_exp) exp_t.nsec = 0; /* Truncate(time.Second) */
  buckets_iam *iam = c->s->iam;
  char *policy_json = NULL, *claims_json = NULL;
  char *target_user = NULL;
  const char **groups = NULL;
  size_t ngroups = 0;
  buckets_ldapidp *lp = ldap ? buckets_s3_ldap(c->s) : NULL;
  char **ldap_groups = NULL;
  size_t nldap_groups = 0;
  buckets_ldap_dnres dn = {0};

  if ((ak && has_space_be(ak)) || (ak && *ak && (!sk || !*sk)) || (sk && *sk && (!ak || !*ak)) ||
      (name && strlen(name) > 32) || (desc && strlen(desc) > 256)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT);
    goto out;
  }
  if (ak && strcmp(ak, BUCKETS_SR_SVC_ACCOUNT) == 0) { /* reserved for site replication */
    iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
    goto out;
  }
  target_user = buckets_xstrdup(target && *target ? target : requestor(c));
  bool deny_only = strcmp(target_user, requestor(c)) == 0 ||
                   (c->ident->parent && strcmp(target_user, c->ident->parent) == 0);
  if (ldap && !deny_only && buckets_ldapidp_enabled(lp)) {
    char e[512];
    if (buckets_ldapidp_validated_user(lp, target_user, &dn, e, sizeof(e)) > 0 && c->ident->parent &&
        strcmp(dn.norm_dn, c->ident->parent) == 0)
      deny_only = true;
    buckets_ldap_dnres_free(&dn);
  }
  if (has_exp) {
    char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
    time_str(exp_t, ts);
    buckets_s3_cond_override(c, "svcacct-policy-expiration", ts);
  }
  if (!allowed(c, "admin:CreateServiceAccount", deny_only)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  if (pol && !yyjson_is_null(pol)) {
    policy_json = yyjson_val_write(pol, 0, NULL);
    char err[512];
    buckets_policy *p;
    if (!buckets_policy_parse(policy_json, strlen(policy_json), &p, err, sizeof(err))) {
      custom_error(c, 400, "XMinioMalformedIAMPolicy", err);
      goto out;
    }
    buckets_policy_free(p);
  }
  if (ak && strcmp(ak, buckets_iam_root_access_key(iam)) == 0) {
    buckets_admin_error(c, BUCKETS_ERR_ADD_USER_INVALID_ARGUMENT);
    goto out;
  }
  bool derived = buckets_iam_ident_is_svc(c->ident) || buckets_iam_ident_is_temp(c->ident);
  if (ldap) {
    if (!buckets_ldapidp_enabled(lp)) {
      buckets_admin_error(c, BUCKETS_ERR_ADMIN_LDAP_NOT_ENABLED);
      goto out;
    }
    char e[1024], msg[1400];
    if (strcmp(target_user, requestor(c)) == 0 || strcmp(target_user, requestor_parent(c)) == 0) {
      if (derived) {
        if (!c->ident->parent || !*c->ident->parent) {
          buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR,
                                  "service accounts cannot be generated for temporary credentials without parent");
          goto out;
        }
        free(target_user);
        target_user = buckets_xstrdup(c->ident->parent);
      }
      groups = (const char **)c->ident->groups;
      ngroups = c->ident->ngroups;
      int r = buckets_ldapidp_validated_user(lp, target_user, &dn, e, sizeof(e));
      if (r < 0) {
        buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, e);
        goto out;
      }
      if (r == 0) {
        buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_NO_SUCH_USER, "Specified user does not exist on LDAP server");
        goto out;
      }
      claims_json = sender_claims(c);
    } else {
      bool is_dn = buckets_ldapidp_parses_as_dn(target_user);
      int r = buckets_ldapidp_lookup_user(lp, target_user, &dn, &ldap_groups, &nldap_groups, e, sizeof(e));
      if (r <= 0) {
        if (strstr(e, "User DN not found for:"))
          buckets_admin_error_msg(c, is_dn ? BUCKETS_ERR_ADMIN_LDAP_EXPECTED_LOGIN_NAME : BUCKETS_ERR_ADMIN_NO_SUCH_USER,
                                  e);
        else buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, e);
        goto out;
      }
      char *pols = buckets_iam_policy_db_get(iam, dn.norm_dn, ldap_groups, nldap_groups);
      bool none = !*pols;
      free(pols);
      if (none) {
        buckets_buf g = BUCKETS_BUF_INIT;
        join_groups(&g, ldap_groups, nldap_groups);
        snprintf(msg, sizeof(msg), "No policy set for user `%s` or any of their groups: `%s`", dn.actual_dn, g.data);
        buckets_buf_free(&g);
        buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_NO_SUCH_USER, msg);
        goto out;
      }
      yyjson_mut_doc *cd = yyjson_mut_doc_new(NULL);
      yyjson_mut_val *croot = yyjson_mut_obj(cd);
      yyjson_mut_doc_set_root(cd, croot);
      yyjson_mut_obj_add_strcpy(cd, croot, "ldapUsername", target_user);
      yyjson_mut_obj_add_strcpy(cd, croot, "ldapUser", dn.norm_dn);
      yyjson_mut_obj_add_strcpy(cd, croot, "ldapActualUser", dn.actual_dn);
      add_ldap_attr_claims(cd, croot, &dn);
      claims_json = yyjson_mut_write(cd, 0, NULL);
      yyjson_mut_doc_free(cd);
      free(target_user);
      target_user = buckets_xstrdup(dn.norm_dn);
      groups = (const char **)ldap_groups;
      ngroups = nldap_groups;
    }
  } else if (!buckets_iam_ldap_mode(iam) && strcmp(target_user, requestor(c)) != 0) {
    buckets_iam_ident *tu = buckets_iam_get_ident(iam, target_user);
    bool regular = tu && tu->type == BUCKETS_IAM_REG && !buckets_iam_ident_is_svc(tu);
    buckets_iam_ident_release(tu);
    if (!regular && strcmp(target_user, buckets_iam_root_access_key(iam)) != 0) {
      char msg[512];
      snprintf(msg, sizeof(msg), "Specified target user %s does not exist", target_user);
      buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_NO_SUCH_USER, msg);
      goto out;
    }
  }
  bool for_self = strcmp(target_user, requestor(c)) == 0 || strcmp(target_user, requestor_parent(c)) == 0;
  if (!ldap && for_self) {
    if (derived) {
      free(target_user);
      target_user = buckets_xstrdup(requestor_parent(c));
    }
    groups = (const char **)c->ident->groups;
    ngroups = c->ident->ngroups;
    if (c->ident->claims) claims_json = yyjson_write(c->ident->claims, 0, NULL);
  }
  buckets_iam_svc_opts o = {
      .parent = target_user,
      .groups = groups,
      .ngroups = ngroups,
      .access_key = ak,
      .secret_key = sk,
      .session_policy = policy_json,
      .name = name,
      .description = desc,
      .expiration = has_exp ? &exp_t : NULL,
      .claims_json = claims_json,
  };
  buckets_iam_ident *svc;
  char err[512] = "";
  buckets_iam_err e = buckets_iam_add_svc(iam, &o, &svc, err, sizeof(err));
  if (e == BUCKETS_IAM_ERR_SVC_NOT_ALLOWED) {
    custom_error(c, 400, "XMinioIAMServiceAccountNotAllowed", "Specified service account action is not allowed");
    goto out;
  }
  if (e == BUCKETS_IAM_ERR_SESSION_POLICY_TOO_LARGE) {
    custom_error(c, 400, "XMinioIAMServiceAccountSessionPolicyTooLarge", buckets_iam_strerror(e));
    goto out;
  }
  if (e == BUCKETS_IAM_ERR_MALFORMED_POLICY) {
    custom_error(c, 400, "XMinioMalformedIAMPolicy", err);
    goto out;
  }
  if (e) {
    iam_error(c, e, NULL);
    goto out;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *out = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, out);
  yyjson_mut_val *cr = yyjson_mut_obj_add_obj(d, out, "credentials");
  yyjson_mut_obj_add_strcpy(d, cr, "accessKey", svc->access_key);
  yyjson_mut_obj_add_strcpy(d, cr, "secretKey", svc->secret_key);
  add_time(d, cr, "expiration", svc->expiration);
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
  buckets_sr_iam_svc_create(c->s->sr, svc->access_key);
  buckets_iam_ident_release(svc);
out:
  free(target_user);
  free(policy_json);
  free(claims_json);
  buckets_ldap_strv_free(ldap_groups, nldap_groups);
  buckets_ldap_dnres_free(&dn);
  buckets_ldapidp_release(lp);
  yyjson_doc_free(req);
}

static void h_add_svc(s3_ctx *c) { add_svc(c, false); }
static void h_add_svc_ldap(s3_ctx *c) { add_svc(c, true); }

static void h_update_svc(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *ak = qget(c, "accessKey");
  if (!*ak) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  buckets_iam *iam = c->s->iam;
  buckets_iam_ident *svc = buckets_iam_get_ident(iam, ak);
  if (!svc || !buckets_iam_ident_is_svc(svc)) {
    buckets_iam_ident_release(svc);
    iam_error(c, BUCKETS_IAM_ERR_NO_SUCH_SVC, NULL);
    return;
  }
  buckets_iam_ident_release(svc);
  yyjson_doc *req = read_encrypted(c);
  if (!req) return;
  yyjson_val *root = yyjson_doc_get_root(req);
  const char *nsk = yyjson_get_str(yyjson_obj_get(root, "newSecretKey"));
  const char *nstatus = yyjson_get_str(yyjson_obj_get(root, "newStatus"));
  const char *nname = yyjson_get_str(yyjson_obj_get(root, "newName"));
  const char *ndesc = yyjson_get_str(yyjson_obj_get(root, "newDescription"));
  yyjson_val *npol = yyjson_obj_get(root, "newPolicy");
  buckets_iam_time exp_t;
  bool has_exp = parse_time(yyjson_obj_get(root, "newExpiration"), &exp_t);
  char *policy_json = NULL;
  if ((nname && strlen(nname) > 32) || (ndesc && strlen(ndesc) > 256)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT);
    goto out;
  }
  if (has_exp) {
    char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
    time_str(exp_t, ts);
    buckets_s3_cond_override(c, "svcacct-policy-expiration", ts);
  }
  if (!allowed(c, "admin:UpdateServiceAccount", false)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  if (npol && !yyjson_is_null(npol)) {
    policy_json = yyjson_val_write(npol, 0, NULL);
    char err[512];
    buckets_policy *p;
    if (!buckets_policy_parse(policy_json, strlen(policy_json), &p, err, sizeof(err))) {
      custom_error(c, 400, "XMinioMalformedIAMPolicy", err);
      goto out;
    }
    buckets_policy_free(p);
  }
  buckets_iam_svc_update u = {
      .secret_key = nsk,
      .status = nstatus,
      .name = nname,
      .description = ndesc,
      .expiration = has_exp ? &exp_t : NULL,
      .set_policy = policy_json != NULL,
      .session_policy = policy_json,
  };
  char err[512] = "";
  buckets_iam_err e = buckets_iam_update_svc(iam, ak, &u, err, sizeof(err));
  if (e == BUCKETS_IAM_ERR_MALFORMED_POLICY) {
    custom_error(c, 400, "XMinioMalformedIAMPolicy", err);
  } else if (e) {
    iam_error(c, e, NULL);
  } else {
    c->resp->status = 204;
    buckets_sr_iam_svc_update(c->s->sr, ak, nsk, nstatus, nname, ndesc, policy_json, has_exp, exp_t.sec);
  }
out:
  free(policy_json);
  yyjson_doc_free(req);
}

/* The effective policy of a service account, as InfoServiceAccount shows it. */
/* GetCombinedPolicy: the statements of the named policies (comma-separated)
 * merged into one policy, as indented JSON. */
static char *combined_policy_json(buckets_iam *iam, const char *names) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "Version", "2012-10-17");
  yyjson_mut_val *st = yyjson_mut_obj_add_arr(d, root, "Statement");
  const char *p = names;
  while (*p) {
    const char *e = strchr(p, ',');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    char *one = buckets_xstrndup(p, n);
    buckets_iam_policy_doc pd;
    if (buckets_iam_get_policy(iam, one, &pd) == BUCKETS_IAM_OK) {
      yyjson_doc *pj = yyjson_read(pd.json, strlen(pd.json), 0);
      yyjson_val *sts = pj ? yyjson_obj_get(yyjson_doc_get_root(pj), "Statement") : NULL;
      size_t i, max;
      yyjson_val *s;
      if (yyjson_is_arr(sts)) {
        yyjson_arr_foreach(sts, i, max, s) {
          /* MergePolicies drops duplicate statements. */
          bool dup = false;
          yyjson_mut_val *copy = yyjson_val_mut_copy(d, s);
          size_t k, kmax;
          yyjson_mut_val *prev;
          yyjson_mut_arr_foreach(st, k, kmax, prev) { dup |= yyjson_mut_equals(prev, copy); }
          if (!dup) yyjson_mut_arr_append(st, copy);
        }
      } else if (yyjson_is_obj(sts)) {
        yyjson_mut_arr_append(st, yyjson_val_mut_copy(d, sts));
      }
      yyjson_doc_free(pj);
      buckets_iam_policy_doc_free(&pd, 1);
    }
    free(one);
    p = e ? e + 1 : p + n;
  }
  char *json = yyjson_mut_write(d, YYJSON_WRITE_PRETTY, NULL);
  yyjson_mut_doc_free(d);
  return json;
}

static char *svc_policy_json(buckets_iam *iam, const buckets_iam_ident *svc, bool *implied) {
  *implied = !svc->has_session_policy || !svc->session_policy || buckets_policy_is_blank(svc->session_policy);
  if (!*implied) return buckets_xstrdup(svc->session_policy_json);
  /* GetCombinedPolicy(PolicyDBGet(parent, groups...)) */
  char *names = buckets_iam_policy_db_get(iam, svc->parent ? svc->parent : "", svc->groups, svc->ngroups);
  char *json = combined_policy_json(iam, names);
  free(names);
  return json;
}

static void h_info_svc(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *ak = qget(c, "accessKey");
  if (!*ak) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  buckets_iam *iam = c->s->iam;
  buckets_iam_ident *svc = buckets_iam_get_ident(iam, ak);
  if (!svc || !buckets_iam_ident_is_svc(svc)) {
    buckets_iam_ident_release(svc);
    iam_error(c, BUCKETS_IAM_ERR_NO_SUCH_SVC, NULL);
    return;
  }
  if (!allowed(c, "admin:ListServiceAccounts", false) &&
      strcmp(requestor_parent(c), svc->parent ? svc->parent : "") != 0) {
    buckets_iam_ident_release(svc);
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  bool implied;
  char *policy = svc_policy_json(iam, svc, &implied);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "parentUser", svc->parent ? svc->parent : "");
  yyjson_mut_obj_add_strcpy(d, root, "accountStatus", svc->status);
  yyjson_mut_obj_add_bool(d, root, "impliedPolicy", implied);
  yyjson_mut_obj_add_strcpy(d, root, "policy", policy);
  if (svc->name) yyjson_mut_obj_add_strcpy(d, root, "name", svc->name);
  if (svc->description) yyjson_mut_obj_add_strcpy(d, root, "description", svc->description);
  if (buckets_iam_time_is_set(svc->expiration)) add_time(d, root, "expiration", svc->expiration);
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
  free(policy);
  buckets_iam_ident_release(svc);
}

static void h_list_svc(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *user = qget(c, "user");
  const char *target = requestor_parent(c);
  if (*user && strcmp(user, requestor(c)) != 0) {
    if (!allowed(c, "admin:ListServiceAccounts", false)) {
      buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
      return;
    }
    target = user;
  }
  buckets_iam_ident **list;
  size_t n;
  buckets_iam_list_derived(c->s->iam, target, BUCKETS_IAM_SVC, &list, &n);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_val *accounts = n ? yyjson_mut_obj_add_arr(d, root, "accounts") : NULL;
  if (!n) yyjson_mut_obj_add_null(d, root, "accounts");
  for (size_t i = 0; i < n; i++) {
    buckets_iam_ident *svc = list[i];
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, accounts);
    yyjson_mut_obj_add_strcpy(d, o, "parentUser", svc->parent);
    yyjson_mut_obj_add_strcpy(d, o, "accountStatus", svc->status);
    const char *sa = buckets_iam_ident_claim(svc, "sa-policy");
    yyjson_mut_obj_add_bool(d, o, "impliedPolicy", sa && strcmp(sa, "inherited-policy") == 0);
    yyjson_mut_obj_add_strcpy(d, o, "accessKey", svc->access_key);
    if (svc->name) yyjson_mut_obj_add_strcpy(d, o, "name", svc->name);
    if (svc->description) yyjson_mut_obj_add_strcpy(d, o, "description", svc->description);
    add_time(d, o, "expiration", svc->expiration);
    buckets_iam_ident_release(svc);
  }
  free(list);
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
}

static void h_delete_svc(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *ak = qget(c, "accessKey");
  if (!*ak) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT);
    return;
  }
  if (strcmp(ak, BUCKETS_SR_SVC_ACCOUNT) == 0 && buckets_sr_enabled(c->s->sr)) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_ARGUMENT);
    return;
  }
  buckets_iam *iam = c->s->iam;
  buckets_iam_ident *svc = buckets_iam_get_ident(iam, ak);
  if (!svc || !buckets_iam_ident_is_svc(svc)) {
    buckets_iam_ident_release(svc);
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_SERVICE_ACCOUNT_NOT_FOUND);
    return;
  }
  bool own = svc->parent && strcmp(requestor_parent(c), svc->parent) == 0;
  buckets_iam_ident_release(svc);
  if (!allowed(c, "admin:RemoveServiceAccount", false) && !own) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_SERVICE_ACCOUNT_NOT_FOUND);
    return;
  }
  buckets_iam_err e = buckets_iam_delete_svc(iam, ak);
  if (e) {
    iam_error(c, e, NULL);
    return;
  }
  c->resp->status = 204;
  buckets_sr_iam_svc_delete(c->s->sr, ak);
}

/* ---- access keys, temporary accounts and policy entities ----------------------------------- */

/* Every value of a repeated query parameter (r.Form["users"]). */
static size_t qall(s3_ctx *c, const char *key, const char ***out) {
  *out = buckets_xcalloc(c->q.n ? c->q.n : 1, sizeof(char *));
  size_t n = 0;
  for (size_t i = 0; i < c->q.n; i++) {
    if (strcmp(c->q.items[i].key, key) == 0 && *c->q.items[i].value) (*out)[n++] = c->q.items[i].value;
  }
  return n;
}

static void add_key_infos(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, buckets_iam_ident **ids, size_t n) {
  if (!n) {
    yyjson_mut_obj_add_null(d, o, key);
    return;
  }
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, key);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, a);
    yyjson_mut_obj_add_str(d, e, "parentUser", "");
    yyjson_mut_obj_add_str(d, e, "accountStatus", "");
    yyjson_mut_obj_add_bool(d, e, "impliedPolicy", false);
    yyjson_mut_obj_add_strcpy(d, e, "accessKey", ids[i]->access_key);
    add_time(d, e, "expiration", ids[i]->expiration);
  }
}

static void h_list_access_keys_bulk(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char **users;
  size_t nu = qall(c, "users", &users);
  bool all = strcmp(qget(c, "all"), "true") == 0;
  bool self_only = !all && nu == 0;
  buckets_iam *iam = c->s->iam;
  yyjson_mut_doc *d = NULL;
  if (all && nu) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    goto out;
  }
  if (all && !allowed(c, "admin:ListUsers", false)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  if (nu == 1 && (strcmp(users[0], requestor(c)) == 0 || strcmp(users[0], requestor_parent(c)) == 0)) self_only = true;
  if (!allowed(c, "admin:ListServiceAccounts", self_only)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  const char *lt = qget(c, "listType");
  bool sts = strcmp(lt, "sts-only") == 0 || strcmp(lt, "all") == 0;
  bool svc = strcmp(lt, "svcacc-only") == 0 || strcmp(lt, "all") == 0;
  if (!sts && !svc && strcmp(lt, "users-only") != 0) {
    buckets_admin_error_msg(c, BUCKETS_ERR_INVALID_REQUEST, "invalid list type");
    goto out;
  }
  /* The users to report: everyone (and root), the given ones that exist, or self. */
  char **names = NULL;
  size_t nn = 0;
  if (all) {
    buckets_iam_user_info *ui;
    size_t n;
    buckets_iam_list_users(iam, &ui, &n);
    names = buckets_xcalloc(n + 1, sizeof(char *));
    for (size_t i = 0; i < n; i++) names[nn++] = buckets_xstrdup(ui[i].name);
    names[nn++] = buckets_xstrdup(buckets_iam_root_access_key(iam));
    buckets_iam_user_info_free(ui, n);
    free(ui);
  } else {
    names = buckets_xcalloc(nu + 1, sizeof(char *));
    if (self_only && !nu) {
      names[nn++] = buckets_xstrdup(requestor_parent(c));
    } else {
      for (size_t i = 0; i < nu; i++) {
        buckets_iam_ident *id;
        bool exists = buckets_iam_get_key(iam, users[i], &id) == BUCKETS_IAM_KEY_OK;
        buckets_iam_ident_release(id);
        if (exists) names[nn++] = buckets_xstrdup(users[i]);
      }
    }
  }
  d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < nn; i++) {
    buckets_iam_ident **sk = NULL, **vk = NULL;
    size_t ns = 0, nv = 0;
    if (sts) buckets_iam_list_derived(iam, names[i], BUCKETS_IAM_STS, &sk, &ns);
    if (svc) buckets_iam_list_derived(iam, names[i], BUCKETS_IAM_SVC, &vk, &nv);
    bool skip = (sts && !svc && !ns) || (svc && !sts && !nv);
    if (!skip) {
      yyjson_mut_val *o = yyjson_mut_obj(d);
      add_key_infos(d, o, "serviceAccounts", vk, nv);
      add_key_infos(d, o, "stsKeys", sk, ns);
      yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, names[i]), o);
    }
    for (size_t k = 0; k < ns; k++) buckets_iam_ident_release(sk[k]);
    for (size_t k = 0; k < nv; k++) buckets_iam_ident_release(vk[k]);
    free(sk);
    free(vk);
    free(names[i]);
  }
  free(names);
  write_json(c, d, true);
out:
  yyjson_mut_doc_free(d);
  free(users);
}

/* InfoAccessKey / TemporaryAccountInfo share this shape. */
/* guessUserProvider */
static void guess_user_provider(const buckets_iam_ident *id, char *out, size_t cap) {
  snprintf(out, cap, "builtin");
  if (!buckets_iam_ident_is_svc(id) && !buckets_iam_ident_is_temp(id)) return;
  if (buckets_iam_ident_claim(id, "ldapUser")) {
    snprintf(out, cap, "ldap");
  } else if (buckets_iam_ident_claim(id, "sub")) {
    const char *p = id->parent ? id->parent : "";
    const char *sep = strchr(p, '/');
    if (sep) snprintf(out, cap, "%.*s", (int)(sep - p), p);
    else snprintf(out, cap, "openid");
  }
}

static void write_key_info(s3_ctx *c, buckets_iam_ident *id, bool access_key_form) {
  bool implied;
  char *policy;
  if (buckets_iam_ident_is_svc(id)) {
    policy = svc_policy_json(c->s->iam, id, &implied);
  } else {
    /* STS: the session policy, else the parent's. */
    implied = !id->has_session_policy;
    policy = implied || !id->session_policy_json ? NULL : buckets_xstrdup(id->session_policy_json);
    if (!policy) {
      buckets_iam_ident tmp = *id;
      tmp.has_session_policy = false;
      policy = svc_policy_json(c->s->iam, &tmp, &implied);
      implied = !id->has_session_policy;
    }
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  if (access_key_form) yyjson_mut_obj_add_strcpy(d, root, "AccessKey", id->access_key);
  yyjson_mut_obj_add_strcpy(d, root, "parentUser", id->parent ? id->parent : "");
  yyjson_mut_obj_add_strcpy(d, root, "accountStatus", id->status);
  yyjson_mut_obj_add_bool(d, root, "impliedPolicy", implied);
  yyjson_mut_obj_add_strcpy(d, root, "policy", policy);
  if (id->name) yyjson_mut_obj_add_strcpy(d, root, "name", id->name);
  if (id->description) yyjson_mut_obj_add_strcpy(d, root, "description", id->description);
  if (buckets_iam_time_is_set(id->expiration)) add_time(d, root, "expiration", id->expiration);
  if (access_key_form) {
    yyjson_mut_obj_add_str(d, root, "userType", buckets_iam_ident_is_temp(id) ? "STS" : "Service Account");
    char provider[128];
    guess_user_provider(id, provider, sizeof(provider));
    yyjson_mut_obj_add_strcpy(d, root, "userProvider", provider);
    const char *ldap_user = strcmp(provider, "ldap") == 0 ? buckets_iam_ident_claim(id, "ldapUser") : NULL;
    yyjson_mut_val *ldap = yyjson_mut_obj_add_obj(d, root, "ldapSpecificInfo");
    yyjson_mut_obj_add_strcpy(d, ldap, "username", ldap_user ? ldap_user : "");
    /* getOpenIDInfoFromClaims */
    const char *cfg_name = "", *readable = "", *id_claim = "";
    buckets_openid *o = strcmp(provider, "openid") == 0 ? buckets_s3_openid(c->s) : NULL;
    if (o && !buckets_openid_by_arn(o, buckets_iam_ident_claim(id, "roleArn"), &cfg_name, &readable, &id_claim)) {
      cfg_name = readable = id_claim = "";
    }
    yyjson_mut_val *oidc = yyjson_mut_obj_add_obj(d, root, "openIDSpecificInfo");
    yyjson_mut_obj_add_strcpy(d, oidc, "configName", cfg_name);
    const char *uid = *id_claim ? buckets_iam_ident_claim(id, id_claim) : NULL;
    yyjson_mut_obj_add_strcpy(d, oidc, "userID", uid ? uid : "");
    yyjson_mut_obj_add_strcpy(d, oidc, "userIDClaim", id_claim);
    if (*readable) {
      const char *dn = buckets_iam_ident_claim(id, readable);
      if (dn && *dn) yyjson_mut_obj_add_strcpy(d, oidc, "displayName", dn);
      yyjson_mut_obj_add_strcpy(d, oidc, "displayNameClaim", readable);
    }
    buckets_openid_release(o);
  }
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
  free(policy);
}

static void h_info_access_key(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *ak = qget(c, "accessKey");
  if (!*ak) ak = requestor(c);
  buckets_iam_ident *id = buckets_iam_get_ident(c->s->iam, ak);
  if (!allowed(c, "admin:ListServiceAccounts", false) &&
      (!id || !id->parent || strcmp(requestor_parent(c), id->parent) != 0)) {
    buckets_iam_ident_release(id);
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  if (!id || !(buckets_iam_ident_is_temp(id) || buckets_iam_ident_is_svc(id))) {
    buckets_iam_ident_release(id);
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_NO_SUCH_ACCESS_KEY);
    return;
  }
  write_key_info(c, id, true);
  buckets_iam_ident_release(id);
}

static void h_temp_account_info(s3_ctx *c) {
  if (!admin_req1(c, "admin:ListTemporaryAccounts")) return;
  buckets_iam_ident *id = buckets_iam_get_ident(c->s->iam, qget(c, "accessKey"));
  if (!id || id->type != BUCKETS_IAM_STS) {
    buckets_iam_ident_release(id);
    custom_error(c, 404, "XMinioAdminNoSuchTempAccount", "The specified temporary account does not exist");
    return;
  }
  write_key_info(c, id, false);
  buckets_iam_ident_release(id);
}

static void h_policy_entities(s3_ctx *c) {
  static const char *const actions[] = {"admin:ListGroups", "admin:ListUsers", "admin:ListUserPolicies"};
  if (!admin_req(c, actions, 3)) return;
  const char **u, **g, **p;
  size_t nu = qall(c, "user", &u), ng = qall(c, "group", &g), np = qall(c, "policy", &p);
  char *json = buckets_iam_policy_entities_json(c->s->iam, u, nu, g, ng, p, np);
  free(u);
  free(g);
  free(p);
  buckets_buf_reset(&c->resp->body);
  if (!buckets_madmin_encrypt(c->ident->secret_key, json, strlen(json), &c->resp->body)) {
    free(json);
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  free(json);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

/* ---- account info ---------------------------------------------------------------------------- */

/* madmin.BackendInfo (ObjectLayer.BackendInfo). */
static void add_backend_info(s3_ctx *c, yyjson_mut_doc *d, yyjson_mut_val *o) {
  buckets_objlayer *L = c->s->layer;
  yyjson_mut_obj_add_int(d, o, "Type", 2); /* madmin.Erasure */
  yyjson_mut_obj_add_bool(d, o, "GatewayOnline", false);
  yyjson_mut_obj_add_null(d, o, "OnlineDisks");
  yyjson_mut_obj_add_null(d, o, "OfflineDisks");
  yyjson_mut_val *sd = yyjson_mut_obj_add_arr(d, o, "StandardSCData");
  yyjson_mut_obj_add_null(d, o, "StandardSCParities");
  yyjson_mut_val *rd = yyjson_mut_obj_add_arr(d, o, "RRSCData");
  yyjson_mut_obj_add_null(d, o, "RRSCParities");
  yyjson_mut_val *ts = yyjson_mut_obj_add_arr(d, o, "TotalSets");
  yyjson_mut_val *dps = yyjson_mut_obj_add_arr(d, o, "DrivesPerSet");
  int parity = 0, rrs = 0;
  for (size_t p = 0, first = 0; L && p < L->npools; p++) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, first, &pl);
    if (p == 0) {
      parity = pl.parity;
      rrs = pl.set_size > 1 ? 1 : 0;
    }
    yyjson_mut_arr_add_int(d, sd, (int)pl.set_size - parity);
    yyjson_mut_arr_add_int(d, rd, (int)pl.set_size - rrs);
    yyjson_mut_arr_add_int(d, dps, (int)pl.set_size);
    yyjson_mut_arr_add_int(d, ts, (int)pl.nsets);
    first += pl.pool_drives;
  }
  yyjson_mut_obj_add_int(d, o, "StandardSCParity", parity);
  yyjson_mut_obj_add_int(d, o, "RRSCParity", rrs);
}

/* AccountInfoHandler: the requestor's effective policy and the buckets it
 * can read or write. (Usage and bucket features come with the scanner and
 * bucket metadata.) */
static void h_account_info(s3_ctx *c) {
  if (!admin_signed(c)) return;
  buckets_iam *iam = c->s->iam;
  buckets_s3_cond_override(c, "prefix", "");
  buckets_s3_cond_override(c, "delimiter", "/");
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(c->s->layer, &bk, &nb) != BUCKETS_OBJ_OK) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  const char *account = requestor(c);
  if (buckets_iam_ident_is_temp(c->ident) || buckets_iam_ident_is_svc(c->ident)) account = requestor_parent(c);
  buckets_plugins *pl = buckets_s3_plugins(c->s);
  bool authz = buckets_authz_plugin_enabled(pl);
  buckets_plugins_release(pl);
  char *policy;
  if (strcmp(account, buckets_iam_root_access_key(iam)) == 0 || authz) {
    policy = combined_policy_json(iam, "consoleAdmin");
  } else {
    bool role, claim;
    char *names = buckets_iam_ident_policies(iam, c->ident, &role, &claim);
    if (!role && !claim) {
      free(names);
      names = buckets_iam_policy_db_get(iam, account, c->ident->groups, c->ident->ngroups);
    }
    policy = combined_policy_json(iam, names);
    free(names);
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "AccountName", account);
  add_backend_info(c, d, yyjson_mut_obj_add_obj(d, root, "Server"));
  yyjson_doc *pd = yyjson_read(policy, strlen(policy), 0);
  yyjson_mut_obj_add_val(d, root, "Policy", yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
  yyjson_doc_free(pd);
  free(policy);
  yyjson_mut_val *arr = NULL;
  for (size_t i = 0; i < nb; i++) {
    bool rd = buckets_s3_allowed(c, "s3:ListBucket", bk[i].name, "", false) ||
              buckets_s3_allowed(c, "s3:GetBucketLocation", bk[i].name, "", false);
    bool wr = buckets_s3_allowed(c, "s3:PutObject", bk[i].name, "", false);
    if (!rd && !wr) continue;
    if (!arr) arr = yyjson_mut_obj_add_arr(d, root, "Buckets");
    yyjson_mut_val *b = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, b, "name", bk[i].name);
    yyjson_mut_obj_add_uint(d, b, "size", 0);
    yyjson_mut_obj_add_uint(d, b, "objects", 0);
    yyjson_mut_obj_add_null(d, b, "objectHistogram");
    yyjson_mut_obj_add_null(d, b, "objectsVersionsHistogram");
    yyjson_mut_val *det = yyjson_mut_obj_add_obj(d, b, "details");
    yyjson_mut_obj_add_bool(d, det, "versioning", false);
    yyjson_mut_obj_add_bool(d, det, "versioningSuspended", false);
    yyjson_mut_obj_add_bool(d, det, "locking", false);
    yyjson_mut_obj_add_bool(d, det, "replication", false);
    yyjson_mut_obj_add_null(d, det, "tags");
    yyjson_mut_obj_add_null(d, det, "quota");
    yyjson_mut_obj_add_null(d, b, "prefixUsage");
    add_time(d, b, "created", (buckets_iam_time){(long long)bk[i].created, 0});
    yyjson_mut_val *acc = yyjson_mut_obj_add_obj(d, b, "access");
    yyjson_mut_obj_add_bool(d, acc, "read", rd);
    yyjson_mut_obj_add_bool(d, acc, "write", wr);
  }
  if (!arr) yyjson_mut_obj_add_null(d, root, "Buckets");
  write_json(c, d, false);
  yyjson_mut_doc_free(d);
  buckets_bucket_info_free(bk, nb);
}

/* ---- LDAP (admin-handlers-idp-ldap.go) --------------------------------------------------------- */

static bool ldap_user_pred(void *ud, const char *name) { return buckets_ldapidp_is_user_dn(ud, name); }
static bool ldap_group_pred(void *ud, const char *name) { return buckets_ldapidp_is_group_dn(ud, name); }

static void write_encrypted_json(s3_ctx *c, const char *json) {
  buckets_buf_reset(&c->resp->body);
  if (!buckets_madmin_encrypt(c->ident->secret_key, json, strlen(json), &c->resp->body)) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

/* ListLDAPPolicyMappingEntities (QueryLDAPPolicyEntities). */
static void h_ldap_policy_entities(s3_ctx *c) {
  static const char *const actions[] = {"admin:ListGroups", "admin:ListUsers", "admin:ListUserPolicies"};
  if (!admin_req(c, actions, 3)) return;
  buckets_ldapidp *lp = buckets_s3_ldap(c->s);
  if (!buckets_ldapidp_enabled(lp)) {
    buckets_ldapidp_release(lp);
    iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
    return;
  }
  const char **u, **g, **p;
  size_t nu = qall(c, "user", &u), ng = qall(c, "group", &g), np = qall(c, "policy", &p);
  /* createCleanEntitiesQuery: users found in the directory by their DN
   * (with their groups), and as given; groups as given and by their DN. */
  buckets_iam_entity_user *eu = buckets_xcalloc(2 * nu + 1, sizeof(*eu));
  buckets_ldap_dnres *res = buckets_xcalloc(nu + 1, sizeof(*res));
  char ***ug = buckets_xcalloc(nu + 1, sizeof(char **));
  size_t *nug = buckets_xcalloc(nu + 1, sizeof(size_t)), neu = 0;
  char err[1024];
  for (size_t i = 0; i < nu; i++) {
    if (buckets_ldapidp_validated_user_groups(lp, u[i], &res[i], &ug[i], &nug[i], err, sizeof(err)) > 0)
      eu[neu++] = (buckets_iam_entity_user){res[i].norm_dn, ug[i], nug[i]};
    eu[neu++] = (buckets_iam_entity_user){u[i], NULL, 0};
  }
  const char **gs = buckets_xcalloc(2 * ng + 1, sizeof(char *));
  char **gnorm = buckets_xcalloc(ng + 1, sizeof(char *));
  size_t ngs = 0;
  for (size_t i = 0; i < ng; i++) {
    gs[ngs++] = g[i];
    buckets_ldap_dnres r;
    bool under;
    if (buckets_ldapidp_validated_group(lp, g[i], &r, &under, err, sizeof(err)) > 0 && under) {
      gnorm[i] = buckets_xstrdup(r.norm_dn);
      gs[ngs++] = gnorm[i];
    }
    buckets_ldap_dnres_free(&r);
  }
  char *json = buckets_iam_ldap_policy_entities_json(c->s->iam, eu, neu, gs, ngs, p, np, ldap_user_pred,
                                                     ldap_group_pred, lp);
  write_encrypted_json(c, json);
  free(json);
  for (size_t i = 0; i < nu; i++) {
    buckets_ldap_dnres_free(&res[i]);
    buckets_ldap_strv_free(ug[i], nug[i]);
  }
  for (size_t i = 0; i < ng; i++) free(gnorm[i]);
  free(gnorm);
  free(gs);
  free(res);
  free(ug);
  free(nug);
  free(eu);
  free(u);
  free(g);
  free(p);
  buckets_ldapidp_release(lp);
}

static void add_ldap_key_infos(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, buckets_iam_ident **ids,
                               size_t n) {
  add_key_infos(d, o, key, ids, n);
  yyjson_mut_val *a = yyjson_mut_obj_get(o, key);
  for (size_t i = 0; i < n && yyjson_mut_is_arr(a); i++) {
    yyjson_mut_val *e = yyjson_mut_arr_get(a, i);
    if (ids[i]->name && *ids[i]->name) yyjson_mut_obj_add_strcpy(d, e, "name", ids[i]->name);
    if (ids[i]->description && *ids[i]->description)
      yyjson_mut_obj_add_strcpy(d, e, "description", ids[i]->description);
  }
}

static void release_idents(buckets_iam_ident **ids, size_t n) {
  for (size_t i = 0; i < n; i++) buckets_iam_ident_release(ids[i]);
  free(ids);
}

/* One user's ListAccessKeysLDAPResp into o. */
static void ldap_keys_for(buckets_iam *iam, yyjson_mut_doc *d, yyjson_mut_val *o, const char *dn, bool sts,
                          bool svc, size_t *nsts, size_t *nsvc) {
  buckets_iam_ident **list;
  size_t n;
  *nsts = *nsvc = 0;
  if (svc) {
    buckets_iam_list_derived(iam, dn, BUCKETS_IAM_SVC, &list, &n);
    add_ldap_key_infos(d, o, "serviceAccounts", list, n);
    *nsvc = n;
    release_idents(list, n);
  } else {
    yyjson_mut_obj_add_null(d, o, "serviceAccounts");
  }
  if (sts) {
    buckets_iam_list_derived(iam, dn, BUCKETS_IAM_STS, &list, &n);
    add_key_infos(d, o, "stsKeys", list, n);
    *nsts = n;
    release_idents(list, n);
  } else {
    yyjson_mut_obj_add_null(d, o, "stsKeys");
  }
}

/* ListAccessKeysLDAP */
static void h_ldap_list_access_keys(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char *user_dn = qget(c, "userDN");
  bool other = *user_dn && !(c->ident->parent && strcmp(user_dn, c->ident->parent) == 0);
  if (!allowed(c, "admin:ListServiceAccounts", !other)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  if (!other) user_dn = requestor_parent(c);
  buckets_ldapidp *lp = buckets_s3_ldap(c->s);
  buckets_ldap_dnres res;
  char err[1024];
  int r = buckets_ldapidp_validated_user(lp, user_dn, &res, err, sizeof(err));
  buckets_ldapidp_release(lp);
  if (r < 0) {
    buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
    return;
  }
  if (r == 0) {
    iam_error(c, BUCKETS_IAM_ERR_NO_SUCH_USER, NULL);
    return;
  }
  const char *lt = qget(c, "listType");
  bool sts = strcmp(lt, "svcacc-only") != 0, svc = strcmp(lt, "sts-only") != 0;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  size_t a, b;
  ldap_keys_for(c->s->iam, d, root, res.norm_dn, sts, svc, &a, &b);
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
  buckets_ldap_dnres_free(&res);
}

/* ListAccessKeysLDAPBulk */
static void h_ldap_list_access_keys_bulk(s3_ctx *c) {
  if (!admin_signed(c)) return;
  const char **dns;
  size_t ndn = qall(c, "userDNs", &dns);
  bool all = strcmp(qget(c, "all"), "true") == 0;
  bool self_only = !all && ndn == 0;
  buckets_iam *iam = c->s->iam;
  buckets_ldapidp *lp = buckets_s3_ldap(c->s);
  char **users = NULL;
  size_t nusers = 0;
  char err[1024];
  if (all && ndn) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    goto out;
  }
  if (all && !allowed(c, "admin:ListUsers", false)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  if (ndn == 1) {
    buckets_ldap_dnres res;
    const char *parent = c->ident->parent ? c->ident->parent : "";
    if (buckets_ldapidp_validated_user(lp, dns[0], &res, err, sizeof(err)) > 0 && strcmp(res.norm_dn, parent) == 0)
      self_only = true;
    if (strcmp(dns[0], parent) == 0) self_only = true;
    buckets_ldap_dnres_free(&res);
  }
  if (!allowed(c, "admin:ListServiceAccounts", self_only)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  if (all) {
    if (!buckets_iam_ldap_mode(iam)) {
      iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
      goto out;
    }
    char **pols;
    nusers = buckets_iam_sts_user_mappings(iam, ldap_user_pred, lp, &users, &pols);
    buckets_ldap_strv_free(pols, nusers);
  } else {
    const char *self = requestor_parent(c);
    size_t n = self_only && !ndn ? 1 : ndn;
    for (size_t i = 0; i < n; i++) {
      const char *u = self_only && !ndn ? self : dns[i];
      buckets_ldap_dnres res;
      int r = buckets_ldapidp_validated_user(lp, u, &res, err, sizeof(err));
      if (r < 0) {
        buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
        goto out;
      }
      if (r == 0) continue;
      users = buckets_xrealloc(users, (nusers + 1) * sizeof(char *));
      users[nusers++] = buckets_xstrdup(res.norm_dn);
      buckets_ldap_dnres_free(&res);
    }
  }
  const char *lt = qget(c, "listType");
  bool sts = strcmp(lt, "sts-only") == 0 || strcmp(lt, "all") == 0;
  bool svc = strcmp(lt, "svcacc-only") == 0 || strcmp(lt, "all") == 0;
  if (!sts && !svc && strcmp(lt, "users-only") != 0) {
    buckets_admin_error_msg(c, BUCKETS_ERR_INVALID_REQUEST, "invalid list type");
    goto out;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < nusers; i++) {
    char *ext = buckets_ldapidp_decode(users[i]);
    if (yyjson_mut_obj_get(root, ext)) {
      free(ext);
      continue;
    }
    yyjson_mut_val *o = yyjson_mut_obj(d);
    size_t a, b;
    ldap_keys_for(iam, d, o, users[i], sts, svc, &a, &b);
    if ((sts && !svc && !a) || (svc && !sts && !b)) {
      free(ext);
      continue;
    }
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, ext), o);
    free(ext);
  }
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
out:
  buckets_ldap_strv_free(users, nusers);
  buckets_ldapidp_release(lp);
  free(dns);
}

/* ListAccessKeysOpenIDBulk */
typedef struct {
  char *parent, *id, *readable;
  buckets_iam_ident **svc, **sts;
  size_t nsvc, nsts;
} oidc_user;

static int cmp_oidc_user(const void *a, const void *b) {
  return strcmp(((const oidc_user *)a)->parent, ((const oidc_user *)b)->parent);
}

static void h_openid_list_access_keys_bulk(s3_ctx *c) {
  if (!admin_signed(c)) return;
  buckets_openid *o = buckets_s3_openid(c->s);
  const char **users = NULL;
  size_t nu = 0;
  buckets_config *cfg = NULL;
  char **targets = NULL;
  size_t nt = 0;
  if (!buckets_openid_enabled(o)) {
    custom_error(c, 400, "OpenIDNotEnabled", "No enabled OpenID Connect identity providers");
    goto out;
  }
  nu = qall(c, "users", &users);
  bool all = strcmp(qget(c, "all"), "true") == 0;
  bool self_only = !all && nu == 0;
  const char *cfg_name = qget(c, "configName");
  bool all_configs = strcmp(qget(c, "allConfigs"), "true") == 0;
  if (!*cfg_name && !all_configs) cfg_name = BUCKETS_CONFIG_DEFAULT_TARGET;
  if (all && nu) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    goto out;
  }
  if (all) {
    if (!allowed(c, "admin:ListUsers", false)) {
      buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
      goto out;
    }
  } else if (nu == 1 && c->ident->parent && strcmp(users[0], c->ident->parent) == 0) {
    self_only = true;
  }
  if (!allowed(c, "admin:ListServiceAccounts", self_only)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    goto out;
  }
  const char *self = requestor_parent(c);
  if (self_only && !nu) {
    users[0] = self;
    nu = 1;
  }
  const char *lt = qget(c, "listType");
  bool list_sts = strcmp(lt, "sts-only") == 0 || strcmp(lt, "all") == 0;
  bool list_svc = strcmp(lt, "svcacc-only") == 0 || strcmp(lt, "all") == 0;
  if (!list_sts && !list_svc && strcmp(lt, "users-only") != 0) {
    buckets_admin_error_msg(c, BUCKETS_ERR_INVALID_REQUEST, "invalid list type");
    goto out;
  }
  /* GetConfigList: the configurations (the default one always) and their role ARNs. */
  cfg = buckets_config_sys_snapshot(c->s->config);
  nt = buckets_config_targets(cfg, "identity_openid", &targets);
  bool has_default = false;
  for (size_t i = 0; i < nt; i++) has_default |= strcmp(targets[i], BUCKETS_CONFIG_DEFAULT_TARGET) == 0;
  if (!has_default) {
    targets = buckets_xrealloc(targets, (nt + 1) * sizeof(char *));
    targets[nt++] = buckets_xstrdup(BUCKETS_CONFIG_DEFAULT_TARGET);
  }
  typedef struct {
    const char *name, *arn, *id_claim, *readable_claim;
    oidc_user *u;
    size_t nu;
  } cfg_ent;
  cfg_ent *ce = buckets_xcalloc(nt, sizeof(*ce));
  size_t nce = 0;
  for (size_t i = 0; i < nt; i++) {
    if (!all_configs && strcmp(cfg_name, targets[i]) != 0) continue;
    const char *arn = NULL, *n2, *rc = "", *ic = "";
    bool live = buckets_openid_target(o, targets[i], &arn);
    if (arn) buckets_openid_by_arn(o, arn, &n2, &rc, &ic);
    else if (live) ic = "sub";
    ce[nce++] = (cfg_ent){targets[i], arn ? arn : "arn:minio:iam:::role/dummy-internal", ic, rc, NULL, 0};
  }
  if (!nce) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_NO_SUCH_CONFIG_TARGET);
    free(ce);
    goto out;
  }
  const char *policy_claim = buckets_openid_claim_name(o);
  for (int pass = 0; pass < 2; pass++) {
    bool svc_pass = pass == 0;
    if (svc_pass ? !list_svc : !list_sts) continue;
    buckets_iam_ident **list;
    size_t n;
    buckets_iam_list_derived(c->s->iam, NULL, svc_pass ? BUCKETS_IAM_SVC : BUCKETS_IAM_STS, &list, &n);
    for (size_t i = 0; i < n; i++) {
      buckets_iam_ident *k = list[i];
      bool keep = false;
      const char *arn = buckets_iam_ident_claim(k, "sub") ? buckets_iam_ident_claim(k, "roleArn") : NULL;
      if (buckets_iam_ident_claim(k, "sub") && !arn && *policy_claim && buckets_iam_ident_claim(k, policy_claim))
        arn = "arn:minio:iam:::role/dummy-internal";
      cfg_ent *e = NULL;
      for (size_t j = 0; arn && j < nce && !e; j++)
        if (strcmp(ce[j].arn, arn) == 0) e = &ce[j];
      const char *id = e && *e->id_claim ? buckets_iam_ident_claim(k, e->id_claim) : NULL;
      if (e) {
        keep = !nu;
        for (size_t j = 0; j < nu && !keep; j++)
          keep = strcmp(users[j], k->parent) == 0 || (id && strcmp(users[j], id) == 0);
      }
      if (!keep) {
        buckets_iam_ident_release(k);
        continue;
      }
      oidc_user *u = NULL;
      for (size_t j = 0; j < e->nu && !u; j++)
        if (strcmp(e->u[j].parent, k->parent) == 0) u = &e->u[j];
      if (!u) {
        e->u = buckets_xrealloc(e->u, (e->nu + 1) * sizeof(oidc_user));
        u = &e->u[e->nu++];
        memset(u, 0, sizeof(*u));
        u->parent = buckets_xstrdup(k->parent);
        u->id = buckets_xstrdup(id ? id : "");
        const char *rn = *e->readable_claim ? buckets_iam_ident_claim(k, e->readable_claim) : NULL;
        u->readable = buckets_xstrdup(rn ? rn : "");
      }
      buckets_iam_ident ***arr = svc_pass ? &u->svc : &u->sts;
      size_t *cnt = svc_pass ? &u->nsvc : &u->nsts;
      *arr = buckets_xrealloc(*arr, (*cnt + 1) * sizeof(buckets_iam_ident *));
      (*arr)[(*cnt)++] = k;
    }
    free(list);
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  /* sorted by configuration name, users by parent */
  for (size_t a = 0; a < nce; a++)
    for (size_t b = a + 1; b < nce; b++)
      if (strcmp(ce[b].name, ce[a].name) < 0) {
        cfg_ent t = ce[a];
        ce[a] = ce[b];
        ce[b] = t;
      }
  for (size_t i = 0; i < nce; i++) {
    yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, root);
    yyjson_mut_obj_add_strcpy(d, e, "configName", ce[i].name);
    yyjson_mut_val *ua = yyjson_mut_obj_add_arr(d, e, "users");
    if (ce[i].nu) qsort(ce[i].u, ce[i].nu, sizeof(oidc_user), cmp_oidc_user);
    for (size_t j = 0; j < ce[i].nu; j++) {
      oidc_user *u = &ce[i].u[j];
      yyjson_mut_val *uo = yyjson_mut_arr_add_obj(d, ua);
      yyjson_mut_obj_add_strcpy(d, uo, "minioAccessKey", u->parent);
      yyjson_mut_obj_add_strcpy(d, uo, "ID", u->id);
      yyjson_mut_obj_add_strcpy(d, uo, "readableName", u->readable);
      add_key_infos(d, uo, "serviceAccounts", u->svc, u->nsvc);
      add_key_infos(d, uo, "stsKeys", u->sts, u->nsts);
      release_idents(u->svc, u->nsvc);
      release_idents(u->sts, u->nsts);
      free(u->parent);
      free(u->id);
      free(u->readable);
    }
    free(ce[i].u);
  }
  write_json(c, d, true);
  yyjson_mut_doc_free(d);
  free(ce);
out:
  for (size_t i = 0; i < nt; i++) free(targets[i]);
  free(targets);
  buckets_config_free(cfg);
  free(users);
  buckets_openid_release(o);
}

/* ServiceV2Handler (and the older ServiceHandler): restart, stop, freeze, unfreeze. */
static void h_service(s3_ctx *c) {
  const char *action = qget(c, "action");
  const char *perm;
  if (strcmp(action, "restart") == 0) perm = "admin:ServiceRestart";
  else if (strcmp(action, "stop") == 0) perm = "admin:ServiceStop";
  else if (strcmp(action, "freeze") == 0 || strcmp(action, "unfreeze") == 0) perm = "admin:ServiceFreeze";
  else {
    buckets_admin_error(c, BUCKETS_ERR_MALFORMED_POST_REQUEST);
    return;
  }
  if (!admin_req1(c, perm)) return;
  bool dry = strcmp(qget(c, "dry-run"), "true") == 0;
  bool process = strcmp(action, "restart") == 0 || strcmp(action, "stop") == 0;
  if (strcmp(qget(c, "type"), "2") == 0) {
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_strcpy(d, root, "action", action);
    yyjson_mut_obj_add_bool(d, root, "dryRun", dry);
    if (process) {
      yyjson_mut_val *res = yyjson_mut_obj_add_arr(d, root, "results");
      const buckets_cluster_info *ci = c->s->cluster;
      for (size_t i = 0; ci && i < ci->nnodes; i++) {
        yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, res);
        yyjson_mut_obj_add_strcpy(d, e, "host", ci->nodes[i]);
      }
      if (!ci || !ci->nnodes) yyjson_mut_obj_add_str(d, yyjson_mut_arr_add_obj(d, res), "host", "127.0.0.1");
    }
    write_json(c, d, false);
    yyjson_mut_doc_free(d);
  } else {
    c->resp->status = 200;
  }
  if (!dry || !process) buckets_s3_service(c->s, action, true);
}

/* RevokeTokens: /revoke-tokens/{userProvider} */
static void h_revoke_tokens(s3_ctx *c) {
  if (!admin_signed(c)) return;
  buckets_str path = c->req->path;
  const char *pfx = ADMIN_PREFIX "/revoke-tokens/";
  char provider[64];
  snprintf(provider, sizeof(provider), "%.*s", (int)(path.n - strlen(pfx)), path.p + strlen(pfx));
  char *user = buckets_xstrdup(qget(c, "user"));
  const char *type = qget(c, "tokenRevokeType");
  bool full = strcmp(qget(c, "fullRevoke"), "true") == 0;
  bool self = !*user;
  buckets_iam *iam = c->s->iam;
  if (!self) {
    /* getUserWithProvider(validate false) */
    if (strcmp(provider, "ldap") == 0) {
      if (!buckets_iam_ldap_mode(iam)) {
        iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
        goto out;
      }
      buckets_ldapidp *lp = buckets_s3_ldap(c->s);
      buckets_ldap_dnres res;
      char err[1024];
      int r = buckets_ldapidp_validated_user(lp, user, &res, err, sizeof(err));
      buckets_ldapidp_release(lp);
      if (r <= 0) {
        iam_error(c, BUCKETS_IAM_ERR_NO_SUCH_USER, NULL);
        goto out;
      }
      free(user);
      user = buckets_xstrdup(res.norm_dn);
      buckets_ldap_dnres_free(&res);
    } else if (strcmp(provider, "builtin") != 0) {
      iam_error(c, BUCKETS_IAM_ERR_NOT_ALLOWED, NULL);
      goto out;
    }
  }
  if ((*user && !*type && !full) || (*type && full)) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    goto out;
  }
  if (!allowed(c, "admin:RemoveServiceAccount", false) || self) {
    const char *parent = requestor_parent(c);
    if (!self && strcmp(user, parent) != 0) {
      buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
      goto out;
    }
    free(user);
    user = buckets_xstrdup(parent);
  }
  if (self && !*type && !full) {
    const char *t = buckets_iam_ident_is_temp(c->ident) ? buckets_iam_ident_claim(c->ident, "tokenRevokeType") : NULL;
    if (!t || !*t) {
      buckets_admin_error(c, BUCKETS_ERR_NO_TOKEN_REVOKE_TYPE);
      goto out;
    }
    type = t;
  }
  buckets_iam_err e = buckets_iam_revoke_tokens(iam, user, type);
  if (e) iam_error(c, e, NULL);
  else c->resp->status = 204;
out:
  free(user);
}

/* ---- routing ------------------------------------------------------------------------------- */

typedef struct {
  const char *method;
  const char *path; /* after /minio/admin/v3 */
  void (*fn)(s3_ctx *c);
  const char *name; /* MinIO's handler (trace: "admin.<name>") */
} route;

static void h_server_info(s3_ctx *c) {
  if (admin_req1(c, "admin:ServerInfo")) buckets_admin_server_info(c);
}
static void h_storage_info(s3_ctx *c) {
  if (admin_req1(c, "admin:StorageInfo")) buckets_admin_storage_info(c);
}
static void h_bg_heal_status(s3_ctx *c) {
  if (admin_req1(c, "admin:Heal")) buckets_admin_background_heal_status(c);
}

/* TraceHandler: madmin.TraceInfo records as they happen, as JSON lines */
/* A stream of this node's records merged with the peers' (MinIO's trace and
 * console log handlers subscribe locally and to every peer). */
typedef struct {
  void *sub;
  long (*read)(void *, char *, size_t);
  void (*push)(void *, const char *, size_t);
  void (*free)(void *);
  buckets_peer_relay *relay;
} merged_stream;

static long merged_read(void *ud, char *buf, size_t cap) {
  merged_stream *m = ud;
  return m->read(m->sub, buf, cap);
}

static void merged_push(void *ud, const char *line, size_t n) {
  merged_stream *m = ud;
  m->push(m->sub, line, n);
}

static void merged_free(void *ud) {
  merged_stream *m = ud;
  buckets_peer_relay_stop(m->relay); /* before the subscriber it pushes into */
  m->free(m->sub);
  free(m);
}

static void trace_push(void *sub, const char *line, size_t n) { buckets_trace_sub_push(sub, line, n); }
static void console_push(void *sub, const char *line, size_t n) { buckets_console_sub_push(sub, line, n); }

static void merged_start(s3_ctx *c, merged_stream *m, const char *target, const char *node) {
  size_t np = 0;
  buckets_http_client *const *all = buckets_peer_clients(c->s->peers, &np);
  buckets_http_client **peers = buckets_xcalloc(np ? np : 1, sizeof(*peers));
  size_t k = 0;
  for (size_t i = 0; i < np; i++) {
    char name[300];
    snprintf(name, sizeof(name), "%s:%d", buckets_http_client_host(all[i]), buckets_http_client_port(all[i]));
    if (!node || !*node || strcasecmp(name, node) == 0) peers[k++] = all[i];
  }
  m->relay = buckets_peer_relay_start(peers, k, target, merged_push, m);
  free(peers);
  buckets_http_resp_header(c->resp, "Content-Type", "text/event-stream");
  buckets_http_resp_header(c->resp, "Cache-Control", "no-cache");
  buckets_http_resp_header(c->resp, "X-Accel-Buffering", "no");
  c->resp->status = 200;
  c->resp->chunked = true;
  c->resp->stream = merged_read;
  c->resp->stream_ud = m;
  c->resp->stream_free = merged_free;
}

static const char *query_param(void *ud, const char *key) { return buckets_query_get(ud, key); }

/* TraceHandler: ServiceTraceOpts from the query; records from every node */
static void h_trace(s3_ctx *c) {
  if (!admin_req1(c, "admin:ServerTrace")) return;
  buckets_trace_opts o;
  buckets_trace_params tp = {query_param, &c->q};
  if (!buckets_trace_opts_parse(&tp, &o)) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  merged_stream *m = buckets_xcalloc(1, sizeof(*m));
  *m = (merged_stream){buckets_trace_subscribe(&o), buckets_trace_sub_read, trace_push, buckets_trace_sub_free, NULL};
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/trace?");
  buckets_buf_append(&t, c->req->query.p, c->req->query.n);
  buckets_buf_append_char(&t, '\0');
  merged_start(c, m, t.data, NULL);
  buckets_buf_free(&t);
}

/* ConsoleLogHandler: the last `limit` records, then new ones, from every
 * node (or the one named by node) */
static void h_console_log(s3_ctx *c) {
  if (!admin_req1(c, "admin:ConsoleLog")) return;
  const char *node = buckets_query_get(&c->q, "node");
  const char *limit = buckets_query_get(&c->q, "limit");
  char *end = NULL;
  long last = limit ? strtol(limit, &end, 10) : 10;
  if (!limit || !*limit || *end) last = 10;
  uint32_t mask = buckets_log_kind_mask(buckets_query_get(&c->q, "logType"));
  buckets_http_resp_header(c->resp, "Connection", "close");
  merged_stream *m = buckets_xcalloc(1, sizeof(*m));
  *m = (merged_stream){buckets_console_subscribe(node, (int)last, mask), buckets_console_sub_read, console_push,
                       buckets_console_sub_free, NULL};
  char target[128];
  snprintf(target, sizeof(target), BUCKETS_INTERNODE_PREFIX "peer/log?mask=%u", mask);
  merged_start(c, m, target, node);
}

static void h_attach(s3_ctx *c) { attach_detach(c, true, false); }
static void h_detach(s3_ctx *c) { attach_detach(c, false, false); }
static void h_ldap_attach(s3_ctx *c) { attach_detach(c, true, true); }
static void h_ldap_detach(s3_ctx *c) { attach_detach(c, false, true); }

static const route k_routes[] = {
    {"GET", "/info", h_server_info, "ServerInfo"},
    {"GET", "/storageinfo", h_storage_info, "StorageInfo"},
    {"POST", "/background-heal/status", h_bg_heal_status, "BackgroundHealStatus"},
    {"POST", "/heal/**", buckets_admin_heal, "Heal"},
    {"GET", "/top/locks", buckets_admin_top_locks, "TopLocks"},
    {"GET", "/inspect-data", buckets_admin_inspect_data, "InspectData"},
    {"POST", "/inspect-data", buckets_admin_inspect_data, "InspectData"},
    {"GET", "/export-bucket-metadata", buckets_admin_export_bucket_metadata, "ExportBucketMetadata"},
    {"PUT", "/import-bucket-metadata", buckets_admin_import_bucket_metadata, "ImportBucketMetadata"},
    {"POST", "/force-unlock", buckets_admin_force_unlock, "ForceUnlock"},
    {"GET", "/trace", h_trace, "Trace"},
    {"GET", "/log", h_console_log, "ConsoleLog"},
    {"GET", "/get-config-kv", buckets_admin_config_get_kv, "GetConfigKV"},
    {"PUT", "/set-config-kv", buckets_admin_config_set_kv, "SetConfigKV"},
    {"DELETE", "/del-config-kv", buckets_admin_config_del_kv, "DelConfigKV"},
    {"GET", "/help-config-kv", buckets_admin_config_help, "HelpConfigKV"},
    {"GET", "/list-config-history-kv", buckets_admin_config_history_list, "ListConfigHistoryKV"},
    {"DELETE", "/clear-config-history-kv", buckets_admin_config_history_clear, "ClearConfigHistoryKV"},
    {"PUT", "/restore-config-history-kv", buckets_admin_config_history_restore, "RestoreConfigHistoryKV"},
    {"GET", "/config", buckets_admin_config_export, "GetConfig"},
    {"PUT", "/config", buckets_admin_config_import, "SetConfig"},
    {"PUT", "/add-user", h_add_user, "AddUser"},
    {"DELETE", "/remove-user", h_remove_user, "RemoveUser"},
    {"GET", "/list-users", h_list_users, "ListBucketUsers"},
    {"GET", "/user-info", h_user_info, "GetUserInfo"},
    {"PUT", "/set-user-status", h_set_user_status, "SetUserStatus"},
    {"PUT", "/update-group-members", h_update_group_members, "UpdateGroupMembers"},
    {"GET", "/group", h_get_group, "GetGroup"},
    {"GET", "/groups", h_list_groups, "ListGroups"},
    {"PUT", "/set-group-status", h_set_group_status, "SetGroupStatus"},
    {"GET", "/list-canned-policies", h_list_policies, "ListBucketPolicies"},
    {"GET", "/info-canned-policy", h_info_policy, "InfoCannedPolicy"},
    {"PUT", "/add-canned-policy", h_add_policy, "AddCannedPolicy"},
    {"DELETE", "/remove-canned-policy", h_remove_policy, "RemoveCannedPolicy"},
    {"PUT", "/set-user-or-group-policy", h_set_user_or_group_policy, "SetPolicyForUserOrGroup"},
    {"POST", "/idp/builtin/policy/attach", h_attach, "AttachDetachPolicyBuiltin"},
    {"POST", "/idp/builtin/policy/detach", h_detach, "AttachDetachPolicyBuiltin"},
    {"PUT", "/add-service-account", h_add_svc, "AddServiceAccount"},
    {"POST", "/update-service-account", h_update_svc, "UpdateServiceAccount"},
    {"GET", "/info-service-account", h_info_svc, "InfoServiceAccount"},
    {"GET", "/list-service-accounts", h_list_svc, "ListServiceAccounts"},
    {"DELETE", "/delete-service-account", h_delete_svc, "DeleteServiceAccount"},
    {"GET", "/list-access-keys-bulk", h_list_access_keys_bulk, "ListAccessKeysBulk"},
    {"POST", "/revoke-tokens/*", h_revoke_tokens, "RevokeTokens"},
    {"POST", "/service", h_service, "ServiceV2"},
    {"GET", "/export-iam", buckets_admin_export_iam, "ExportIAM"},
    {"PUT", "/import-iam", buckets_admin_import_iam, "ImportIAM"},
    {"PUT", "/import-iam-v2", buckets_admin_import_iam_v2, "ImportIAMV2"},
    {"GET", "/accountinfo", h_account_info, "AccountInfo"},
    {"GET", "/idp/openid/list-access-keys-bulk", h_openid_list_access_keys_bulk, "ListAccessKeysOpenIDBulk"},
    {"GET", "/idp/ldap/policy-entities", h_ldap_policy_entities, "ListLDAPPolicyMappingEntities"},
    {"POST", "/idp/ldap/policy/attach", h_ldap_attach, "AttachDetachPolicyLDAP"},
    {"POST", "/idp/ldap/policy/detach", h_ldap_detach, "AttachDetachPolicyLDAP"},
    {"PUT", "/idp/ldap/add-service-account", h_add_svc_ldap, "AddServiceAccountLDAP"},
    {"GET", "/idp/ldap/list-access-keys", h_ldap_list_access_keys, "ListAccessKeysLDAP"},
    {"GET", "/idp/ldap/list-access-keys-bulk", h_ldap_list_access_keys_bulk, "ListAccessKeysLDAPBulk"},
    {"GET", "/info-access-key", h_info_access_key, "InfoAccessKey"},
    {"GET", "/temporary-account-info", h_temp_account_info, "TemporaryAccountInfo"},
    {"GET", "/idp/builtin/policy-entities", h_policy_entities, "ListPolicyMappingEntities"},
    {"GET", "/get-bucket-quota", buckets_admin_get_bucket_quota, "GetBucketQuotaConfig"},
    {"PUT", "/set-bucket-quota", buckets_admin_set_bucket_quota, "PutBucketQuotaConfig"},
    {"GET", "/datausageinfo", buckets_admin_data_usage_info, "DataUsageInfo"},
    {"PUT", "/set-remote-target", buckets_admin_set_remote_target, "SetRemoteTarget"},
    {"GET", "/list-remote-targets", buckets_admin_list_remote_targets, "ListRemoteTargets"},
    {"DELETE", "/remove-remote-target", buckets_admin_remove_remote_target, "RemoveRemoteTarget"},
    {"POST", "/replication/diff", buckets_admin_replication_diff, "ReplicationDiff"},
    {"GET", "/replication/mrf", buckets_admin_replication_mrf, "ReplicationMRF"},
    {"PUT", "/tier", buckets_admin_tier_add, "AddTier"},
    {"GET", "/tier", buckets_admin_tier_list, "ListTier"},
    {"POST", "/tier/*", buckets_admin_tier_edit, "EditTier"},
    {"DELETE", "/tier/*", buckets_admin_tier_remove, "RemoveTier"},
    {"GET", "/tier/*", buckets_admin_tier_verify, "VerifyTier"},
    {"GET", "/tier-stats", buckets_admin_tier_stats, "TierStats"},
    {"POST", "/start-job", buckets_admin_batch_start, "StartBatchJob"},
    {"GET", "/list-jobs", buckets_admin_batch_list, "ListBatchJobs"},
    {"GET", "/status-job", buckets_admin_batch_status, "BatchJobStatus"},
    {"GET", "/describe-job", buckets_admin_batch_describe, "DescribeBatchJob"},
    {"DELETE", "/cancel-job", buckets_admin_batch_cancel, "CancelBatchJob"},
    {"GET", "/metrics", buckets_admin_metrics, "Metrics"},
    {"GET", "/pools/list", buckets_admin_pools_list, "ListPools"},
    {"GET", "/pools/status", buckets_admin_pools_status, "StatusPool"},
    {"POST", "/pools/decommission", buckets_admin_decommission, "StartDecommission"},
    {"POST", "/pools/cancel", buckets_admin_decommission_cancel, "CancelDecommission"},
    {"POST", "/rebalance/start", buckets_admin_rebalance_start, "RebalanceStart"},
    {"GET", "/rebalance/status", buckets_admin_rebalance_status, "RebalanceStatus"},
    {"POST", "/rebalance/stop", buckets_admin_rebalance_stop, "RebalanceStop"},
    {"PUT", "/site-replication/add", buckets_admin_sr_add, "SiteReplicationAdd"},
    {"PUT", "/site-replication/remove", buckets_admin_sr_remove, "SiteReplicationRemove"},
    {"GET", "/site-replication/info", buckets_admin_sr_info, "SiteReplicationInfo"},
    {"GET", "/site-replication/metainfo", buckets_admin_sr_metainfo, "SiteReplicationMetaInfo"},
    {"GET", "/site-replication/status", buckets_admin_sr_status, "SiteReplicationStatus"},
    {"PUT", "/site-replication/peer/join", buckets_admin_sr_peer_join, "SRPeerJoin"},
    {"PUT", "/site-replication/peer/bucket-ops", buckets_admin_sr_peer_bucket_ops, "SRPeerBucketOps"},
    {"PUT", "/site-replication/peer/iam-item", buckets_admin_sr_peer_iam_item, "SRPeerReplicateIAMItem"},
    {"PUT", "/site-replication/peer/bucket-meta", buckets_admin_sr_peer_bucket_meta, "SRPeerReplicateBucketItem"},
    {"GET", "/site-replication/peer/idp-settings", buckets_admin_sr_peer_idp_settings, "SRPeerGetIDPSettings"},
    {"PUT", "/site-replication/edit", buckets_admin_sr_edit, "SiteReplicationEdit"},
    {"PUT", "/site-replication/peer/edit", buckets_admin_sr_peer_edit, "SRPeerEdit"},
    {"PUT", "/site-replication/peer/remove", buckets_admin_sr_peer_remove, "SRPeerRemove"},
    {"PUT", "/site-replication/resync/op", buckets_admin_sr_resync_op, "SiteReplicationResyncOp"},
    {"PUT", "/site-replication/state/edit", buckets_admin_sr_state_edit, "SRStateEdit"},
    {"POST", "/kms/status", buckets_admin_kms_status_v3, "KMSStatus"},
    {"POST", "/kms/key/create", buckets_admin_kms_create_key_v3, "KMSCreateKey"},
    {"GET", "/kms/key/status", buckets_admin_kms_key_status_v3, "KMSKeyStatus"},
};

bool buckets_admin_is_admin_path(buckets_str path) { return buckets_str_has_prefix(path, ADMIN_PREFIX "/"); }

void buckets_admin_handle(s3_ctx *c) {
  buckets_str path = c->req->path;
  buckets_str rest = {path.p + strlen(ADMIN_PREFIX), path.n - strlen(ADMIN_PREFIX)};
  bool path_known = false;
  if (buckets_admin_is_idp_config(path)) {
    if (!c->s->layer) buckets_admin_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
    else buckets_admin_idp_config(c);
    return;
  }
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_routes); i++) {
    const char *rp = k_routes[i].path;
    size_t rl = strlen(rp);
    bool deep = rl > 1 && rp[rl - 1] == '*' && rp[rl - 2] == '*'; /* any rest, slashes too */
    bool match = deep                        ? rest.n >= rl - 2 && memcmp(rest.p, rp, rl - 2) == 0
                 : rl && rp[rl - 1] == '*' ? rest.n >= rl && memcmp(rest.p, rp, rl - 1) == 0 &&
                                               !memchr(rest.p + rl - 1, '/', rest.n - (rl - 1))
                                           : buckets_str_eq_c(rest, rp);
    if (!match) continue;
    path_known = true;
    if (!buckets_str_eq_c(c->req->method, k_routes[i].method)) continue;
    c->op_name = k_routes[i].name; /* for trace */
    if (!c->s->layer) {
      buckets_admin_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
      return;
    }
    k_routes[i].fn(c);
    return;
  }
  (void)path_known;
  buckets_admin_unsupported(c);
}

/* errorResponseHandler: an unknown admin route, or a known one with
 * another method (or one this setup does not register). */
void buckets_admin_unsupported(s3_ctx *c) {
  const buckets_cluster_info *ci = c->s->cluster;
  const char *mode = ci && ci->distributed                   ? "mode-server-distributed-xl"
                     : c->s->layer && c->s->layer->nall == 1 ? "mode-server-xl-single"
                                                             : "mode-server-xl";
  char msg[128];
  snprintf(msg, sizeof(msg), "This 'admin' API is not supported by server in '%s'", mode);
  buckets_admin_json_error(c, 426, "XMinioAdminVersionMismatch", msg, NULL, NULL);
}

/* ---- shared with the other admin handler files -------------------------------------------- */

bool buckets_admin_authorize(s3_ctx *c, const char *action) { return admin_req1(c, action); }
bool buckets_admin_authorize_any(s3_ctx *c, const char *const *actions, size_t n) { return admin_req(c, actions, n); }

void buckets_admin_custom_error(s3_ctx *c, int status, const char *code, const char *message) {
  custom_error(c, status, code, message);
}

void buckets_admin_iam_error(s3_ctx *c, buckets_iam_err e, const char *detail) { iam_error(c, e, detail); }
