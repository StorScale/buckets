/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin config: get/set/reset/export/import/history
 * (MinIO's cmd/admin-handlers-config-kv.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "notify/targets.h"
#include "config/sys.h"
#include "iam/ldapidp.h"
#include "iam/openid.h"
#include "core/timefmt.h"
#include "crypto/madmin.h"

#define MAX_ECONFIG_JSON 262272

static void json_error(s3_ctx *c, int status, const char *code, const char *message) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "Code", code);
  yyjson_mut_obj_add_strcpy(d, root, "Message", message);
  yyjson_mut_obj_add_strcpy(d, root, "Resource", c->path ? c->path : "/");
  yyjson_mut_obj_add_str(d, root, "RequestId", c->request_id);
  yyjson_mut_obj_add_str(d, root, "HostId", c->s->host_id);
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  c->resp->status = status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, json, len);
  free(json);
  yyjson_mut_doc_free(d);
}

/* ErrConfigGeneric: 400 XMinioConfigError. */
static void config_error(s3_ctx *c, const char *msg) { json_error(c, 400, "XMinioConfigError", msg); }
/* writeCustomErrorResponseJSON(ErrAdminConfigBadJSON, err). */
static void bad_config(s3_ctx *c, const char *msg) { json_error(c, 400, "XMinioAdminConfigBadJSON", msg); }

static bool authorized(s3_ctx *c) {
  if (!c->ident || c->auth != BUCKETS_AUTH_SIGV4_HEADER || !buckets_http_header_get(c->req, "X-Amz-Content-Sha256").p ||
      !buckets_s3_allowed(c, "admin:ConfigUpdate", NULL, NULL, false)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return false;
  }
  if (!c->s->config) {
    buckets_admin_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
    return false;
  }
  return true;
}

/* The madmin-encrypted request body, as a NUL-terminated string. */
static char *read_body(s3_ctx *c) {
  if (c->req->body_len > MAX_ECONFIG_JSON) {
    json_error(c, 400, "XMinioAdminConfigTooLarge",
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
  return buckets_buf_detach(&plain);
}

static void reply_encrypted(s3_ctx *c, const char *data, size_t n) {
  buckets_buf_reset(&c->resp->body);
  if (!buckets_madmin_encrypt(c->ident->secret_key, data, n, &c->resp->body)) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

static const char *q(s3_ctx *c, const char *k) {
  const char *v = buckets_query_get(&c->q, k);
  return v ? v : "";
}

void buckets_admin_config_get_kv(s3_ctx *c) {
  if (!authorized(c)) return;
  const char *key = q(c, "key");
  char sub[128];
  const char *colon = strchr(key, ':');
  snprintf(sub, sizeof(sub), "%.*s", colon ? (int)(colon - key) : (int)strlen(key), key);
  const char *target = colon ? (colon[1] ? colon + 1 : BUCKETS_CONFIG_DEFAULT_TARGET) : NULL;
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  buckets_buf out = BUCKETS_BUF_INIT;
  char err[512];
  if (!buckets_config_get_text(cfg, sub, target, true, &out, err, sizeof(err))) config_error(c, err);
  else reply_encrypted(c, out.data ? out.data : "", out.len);
  buckets_buf_free(&out);
  buckets_config_free(cfg);
}

static void applied(s3_ctx *c, bool dynamic) {
  if (dynamic) buckets_http_resp_header(c->resp, "x-minio-config-applied", "true");
  c->resp->status = 200;
}

/* validateConfig with the request's targets (ParseConfigTargetID): the
 * notification targets it names must be reachable. */
static bool validate_set(buckets_config *cfg, const char *sub, const char *text, char *err, size_t errlen) {
  char **names = NULL;
  size_t n = 0;
  for (const char *p = text; *p;) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    if (len && *p != '#') {
      size_t w = 0;
      while (w < len && p[w] != ' ' && p[w] != '\t') w++;
      const char *colon = memchr(p, ':', w);
      names = buckets_xrealloc(names, (n + 1) * sizeof(char *));
      names[n++] = colon ? buckets_xstrndup(colon + 1, (size_t)(p + w - colon - 1)) : buckets_xstrdup("");
    }
    p += len + (eol != NULL);
  }
  buckets_targets_probe_set(sub, names, n);
  bool ok = buckets_config_validate(cfg, sub, err, errlen);
  buckets_targets_probe_set(NULL, NULL, 0);
  for (size_t i = 0; i < n; i++) free(names[i]);
  free(names);
  return ok;
}

void buckets_admin_config_set_kv(s3_ctx *c) {
  if (!authorized(c)) return;
  char *text = read_body(c);
  if (!text) return;
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  char err[1024], sub[128];
  bool dynamic;
  if (!buckets_config_set_text(cfg, text, &dynamic, err, sizeof(err)) ||
      !buckets_config_subsys_of(text, sub, sizeof(sub), err, sizeof(err))) {
    config_error(c, err);
  } else if (!validate_set(cfg, sub, text, err, sizeof(err))) {
    bad_config(c, err);
  } else {
    bool ok = buckets_config_sys_update(c->s->config, cfg, text, sub, err, sizeof(err));
    cfg = NULL;
    if (!ok) buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
    else applied(c, dynamic);
  }
  buckets_config_free(cfg);
  free(text);
}

void buckets_admin_config_del_kv(s3_ctx *c) {
  if (!authorized(c)) return;
  char *text = read_body(c);
  if (!text) return;
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  char err[1024], sub[128];
  if (!buckets_config_subsys_of(text, sub, sizeof(sub), err, sizeof(err)) ||
      !buckets_config_del_text(cfg, text, err, sizeof(err))) {
    config_error(c, err);
  } else if (!buckets_config_validate(cfg, sub, err, sizeof(err))) {
    bad_config(c, err);
  } else {
    bool ok = buckets_config_sys_update(c->s->config, cfg, NULL, sub, err, sizeof(err));
    cfg = NULL;
    if (!ok) buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
    else applied(c, buckets_config_is_dynamic(sub));
  }
  buckets_config_free(cfg);
  free(text);
}

void buckets_admin_config_help(s3_ctx *c) {
  if (!authorized(c)) return;
  char err[256];
  char *json = buckets_config_help_json(q(c, "subSys"), q(c, "key"), buckets_query_has(&c->q, "env"), err, sizeof(err));
  if (!json) {
    config_error(c, err);
    return;
  }
  buckets_buf_reset(&c->resp->body);
  buckets_buf_appendf(&c->resp->body, "%s\n", json);
  free(json);
  c->resp->status = 200;
}

void buckets_admin_config_history_list(s3_ctx *c) {
  if (!authorized(c)) return;
  int count = atoi(q(c, "count"));
  buckets_config_history *h;
  size_t n = buckets_config_sys_history(c->s->config, count > 0 ? count : -1, true, &h);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, arr);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, e, "restoreId", h[i].restore_id);
    char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
    buckets_time_rfc3339_nano(h[i].create_ns / 1000000000LL, (long)(h[i].create_ns % 1000000000LL), ts);
    yyjson_mut_obj_add_strcpy(d, e, "createTime", ts);
    yyjson_mut_obj_add_strcpy(d, e, "data", h[i].data ? h[i].data : "");
  }
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  reply_encrypted(c, json, len);
  free(json);
  yyjson_mut_doc_free(d);
  buckets_config_history_free(h, n);
}

void buckets_admin_config_history_clear(s3_ctx *c) {
  if (!authorized(c)) return;
  const char *id = q(c, "restoreId");
  if (!*id) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  if (strcmp(id, "all") == 0) {
    buckets_config_history *h;
    size_t n = buckets_config_sys_history(c->s->config, -1, false, &h);
    for (size_t i = 0; i < n; i++) buckets_config_sys_history_delete(c->s->config, h[i].restore_id);
    buckets_config_history_free(h, n);
  } else if (!buckets_config_sys_history_delete(c->s->config, id)) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
}

void buckets_admin_config_history_restore(s3_ctx *c) {
  if (!authorized(c)) return;
  const char *id = q(c, "restoreId");
  buckets_buf text = BUCKETS_BUF_INIT;
  if (!*id || !buckets_config_sys_history_read(c->s->config, id, &text)) {
    buckets_buf_free(&text);
    json_error(c, 404, "XMinioConfigNotFoundError", "config history entry not found");
    return;
  }
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  char err[1024];
  if (!buckets_config_set_text(cfg, text.data ? text.data : "", NULL, err, sizeof(err))) {
    config_error(c, err);
  } else if (!buckets_config_validate(cfg, "", err, sizeof(err))) {
    bad_config(c, err);
  } else {
    bool ok = buckets_config_sys_update(c->s->config, cfg, NULL, "", err, sizeof(err));
    cfg = NULL;
    if (!ok) {
      buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
    } else {
      buckets_config_sys_history_delete(c->s->config, id);
      c->resp->status = 200;
    }
  }
  buckets_config_free(cfg);
  buckets_buf_free(&text);
}

void buckets_admin_config_export(s3_ctx *c) {
  if (!authorized(c)) return;
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_config_export(cfg, &out);
  reply_encrypted(c, out.data ? out.data : "", out.len);
  buckets_buf_free(&out);
  buckets_config_free(cfg);
}

void buckets_admin_config_import(s3_ctx *c) {
  if (!authorized(c)) return;
  char *text = read_body(c);
  if (!text) return;
  buckets_config *cfg = buckets_config_new();
  char err[1024];
  if (!buckets_config_set_text(cfg, text, NULL, err, sizeof(err))) {
    config_error(c, err);
  } else if (!buckets_config_validate(cfg, "", err, sizeof(err))) {
    bad_config(c, err);
  } else {
    bool ok = buckets_config_sys_update(c->s->config, cfg, text, "", err, sizeof(err));
    cfg = NULL;
    if (!ok) buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
    else c->resp->status = 200;
  }
  buckets_config_free(cfg);
  free(text);
}

/* ---- mc idp openid|ldap (admin-handlers-idp-config.go) ------------------------------------ */

#define IDP_PREFIX "/minio/admin/v3/idp-config/"

static const char *idp_subsys(const char *type) {
  if (strcmp(type, "openid") == 0) return "identity_openid";
  if (strcmp(type, "ldap") == 0) return "identity_ldap";
  return NULL;
}

static void invalid_idp_type(s3_ctx *c) {
  json_error(c, 400, "XMinioAdminConfigInvalidIDPType",
             "Invalid IDP configuration type - must be one of [ldap openid]");
}

static bool is_target(const buckets_config *cfg, const char *subsys, const char *name) {
  if (strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) == 0) return true;
  char **t;
  size_t n = buckets_config_targets(cfg, subsys, &t);
  bool found = false;
  for (size_t i = 0; i < n; i++) {
    found |= strcmp(t[i], name) == 0;
    free(t[i]);
  }
  free(t);
  return found;
}

static int cmp_info(const void *a, const void *b) {
  return strcmp(((const buckets_config_kvsrc *)a)->key, ((const buckets_config_kvsrc *)b)->key);
}

/* GetConfigInfo for either type: the non-default values (with the live
 * enable state and role ARN for OpenID), sorted by key. false: no such target. */
static bool idp_info(s3_ctx *c, const buckets_config *cfg, const char *type, const char *name, yyjson_mut_doc *d,
                     yyjson_mut_val *arr, bool *has_env) {
  bool openid = strcmp(type, "openid") == 0;
  const char *subsys = idp_subsys(type);
  if (has_env) *has_env = false;
  if (openid ? !is_target(cfg, subsys, name) : strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) != 0) return false;
  buckets_config_kvsrc *kv;
  size_t n = buckets_config_resolved(cfg, subsys, name, true, &kv);
  buckets_openid *o = openid ? buckets_s3_openid(c->s) : NULL;
  const char *arn = NULL;
  bool live = openid && buckets_openid_target(o, name, &arn);
  buckets_config_kvsrc *res = buckets_xcalloc(n + 2, sizeof(*res));
  size_t nr = 0;
  for (size_t i = 0; i < n; i++) {
    if (kv[i].src == BUCKETS_CFG_SRC_DEF) {
      if (!openid || strcmp(kv[i].key, "enable") != 0 || !live) continue;
      free(kv[i].value);
      kv[i].value = buckets_xstrdup(buckets_openid_enabled(o) ? "on" : "off");
    }
    res[nr++] = kv[i];
    if (kv[i].src == BUCKETS_CFG_SRC_ENV && has_env) *has_env = true;
  }
  if (arn) res[nr++] = (buckets_config_kvsrc){"roleARN", (char *)arn, 0};
  qsort(res, nr, sizeof(*res), cmp_info);
  for (size_t i = 0; i < nr; i++) {
    yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, e, "key", res[i].key);
    yyjson_mut_obj_add_strcpy(d, e, "value", res[i].value);
    yyjson_mut_obj_add_bool(d, e, "isCfg", res[i].src != 0);
    yyjson_mut_obj_add_bool(d, e, "isEnv", res[i].src == BUCKETS_CFG_SRC_ENV);
  }
  free(res);
  buckets_config_kvsrc_free(kv, n);
  buckets_openid_release(o);
  return true;
}

static size_t idp_info_count(s3_ctx *c, const buckets_config *cfg, const char *type, const char *name) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  size_t n = idp_info(c, cfg, type, name, d, arr, NULL) ? yyjson_mut_arr_size(arr) : 0;
  yyjson_mut_doc_free(d);
  return n;
}

/* An LDAP validation error, as Validation.FormatError. */
static bool ldap_validation_error(s3_ctx *c, const char *err) {
  static const char *const results[] = {
      "LDAP Server Connection Error", "LDAP Server Connection Parameters Misconfigured", "LDAP Lookup Bind Error",
      "User Search Parameters Misconfigured", "Group Search Parameters Misconfigured"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(results); i++) {
    size_t n = strlen(results[i]);
    if (strncmp(err, results[i], n) != 0 || strncmp(err + n, ": ", 2) != 0) continue;
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&b, "Result: %s\nDetail: %s", results[i], err + n + 2);
    json_error(c, 400, "XMinioAdminConfigLDAPValidation", b.data);
    buckets_buf_free(&b);
    return true;
  }
  return false;
}

static void idp_validation_error(s3_ctx *c, const char *subsys, const char *err) {
  if (strcmp(subsys, "identity_ldap") == 0 && ldap_validation_error(c, err)) return;
  bad_config(c, err);
}

static void idp_add_update(s3_ctx *c, const char *type, const char *name, bool update) {
  if (c->req->body_len > MAX_ECONFIG_JSON) {
    json_error(c, 400, "XMinioAdminConfigTooLarge",
               "Configuration data provided exceeds the allowed maximum of 262272 bytes");
    return;
  }
  buckets_str ct = buckets_http_header_get(c->req, "Content-Type");
  if (!ct.p || !buckets_str_eq_c(ct, "application/octet-stream")) {
    buckets_admin_error(c, BUCKETS_ERR_BAD_REQUEST);
    return;
  }
  char *body = read_body(c);
  if (!body) return;
  const char *subsys = idp_subsys(type);
  buckets_config *cfg = NULL;
  buckets_buf line = BUCKETS_BUF_INIT;
  if (!subsys) {
    invalid_idp_type(c);
    goto out;
  }
  if (!*name) name = BUCKETS_CONFIG_DEFAULT_TARGET;
  if (strcmp(type, "ldap") == 0 && strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) != 0) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_LDAP_NON_DEFAULT_CONFIG_NAME);
    goto out;
  }
  cfg = buckets_config_sys_snapshot(c->s->config);
  /* handleCreateUpdateValidation */
  bool exists = strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) != 0 ? is_target(cfg, subsys, name)
                                                                 : idp_info_count(c, cfg, type, name) > 0;
  if (exists != update) {
    buckets_admin_error(c, update ? BUCKETS_ERR_ADMIN_CONFIG_IDP_CFG_NAME_DOES_NOT_EXIST
                                  : BUCKETS_ERR_ADMIN_CONFIG_IDP_CFG_NAME_ALREADY_EXISTS);
    goto out;
  }
  buckets_buf_appendf(&line, "%s%s%s %s", subsys, strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) ? ":" : "",
                      strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) ? name : "", body);
  char err[1024];
  bool dynamic;
  if (!buckets_config_set_text(cfg, line.data, &dynamic, err, sizeof(err))) {
    config_error(c, err);
    goto out;
  }
  if (dynamic) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    goto out;
  }
  if (!buckets_config_validate(cfg, subsys, err, sizeof(err))) {
    idp_validation_error(c, subsys, err);
    goto out;
  }
  bool ok = buckets_config_sys_update(c->s->config, cfg, line.data, subsys, err, sizeof(err));
  cfg = NULL;
  if (!ok) buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
  else c->resp->status = 200;
out:
  buckets_buf_free(&line);
  buckets_config_free(cfg);
  free(body);
}

static void idp_list(s3_ctx *c, const char *type) {
  const char *subsys = idp_subsys(type);
  if (!subsys) {
    invalid_idp_type(c);
    return;
  }
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  char **t;
  size_t n = buckets_config_targets(cfg, subsys, &t);
  bool has_default = false;
  for (size_t i = 0; i < n; i++) has_default |= strcmp(t[i], BUCKETS_CONFIG_DEFAULT_TARGET) == 0;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, arr);
  bool openid = strcmp(type, "openid") == 0;
  buckets_openid *o = openid ? buckets_s3_openid(c->s) : NULL;
  buckets_ldapidp *lp = openid ? NULL : buckets_s3_ldap(c->s);
  for (size_t i = 0; i < n + !has_default; i++) {
    const char *name = i < n ? t[i] : BUCKETS_CONFIG_DEFAULT_TARGET;
    yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_str(d, e, "type", type);
    yyjson_mut_obj_add_strcpy(d, e, "name", name);
    const char *arn = NULL;
    bool live = openid && buckets_openid_target(o, name, &arn);
    yyjson_mut_obj_add_bool(d, e, "enabled", openid ? live && buckets_openid_enabled(o) : buckets_ldapidp_enabled(lp));
    if (arn) yyjson_mut_obj_add_strcpy(d, e, "roleARN", arn);
  }
  for (size_t i = 0; i < n; i++) free(t[i]);
  free(t);
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  reply_encrypted(c, json, len);
  free(json);
  yyjson_mut_doc_free(d);
  buckets_openid_release(o);
  buckets_ldapidp_release(lp);
  buckets_config_free(cfg);
}

static void idp_get(s3_ctx *c, const char *type, const char *name) {
  if (!idp_subsys(type)) {
    invalid_idp_type(c);
    return;
  }
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "type", type);
  if (*name) yyjson_mut_obj_add_strcpy(d, root, "name", name);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, root, "info");
  if (!idp_info(c, cfg, type, name, d, arr, NULL)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_NO_SUCH_CONFIG_TARGET);
  } else {
    size_t len;
    char *json = yyjson_mut_write(d, 0, &len);
    reply_encrypted(c, json, len);
    free(json);
  }
  yyjson_mut_doc_free(d);
  buckets_config_free(cfg);
}

static void idp_delete(s3_ctx *c, const char *type, const char *name) {
  const char *subsys = idp_subsys(type);
  if (!subsys) {
    invalid_idp_type(c);
    return;
  }
  buckets_config *cfg = buckets_config_sys_snapshot(c->s->config);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  bool has_env;
  char err[1024];
  if (!idp_info(c, cfg, type, name, d, arr, &has_env)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_NO_SUCH_CONFIG_TARGET);
  } else if (has_env) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_CONFIG_ENV_OVERRIDDEN);
  } else {
    char key[300];
    snprintf(key, sizeof(key), "%s%s%s", subsys, strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) ? ":" : "",
             strcmp(name, BUCKETS_CONFIG_DEFAULT_TARGET) ? name : "");
    if (!buckets_config_del_text(cfg, key, err, sizeof(err))) {
      buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
    } else if (!buckets_config_validate(cfg, subsys, err, sizeof(err))) {
      idp_validation_error(c, subsys, err);
    } else {
      bool ok = buckets_config_sys_update(c->s->config, cfg, NULL, subsys, err, sizeof(err));
      cfg = NULL;
      if (!ok) buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, err);
      else c->resp->status = 200;
    }
  }
  yyjson_mut_doc_free(d);
  buckets_config_free(cfg);
}

bool buckets_admin_is_idp_config(buckets_str path) {
  return buckets_str_has_prefix(path, IDP_PREFIX) ||
         (path.n == strlen(IDP_PREFIX) - 1 && memcmp(path.p, IDP_PREFIX, path.n) == 0);
}

void buckets_admin_idp_config(s3_ctx *c) {
  if (!authorized(c)) return;
  buckets_str path = c->req->path;
  size_t off = strlen(IDP_PREFIX);
  char rest[512] = "";
  if (path.n > off) snprintf(rest, sizeof(rest), "%.*s", (int)(path.n - off), path.p + off);
  char *slash = strchr(rest, '/');
  const char *type = rest, *name = NULL;
  if (slash) {
    *slash = '\0';
    name = slash + 1;
  }
  buckets_str m = c->req->method;
  if (!name) {
    if (buckets_str_eq_c(m, "GET")) idp_list(c, type);
    else buckets_admin_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
  } else if (buckets_str_eq_c(m, "PUT")) {
    idp_add_update(c, type, name, false);
  } else if (buckets_str_eq_c(m, "POST")) {
    idp_add_update(c, type, name, true);
  } else if (buckets_str_eq_c(m, "GET")) {
    idp_get(c, type, name);
  } else if (buckets_str_eq_c(m, "DELETE")) {
    idp_delete(c, type, name);
  } else {
    buckets_admin_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
  }
}
