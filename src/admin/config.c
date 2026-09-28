/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin config: get/set/reset/export/import/history
 * (MinIO's cmd/admin-handlers-config-kv.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "config/sys.h"
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
  } else if (!buckets_config_validate(cfg, sub, err, sizeof(err))) {
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
