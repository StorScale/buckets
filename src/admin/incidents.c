/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Ransomware alerts' incidents (docs/design/ransomware-alerts.md), Buckets extensions to the admin API:
 *   GET  /minio/admin/v3/buckets/incidents?state=open|all                          admin:ServerInfo
 *        {"incidents": [...] (newest first, as ransomware/ransomware.h stores them),
 *         "rule": {"floor", "factor", "windowMinutes"}, "response": "disable" | "alert"}
 *   POST /minio/admin/v3/buckets/incidents?id=<id>&action=disable|undo|false-alarm  admin:ConfigUpdate
 *        disable turns the credential behind it off, as BUCKETS_RANSOMWARE_RESPONSE=disable does on its own; undo
 *        turns it back on (a key or a user); false-alarm marks the incident so. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "object/sysconfig.h"
#include "ransomware/ransomware.h"
#include "s3/ransomguard.h"

static void reply(s3_ctx *c, yyjson_mut_doc *d) {
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  if (j) buckets_buf_append(&c->resp->body, j, len);
  free(j);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

static yyjson_mut_doc *load(s3_ctx *c) {
  buckets_buf raw = BUCKETS_BUF_INIT;
  buckets_sysconfig_read(c->s->layer, BUCKETS_RW_INCIDENTS_PATH, &raw, NULL);
  yyjson_mut_doc *d = buckets_rw_incidents_parse(raw.data, raw.len);
  /* keep the leader's bookkeeping when writing back */
  yyjson_doc *rd = raw.len ? yyjson_read(raw.data, raw.len, 0) : NULL;
  yyjson_val *since = yyjson_obj_get(yyjson_doc_get_root(rd), "since");
  if (since) yyjson_mut_obj_add_val(d, yyjson_mut_doc_get_root(d), "since", yyjson_val_mut_copy(d, since));
  yyjson_doc_free(rd);
  buckets_buf_free(&raw);
  return d;
}

void buckets_admin_incidents(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ServerInfo")) return;
  const char *state = buckets_query_get(&c->q, "state");
  bool open_only = state && !strcmp(state, "open");
  yyjson_mut_doc *d = load(c);
  yyjson_mut_val *all = yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents");
  yyjson_mut_doc *o = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(o), *arr = yyjson_mut_obj_add_arr(o, root, "incidents");
  yyjson_mut_doc_set_root(o, root);
  for (size_t i = yyjson_mut_arr_size(all); i-- > 0;) { /* newest first */
    yyjson_mut_val *x = yyjson_mut_arr_get(all, i);
    if (open_only && yyjson_mut_get_sint(yyjson_mut_obj_get(x, "closed"))) continue;
    yyjson_mut_arr_append(arr, yyjson_mut_val_mut_copy(o, x));
  }
  buckets_rw_rule rule;
  buckets_rw_rule_from_env(&rule);
  yyjson_mut_val *r = yyjson_mut_obj_add_obj(o, root, "rule");
  yyjson_mut_obj_add_uint(o, r, "floor", rule.floor);
  yyjson_mut_obj_add_real(o, r, "factor", rule.factor);
  yyjson_mut_obj_add_int(o, r, "windowMinutes", rule.window_min);
  const char *resp = getenv("BUCKETS_RANSOMWARE_RESPONSE");
  yyjson_mut_obj_add_str(o, root, "response", resp && !strcmp(resp, "disable") ? "disable" : "alert");
  reply(c, o);
  yyjson_mut_doc_free(o);
  yyjson_mut_doc_free(d);
}

void buckets_admin_incident_action(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ConfigUpdate")) return;
  const char *id = buckets_query_get(&c->q, "id"), *action = buckets_query_get(&c->q, "action");
  if (!id || !action ||
      (strcmp(action, "false-alarm") && strcmp(action, "undo") && strcmp(action, "disable"))) {
    buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT,
                            "id, and action disable, undo or false-alarm");
    return;
  }
  yyjson_mut_doc *d = load(c);
  yyjson_mut_val *x = NULL, *it;
  size_t i, max;
  yyjson_mut_arr_foreach(yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents"), i, max, it) {
    const char *xid = yyjson_mut_get_str(yyjson_mut_obj_get(it, "id"));
    if (xid && !strcmp(xid, id)) x = it;
  }
  if (!x) {
    yyjson_mut_doc_free(d);
    buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, "no such incident");
    return;
  }
  yyjson_mut_val *c0 = yyjson_mut_arr_get_first(yyjson_mut_obj_get(x, "credentials"));
  const char *ak = yyjson_mut_get_str(yyjson_mut_obj_get(c0, "accessKey"));
  const char *user = yyjson_mut_get_str(yyjson_mut_obj_get(c0, "user"));
  const char *type = yyjson_mut_get_str(yyjson_mut_obj_get(c0, "type"));
  if (!strcmp(action, "false-alarm")) {
    yyjson_mut_obj_remove_key(x, "falseAlarm");
    yyjson_mut_obj_add_bool(d, x, "falseAlarm", true);
  } else if (!strcmp(action, "disable")) {
    const char *was = yyjson_mut_get_str(yyjson_mut_obj_get(x, "action"));
    bool undone = yyjson_mut_get_bool(yyjson_mut_obj_get(x, "undone"));
    if (was && strcmp(was, "none") && !undone) {
      yyjson_mut_doc_free(d);
      buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, "the credential is already turned off");
      return;
    }
    char err[256];
    const char *done =
        buckets_ransomguard_disable(c->s, ak ? ak : "", user ? user : "", type ? type : "", err, sizeof(err));
    if (!strcmp(done, "none")) {
      yyjson_mut_doc_free(d);
      buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, *err ? err : "nothing to turn off");
      return;
    }
    yyjson_mut_obj_remove_key(x, "action");
    yyjson_mut_obj_add_str(d, x, "action", done);
    yyjson_mut_obj_remove_key(x, "undone");
    yyjson_mut_obj_add_bool(d, x, "undone", false);
  } else {
    if (yyjson_mut_get_bool(yyjson_mut_obj_get(x, "undone"))) {
      yyjson_mut_doc_free(d);
      buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, "already undone");
      return;
    }
    char err[256];
    if (!buckets_ransomguard_undo(c->s, yyjson_mut_get_str(yyjson_mut_obj_get(x, "action")), ak ? ak : "",
                                  type ? type : "", err, sizeof(err))) {
      yyjson_mut_doc_free(d);
      buckets_admin_error_msg(c, BUCKETS_ERR_ADMIN_INVALID_ARGUMENT, err);
      return;
    }
    yyjson_mut_obj_remove_key(x, "undone");
    yyjson_mut_obj_add_bool(d, x, "undone", true);
  }
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_obj_err e =
      j ? buckets_sysconfig_write(c->s->layer, BUCKETS_RW_INCIDENTS_PATH, j, len) : BUCKETS_OBJ_ERR_IO;
  free(j);
  if (e) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
  } else { /* the incident as it is now */
    yyjson_mut_doc *o = yyjson_mut_doc_new(NULL);
    yyjson_mut_doc_set_root(o, yyjson_mut_val_mut_copy(o, x));
    reply(c, o);
    yyjson_mut_doc_free(o);
  }
  yyjson_mut_doc_free(d);
}
