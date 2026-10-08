/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* What SCIM has been told, for the console (docs/design/scim.md), a Buckets extension to the admin API:
 *   GET /minio/admin/v3/buckets/scim      admin:ListUsers
 *   -> {"enabled", "provider", "people": [{"id", "externalId", "userName", "displayName", "active", "deleted",
 *       "modified", "credentials"}], "holders": people with credentials from this provider, "matched": of those,
 *       how many SCIM names, "me": {"person", "named", "state"} for the signed-in person}
 * holders > 0 with matched 0 usually means externalId isn't the tokens' ID (Entra: map objectId to externalId). */
#include "iam/scim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "iam/idsync.h"
#include "object/sysconfig.h"

void buckets_admin_scim(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ListUsers")) return;
  buckets_s3_server *s = c->s;
  buckets_idsync_settings st;
  char err[512];
  bool have = buckets_idsync_settings_from_env(&st, err, sizeof(err)) && *st.provider;
  buckets_scim_store sc = {0};
  bool read_ok = false;
  for (int attempt = 0; attempt < 20 && !read_ok; attempt++) { /* drives or peers still coming up: again */
    if (attempt) nanosleep(&(struct timespec){0, 250000000L}, NULL);
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_obj_err e =
        s->layer ? buckets_sysconfig_read(s->layer, BUCKETS_SCIM_PATH, &b, NULL) : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
    read_ok = (!e || e == BUCKETS_OBJ_ERR_NO_SUCH_KEY) && buckets_scim_store_parse(b.data, b.len, &sc);
    buckets_buf_free(&b);
  }
  if (!read_ok) {
    buckets_admin_custom_error(c, 500, "InternalError", "SCIM's records could not be read");
    return;
  }
  /* the provider's people with credentials, and how many each holds */
  const char **holders = NULL;
  size_t *counts = NULL, nh = 0;
  for (int t = 0; have && t < 2; t++) {
    buckets_iam_ident **l;
    size_t n;
    buckets_iam_list_derived(s->iam, NULL, t ? BUCKETS_IAM_SVC : BUCKETS_IAM_STS, &l, &n);
    for (size_t i = 0; i < n; i++) {
      const char *p = buckets_idsync_person_of(
          &st, buckets_iam_ident_claim(l[i], "tid"), buckets_iam_ident_claim(l[i], "oid"),
          buckets_iam_ident_claim(l[i], "iss"), buckets_iam_ident_claim(l[i], "sub"));
      if (p && !(l[i]->type == BUCKETS_IAM_STS && buckets_iam_ident_is_expired(l[i]))) {
        size_t k = 0;
        while (k < nh && strcmp(holders[k], p) != 0) k++;
        if (k == nh) {
          holders = buckets_xrealloc(holders, (nh + 1) * sizeof(*holders));
          counts = buckets_xrealloc(counts, (nh + 1) * sizeof(*counts));
          holders[nh] = buckets_xstrdup(p);
          counts[nh++] = 0;
        }
        counts[k]++;
      }
      buckets_iam_ident_release(l[i]);
    }
    free(l);
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *arr = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_bool(d, root, "enabled", have && st.scim);
  yyjson_mut_obj_add_strcpy(d, root, "provider", have ? st.provider : "");
  for (size_t i = 0; i < sc.n; i++) {
    const buckets_scim_user *u = &sc.u[i];
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "id", u->id);
    yyjson_mut_obj_add_strcpy(d, o, "externalId", u->external_id ? u->external_id : "");
    yyjson_mut_obj_add_strcpy(d, o, "userName", u->user_name ? u->user_name : "");
    yyjson_mut_obj_add_strcpy(d, o, "displayName", u->display_name ? u->display_name : "");
    yyjson_mut_obj_add_bool(d, o, "active", u->active);
    yyjson_mut_obj_add_bool(d, o, "deleted", u->deleted);
    yyjson_mut_obj_add_int(d, o, "modified", u->modified);
    size_t creds = 0;
    for (size_t k = 0; u->external_id && k < nh; k++)
      if (!strcmp(holders[k], u->external_id)) creds = counts[k];
    yyjson_mut_obj_add_uint(d, o, "credentials", creds);
  }
  yyjson_mut_obj_add_val(d, root, "people", arr);
  size_t matched = 0;
  for (size_t k = 0; k < nh; k++) matched += buckets_scim_state_of(&sc, holders[k]) != BUCKETS_IDSYNC_UNKNOWN;
  yyjson_mut_obj_add_uint(d, root, "holders", nh);
  yyjson_mut_obj_add_uint(d, root, "matched", matched);
  /* the signed-in person: the console's test */
  const char *me = have && c->ident ? buckets_idsync_person_of(&st, buckets_iam_ident_claim(c->ident, "tid"),
                                                               buckets_iam_ident_claim(c->ident, "oid"),
                                                               buckets_iam_ident_claim(c->ident, "iss"),
                                                               buckets_iam_ident_claim(c->ident, "sub"))
                                    : NULL;
  yyjson_mut_val *mo = yyjson_mut_obj_add_obj(d, root, "me");
  if (me) {
    buckets_idsync_state state = buckets_scim_state_of(&sc, me);
    yyjson_mut_obj_add_strcpy(d, mo, "person", me);
    yyjson_mut_obj_add_bool(d, mo, "named", state != BUCKETS_IDSYNC_UNKNOWN);
    yyjson_mut_obj_add_str(d, mo, "state", buckets_idsync_state_name(state));
  }
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  if (j) buckets_buf_append(&c->resp->body, j, len);
  free(j);
  yyjson_mut_doc_free(d);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
  for (size_t k = 0; k < nh; k++) free((char *)holders[k]);
  free(holders);
  free(counts);
  buckets_scim_store_free(&sc);
}
