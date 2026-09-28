/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin cluster iam export|import: IAM state as a zip of JSON files
 * (MinIO's ExportIAM / ImportIAM / ImportIAMV2 in admin-handlers-users.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "core/timefmt.h"
#include "core/zip.h"
#include "iam/ldapidp.h"

#define ASSETS "iam-assets/"

static const char *const k_files[] = {"policies.json",     "users.json",          "groups.json",
                                      "svcaccts.json",     "user_mappings.json",  "group_mappings.json",
                                      "stsuser_mappings.json"};

static void add_time(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, buckets_iam_time t) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(t.sec, t.nsec, ts);
  yyjson_mut_obj_add_strcpy(d, o, key, ts);
}

static void add_file(buckets_zip_writer *z, const char *file, yyjson_mut_doc *d) {
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  char name[128];
  snprintf(name, sizeof(name), ASSETS "%s", file);
  buckets_zip_add(z, name, json, len, time(NULL));
  free(json);
}

static yyjson_mut_doc *new_obj(yyjson_mut_val **root) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, *root);
  return d;
}

static void export_mappings(buckets_iam *iam, buckets_zip_writer *z, const char *file, buckets_iam_utype t,
                            bool group) {
  yyjson_mut_val *root;
  yyjson_mut_doc *d = new_obj(&root);
  buckets_iam_mapping *m;
  size_t n = buckets_iam_list_mappings(iam, t, group, &m);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *o = yyjson_mut_obj(d);
    yyjson_mut_obj_add_int(d, o, "version", 1);
    yyjson_mut_obj_add_strcpy(d, o, "policy", m[i].policies);
    add_time(d, o, "updatedAt", m[i].updated);
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, m[i].name), o);
  }
  buckets_iam_mappings_free(m, n);
  add_file(z, file, d);
  yyjson_mut_doc_free(d);
}

void buckets_admin_export_iam(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ExportIAM")) return;
  buckets_iam *iam = c->s->iam;
  buckets_zip_writer z;
  buckets_zip_writer_init(&z);
  yyjson_mut_val *root;
  yyjson_mut_doc *d;

  /* policies.json: every policy, canned ones included */
  d = new_obj(&root);
  buckets_iam_policy_doc *pols;
  size_t np;
  buckets_iam_list_policies(iam, &pols, &np);
  for (size_t i = 0; i < np; i++) {
    yyjson_doc *pd = yyjson_read(pols[i].json, strlen(pols[i].json), 0);
    if (pd) yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, pols[i].name), yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
    yyjson_doc_free(pd);
  }
  buckets_iam_policy_doc_free(pols, np);
  free(pols);
  add_file(&z, k_files[0], d);
  yyjson_mut_doc_free(d);

  /* users.json: madmin.AddOrUpdateUserReq per regular user */
  d = new_obj(&root);
  buckets_iam_user_info *ui;
  size_t nu;
  buckets_iam_list_users(iam, &ui, &nu);
  for (size_t i = 0; i < nu; i++) {
    buckets_iam_ident *id = buckets_iam_get_ident(iam, ui[i].name);
    if (!id) continue;
    yyjson_mut_val *o = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, o, "secretKey", id->secret_key);
    yyjson_mut_obj_add_str(d, o, "status", strcmp(id->status, "off") == 0 ? "disabled" : "enabled");
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, ui[i].name), o);
    buckets_iam_ident_release(id);
  }
  buckets_iam_user_info_free(ui, nu);
  free(ui);
  add_file(&z, k_files[1], d);
  yyjson_mut_doc_free(d);

  /* groups.json: GroupInfo per built-in group */
  d = new_obj(&root);
  char **groups;
  size_t ng;
  buckets_iam_list_groups(iam, &groups, &ng);
  for (size_t i = 0; i < ng; i++) {
    buckets_iam_group_desc gd;
    if (!buckets_iam_ldap_mode(iam) && buckets_iam_group_describe(iam, groups[i], &gd) == BUCKETS_IAM_OK &&
        gd.status && *gd.status) {
      yyjson_mut_val *o = yyjson_mut_obj(d);
      yyjson_mut_obj_add_int(d, o, "version", 1);
      yyjson_mut_obj_add_strcpy(d, o, "status", gd.status);
      yyjson_mut_val *ms = yyjson_mut_obj_add_arr(d, o, "members");
      for (size_t k = 0; k < gd.nmembers; k++) yyjson_mut_arr_add_strcpy(d, ms, gd.members[k]);
      add_time(d, o, "updatedAt", gd.updated);
      yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, groups[i]), o);
      buckets_iam_group_desc_free(&gd);
    }
    free(groups[i]);
  }
  free(groups);
  add_file(&z, k_files[2], d);
  yyjson_mut_doc_free(d);

  /* svcaccts.json: madmin.SRSvcAccCreate per service account */
  d = new_obj(&root);
  buckets_iam_ident **svcs;
  size_t ns;
  buckets_iam_list_derived(iam, NULL, BUCKETS_IAM_SVC, &svcs, &ns);
  for (size_t i = 0; i < ns; i++) {
    buckets_iam_ident *sv = svcs[i];
    if (strcmp(sv->access_key, "site-replicator-0") != 0) {
      yyjson_mut_val *o = yyjson_mut_obj(d);
      yyjson_mut_obj_add_strcpy(d, o, "parent", sv->parent ? sv->parent : "");
      yyjson_mut_obj_add_strcpy(d, o, "accessKey", sv->access_key);
      yyjson_mut_obj_add_strcpy(d, o, "secretKey", sv->secret_key);
      if (sv->ngroups) {
        yyjson_mut_val *g = yyjson_mut_obj_add_arr(d, o, "groups");
        for (size_t k = 0; k < sv->ngroups; k++) yyjson_mut_arr_add_strcpy(d, g, sv->groups[k]);
      } else {
        yyjson_mut_obj_add_null(d, o, "groups");
      }
      if (sv->claims) yyjson_mut_obj_add_val(d, o, "claims", yyjson_val_mut_copy(d, yyjson_doc_get_root(sv->claims)));
      else yyjson_mut_obj_add_null(d, o, "claims");
      yyjson_doc *sp = sv->has_session_policy && sv->session_policy_json
                           ? yyjson_read(sv->session_policy_json, strlen(sv->session_policy_json), 0)
                           : NULL;
      if (sp) yyjson_mut_obj_add_val(d, o, "sessionPolicy", yyjson_val_mut_copy(d, yyjson_doc_get_root(sp)));
      else yyjson_mut_obj_add_null(d, o, "sessionPolicy");
      yyjson_doc_free(sp);
      yyjson_mut_obj_add_strcpy(d, o, "status", sv->status);
      yyjson_mut_obj_add_strcpy(d, o, "name", sv->name ? sv->name : "");
      yyjson_mut_obj_add_strcpy(d, o, "description", sv->description ? sv->description : "");
      add_time(d, o, "expiration", sv->expiration);
      yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, sv->access_key), o);
    }
    buckets_iam_ident_release(sv);
  }
  free(svcs);
  add_file(&z, k_files[3], d);
  yyjson_mut_doc_free(d);

  export_mappings(iam, &z, k_files[4], BUCKETS_IAM_REG, false);
  export_mappings(iam, &z, k_files[5], BUCKETS_IAM_REG, true);
  export_mappings(iam, &z, k_files[6], BUCKETS_IAM_STS, false);

  buckets_zip_finish(&z);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, z.out.data, z.out.len);
  buckets_zip_writer_free(&z);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/zip");
}

/* ---- import -------------------------------------------------------------------------------------- */

typedef struct {
  yyjson_mut_doc *d;
  yyjson_mut_val *skipped, *removed, *added, *failed;
} result;

static yyjson_mut_val *list_of(result *r, yyjson_mut_val *section, const char *key) {
  yyjson_mut_val *a = yyjson_mut_obj_get(section, key);
  if (!a) a = yyjson_mut_obj_add_arr(r->d, section, key);
  return a;
}

static void note(result *r, yyjson_mut_val *section, const char *key, const char *name) {
  yyjson_mut_arr_add_strcpy(r->d, list_of(r, section, key), name);
}

static void note_failed(result *r, const char *key, const char *name) {
  yyjson_mut_val *e = yyjson_mut_arr_add_obj(r->d, list_of(r, r->failed, key));
  yyjson_mut_obj_add_strcpy(r->d, e, "name", name);
  yyjson_mut_obj_add_obj(r->d, e, "error"); /* a Go error marshals as {} */
}

static yyjson_mut_val *split_policies(yyjson_mut_doc *d, const char *csv) {
  yyjson_mut_val *a = yyjson_mut_arr(d);
  for (const char *p = csv; p && *p;) {
    const char *e = strchr(p, ',');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    yyjson_mut_arr_add_strncpy(d, a, p, n);
    p = e ? e + 1 : p + n;
  }
  return a;
}

static void note_mapping(result *r, const char *key, const char *name, const char *csv, bool ok) {
  if (ok) {
    yyjson_mut_val *m = yyjson_mut_arr_add_obj(r->d, list_of(r, r->added, key));
    yyjson_mut_obj_add(m, yyjson_mut_strcpy(r->d, name), split_policies(r->d, csv));
  } else {
    yyjson_mut_val *e = yyjson_mut_arr_add_obj(r->d, list_of(r, r->failed, key));
    yyjson_mut_obj_add_strcpy(r->d, e, "name", name);
    yyjson_mut_obj_add_val(r->d, e, "policies", split_policies(r->d, csv));
    yyjson_mut_obj_add_obj(r->d, e, "error");
  }
}

/* importError / importErrorWithAPIErr */
static void import_error(s3_ctx *c, buckets_s3_error code, const char *file, const char *entity, const char *err) {
  char msg[1024];
  if (entity && *entity) snprintf(msg, sizeof(msg), "error importing %s from %s with: %s", entity, file, err);
  else snprintf(msg, sizeof(msg), "error importing %s with: %s", file, err);
  buckets_admin_error_msg(c, code, msg);
}

/* Reads and parses one file of the archive: NULL with *missing when it is
 * not there; NULL (an error answered) when it does not parse. */
static yyjson_doc *read_file(s3_ctx *c, const buckets_zip_reader *zr, const char *file, bool *missing) {
  char name[128];
  snprintf(name, sizeof(name), ASSETS "%s", file);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_zip_status st = buckets_zip_read(zr, name, &b);
  *missing = st == BUCKETS_ZIP_NOT_FOUND;
  yyjson_doc *d = NULL;
  if (st == BUCKETS_ZIP_CORRUPT) {
    import_error(c, BUCKETS_ERR_INVALID_REQUEST, file, NULL, "zip: not a valid zip file");
  } else if (st == BUCKETS_ZIP_OK) {
    d = yyjson_read(b.data ? b.data : "", b.len, 0);
    if (!d || !yyjson_is_obj(yyjson_doc_get_root(d))) {
      yyjson_doc_free(d);
      d = NULL;
      import_error(c, BUCKETS_ERR_ADMIN_CONFIG_BAD_JSON, file, NULL, "invalid JSON");
    }
  }
  buckets_buf_free(&b);
  return d;
}

static bool has_space_be(const char *s) {
  size_t n = strlen(s);
  return n && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n');
}

typedef struct {
  char *key;
  const char *orig;
} dn_key;

/* NormalizeLDAPMappingImport: keys that are DNs must be in the directory
 * (else they are skipped) and are renamed to their normalized form. */
static bool normalize_ldap_keys(s3_ctx *c, yyjson_mut_doc *md, yyjson_mut_val *map, bool group, result *r,
                                const char *skip_key, const char *file) {
  buckets_ldapidp *lp = buckets_s3_ldap(c->s);
  bool ok = true;
  size_t idx, max;
  yyjson_mut_val *k, *v;
  dn_key *ren = NULL;
  size_t nren = 0;
  char **skipped = NULL;
  size_t nskipped = 0;
  yyjson_mut_obj_foreach(map, idx, max, k, v) {
    const char *key = yyjson_mut_get_str(k);
    if (!buckets_ldapidp_parses_as_dn(key)) continue;
    buckets_ldap_dnres res;
    bool under = true;
    char err[1024];
    int f = group ? buckets_ldapidp_validated_group(lp, key, &res, &under, err, sizeof(err))
                  : buckets_ldapidp_validated_user(lp, key, &res, err, sizeof(err));
    if (f < 0) {
      char msg[1400];
      snprintf(msg, sizeof(msg), "errors validating LDAP DN: could not validate `%s` exists in LDAP directory: %s", key,
               err);
      import_error(c, BUCKETS_ERR_INTERNAL_ERROR, file, NULL, msg);
      ok = false;
      break;
    }
    if (f == 0 || !under) {
      skipped = buckets_xrealloc(skipped, (nskipped + 1) * sizeof(char *));
      skipped[nskipped++] = buckets_xstrdup(key);
    } else if (strcmp(res.norm_dn, key) != 0) {
      ren = buckets_xrealloc(ren, (nren + 1) * sizeof(*ren));
      ren[nren++] = (dn_key){buckets_xstrdup(res.norm_dn), key};
    }
    buckets_ldap_dnres_free(&res);
  }
  for (size_t i = 0; ok && i < nskipped; i++) {
    note(r, r->skipped, skip_key, skipped[i]);
    yyjson_mut_obj_remove_key(map, skipped[i]);
  }
  for (size_t i = 0; ok && i < nren; i++) {
    yyjson_mut_val *val = yyjson_mut_obj_get(map, ren[i].orig);
    yyjson_mut_val *existing = yyjson_mut_obj_get(map, ren[i].key);
    if (existing && val && !yyjson_mut_equals(yyjson_mut_obj_get(existing, "policy"), yyjson_mut_obj_get(val, "policy"))) {
      char msg[1024];
      snprintf(msg, sizeof(msg), "multiple DNs map to the same LDAP DN[%s]: [%s]; please remove DNs that are not needed",
               ren[i].key, ren[i].orig);
      import_error(c, BUCKETS_ERR_INTERNAL_ERROR, file, NULL, msg);
      ok = false;
      break;
    }
    yyjson_mut_val *copy = val ? yyjson_mut_val_mut_copy(md, val) : NULL;
    yyjson_mut_obj_remove_key(map, ren[i].orig);
    /* the old mapping in storage goes */
    buckets_iam_policy_set(c->s->iam, ren[i].orig, group, BUCKETS_IAM_STS, "");
    if (!existing && copy) yyjson_mut_obj_add(map, yyjson_mut_strcpy(md, ren[i].key), copy);
  }
  for (size_t i = 0; i < nren; i++) free(ren[i].key);
  free(ren);
  for (size_t i = 0; i < nskipped; i++) free(skipped[i]);
  free(skipped);
  buckets_ldapidp_release(lp);
  return ok;
}

/* Imports one of the mapping files. */
static bool import_mappings(s3_ctx *c, const buckets_zip_reader *zr, const char *file, buckets_iam_utype t,
                            bool group, const char *added_key, result *r) {
  bool missing;
  yyjson_doc *doc = read_file(c, zr, file, &missing);
  if (!doc) return missing;
  buckets_iam *iam = c->s->iam;
  yyjson_mut_doc *md = yyjson_doc_mut_copy(doc, NULL);
  yyjson_doc_free(doc);
  yyjson_mut_val *map = yyjson_mut_doc_get_root(md);
  bool ok = true;
  if (buckets_iam_ldap_mode(iam) && (group || t == BUCKETS_IAM_STS))
    ok = normalize_ldap_keys(c, md, map, group, r, group ? "groups" : "users", file);
  size_t idx, max;
  yyjson_mut_val *k, *v;
  yyjson_mut_obj_foreach(map, idx, max, k, v) {
    if (!ok) break;
    const char *name = yyjson_mut_get_str(k);
    const char *pols = yyjson_mut_get_str(yyjson_mut_obj_get(v, "policy"));
    if (!pols) pols = "";
    if (!group) {
      buckets_iam_ident *cur = buckets_iam_get_ident(iam, name);
      bool temp = cur && buckets_iam_ident_is_temp(cur);
      buckets_iam_ident_release(cur);
      if (temp) {
        import_error(c, BUCKETS_ERR_INTERNAL_ERROR, file, name, "Specified IAM action is not allowed");
        ok = false;
        break;
      }
    }
    buckets_iam_err e = buckets_iam_policy_set(iam, name, group, t, pols);
    note_mapping(r, added_key, name, pols, e == BUCKETS_IAM_OK);
  }
  yyjson_mut_doc_free(md);
  return ok;
}

static void import_iam(s3_ctx *c, bool v2) {
  if (!buckets_admin_authorize(c, "admin:ImportIAM")) return;
  buckets_s3_error re = buckets_s3_read_doc(c);
  if (re) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  buckets_zip_reader zr;
  if (!buckets_zip_open(&zr, c->doc.data, c->doc.len)) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  buckets_iam *iam = c->s->iam;
  result r = {0};
  r.d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(r.d);
  yyjson_mut_doc_set_root(r.d, root);
  r.skipped = yyjson_mut_obj_add_obj(r.d, root, "skipped");
  r.removed = yyjson_mut_obj_add_obj(r.d, root, "removed");
  r.added = yyjson_mut_obj_add_obj(r.d, root, "added");
  r.failed = yyjson_mut_obj_add_obj(r.d, root, "failed");
  bool missing;
  yyjson_doc *doc;
  size_t idx, max;
  yyjson_val *k, *v;
  char err[1024];

  /* policies first */
  if ((doc = read_file(c, &zr, k_files[0], &missing))) {
    bool ok = true;
    yyjson_obj_foreach(yyjson_doc_get_root(doc), idx, max, k, v) {
      const char *name = yyjson_get_str(k);
      yyjson_val *st = yyjson_obj_get(v, "Statement");
      buckets_iam_err e;
      if (!st || yyjson_is_null(st) || (yyjson_is_arr(st) && !yyjson_arr_size(st))) {
        e = buckets_iam_delete_policy(iam, name);
        if (e == BUCKETS_IAM_ERR_NO_SUCH_POLICY) e = BUCKETS_IAM_OK;
        note(&r, r.removed, "policies", name);
      } else {
        size_t len;
        char *json = yyjson_val_write(v, 0, &len);
        err[0] = '\0';
        e = buckets_iam_set_policy(iam, name, json, len, err, sizeof(err));
        free(json);
        note(&r, r.added, "policies", name);
      }
      if (e) {
        import_error(c, BUCKETS_ERR_INTERNAL_ERROR, k_files[0], name, *err ? err : buckets_iam_strerror(e));
        ok = false;
        break;
      }
    }
    yyjson_doc_free(doc);
    if (!ok) goto out;
  } else if (!missing) {
    goto out;
  }

  /* users */
  if ((doc = read_file(c, &zr, k_files[1], &missing))) {
    bool ok = true;
    yyjson_obj_foreach(yyjson_doc_get_root(doc), idx, max, k, v) {
      const char *ak = yyjson_get_str(k);
      buckets_iam_ident *cur = buckets_iam_get_ident(iam, ak);
      bool derived = cur && (buckets_iam_ident_is_temp(cur) || buckets_iam_ident_is_svc(cur));
      bool known = cur != NULL;
      buckets_iam_ident_release(cur);
      if (strcmp(ak, buckets_iam_root_access_key(iam)) == 0 || derived) {
        import_error(c, BUCKETS_ERR_ADD_USER_INVALID_ARGUMENT, k_files[1], ak, "<nil>");
        ok = false;
        break;
      }
      if (!known && has_space_be(ak)) {
        import_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT, k_files[1], ak, "<nil>");
        ok = false;
        break;
      }
      const char *sk = yyjson_get_str(yyjson_obj_get(v, "secretKey"));
      const char *status = yyjson_get_str(yyjson_obj_get(v, "status"));
      buckets_iam_err e = buckets_iam_add_user(iam, ak, sk ? sk : "", status ? status : "enabled");
      if (e) note_failed(&r, "users", ak);
      else note(&r, r.added, "users", ak);
    }
    yyjson_doc_free(doc);
    if (!ok) goto out;
  } else if (!missing) {
    goto out;
  }

  /* groups */
  if ((doc = read_file(c, &zr, k_files[2], &missing))) {
    bool ok = true;
    yyjson_obj_foreach(yyjson_doc_get_root(doc), idx, max, k, v) {
      const char *g = yyjson_get_str(k);
      buckets_iam_group_desc gd;
      buckets_iam_err ge = buckets_iam_group_describe(iam, g, &gd);
      if (!ge) buckets_iam_group_desc_free(&gd);
      if (ge == BUCKETS_IAM_ERR_NO_SUCH_GROUP && has_space_be(g)) {
        import_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT, k_files[2], g, buckets_iam_strerror(ge));
        ok = false;
        break;
      }
      yyjson_val *ms = yyjson_obj_get(v, "members");
      size_t n = yyjson_is_arr(ms) ? yyjson_arr_size(ms) : 0, j, jm;
      const char **members = buckets_xcalloc(n ? n : 1, sizeof(char *));
      size_t nm = 0;
      yyjson_val *m;
      if (n) yyjson_arr_foreach(ms, j, jm, m) {
          if (yyjson_is_str(m)) members[nm++] = yyjson_get_str(m);
        }
      buckets_iam_err e = buckets_iam_group_add_members(iam, g, members, nm);
      free(members);
      if (e) note_failed(&r, "groups", g);
      else note(&r, r.added, "groups", g);
    }
    yyjson_doc_free(doc);
    if (!ok) goto out;
  } else if (!missing) {
    goto out;
  }

  /* service accounts */
  if ((doc = read_file(c, &zr, k_files[3], &missing))) {
    bool ok = true;
    yyjson_mut_doc *md = yyjson_doc_mut_copy(doc, NULL);
    yyjson_doc_free(doc);
    yyjson_mut_val *map = yyjson_mut_doc_get_root(md);
    size_t mi, mmax;
    yyjson_mut_val *mk, *mv;
    if (buckets_iam_ldap_mode(iam)) {
      /* NormalizeLDAPAccessKeypairs: parents that are DNs must be LDAP users. */
      buckets_ldapidp *lp = buckets_s3_ldap(c->s);
      yyjson_mut_obj_foreach(map, mi, mmax, mk, mv) {
        const char *parent = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "parent"));
        if (!parent || !buckets_ldapidp_parses_as_dn(parent)) continue;
        buckets_ldap_dnres res;
        bool under = false;
        int f = buckets_ldapidp_validated_user(lp, parent, &res, err, sizeof(err));
        if (f > 0) under = buckets_ldapidp_is_user_dn(lp, res.norm_dn);
        if (f < 0) {
          import_error(c, BUCKETS_ERR_INTERNAL_ERROR, k_files[3], NULL, err);
          ok = false;
          break;
        }
        if (f == 0 || !under) {
          note(&r, r.skipped, "serviceAccounts", yyjson_mut_get_str(mk));
          yyjson_mut_obj_put(mv, yyjson_mut_str(md, "skip"), yyjson_mut_true(md));
        } else if (strcmp(res.norm_dn, parent) != 0) {
          yyjson_mut_obj_put(mv, yyjson_mut_str(md, "parent"), yyjson_mut_strcpy(md, res.norm_dn));
        }
        if (f > 0) buckets_ldap_dnres_free(&res);
      }
      buckets_ldapidp_release(lp);
    }
    yyjson_mut_obj_foreach(map, mi, mmax, mk, mv) {
      if (!ok) break;
      const char *user = yyjson_mut_get_str(mk);
      if (yyjson_mut_obj_get(mv, "skip")) continue;
      const char *ak = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "accessKey"));
      yyjson_mut_val *spv = yyjson_mut_obj_get(mv, "sessionPolicy");
      char *sp = spv && !yyjson_mut_is_null(spv) ? yyjson_mut_val_write(spv, 0, NULL) : NULL;
      if (sp) {
        buckets_policy *p;
        if (!buckets_policy_parse(sp, strlen(sp), &p, err, sizeof(err))) {
          import_error(c, BUCKETS_ERR_INTERNAL_ERROR, k_files[3], user, err);
          free(sp);
          ok = false;
          break;
        }
        buckets_policy_free(p);
      }
      if (ak && has_space_be(ak)) {
        free(sp);
        buckets_admin_error(c, BUCKETS_ERR_ADMIN_RESOURCE_INVALID_ARGUMENT);
        ok = false;
        break;
      }
      buckets_iam_ident *cur = ak ? buckets_iam_get_ident(iam, ak) : NULL;
      bool exists = cur && buckets_iam_ident_is_svc(cur);
      buckets_iam_ident_release(cur);
      if (exists && buckets_iam_delete_svc(iam, ak) != BUCKETS_IAM_OK) {
        char msg[512];
        snprintf(msg, sizeof(msg), "failed to delete existing service account (%s) before importing it", ak);
        import_error(c, BUCKETS_ERR_INTERNAL_ERROR, k_files[3], user, msg);
        free(sp);
        ok = false;
        break;
      }
      yyjson_mut_val *gv = yyjson_mut_obj_get(mv, "groups");
      size_t ngr = yyjson_mut_is_arr(gv) ? yyjson_mut_arr_size(gv) : 0;
      const char **grs = buckets_xcalloc(ngr ? ngr : 1, sizeof(char *));
      for (size_t j = 0; j < ngr; j++) grs[j] = yyjson_mut_get_str(yyjson_mut_arr_get(gv, j));
      yyjson_mut_val *cv = yyjson_mut_obj_get(mv, "claims");
      char *claims = cv && yyjson_mut_is_obj(cv) ? yyjson_mut_val_write(cv, 0, NULL) : NULL;
      buckets_iam_time exp_t = {0, 0};
      const char *es = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "expiration"));
      bool has_exp = es && buckets_time_parse_rfc3339(es, &exp_t.sec, &exp_t.nsec) && buckets_iam_time_is_set(exp_t);
      buckets_iam_svc_opts o = {
          .parent = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "parent")),
          .groups = grs,
          .ngroups = ngr,
          .access_key = user,
          .secret_key = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "secretKey")),
          .session_policy = sp,
          .name = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "name")),
          .description = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "description")),
          .expiration = has_exp ? &exp_t : NULL,
          .claims_json = claims,
      };
      buckets_iam_err e = buckets_iam_add_svc(iam, &o, NULL, err, sizeof(err));
      const char *status = yyjson_mut_get_str(yyjson_mut_obj_get(mv, "status"));
      if (!e && status && strcmp(status, "off") == 0) {
        buckets_iam_svc_update u = {.status = "off"};
        buckets_iam_update_svc(iam, user, &u, err, sizeof(err));
      }
      if (e) note_failed(&r, "serviceAccounts", user);
      else note(&r, r.added, "serviceAccounts", user);
      free(grs);
      free(claims);
      free(sp);
    }
    yyjson_mut_doc_free(md);
    if (!ok) goto out;
  } else if (!missing) {
    goto out;
  }

  if (!import_mappings(c, &zr, k_files[4], BUCKETS_IAM_REG, false, "userPolicies", &r)) goto out;
  if (!import_mappings(c, &zr, k_files[5], BUCKETS_IAM_REG, true, "groupPolicies", &r)) goto out;
  if (!import_mappings(c, &zr, k_files[6], BUCKETS_IAM_STS, false, "stsPolicies", &r)) goto out;

  c->resp->status = 200;
  buckets_buf_reset(&c->resp->body);
  if (v2) {
    /* omitempty on each section */
    yyjson_mut_val *secs[] = {r.skipped, r.removed, r.added, r.failed};
    const char *names[] = {"skipped", "removed", "added", "failed"};
    for (int i = 0; i < 4; i++)
      if (!yyjson_mut_obj_size(secs[i])) yyjson_mut_obj_remove_key(root, names[i]);
    size_t len;
    char *json = yyjson_mut_write(r.d, 0, &len);
    buckets_buf_append(&c->resp->body, json, len);
    free(json);
    buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  }
out:
  yyjson_mut_doc_free(r.d);
}

void buckets_admin_import_iam(s3_ctx *c) { import_iam(c, false); }
void buckets_admin_import_iam_v2(s3_ctx *c) { import_iam(c, true); }
