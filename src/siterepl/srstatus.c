/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Site replication status and healing (MinIO's SiteReplicationMetaInfo,
 * siteReplicationStatus and the heal routine in cmd/site-replication.go):
 * every site reports its buckets, bucket metadata and IAM (SRInfo), the
 * reports are compared, and the site with the latest change of an entity
 * pushes it to the sites that differ. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bucket/metasys.h"
#include "core/log.h"
#include "crypto/base64.h"
#include "iam/iam.h"
#include "iam/policy.h"
#include "s3/server.h"
#include "siterepl/internal.h"

/* ---- small string sets -------------------------------------------------------------------- */

typedef struct {
  char **v;
  size_t n;
} strset;

static bool set_has(const strset *s, const char *x) {
  for (size_t i = 0; i < s->n; i++)
    if (strcmp(s->v[i], x) == 0) return true;
  return false;
}

static void set_add(strset *s, const char *x) {
  if (set_has(s, x)) return;
  s->v = buckets_xrealloc(s->v, (s->n + 1) * sizeof(char *));
  s->v[s->n++] = buckets_xstrdup(x);
}

static void set_free(strset *s) {
  for (size_t i = 0; i < s->n; i++) free(s->v[i]);
  free(s->v);
  memset(s, 0, sizeof(*s));
}

static void obj_keys(yyjson_val *o, strset *s) {
  size_t idx, max;
  yyjson_val *k, *v;
  if (!yyjson_is_obj(o)) return;
  yyjson_obj_foreach(o, idx, max, k, v) set_add(s, yyjson_get_str(k));
}

static const char *jstr(yyjson_val *o, const char *key) {
  const char *s = yyjson_get_str(yyjson_obj_get(o, key));
  return s ? s : "";
}

static char *b64(const void *data, size_t n) {
  char *out = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
  buckets_base64_encode((const uint8_t *)data, n, out);
  return out;
}

/* ---- SRInfo of this site ------------------------------------------------------------------------ */

static buckets_sr_time go_t(buckets_gotime t) { return (buckets_sr_time){t.sec, t.nsec}; }
static buckets_sr_time iam_t(buckets_iam_time t) { return (buckets_sr_time){t.sec, t.nsec}; }

static void add_b64_cfg(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, const buckets_buf *v) {
  if (!v->len) return;
  char *s = b64(v->data, v->len);
  yyjson_mut_obj_add_strcpy(d, o, key, s);
  free(s);
}

static yyjson_mut_val *bucket_info(buckets_sr *sr, yyjson_mut_doc *d, const char *bucket, buckets_sr_time created,
                                   buckets_sr_time deleted) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "bucket", bucket);
  bool exists = sr_time_is_zero(deleted) || (!sr_time_is_zero(created) && sr_time_after(created, deleted));
  buckets_bucket_state *st = exists ? buckets_metasys_get(sr->s->meta, bucket) : NULL;
  buckets_sr_time zero = sr_zero_time();
  buckets_sr_time t_pol = zero, t_tag = zero, t_olock = zero, t_sse = zero, t_ver = zero, t_repl = zero,
                  t_quota = zero;
  if (st) {
    const buckets_bucket_meta *m = &st->meta;
    if (m->config[BUCKETS_BCFG_POLICY].len) {
      yyjson_doc *pd = yyjson_read(m->config[BUCKETS_BCFG_POLICY].data, m->config[BUCKETS_BCFG_POLICY].len, 0);
      if (pd) yyjson_mut_obj_add(o, yyjson_mut_str(d, "policy"), yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
      yyjson_doc_free(pd);
    }
    t_pol = go_t(m->updated[BUCKETS_BCFG_POLICY]);
    add_b64_cfg(d, o, "versioningConfig", &m->config[BUCKETS_BCFG_VERSIONING]);
    add_b64_cfg(d, o, "tags", &m->config[BUCKETS_BCFG_TAGGING]);
    add_b64_cfg(d, o, "objectLockConfig", &m->config[BUCKETS_BCFG_OBJECT_LOCK]);
    add_b64_cfg(d, o, "sseConfig", &m->config[BUCKETS_BCFG_ENCRYPTION]);
    add_b64_cfg(d, o, "replicationConfig", &m->config[BUCKETS_BCFG_REPLICATION]);
    add_b64_cfg(d, o, "quotaConfig", &m->config[BUCKETS_BCFG_QUOTA]);
    if (m->config[BUCKETS_BCFG_TAGGING].len) t_tag = go_t(m->updated[BUCKETS_BCFG_TAGGING]);
    if (m->config[BUCKETS_BCFG_OBJECT_LOCK].len) t_olock = go_t(m->updated[BUCKETS_BCFG_OBJECT_LOCK]);
    if (m->config[BUCKETS_BCFG_ENCRYPTION].len) t_sse = go_t(m->updated[BUCKETS_BCFG_ENCRYPTION]);
    if (m->config[BUCKETS_BCFG_VERSIONING].len) t_ver = go_t(m->updated[BUCKETS_BCFG_VERSIONING]);
    if (m->config[BUCKETS_BCFG_REPLICATION].len) t_repl = go_t(m->updated[BUCKETS_BCFG_REPLICATION]);
    if (m->config[BUCKETS_BCFG_QUOTA].len) t_quota = go_t(m->updated[BUCKETS_BCFG_QUOTA]);
    buckets_bucket_state_release(st);
  }
  sr_add_time(d, o, "policyTimestamp", t_pol);
  sr_add_time(d, o, "tagTimestamp", t_tag);
  sr_add_time(d, o, "olockTimestamp", t_olock);
  sr_add_time(d, o, "sseTimestamp", t_sse);
  sr_add_time(d, o, "versioningTimestamp", t_ver);
  sr_add_time(d, o, "replicationConfigTimestamp", t_repl);
  sr_add_time(d, o, "quotaTimestamp", t_quota);
  sr_add_time(d, o, "expLCTimestamp", zero);
  sr_add_time(d, o, "bucketTimestamp", created);
  sr_add_time(d, o, "bucketDeletedTimestamp", deleted);
  sr_add_time(d, o, "corsTimestamp", zero);
  return o;
}

static buckets_sr_time bucket_created(buckets_sr *sr, const char *bucket, time_t fallback) {
  buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bucket);
  buckets_sr_time t = st->exists ? go_t(st->meta.created) : (buckets_sr_time){fallback, 0};
  buckets_bucket_state_release(st);
  if (sr_time_is_zero(t)) t = (buckets_sr_time){fallback, 0};
  return t;
}

static void add_buckets(buckets_sr *sr, const buckets_sr_status_opts *o, yyjson_mut_doc *d, yyjson_mut_val *root) {
  buckets_objlayer *L = sr->s->layer;
  if (o->entity == 1) {
    const char *b = o->entity_value ? o->entity_value : "";
    buckets_sr_time created = sr_zero_time(), deleted = sr_zero_time();
    if (buckets_obj_stat_bucket(L, b) == BUCKETS_OBJ_OK) {
      created = bucket_created(sr, b, time(NULL));
    } else {
      time_t t = o->show_deleted ? buckets_obj_bucket_deleted_at(L, b) : 0;
      if (!t) {
        yyjson_mut_obj_add_null(d, root, "Buckets");
        return;
      }
      deleted = (buckets_sr_time){t, 0};
    }
    yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, root, "Buckets");
    yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, b), bucket_info(sr, d, b, created, deleted));
    return;
  }
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, root, "Buckets");
  buckets_bucket_info *bs = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(L, &bs, &nb) == BUCKETS_OBJ_OK) {
    for (size_t i = 0; i < nb; i++)
      yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, bs[i].name),
                         bucket_info(sr, d, bs[i].name, bucket_created(sr, bs[i].name, bs[i].created), sr_zero_time()));
  }
  if (o->show_deleted) {
    buckets_bucket_info *ds;
    size_t nd;
    if (buckets_obj_list_deleted_buckets(L, &ds, &nd) == BUCKETS_OBJ_OK) {
      for (size_t i = 0; i < nd; i++) {
        bool live = false;
        for (size_t k = 0; k < nb && !live; k++) live = strcmp(bs[k].name, ds[i].name) == 0;
        if (!live)
          yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, ds[i].name),
                             bucket_info(sr, d, ds[i].name, sr_zero_time(), (buckets_sr_time){ds[i].created, 0}));
      }
      buckets_bucket_info_free(ds, nd);
    }
  }
  buckets_bucket_info_free(bs, nb);
}

static void add_policies(buckets_sr *sr, const buckets_sr_status_opts *o, yyjson_mut_doc *d, yyjson_mut_val *root) {
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, root, "Policies");
  buckets_iam_policy_doc *docs;
  size_t n;
  buckets_iam_list_policies(sr->s->iam, &docs, &n);
  for (size_t i = 0; i < n; i++) {
    if (o->entity == 2 && strcmp(docs[i].name, o->entity_value ? o->entity_value : "") != 0) continue;
    yyjson_mut_val *p = yyjson_mut_obj(d);
    yyjson_doc *pd = yyjson_read(docs[i].json, strlen(docs[i].json), 0);
    if (pd) yyjson_mut_obj_add(p, yyjson_mut_str(d, "policy"), yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
    else yyjson_mut_obj_add_null(d, p, "policy");
    yyjson_doc_free(pd);
    sr_add_time(d, p, "updatedAt", iam_t(docs[i].updated));
    yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, docs[i].name), p);
  }
  buckets_iam_policy_doc_free(docs, n);
  free(docs);
}

static yyjson_mut_val *mapping_json(yyjson_mut_doc *d, const char *name, int user_type, bool group,
                                    const char *policies, buckets_sr_time updated) {
  yyjson_mut_val *p = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, p, "userOrGroup", name);
  yyjson_mut_obj_add_int(d, p, "userType", user_type);
  yyjson_mut_obj_add_bool(d, p, "isGroup", group);
  yyjson_mut_obj_add_strcpy(d, p, "policy", policies);
  sr_add_time(d, p, "createdAt", sr_zero_time());
  sr_add_time(d, p, "updatedAt", updated);
  return p;
}

static void add_users(buckets_sr *sr, const buckets_sr_status_opts *o, yyjson_mut_doc *d, yyjson_mut_val *root) {
  buckets_iam *iam = sr->s->iam;
  const char *only = o->entity == 3 ? (o->entity_value ? o->entity_value : "") : NULL;
  yyjson_mut_val *up = yyjson_mut_obj_add_obj(d, root, "UserPolicies");
  static const struct {
    buckets_iam_utype t;
    int minio;
  } kinds[] = {{BUCKETS_IAM_REG, 0}, {BUCKETS_IAM_STS, 1}, {BUCKETS_IAM_SVC, 2}};
  for (size_t k = 0; k < 3; k++) {
    if (only && k) break; /* an entity: its regular mapping (GetMappedPolicy) */
    buckets_iam_mapping *m;
    size_t n = buckets_iam_list_mappings(iam, kinds[k].t, false, &m);
    for (size_t i = 0; i < n; i++) {
      if (only && strcmp(m[i].name, only) != 0) continue;
      yyjson_mut_obj_remove_str(up, m[i].name);
      yyjson_mut_obj_add(up, yyjson_mut_strcpy(d, m[i].name),
                         mapping_json(d, m[i].name, kinds[k].minio, false, m[i].policies, iam_t(m[i].updated)));
    }
    buckets_iam_mappings_free(m, n);
  }
  yyjson_mut_val *ui = yyjson_mut_obj_add_obj(d, root, "UserInfoMap");
  const char *root_ak = buckets_iam_root_access_key(iam);
  if (only) {
    buckets_iam_user_info u;
    if (buckets_iam_get_user_info(iam, only, &u) == BUCKETS_IAM_OK) {
      yyjson_mut_val *v = yyjson_mut_obj(d);
      if (*u.policy) yyjson_mut_obj_add_strcpy(d, v, "policyName", u.policy);
      yyjson_mut_obj_add_str(d, v, "status", u.enabled ? "enabled" : "disabled");
      if (u.nmember_of) {
        yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, v, "memberOf");
        for (size_t i = 0; i < u.nmember_of; i++) yyjson_mut_arr_add_strcpy(d, a, u.member_of[i]);
      }
      sr_add_time(d, v, "updatedAt", iam_t(u.updated));
      yyjson_mut_obj_add(ui, yyjson_mut_strcpy(d, only), v);
      buckets_iam_user_info_free(&u, 1);
    }
    return;
  }
  buckets_iam_user_info *users;
  size_t nu;
  buckets_iam_list_users(iam, &users, &nu);
  for (size_t i = 0; i < nu; i++) {
    buckets_iam_ident *id = buckets_iam_get_ident(iam, users[i].name);
    yyjson_mut_val *v = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, v, "status", id ? id->status : (users[i].enabled ? "on" : "off"));
    sr_add_time(d, v, "updatedAt", sr_zero_time());
    yyjson_mut_obj_add(ui, yyjson_mut_strcpy(d, users[i].name), v);
    buckets_iam_ident_release(id);
  }
  buckets_iam_user_info_free(users, nu);
  free(users);
  for (int t = 0; t < 2; t++) {
    buckets_iam_ident **ids;
    size_t n;
    buckets_iam_list_derived(iam, NULL, t == 0 ? BUCKETS_IAM_SVC : BUCKETS_IAM_STS, &ids, &n);
    for (size_t i = 0; i < n; i++) {
      const buckets_iam_ident *id = ids[i];
      if (strcmp(id->access_key, BUCKETS_SR_SVC_ACCOUNT) != 0 && !(id->parent && strcmp(id->parent, root_ak) == 0)) {
        yyjson_mut_val *v = yyjson_mut_obj(d);
        yyjson_mut_obj_add_strcpy(d, v, "status", id->status);
        sr_add_time(d, v, "updatedAt", sr_zero_time());
        yyjson_mut_obj_remove_str(ui, id->access_key);
        yyjson_mut_obj_add(ui, yyjson_mut_strcpy(d, id->access_key), v);
      }
      buckets_iam_ident_release(ids[i]);
    }
    free(ids);
  }
}

static yyjson_mut_val *group_desc_json(yyjson_mut_doc *d, const buckets_iam_group_desc *g) {
  yyjson_mut_val *v = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, v, "name", g->name ? g->name : "");
  yyjson_mut_obj_add_strcpy(d, v, "status", g->status ? g->status : "");
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, v, "members");
  for (size_t i = 0; i < g->nmembers; i++) yyjson_mut_arr_add_strcpy(d, a, g->members[i]);
  yyjson_mut_obj_add_strcpy(d, v, "policy", g->policy ? g->policy : "");
  sr_add_time(d, v, "updatedAt", iam_t(g->updated));
  return v;
}

static void add_groups(buckets_sr *sr, const buckets_sr_status_opts *o, yyjson_mut_doc *d, yyjson_mut_val *root) {
  buckets_iam *iam = sr->s->iam;
  const char *only = o->entity == 4 ? (o->entity_value ? o->entity_value : "") : NULL;
  yyjson_mut_val *gp = yyjson_mut_obj_add_obj(d, root, "GroupPolicies");
  buckets_iam_mapping *m;
  size_t n = buckets_iam_list_mappings(sr->s->iam, BUCKETS_IAM_REG, true, &m);
  for (size_t i = 0; i < n; i++) {
    if (only && strcmp(m[i].name, only) != 0) continue;
    yyjson_mut_obj_add(gp, yyjson_mut_strcpy(d, m[i].name),
                       mapping_json(d, m[i].name, 0, true, m[i].policies, iam_t(m[i].updated)));
  }
  buckets_iam_mappings_free(m, n);
  yyjson_mut_val *gd = yyjson_mut_obj_add_obj(d, root, "GroupDescMap");
  char **groups;
  size_t ng;
  buckets_iam_list_groups(iam, &groups, &ng);
  for (size_t i = 0; i < ng; i++) {
    buckets_iam_group_desc g;
    if ((!only || strcmp(groups[i], only) == 0) && buckets_iam_group_describe(iam, groups[i], &g) == BUCKETS_IAM_OK) {
      yyjson_mut_obj_add(gd, yyjson_mut_strcpy(d, groups[i]), group_desc_json(d, &g));
      buckets_iam_group_desc_free(&g);
    }
    free(groups[i]);
  }
  free(groups);
}

static yyjson_mut_val *peers_state_json(yyjson_mut_doc *d, const sr_snapshot *s) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "name", s->name);
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, o, "peers");
  for (size_t i = 0; i < s->npeers; i++) {
    const buckets_sr_peer *p = &s->peers[i];
    yyjson_mut_val *v = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, v, "endpoint", p->endpoint);
    yyjson_mut_obj_add_strcpy(d, v, "name", p->name);
    yyjson_mut_obj_add_strcpy(d, v, "deploymentID", p->deployment_id);
    yyjson_mut_obj_add_strcpy(d, v, "sync", p->sync);
    yyjson_mut_val *bw = yyjson_mut_obj_add_obj(d, v, "defaultbandwidth");
    yyjson_mut_obj_add_uint(d, bw, "bandwidthLimitPerBucket", p->bw_limit);
    yyjson_mut_obj_add_bool(d, bw, "set", p->bw_set);
    sr_add_time(d, bw, "updatedAt", p->bw_updated);
    yyjson_mut_obj_add_bool(d, v, "replicate-ilm-expiry", p->replicate_ilm_expiry);
    yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, p->deployment_id), v);
  }
  sr_add_time(d, o, "updatedAt", s->updated);
  return o;
}

bool buckets_sr_metainfo_json(buckets_sr *sr, const buckets_sr_status_opts *o, buckets_buf *out, buckets_sr_err *e) {
  if (!sr->s->layer) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "object layer not ready");
    return false;
  }
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_bool(d, root, "Enabled", false);
  yyjson_mut_obj_add_str(d, root, "Name", "");
  yyjson_mut_obj_add_strcpy(d, root, "DeploymentID", s.enabled ? sr_self_id(sr) : "");
  if (s.enabled && (o->buckets || o->entity == 1)) add_buckets(sr, o, d, root);
  else yyjson_mut_obj_add_null(d, root, "Buckets");
  if (s.enabled && (o->policies || o->entity == 2)) add_policies(sr, o, d, root);
  else yyjson_mut_obj_add_null(d, root, "Policies");
  if (s.enabled && (o->users || o->entity == 3)) {
    add_users(sr, o, d, root);
  } else {
    yyjson_mut_obj_add_null(d, root, "UserPolicies");
    yyjson_mut_obj_add_null(d, root, "UserInfoMap");
  }
  if (s.enabled && (o->groups || o->entity == 4)) {
    add_groups(sr, o, d, root);
  } else {
    yyjson_mut_obj_add_null(d, root, "GroupDescMap");
    yyjson_mut_obj_add_null(d, root, "GroupPolicies");
  }
  yyjson_mut_obj_add_null(d, root, "ReplicationCfg");
  if (s.enabled && (o->ilm_expiry_rules || o->entity == 5)) yyjson_mut_obj_add_obj(d, root, "ILMExpiryRules");
  else yyjson_mut_obj_add_null(d, root, "ILMExpiryRules");
  if (s.enabled && o->peer_state) {
    yyjson_mut_obj_add(root, yyjson_mut_str(d, "State"), peers_state_json(d, &s));
  } else {
    yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, root, "State");
    yyjson_mut_obj_add_str(d, st, "name", "");
    yyjson_mut_obj_add_null(d, st, "peers");
    sr_add_time(d, st, "updatedAt", sr_zero_time());
  }
  size_t n;
  char *j = yyjson_mut_write(d, 0, &n);
  buckets_buf_append(out, j, n);
  buckets_buf_append_c(out, "\n");
  free(j);
  yyjson_mut_doc_free(d);
  sr_snapshot_free(&s);
  return true;
}

/* ---- collecting every site's SRInfo ---------------------------------------------------------- */

typedef struct {
  sr_snapshot snap;
  yyjson_doc **sri; /* by peer index (sorted by name); an empty object when unreachable */
  size_t n;
} collect;

static void collect_free(collect *c) {
  for (size_t i = 0; i < c->n; i++) yyjson_doc_free(c->sri[i]);
  free(c->sri);
  sr_snapshot_free(&c->snap);
}

static void opts_query(const buckets_sr_status_opts *o, buckets_buf *q) {
#define B(k, v) buckets_buf_appendf(q, "%s%s=%s", q->len ? "&" : "", k, (v) ? "true" : "false")
  B("buckets", o->buckets);
  B("policies", o->policies);
  B("users", o->users);
  B("groups", o->groups);
  B("showDeleted", o->show_deleted);
  B("metrics", o->metrics);
  B("ilm-expiry-rules", o->ilm_expiry_rules);
  B("peer-state", o->peer_state);
#undef B
  static const char *names[] = {"", "bucket", "policy", "user", "group", "ilm-expiry-rule"};
  if (o->entity > 0 && o->entity <= 5) {
    buckets_buf_append_c(q, "&entityvalue=");
    buckets_url_encode(q, o->entity_value ? o->entity_value : "", false);
    buckets_buf_appendf(q, "&entity=%s", names[o->entity]);
  }
}

static bool collect_all(buckets_sr *sr, const buckets_sr_status_opts *o, collect *c, char *err, size_t errlen) {
  sr_snapshot_take(sr, &c->snap);
  c->n = c->snap.npeers;
  c->sri = buckets_xcalloc(c->n + 1, sizeof(yyjson_doc *));
  const char *self = sr_self_id(sr);
  buckets_buf q = BUCKETS_BUF_INIT;
  opts_query(o, &q);
  bool ok = true;
  for (size_t i = 0; i < c->n; i++) {
    buckets_buf b = BUCKETS_BUF_INIT;
    const buckets_sr_peer *p = &c->snap.peers[i];
    if (strcmp(p->deployment_id, self) == 0) {
      buckets_sr_err e;
      buckets_sr_metainfo_json(sr, o, &b, &e);
    } else {
      char e[1024];
      if (!sr_peer_call(sr, p->deployment_id, "GET", "/site-replication/metainfo", q.data, NULL, 0, &b, e, sizeof(e))) {
        buckets_buf_reset(&b);
        if (!strstr(e, "connection") && !strstr(e, "timed out") && !strstr(e, "refused") && !strstr(e, "resolve")) {
          snprintf(err, errlen, "'ReplicationStatus' on site %s (%s): failed(%s)", p->name, p->deployment_id, e);
          ok = false;
        }
      }
    }
    c->sri[i] = b.len ? yyjson_read(b.data, b.len, 0) : NULL;
    if (!c->sri[i]) c->sri[i] = yyjson_read("{}", 2, 0);
    buckets_buf_free(&b);
  }
  buckets_buf_free(&q);
  return ok;
}

static yyjson_val *sri_get(const collect *c, size_t i, const char *map, const char *key) {
  return yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(c->sri[i]), map), key);
}

static const char *sri_dep(const collect *c, size_t i) {
  const char *d = jstr(yyjson_doc_get_root(c->sri[i]), "DeploymentID");
  return *d ? d : c->snap.peers[i].deployment_id;
}

/* ---- the comparisons (isReplicated & co) -------------------------------------------------------- */

static bool values_replicated(size_t cnt, size_t total, const strset *vals) {
  if (cnt > 0 && cnt < total) return false;
  return vals->n <= 1;
}

/* bucket metadata of one kind: base64 strings (absent -> not counted) */
typedef struct {
  size_t count;
  strset vals;
} cfg_cmp;

static void cfg_add(cfg_cmp *cc, yyjson_val *bi, const char *key) {
  const char *s = yyjson_get_str(yyjson_obj_get(bi, key));
  if (!s) return;
  uint8_t *dec = buckets_xmalloc(strlen(s) * 3 / 4 + 4);
  long k = buckets_base64_decode(s, strlen(s), dec);
  if (k >= 0) {
    dec[k] = 0;
    cc->count++;
    set_add(&cc->vals, (char *)dec);
  }
  free(dec);
}

static bool json_equal(yyjson_val *a, yyjson_val *b) { return a && b && yyjson_equals(a, b); }

static bool bucket_policy_replicated(const collect *c, const char *b) {
  size_t cnt = 0;
  yyjson_val *prev = NULL;
  bool same = true;
  for (size_t i = 0; i < c->n; i++) {
    yyjson_val *p = yyjson_obj_get(sri_get(c, i, "Buckets", b), "policy");
    if (!p || yyjson_is_null(p)) continue;
    cnt++;
    if (!prev) prev = p;
    else same &= json_equal(prev, p);
  }
  if (cnt > 0 && cnt != c->n) return false;
  return same;
}

static bool quota_replicated(const collect *c, const char *b) {
  size_t cnt = 0;
  uint64_t q0 = 0;
  char t0[32] = "";
  bool first = true, same = true;
  for (size_t i = 0; i < c->n; i++) {
    const char *s = yyjson_get_str(yyjson_obj_get(sri_get(c, i, "Buckets", b), "quotaConfig"));
    if (!s) continue;
    uint8_t *dec = buckets_xmalloc(strlen(s) * 3 / 4 + 4);
    long k = buckets_base64_decode(s, strlen(s), dec);
    yyjson_doc *qd = k >= 0 ? yyjson_read((char *)dec, (size_t)k, 0) : NULL;
    free(dec);
    if (!qd) continue;
    cnt++;
    yyjson_val *r = yyjson_doc_get_root(qd);
    uint64_t q = yyjson_get_uint(yyjson_obj_get(r, "quota"));
    if (!q) q = yyjson_get_uint(yyjson_obj_get(r, "size"));
    const char *t = jstr(r, "quotatype");
    if (first) {
      q0 = q;
      snprintf(t0, sizeof(t0), "%s", t);
      first = false;
    } else if (q != q0 || strcmp(t, t0) != 0) {
      same = false;
    }
    yyjson_doc_free(qd);
  }
  if (cnt == 0) return true;
  if (cnt != c->n) return false;
  return same;
}

/* isBktReplCfgReplicated */
static bool repl_cfg_replicated(const collect *c, const char *b) {
  size_t cnt = 0;
  bool ok = true;
  size_t prev_rules = (size_t)-1;
  for (size_t i = 0; i < c->n; i++) {
    const char *s = yyjson_get_str(yyjson_obj_get(sri_get(c, i, "Buckets", b), "replicationConfig"));
    if (!s) continue;
    uint8_t *dec = buckets_xmalloc(strlen(s) * 3 / 4 + 4);
    long k = buckets_base64_decode(s, strlen(s), dec);
    buckets_replication cfg;
    char perr[256];
    bool parsed = k >= 0 && buckets_replication_parse((char *)dec, (size_t)k, &cfg, perr, sizeof(perr));
    free(dec);
    if (!parsed) continue;
    cnt++;
    if (prev_rules != (size_t)-1 && prev_rules != cfg.n) ok = false;
    if (prev_rules != (size_t)-1 && cfg.n != c->n - 1) ok = false;
    if (prev_rules != (size_t)-1) {
      for (size_t r = 0; r < cfg.n; r++) {
        const buckets_repl_rule *rl = &cfg.rules[r];
        if (!rl->id || strncmp(rl->id, "site-repl-", 10) != 0) ok = false;
        if ((rl->dm_status && strcmp(rl->dm_status, "Disabled") == 0) ||
            (rl->del_status && strcmp(rl->del_status, "Disabled") == 0) ||
            (rl->existing_status && strcmp(rl->existing_status, "Disabled") == 0) ||
            (rl->replica_mod_status && strcmp(rl->replica_mod_status, "Disabled") == 0))
          ok = false;
      }
    }
    prev_rules = cfg.n;
    buckets_replication_free(&cfg);
  }
  if (cnt > 0 && cnt != c->n) return false;
  return ok;
}

static bool members_equal(yyjson_val *a, yyjson_val *b) {
  if (yyjson_arr_size(a) != yyjson_arr_size(b)) return false;
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(a, i, max, v) {
    bool found = false;
    size_t j, mj;
    yyjson_val *w;
    yyjson_arr_foreach(b, j, mj, w) found |= yyjson_equals(v, w);
    if (!found) return false;
  }
  return true;
}

static bool user_info_equal(yyjson_val *a, yyjson_val *b) {
  return strcmp(jstr(a, "policyName"), jstr(b, "policyName")) == 0 && strcmp(jstr(a, "status"), jstr(b, "status")) == 0 &&
         strcmp(jstr(a, "secretKey"), jstr(b, "secretKey")) == 0 &&
         members_equal(yyjson_obj_get(a, "memberOf"), yyjson_obj_get(b, "memberOf"));
}

static bool group_desc_equal(yyjson_val *a, yyjson_val *b) {
  return strcmp(jstr(a, "name"), jstr(b, "name")) == 0 && strcmp(jstr(a, "status"), jstr(b, "status")) == 0 &&
         strcmp(jstr(a, "policy"), jstr(b, "policy")) == 0 &&
         members_equal(yyjson_obj_get(a, "members"), yyjson_obj_get(b, "members"));
}

static bool mapping_equal(yyjson_val *a, yyjson_val *b) {
  return strcmp(jstr(a, "policy"), jstr(b, "policy")) == 0 &&
         yyjson_get_bool(yyjson_obj_get(a, "isGroup")) == yyjson_get_bool(yyjson_obj_get(b, "isGroup")) &&
         strcmp(jstr(a, "userOrGroup"), jstr(b, "userOrGroup")) == 0;
}

/* An entity present on cnt sites, all equal by eq (absent entries skipped as zero values). */
static bool entries_replicated(const collect *c, const char *map, const char *key, bool (*eq)(yyjson_val *, yyjson_val *)) {
  size_t cnt = 0;
  for (size_t i = 0; i < c->n; i++) cnt += sri_get(c, i, map, key) != NULL;
  if (cnt > 0 && cnt != c->n) return false;
  yyjson_val *prev = NULL;
  for (size_t i = 0; i < c->n; i++) {
    yyjson_val *v = sri_get(c, i, map, key);
    if (!v) continue;
    if (!prev) prev = v;
    else if (!eq(prev, v)) return false;
  }
  return true;
}

static bool policy_equal(yyjson_val *a, yyjson_val *b) {
  return json_equal(yyjson_obj_get(a, "policy"), yyjson_obj_get(b, "policy"));
}

/* ---- the status response --------------------------------------------------------------------------- */

typedef struct {
  long v[28];
} site_sum;

enum {
  RB, RT, RBP, RIP, RU, RG, RLC, RSSE, RVC, RQC, RUPM, RGPM, RILM, RCORS, /* replicated */
  TB, TT, TBP, TIP, TLC, TSSE, TVC, TQC, TU, TG, TUPM, TGPM, TILM, TCORS  /* totals */
};

static const char *k_sum_names[] = {
    "ReplicatedBuckets", "ReplicatedTags", "ReplicatedBucketPolicies", "ReplicatedIAMPolicies", "ReplicatedUsers",
    "ReplicatedGroups", "ReplicatedLockConfig", "ReplicatedSSEConfig", "ReplicatedVersioningConfig",
    "ReplicatedQuotaConfig", "ReplicatedUserPolicyMappings", "ReplicatedGroupPolicyMappings",
    "ReplicatedILMExpiryRules", "ReplicatedCorsConfig", "TotalBucketsCount", "TotalTagsCount",
    "TotalBucketPoliciesCount", "TotalIAMPoliciesCount", "TotalLockConfigCount", "TotalSSEConfigCount",
    "TotalVersioningConfigCount", "TotalQuotaConfigCount", "TotalUsersCount", "TotalGroupsCount",
    "TotalUserPolicyMappingCount", "TotalGroupPolicyMappingCount", "TotalILMExpiryRulesCount", "TotalCorsConfigCount"};

static void add_site_entry(yyjson_mut_doc *d, yyjson_mut_val *stats, const char *entity, const char *dep,
                           yyjson_mut_val *v) {
  yyjson_mut_val *m = yyjson_mut_obj_get(stats, entity);
  if (!m) {
    m = yyjson_mut_obj(d);
    yyjson_mut_obj_add(stats, yyjson_mut_strcpy(d, entity), m);
  }
  yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, dep), v);
}

bool buckets_sr_status_json(buckets_sr *sr, const buckets_sr_status_opts *o, buckets_buf *out, buckets_sr_err *e) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  if (!buckets_sr_enabled(sr)) {
    yyjson_mut_obj_add_bool(d, root, "Enabled", false);
    goto write;
  }
  collect c;
  char err[2048] = "";
  if (!collect_all(sr, o, &c, err, sizeof(err))) {
    collect_free(&c);
    yyjson_mut_doc_free(d);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "Site replication error(s): \n%s", err);
    return false;
  }
  size_t n = c.n;
  site_sum *sum = buckets_xcalloc(n + 1, sizeof(site_sum));
  yyjson_mut_val *bstats = yyjson_mut_obj(d), *pstats = yyjson_mut_obj(d), *ustats = yyjson_mut_obj(d),
                 *gstats = yyjson_mut_obj(d);
  strset buckets = {0}, users = {0}, uwp = {0}, groups = {0}, gwp = {0}, policies = {0};
  for (size_t i = 0; i < n; i++) {
    yyjson_val *r = yyjson_doc_get_root(c.sri[i]);
    obj_keys(yyjson_obj_get(r, "Buckets"), &buckets);
    obj_keys(yyjson_obj_get(r, "UserInfoMap"), &users);
    obj_keys(yyjson_obj_get(r, "GroupDescMap"), &groups);
    obj_keys(yyjson_obj_get(r, "Policies"), &policies);
    obj_keys(yyjson_obj_get(r, "UserPolicies"), &uwp);
    obj_keys(yyjson_obj_get(r, "GroupPolicies"), &gwp);
  }
  if (o->users || o->entity == 3) {
    for (size_t k = 0; k < uwp.n; k++) {
      bool mis = !entries_replicated(&c, "UserPolicies", uwp.v[k], mapping_equal);
      for (size_t i = 0; i < n; i++) {
        sum[i].v[TUPM]++;
        yyjson_val *m = sri_get(&c, i, "UserPolicies", uwp.v[k]);
        if (mis || o->entity == 3) {
          yyjson_mut_val *v = yyjson_mut_obj(d);
          yyjson_mut_obj_add_str(d, v, "DeploymentID", "");
          yyjson_mut_obj_add_bool(d, v, "PolicyMismatch", mis);
          yyjson_mut_obj_add_bool(d, v, "UserInfoMismatch", false);
          yyjson_mut_obj_add_bool(d, v, "HasUser", m != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasPolicyMapping", m && *jstr(m, "policy"));
          add_site_entry(d, ustats, uwp.v[k], sri_dep(&c, i), v);
        }
        if (!mis || o->entity != 3) sum[i].v[RUPM]++;
      }
    }
    for (size_t k = 0; k < users.n; k++) {
      bool mis = !entries_replicated(&c, "UserInfoMap", users.v[k], user_info_equal);
      for (size_t i = 0; i < n; i++) {
        sum[i].v[TU]++;
        if (mis || o->entity == 3) {
          yyjson_mut_val *um = yyjson_mut_obj_get(ustats, users.v[k]);
          yyjson_mut_val *v = um ? yyjson_mut_obj_get(um, sri_dep(&c, i)) : NULL;
          if (!v) {
            v = yyjson_mut_obj(d);
            yyjson_mut_obj_add_str(d, v, "DeploymentID", "");
            yyjson_mut_obj_add_bool(d, v, "PolicyMismatch", false);
            yyjson_mut_obj_add_bool(d, v, "UserInfoMismatch", mis);
            yyjson_mut_obj_add_bool(d, v, "HasUser", sri_get(&c, i, "UserInfoMap", users.v[k]) != NULL);
            yyjson_mut_obj_add_bool(d, v, "HasPolicyMapping", false);
            add_site_entry(d, ustats, users.v[k], sri_dep(&c, i), v);
          } else {
            yyjson_mut_obj_put(v, yyjson_mut_str(d, "UserInfoMismatch"), yyjson_mut_bool(d, mis));
          }
        }
        if (!mis || o->entity != 3) sum[i].v[RU]++;
      }
    }
  }
  if (o->groups || o->entity == 4) {
    for (size_t k = 0; k < gwp.n; k++) {
      bool mis = !entries_replicated(&c, "GroupPolicies", gwp.v[k], mapping_equal);
      for (size_t i = 0; i < n; i++) {
        sum[i].v[TGPM]++;
        yyjson_val *m = sri_get(&c, i, "GroupPolicies", gwp.v[k]);
        if (mis || o->entity == 4) {
          yyjson_mut_val *v = yyjson_mut_obj(d);
          yyjson_mut_obj_add_strcpy(d, v, "DeploymentID", sri_dep(&c, i));
          yyjson_mut_obj_add_bool(d, v, "PolicyMismatch", mis);
          yyjson_mut_obj_add_bool(d, v, "HasGroup", m != NULL);
          yyjson_mut_obj_add_bool(d, v, "GroupDescMismatch", false);
          yyjson_mut_obj_add_bool(d, v, "HasPolicyMapping", m && *jstr(m, "policy"));
          add_site_entry(d, gstats, gwp.v[k], sri_dep(&c, i), v);
        }
        if (!mis && o->entity != 4) sum[i].v[RGPM]++;
      }
    }
    for (size_t k = 0; k < groups.n; k++) {
      bool mis = !entries_replicated(&c, "GroupDescMap", groups.v[k], group_desc_equal);
      for (size_t i = 0; i < n; i++) {
        sum[i].v[TG]++;
        if (mis || o->entity == 4) {
          yyjson_mut_val *gm = yyjson_mut_obj_get(gstats, groups.v[k]);
          yyjson_mut_val *v = gm ? yyjson_mut_obj_get(gm, sri_dep(&c, i)) : NULL;
          if (!v) {
            v = yyjson_mut_obj(d);
            yyjson_mut_obj_add_str(d, v, "DeploymentID", "");
            yyjson_mut_obj_add_bool(d, v, "PolicyMismatch", false);
            yyjson_mut_obj_add_bool(d, v, "HasGroup", sri_get(&c, i, "GroupDescMap", groups.v[k]) != NULL);
            yyjson_mut_obj_add_bool(d, v, "GroupDescMismatch", mis);
            yyjson_mut_obj_add_bool(d, v, "HasPolicyMapping", false);
            add_site_entry(d, gstats, groups.v[k], sri_dep(&c, i), v);
          } else {
            yyjson_mut_obj_put(v, yyjson_mut_str(d, "GroupDescMismatch"), yyjson_mut_bool(d, mis));
          }
        }
        if (!mis && o->entity != 4) sum[i].v[RG]++;
      }
    }
  }
  if (o->policies || o->entity == 2) {
    for (size_t k = 0; k < policies.n; k++) {
      bool mis = !entries_replicated(&c, "Policies", policies.v[k], policy_equal);
      for (size_t i = 0; i < n; i++) {
        yyjson_val *p = sri_get(&c, i, "Policies", policies.v[k]);
        if (p) sum[i].v[TIP]++;
        if (mis || o->entity == 2) {
          yyjson_mut_val *v = yyjson_mut_obj(d);
          yyjson_mut_obj_add_str(d, v, "DeploymentID", "");
          yyjson_mut_obj_add_bool(d, v, "PolicyMismatch", mis);
          yyjson_mut_obj_add_bool(d, v, "HasPolicy", p != NULL);
          add_site_entry(d, pstats, policies.v[k], sri_dep(&c, i), v);
        } else {
          sum[i].v[RIP]++;
        }
      }
    }
  }
  if (o->buckets || o->entity == 1) {
    for (size_t k = 0; k < buckets.n; k++) {
      const char *b = buckets.v[k];
      cfg_cmp tag = {0}, olock = {0}, sse = {0}, ver = {0};
      size_t npol = 0;
      for (size_t i = 0; i < n; i++) {
        yyjson_val *bi = sri_get(&c, i, "Buckets", b);
        cfg_add(&ver, bi, "versioningConfig");
        cfg_add(&tag, bi, "tags");
        cfg_add(&olock, bi, "objectLockConfig");
        cfg_add(&sse, bi, "sseConfig");
        yyjson_val *pol = yyjson_obj_get(bi, "policy");
        npol += pol && !yyjson_is_null(pol);
        sum[i].v[RB]++; /* every site's entry counts, as len(slc) == numSites */
        sum[i].v[TB]++;
        if (tag.count) sum[i].v[TT]++;
        if (olock.count) sum[i].v[TLC]++;
        if (sse.count) sum[i].v[TSSE]++;
        if (ver.count) sum[i].v[TVC]++;
        sum[i].v[TBP]++;
      }
      bool tag_m = !values_replicated(tag.count, n, &tag.vals), olock_m = !values_replicated(olock.count, n, &olock.vals),
           sse_m = !values_replicated(sse.count, n, &sse.vals), ver_m = !values_replicated(ver.count, n, &ver.vals);
      bool pol_m = !bucket_policy_replicated(&c, b), repl_m = !repl_cfg_replicated(&c, b), quota_m = !quota_replicated(&c, b);
      for (size_t i = 0; i < n; i++) {
        yyjson_val *bi = sri_get(&c, i, "Buckets", b);
        buckets_sr_time created = sr_get_time(bi, "bucketTimestamp"), deleted = sr_get_time(bi, "bucketDeletedTimestamp");
        bool has = bi && !sr_time_is_zero(created);
        bool marked = bi && !sr_time_is_zero(deleted) && (sr_time_is_zero(created) || sr_time_after(deleted, created));
        if (tag_m || ver_m || olock_m || sse_m || pol_m || repl_m || quota_m || o->entity == 1) {
          yyjson_mut_val *v = yyjson_mut_obj(d);
          yyjson_mut_obj_add_strcpy(d, v, "DeploymentID", sri_dep(&c, i));
          yyjson_mut_obj_add_bool(d, v, "HasBucket", has);
          yyjson_mut_obj_add_bool(d, v, "BucketMarkedDeleted", marked);
          yyjson_mut_obj_add_bool(d, v, "TagMismatch", tag_m);
          yyjson_mut_obj_add_bool(d, v, "VersioningConfigMismatch", ver_m);
          yyjson_mut_obj_add_bool(d, v, "OLockConfigMismatch", olock_m);
          yyjson_mut_obj_add_bool(d, v, "PolicyMismatch", pol_m);
          yyjson_mut_obj_add_bool(d, v, "SSEConfigMismatch", sse_m);
          yyjson_mut_obj_add_bool(d, v, "ReplicationCfgMismatch", repl_m);
          yyjson_mut_obj_add_bool(d, v, "QuotaCfgMismatch", quota_m);
          yyjson_mut_obj_add_bool(d, v, "CorsCfgMismatch", false);
          yyjson_mut_obj_add_bool(d, v, "HasTagsSet", yyjson_obj_get(bi, "tags") != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasOLockConfigSet", yyjson_obj_get(bi, "objectLockConfig") != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasPolicySet", yyjson_obj_get(bi, "policy") != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasSSECfgSet", yyjson_obj_get(bi, "sseConfig") != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasReplicationCfg", yyjson_obj_get(bi, "replicationConfig") != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasQuotaCfgSet", has && yyjson_obj_get(bi, "quotaConfig") != NULL);
          yyjson_mut_obj_add_bool(d, v, "HasCorsCfgSet", false);
          add_site_entry(d, bstats, b, sri_dep(&c, i), v);
        }
        if (!olock_m && olock.count == n) sum[i].v[RLC]++;
        if (!ver_m && ver.count == n) sum[i].v[RVC]++;
        if (!sse_m && sse.count == n) sum[i].v[RSSE]++;
        if (!pol_m && npol == n) sum[i].v[RBP]++;
        if (!tag_m && tag.count == n) sum[i].v[RT]++;
      }
      set_free(&tag.vals);
      set_free(&olock.vals);
      set_free(&sse.vals);
      set_free(&ver.vals);
    }
  }
  yyjson_mut_obj_add_bool(d, root, "Enabled", true);
  yyjson_mut_obj_add_int(d, root, "MaxBuckets", (int64_t)(o->buckets || o->entity == 1 ? buckets.n : buckets.n));
  yyjson_mut_obj_add_int(d, root, "MaxUsers", (int64_t)users.n);
  yyjson_mut_obj_add_int(d, root, "MaxGroups", (int64_t)groups.n);
  yyjson_mut_obj_add_int(d, root, "MaxPolicies", (int64_t)policies.n);
  yyjson_mut_obj_add_int(d, root, "MaxILMExpiryRules", 0);
  yyjson_mut_val *sites = yyjson_mut_obj_add_obj(d, root, "Sites");
  yyjson_mut_val *ss = yyjson_mut_obj_add_obj(d, root, "StatsSummary");
  bool ilm = false;
  for (size_t i = 0; i < n; i++) {
    const buckets_sr_peer *p = &c.snap.peers[i];
    ilm |= p->replicate_ilm_expiry;
    yyjson_mut_val *v = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, v, "endpoint", p->endpoint);
    yyjson_mut_obj_add_strcpy(d, v, "name", p->name);
    yyjson_mut_obj_add_strcpy(d, v, "deploymentID", p->deployment_id);
    yyjson_mut_obj_add_strcpy(d, v, "sync", p->sync);
    yyjson_mut_val *bw = yyjson_mut_obj_add_obj(d, v, "defaultbandwidth");
    yyjson_mut_obj_add_uint(d, bw, "bandwidthLimitPerBucket", p->bw_limit);
    yyjson_mut_obj_add_bool(d, bw, "set", p->bw_set);
    sr_add_time(d, bw, "updatedAt", p->bw_updated);
    yyjson_mut_obj_add_bool(d, v, "replicate-ilm-expiry", p->replicate_ilm_expiry);
    yyjson_mut_obj_add(sites, yyjson_mut_strcpy(d, p->deployment_id), v);
    yyjson_mut_val *sv = yyjson_mut_obj(d);
    for (size_t k = 0; k < 28; k++) yyjson_mut_obj_add_int(d, sv, k_sum_names[k], sum[i].v[k]);
    yyjson_mut_obj_add(ss, yyjson_mut_strcpy(d, sri_dep(&c, i)), sv);
  }
  yyjson_mut_obj_add(root, yyjson_mut_str(d, "BucketStats"), bstats);
  yyjson_mut_obj_add(root, yyjson_mut_str(d, "PolicyStats"), pstats);
  yyjson_mut_obj_add(root, yyjson_mut_str(d, "UserStats"), ustats);
  yyjson_mut_obj_add(root, yyjson_mut_str(d, "GroupStats"), gstats);
  yyjson_mut_val *mt = yyjson_mut_obj_add_obj(d, root, "Metrics");
  yyjson_mut_val *rm = yyjson_mut_obj_add_obj(d, mt, "replMetrics");
  if (o->metrics) {
    for (size_t i = 0; i < n; i++) {
      const buckets_sr_peer *p = &c.snap.peers[i];
      if (strcmp(p->deployment_id, sr_self_id(sr)) == 0) continue;
      yyjson_mut_val *v = yyjson_mut_obj(d);
      yyjson_mut_obj_add_strcpy(d, v, "deploymentID", p->deployment_id);
      yyjson_mut_obj_add_strcpy(d, v, "endpoint", p->endpoint);
      yyjson_mut_obj_add_bool(d, v, "isOnline", true);
      yyjson_mut_obj_add(rm, yyjson_mut_strcpy(d, p->deployment_id), v);
    }
  }
  if (ilm) yyjson_mut_obj_add_obj(d, root, "ILMExpiryStats");
  else yyjson_mut_obj_add_null(d, root, "ILMExpiryStats");
  set_free(&buckets);
  set_free(&users);
  set_free(&uwp);
  set_free(&groups);
  set_free(&gwp);
  set_free(&policies);
  free(sum);
  collect_free(&c);
write:;
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_buf_append(out, j, len);
  buckets_buf_append_c(out, "\n");
  free(j);
  yyjson_mut_doc_free(d);
  return true;
}

/* ---- healing ---------------------------------------------------------------------------------------- */

static bool is_self(buckets_sr *sr, const collect *c, size_t i) {
  return strcmp(c->snap.peers[i].deployment_id, sr_self_id(sr)) == 0;
}

static buckets_sr_time most_recent(buckets_sr_time a, buckets_sr_time b) {
  if (sr_time_is_zero(a)) return b;
  if (sr_time_is_zero(b)) return a;
  return sr_time_after(a, b) ? a : b;
}

static bool time_eq(buckets_sr_time a, buckets_sr_time b) {
  if (sr_time_is_zero(a) && sr_time_is_zero(b)) return true;
  return a.sec == b.sec && a.nsec == b.nsec;
}

/* healBucket: creates or deletes the bucket per its latest state. */
static void heal_bucket(buckets_sr *sr, const collect *c, const char *b) {
  size_t n = c->n, latest = 0;
  buckets_sr_time last = sr_zero_time();
  bool first = true;
  size_t deleted_cnt = 0, with = 0;
  bool *has = buckets_xcalloc(n + 1, sizeof(bool));
  for (size_t i = 0; i < n; i++) {
    yyjson_val *bi = sri_get(c, i, "Buckets", b);
    buckets_sr_time cr = sr_get_time(bi, "bucketTimestamp"), dl = sr_get_time(bi, "bucketDeletedTimestamp");
    buckets_sr_time recent = most_recent(cr, dl);
    if (first) {
      last = recent;
      latest = i;
      first = false;
    }
    if (sr_time_after(recent, last)) {
      last = recent;
      latest = i;
    }
    if (bi && !sr_time_is_zero(dl) && (sr_time_is_zero(cr) || sr_time_after(dl, cr))) deleted_cnt++;
    has[i] = bi && !sr_time_is_zero(cr);
    with += has[i];
  }
  if (!is_self(sr, c, latest)) {
    free(has);
    return;
  }
  yyjson_val *lb = sri_get(c, latest, "Buckets", b);
  buckets_sr_time created = sr_get_time(lb, "bucketTimestamp"), deleted = sr_get_time(lb, "bucketDeletedTimestamp");
  bool make = with < n;
  enum { NOOP, PURGE, MARK } op = NOOP;
  if (time_eq(last, deleted) && !sr_time_is_zero(deleted)) {
    make = false;
    if (with == n && deleted_cnt == n) op = NOOP;
    else if (with == 0) op = PURGE;
    else op = MARK;
  }
  char err[3000];
  if (make) {
    bool lock = false;
    const char *olc = jstr(lb, "objectLockConfig");
    if (*olc) {
      uint8_t *dec = buckets_xmalloc(strlen(olc) * 3 / 4 + 4);
      long k = buckets_base64_decode(olc, strlen(olc), dec);
      static const char enabled[] =
          "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
      lock = k == (long)strlen(enabled) && memcmp(dec, enabled, (size_t)k) == 0;
      free(dec);
    }
    char ts[64];
    sr_time_str(created, ts);
    buckets_buf q = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&q, "versioningEnabled=true&%screatedAt=", lock ? "lockEnabled=true&" : "");
    buckets_url_encode(&q, ts, false);
    for (size_t i = 0; i < n; i++) {
      if (has[i]) continue;
      if (is_self(sr, c, i)) {
        if (!sr_make_with_versioning(sr, b, lock, created, err, sizeof(err)))
          buckets_log_warn("site replication: error healing bucket %s: %s", b, err);
      } else if (!sr_bucket_op_to_peer(sr, c->snap.peers[i].deployment_id, b, "make-with-versioning", q.data, err,
                                       sizeof(err)) ||
                 !sr_bucket_op_to_peer(sr, c->snap.peers[i].deployment_id, b, "configure-replication", NULL, err,
                                       sizeof(err))) {
        buckets_log_warn("site replication: error healing bucket %s on %s: %s", b, c->snap.peers[i].name, err);
      }
    }
    buckets_buf_free(&q);
    if (!sr_configure_repl(sr, b, err, sizeof(err))) buckets_log_warn("site replication: %s", err);
  } else if (op == PURGE) {
    for (size_t i = 0; i < n; i++) {
      if (has[i]) continue;
      if (is_self(sr, c, i)) sr_purge_deleted_bucket(sr, b);
      else sr_bucket_op_to_peer(sr, c->snap.peers[i].deployment_id, b, "purge-deleted-bucket", NULL, err, sizeof(err));
    }
  } else if (op == MARK) {
    for (size_t i = 0; i < n; i++) {
      if (!has[i]) continue;
      if (is_self(sr, c, i)) {
        if (!sr_local_delete_bucket(sr, b, true, err, sizeof(err)))
          buckets_log_warn("site replication: error healing bucket %s: %s", b, err);
      } else if (!sr_bucket_op_to_peer(sr, c->snap.peers[i].deployment_id, b, "force-delete-bucket", NULL, err,
                                       sizeof(err))) {
        buckets_log_warn("site replication: error healing bucket %s on %s: %s", b, c->snap.peers[i].name, err);
      }
    }
  }
  free(has);
}

/* A bucket configuration: the site with the latest change pushes it to the
 * sites that differ (healTagMetadata, healVersioningMetadata, ...). */
typedef struct {
  const char *key, *ts_key, *type;
  buckets_bucket_cfg cfg;
  bool skip_nil_latest; /* object lock: only a set config is the latest */
  bool raw;             /* policy: JSON, not base64 */
} cfg_kind;

static void heal_cfg(buckets_sr *sr, const collect *c, const char *b, const cfg_kind *k, bool mismatch) {
  if (!mismatch) return;
  size_t n = c->n, latest = 0;
  buckets_sr_time last = sr_zero_time();
  bool first = true;
  for (size_t i = 0; i < n; i++) {
    yyjson_val *bi = sri_get(c, i, "Buckets", b);
    buckets_sr_time up = sr_get_time(bi, k->ts_key), cr = sr_get_time(bi, "bucketTimestamp");
    if (first) {
      last = up;
      latest = i;
      first = false;
    }
    if (time_eq(cr, up)) continue; /* just created: perhaps not yet synced */
    if (k->skip_nil_latest && !yyjson_obj_get(bi, k->key)) continue;
    if (sr_time_after(up, last)) {
      last = up;
      latest = i;
    }
  }
  yyjson_val *lv = yyjson_obj_get(sri_get(c, latest, "Buckets", b), k->key);
  if (k->skip_nil_latest && !lv) return;
  for (size_t i = 0; i < n; i++) {
    yyjson_val *v = yyjson_obj_get(sri_get(c, i, "Buckets", b), k->key);
    bool equal = (!v && !lv) || (v && lv && (k->raw ? yyjson_equals(v, lv) : strcasecmp(yyjson_get_str(v), yyjson_get_str(lv)) == 0));
    if (equal) continue;
    if (is_self(sr, c, i)) {
      if (k->raw) {
        char *j = lv ? yyjson_val_write(lv, 0, NULL) : NULL;
        buckets_metasys_update(sr->s->meta, b, k->cfg, j, j ? strlen(j) : 0);
        free(j);
      } else {
        const char *s = yyjson_get_str(lv);
        uint8_t *dec = s ? buckets_xmalloc(strlen(s) * 3 / 4 + 4) : NULL;
        long kk = s ? buckets_base64_decode(s, strlen(s), dec) : 0;
        if (kk >= 0) buckets_metasys_update(sr->s->meta, b, k->cfg, dec, s ? (size_t)kk : 0);
        free(dec);
      }
      continue;
    }
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_strcpy(d, root, "type", k->type);
    yyjson_mut_obj_add_strcpy(d, root, "bucket", b);
    const char *out_key = strcmp(k->key, "quotaConfig") == 0 ? "quota" : k->key;
    if (lv && strcmp(k->key, "quotaConfig") == 0) { /* quota travels as JSON */
      const char *s = yyjson_get_str(lv);
      uint8_t *dec = buckets_xmalloc(strlen(s) * 3 / 4 + 4);
      long kk = buckets_base64_decode(s, strlen(s), dec);
      yyjson_doc *qd = kk >= 0 ? yyjson_read((char *)dec, (size_t)kk, 0) : NULL;
      if (qd) yyjson_mut_obj_add(root, yyjson_mut_str(d, "quota"), yyjson_val_mut_copy(d, yyjson_doc_get_root(qd)));
      yyjson_doc_free(qd);
      free(dec);
    } else if (lv) {
      yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, out_key), yyjson_val_mut_copy(d, lv));
    }
    if (k->raw || strcmp(k->key, "quotaConfig") == 0) sr_add_time(d, root, "updatedAt", last);
    else sr_add_time(d, root, "updatedAt", sr_zero_time());
    size_t len;
    char *j = yyjson_mut_write(d, 0, &len);
    yyjson_mut_doc_free(d);
    sr_send_bucket_meta(sr, c->snap.peers[i].deployment_id, j, len);
    free(j);
  }
}

static void heal_buckets(buckets_sr *sr) {
  buckets_objlayer *L = sr->s->layer;
  buckets_bucket_info *bs = NULL, *ds = NULL;
  size_t nb = 0, nd = 0;
  buckets_obj_list_buckets(L, &bs, &nb);
  buckets_obj_list_deleted_buckets(L, &ds, &nd);
  strset names = {0};
  for (size_t i = 0; i < nb; i++) set_add(&names, bs[i].name);
  for (size_t i = 0; i < nd; i++) set_add(&names, ds[i].name);
  buckets_bucket_info_free(bs, nb);
  buckets_bucket_info_free(ds, nd);
  static const cfg_kind kinds[] = {
      {"versioningConfig", "versioningTimestamp", "version-config", BUCKETS_BCFG_VERSIONING, false, false},
      {"objectLockConfig", "olockTimestamp", "object-lock-config", BUCKETS_BCFG_OBJECT_LOCK, true, false},
      {"sseConfig", "sseTimestamp", "sse-config", BUCKETS_BCFG_ENCRYPTION, false, false},
      {"policy", "policyTimestamp", "policy", BUCKETS_BCFG_POLICY, false, true},
      {"tags", "tagTimestamp", "tags", BUCKETS_BCFG_TAGGING, false, false},
      {"quotaConfig", "quotaTimestamp", "quota-config", BUCKETS_BCFG_QUOTA, false, false},
  };
  for (size_t k = 0; k < names.n; k++) {
    if (!buckets_sr_enabled(sr)) break;
    const char *b = names.v[k];
    buckets_sr_status_opts o = {.entity = 1, .entity_value = b, .show_deleted = true, .ilm_expiry_rules = true,
                                .peer_state = true};
    collect c;
    char err[2048] = "";
    if (!collect_all(sr, &o, &c, err, sizeof(err))) {
      buckets_log_warn("site replication: heal: %s", err);
      collect_free(&c);
      continue;
    }
    heal_bucket(sr, &c, b);
    bool live = buckets_obj_stat_bucket(L, b) == BUCKETS_OBJ_OK;
    if (live) {
      /* the mismatch flags of the status */
      cfg_cmp ver = {0}, olock = {0}, sse = {0}, tag = {0};
      for (size_t i = 0; i < c.n; i++) {
        yyjson_val *bi = sri_get(&c, i, "Buckets", b);
        cfg_add(&ver, bi, "versioningConfig");
        cfg_add(&olock, bi, "objectLockConfig");
        cfg_add(&sse, bi, "sseConfig");
        cfg_add(&tag, bi, "tags");
      }
      bool mis[6] = {!values_replicated(ver.count, c.n, &ver.vals), !values_replicated(olock.count, c.n, &olock.vals),
                     !values_replicated(sse.count, c.n, &sse.vals), !bucket_policy_replicated(&c, b),
                     !values_replicated(tag.count, c.n, &tag.vals), !quota_replicated(&c, b)};
      set_free(&ver.vals);
      set_free(&olock.vals);
      set_free(&sse.vals);
      set_free(&tag.vals);
      for (size_t i = 0; i < 6; i++) heal_cfg(sr, &c, b, &kinds[i], mis[i]);
      /* healBucketReplicationConfig */
      bool repl_m = !repl_cfg_replicated(&c, b);
      buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, b);
      if (!st->has_replication) repl_m = true;
      for (size_t r = 0; st->has_replication && r < st->replication.n && !repl_m; r++) {
        const buckets_repl_rule *rl = &st->replication.rules[r];
        if (rl->status && strcmp(rl->status, "Disabled") == 0) continue;
        const buckets_bucket_target *tg = NULL;
        for (size_t t = 0; t < st->targets.n && !tg; t++)
          if (strcmp(st->targets.t[t].arn, rl->dest_bucket) == 0) tg = &st->targets.t[t];
        if (!tg) {
          repl_m = true;
          break;
        }
        char url[600];
        snprintf(url, sizeof(url), "%s://%s", tg->secure ? "https" : "http", tg->endpoint);
        bool found = false;
        for (size_t p = 0; p < c.snap.npeers && !found; p++) {
          char ep[600];
          snprintf(ep, sizeof(ep), "%s", c.snap.peers[p].endpoint);
          size_t el = strlen(ep);
          while (el && ep[el - 1] == '/') ep[--el] = '\0';
          found = strcmp(ep, url) == 0;
        }
        if (!found) repl_m = true;
      }
      buckets_bucket_state_release(st);
      if (repl_m && !sr_configure_repl(sr, b, err, sizeof(err)))
        buckets_log_warn("site replication: heal bucket replication config: %s", err);
    }
    collect_free(&c);
  }
  set_free(&names);
}

/* ---- IAM healing ---------------------------------------------------------------------------------- */

/* The site with the latest change of an entity: this site when it holds
 * the newest version (ties included, as MinIO reports some entities
 * without timestamps and picks among equal ones at random; pushing the same
 * item twice is harmless). Returns the index of this site, or of the newest
 * holder when that is another site. */
static size_t latest_by(buckets_sr *sr, const collect *c, const char *map, const char *key, const char *ts_key,
                        buckets_sr_time *last) {
  size_t latest = 0, self = (size_t)-1;
  bool first = true;
  *last = sr_zero_time();
  for (size_t i = 0; i < c->n; i++) {
    yyjson_val *v = sri_get(c, i, map, key);
    if (!v) continue;
    buckets_sr_time t = sr_get_time(v, ts_key);
    if (first || sr_time_after(t, *last)) {
      *last = t;
      latest = i;
      first = false;
    }
  }
  for (size_t i = 0; i < c->n; i++) {
    yyjson_val *v = sri_get(c, i, map, key);
    if (v && is_self(sr, c, i) && time_eq(sr_get_time(v, ts_key), *last)) self = i;
  }
  return self != (size_t)-1 ? self : latest;
}

static void send_item(buckets_sr *sr, const collect *c, size_t i, yyjson_mut_doc *d) {
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  sr_send_iam_item(sr, c->snap.peers[i].deployment_id, j, len);
  free(j);
}

static void heal_policy(buckets_sr *sr, const collect *c, const char *name) {
  bool mis = !entries_replicated(c, "Policies", name, policy_equal);
  buckets_sr_time last;
  size_t latest = latest_by(sr, c, "Policies", name, "updatedAt", &last);
  if (!is_self(sr, c, latest)) return;
  yyjson_val *lp = sri_get(c, latest, "Policies", name);
  for (size_t i = 0; i < c->n; i++) {
    if (is_self(sr, c, i)) continue;
    if (!mis && sri_get(c, i, "Policies", name)) continue;
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_str(d, root, "type", "policy");
    yyjson_mut_obj_add_strcpy(d, root, "name", name);
    yyjson_val *p = yyjson_obj_get(lp, "policy");
    if (p) yyjson_mut_obj_add(root, yyjson_mut_str(d, "policy"), yyjson_val_mut_copy(d, p));
    else yyjson_mut_obj_add_null(d, root, "policy");
    sr_add_time(d, root, "updatedAt", last);
    send_item(sr, c, i, d);
    yyjson_mut_doc_free(d);
  }
}

static void heal_mapping(buckets_sr *sr, const collect *c, const char *map, const char *name, bool group) {
  bool mis = !entries_replicated(c, map, name, mapping_equal);
  buckets_sr_time last;
  size_t latest = latest_by(sr, c, map, name, "updatedAt", &last);
  if (!is_self(sr, c, latest)) return;
  yyjson_val *lm = sri_get(c, latest, map, name);
  for (size_t i = 0; i < c->n; i++) {
    if (is_self(sr, c, i)) continue;
    yyjson_val *m = sri_get(c, i, map, name);
    if (!mis && m && *jstr(m, "policy")) continue;
    if (m && lm && mapping_equal(m, lm)) continue;
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_str(d, root, "type", "policy-mapping");
    yyjson_mut_val *pm = yyjson_mut_obj_add_obj(d, root, "policyMapping");
    yyjson_mut_obj_add_strcpy(d, pm, "userOrGroup", name);
    yyjson_mut_obj_add_int(d, pm, "userType", group ? -1 : yyjson_get_int(yyjson_obj_get(lm, "userType")));
    yyjson_mut_obj_add_bool(d, pm, "isGroup", group);
    yyjson_mut_obj_add_strcpy(d, pm, "policy", jstr(lm, "policy"));
    sr_add_time(d, root, "updatedAt", last);
    send_item(sr, c, i, d);
    yyjson_mut_doc_free(d);
  }
}

static void heal_user(buckets_sr *sr, const collect *c, const char *user) {
  bool mis = !entries_replicated(c, "UserInfoMap", user, user_info_equal);
  if (!mis) return;
  buckets_sr_time last;
  size_t latest = latest_by(sr, c, "UserInfoMap", user, "updatedAt", &last);
  if (!is_self(sr, c, latest)) return;
  yyjson_val *lu = sri_get(c, latest, "UserInfoMap", user);
  buckets_iam *iam = sr->s->iam;
  for (size_t i = 0; i < c->n; i++) {
    if (is_self(sr, c, i)) continue;
    yyjson_val *u = sri_get(c, i, "UserInfoMap", user);
    if (u && lu && user_info_equal(u, lu)) continue;
    buckets_iam_ident *id = buckets_iam_get_ident(iam, user);
    if (!id) continue;
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    if (buckets_iam_ident_is_svc(id)) {
      buckets_iam_ident_release(id);
      yyjson_mut_doc_free(d);
      buckets_sr_iam_svc_create(sr, user); /* to every peer: an update where it exists */
      return;
    }
    if (buckets_iam_ident_is_temp(id)) {
      if (!buckets_iam_ident_is_expired(id)) {
        yyjson_mut_obj_add_str(d, root, "type", "sts-account");
        yyjson_mut_val *s = yyjson_mut_obj_add_obj(d, root, "stsCredential");
        yyjson_mut_obj_add_strcpy(d, s, "accessKey", id->access_key);
        yyjson_mut_obj_add_strcpy(d, s, "secretKey", id->secret_key);
        yyjson_mut_obj_add_strcpy(d, s, "sessionToken", id->session_token ? id->session_token : "");
        yyjson_mut_obj_add_strcpy(d, s, "parentUser", id->parent ? id->parent : "");
        buckets_iam_user_info pu;
        if (id->parent && buckets_iam_get_user_info(iam, id->parent, &pu) == BUCKETS_IAM_OK) {
          if (*pu.policy) yyjson_mut_obj_add_strcpy(d, s, "parentPolicyMapping", pu.policy);
          buckets_iam_user_info_free(&pu, 1);
        }
        sr_add_time(d, root, "updatedAt", last);
        send_item(sr, c, i, d);
      }
    } else {
      yyjson_mut_obj_add_str(d, root, "type", "iam-user");
      yyjson_mut_val *iu = yyjson_mut_obj_add_obj(d, root, "iamUser");
      yyjson_mut_obj_add_strcpy(d, iu, "accessKey", user);
      yyjson_mut_obj_add_bool(d, iu, "isDeleteReq", false);
      yyjson_mut_val *r = yyjson_mut_obj_add_obj(d, iu, "userReq");
      yyjson_mut_obj_add_strcpy(d, r, "secretKey", id->secret_key);
      yyjson_mut_obj_add_strcpy(d, r, "status", jstr(lu, "status"));
      sr_add_time(d, root, "updatedAt", last);
      send_item(sr, c, i, d);
    }
    buckets_iam_ident_release(id);
    yyjson_mut_doc_free(d);
  }
}

static void heal_group(buckets_sr *sr, const collect *c, const char *group) {
  bool mis = !entries_replicated(c, "GroupDescMap", group, group_desc_equal);
  if (!mis) return;
  buckets_sr_time last;
  size_t latest = latest_by(sr, c, "GroupDescMap", group, "updatedAt", &last);
  if (!is_self(sr, c, latest)) return;
  yyjson_val *lg = sri_get(c, latest, "GroupDescMap", group);
  for (size_t i = 0; i < c->n; i++) {
    if (is_self(sr, c, i)) continue;
    yyjson_val *g = sri_get(c, i, "GroupDescMap", group);
    if (g && lg && group_desc_equal(g, lg)) continue;
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_str(d, root, "type", "group-info");
    yyjson_mut_val *r = yyjson_mut_obj_add_obj(d, yyjson_mut_obj_add_obj(d, root, "groupInfo"), "updateReq");
    yyjson_mut_obj_add_strcpy(d, r, "group", group);
    yyjson_val *m = yyjson_obj_get(lg, "members");
    if (m) yyjson_mut_obj_add(r, yyjson_mut_str(d, "members"), yyjson_val_mut_copy(d, m));
    else yyjson_mut_obj_add_null(d, r, "members");
    yyjson_mut_obj_add_strcpy(d, r, "groupStatus", jstr(lg, "status"));
    yyjson_mut_obj_add_bool(d, r, "isRemove", false);
    sr_add_time(d, root, "updatedAt", last);
    send_item(sr, c, i, d);
    yyjson_mut_doc_free(d);
  }
}

static void heal_iam(buckets_sr *sr) {
  buckets_sr_status_opts o = {.users = true, .policies = true, .groups = true};
  collect c;
  char err[2048] = "";
  if (!collect_all(sr, &o, &c, err, sizeof(err))) {
    buckets_log_warn("site replication: heal: %s", err);
    collect_free(&c);
    return;
  }
  strset policies = {0}, users = {0}, groups = {0}, uwp = {0}, gwp = {0};
  for (size_t i = 0; i < c.n; i++) {
    yyjson_val *r = yyjson_doc_get_root(c.sri[i]);
    obj_keys(yyjson_obj_get(r, "Policies"), &policies);
    obj_keys(yyjson_obj_get(r, "UserInfoMap"), &users);
    obj_keys(yyjson_obj_get(r, "GroupDescMap"), &groups);
    obj_keys(yyjson_obj_get(r, "UserPolicies"), &uwp);
    obj_keys(yyjson_obj_get(r, "GroupPolicies"), &gwp);
  }
  for (size_t k = 0; k < policies.n; k++) heal_policy(sr, &c, policies.v[k]);
  for (size_t k = 0; k < users.n; k++) heal_user(sr, &c, users.v[k]);
  for (size_t k = 0; k < groups.n; k++) heal_group(sr, &c, groups.v[k]);
  for (size_t k = 0; k < uwp.n; k++) heal_mapping(sr, &c, "UserPolicies", uwp.v[k], false);
  for (size_t k = 0; k < gwp.n; k++) heal_mapping(sr, &c, "GroupPolicies", gwp.v[k], true);
  set_free(&policies);
  set_free(&users);
  set_free(&groups);
  set_free(&uwp);
  set_free(&gwp);
  collect_free(&c);
}

void sr_heal_once(buckets_sr *sr) {
  heal_iam(sr);
  heal_buckets(sr);
}
