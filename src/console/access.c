/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "console/access.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <yyjson.h>

#include "core/query.h"
#include "iam/access.h"

#define MAX_BODY (64 * 1024)

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

/* ---- the facts ------------------------------------------------------------------------------- */

typedef struct {
  const buckets_console_access_session *sess;
  int status;
  buckets_buf body;
} call;

static yyjson_doc *get(call *c, const char *api, const char *query, bool decrypt) {
  buckets_buf_reset(&c->body);
  c->status = c->sess->admin(c->sess->ud, "GET", api, query, NULL, 0, false, decrypt, &c->body);
  if (c->status != 200) return NULL;
  return yyjson_read(c->body.data ? c->body.data : "", c->body.len, 0);
}

typedef struct {
  yyjson_mut_doc *d;
  yyjson_mut_val *root, *principals, *missing;
  bool openid, ldap;
  int policies_status; /* list-canned-policies' reply: without the policies there is nothing to review */
} facts;

static void missing(facts *f, const char *what) { yyjson_mut_arr_add_str(f->d, f->missing, what); }

static yyjson_mut_val *principal(facts *f, const char *kind, const char *name) {
  yyjson_mut_val *p = yyjson_mut_arr_add_obj(f->d, f->principals);
  yyjson_mut_obj_add_str(f->d, p, "kind", kind);
  yyjson_mut_obj_add_strcpy(f->d, p, "name", name);
  return p;
}

/* "a,b" into an array of names */
static void add_csv(yyjson_mut_doc *d, yyjson_mut_val *arr, const char *csv) {
  while (csv && *csv) {
    const char *comma = strchr(csv, ',');
    size_t n = comma ? (size_t)(comma - csv) : strlen(csv);
    if (n) yyjson_mut_arr_add_strncpy(d, arr, csv, n);
    csv = comma ? comma + 1 : NULL;
  }
}

static yyjson_mut_val *find(facts *f, const char *kind, const char *name) {
  size_t i, max;
  yyjson_mut_val *p;
  yyjson_mut_arr_foreach(f->principals, i, max, p) {
    if (strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(p, "kind")), kind) == 0 &&
        strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(p, "name")), name) == 0)
      return p;
  }
  return NULL;
}

static void add_key(facts *f, call *c, const char *ak, const char *owner, bool implied) {
  if (find(f, "key", ak)) return;
  yyjson_mut_val *p = principal(f, "key", ak);
  yyjson_mut_obj_add_strcpy(f->d, p, "owner", owner);
  if (implied) return;
  /* its own policy, narrowing its owner's */
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&q, "accessKey=");
  buckets_url_encode(&q, ak, false);
  yyjson_doc *info = get(c, "info-access-key", q.data, true);
  buckets_buf_free(&q);
  const char *pol = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(info), "policy"));
  yyjson_doc *pd = pol && *pol ? yyjson_read(pol, strlen(pol), 0) : NULL;
  if (yyjson_is_obj(yyjson_doc_get_root(pd)))
    yyjson_mut_obj_add_val(f->d, p, "policy", yyjson_val_mut_copy(f->d, yyjson_doc_get_root(pd)));
  yyjson_doc_free(pd);
  yyjson_doc_free(info);
}

static void gather(facts *f, const buckets_console_access_session *sess, const char *bucket) {
  f->d = yyjson_mut_doc_new(NULL);
  f->root = yyjson_mut_obj(f->d);
  yyjson_mut_doc_set_root(f->d, f->root);
  f->principals = yyjson_mut_obj_add_arr(f->d, f->root, "principals");
  f->missing = yyjson_mut_arr(f->d);
  call c = {sess, 0, BUCKETS_BUF_INIT};

  yyjson_doc *pol = get(&c, "list-canned-policies", NULL, false);
  f->policies_status = c.status;
  yyjson_val *policies = yyjson_doc_get_root(pol);
  yyjson_mut_obj_add_val(f->d, f->root, "policies",
                         policies ? yyjson_val_mut_copy(f->d, policies) : yyjson_mut_obj(f->d));
  yyjson_mut_val *root = principal(f, "root", "the root user");

  /* local users and groups */
  yyjson_doc *users = get(&c, "list-users", NULL, true);
  if (!users) missing(f, "local users");
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(yyjson_doc_get_root(users), i, max, k, v) {
    yyjson_mut_val *p = principal(f, "user", yyjson_get_str(k));
    add_csv(f->d, yyjson_mut_obj_add_arr(f->d, p, "policies"), yyjson_get_str(yyjson_obj_get(v, "policyName")));
    yyjson_val *mo = yyjson_obj_get(v, "memberOf");
    yyjson_mut_obj_add_val(f->d, p, "groups", mo ? yyjson_val_mut_copy(f->d, mo) : yyjson_mut_arr(f->d));
    const char *st = yyjson_get_str(yyjson_obj_get(v, "status"));
    yyjson_mut_obj_add_strcpy(f->d, p, "status", st ? st : "enabled");
  }
  yyjson_doc *groups = get(&c, "groups", NULL, false);
  if (!groups) missing(f, "groups");
  yyjson_val *g;
  yyjson_arr_foreach(yyjson_doc_get_root(groups), i, max, g) {
    buckets_buf q = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&q, "group=");
    buckets_url_encode(&q, yyjson_get_str(g), false);
    yyjson_doc *gi = get(&c, "group", q.data, false);
    buckets_buf_free(&q);
    yyjson_val *gr = yyjson_doc_get_root(gi);
    yyjson_mut_val *p = principal(f, "group", yyjson_get_str(g));
    add_csv(f->d, yyjson_mut_obj_add_arr(f->d, p, "policies"), yyjson_get_str(yyjson_obj_get(gr, "policy")));
    yyjson_val *mem = yyjson_obj_get(gr, "members");
    yyjson_mut_obj_add_val(f->d, p, "members", mem ? yyjson_val_mut_copy(f->d, mem) : yyjson_mut_arr(f->d));
    const char *st = yyjson_get_str(yyjson_obj_get(gr, "status"));
    yyjson_mut_obj_add_strcpy(f->d, p, "status", st ? st : "enabled");
    yyjson_doc_free(gi);
  }

  /* LDAP users and groups, with the policies attached to their DNs */
  yyjson_doc *ldap = get(&c, "idp/ldap/policy-entities", NULL, true);
  f->ldap = ldap != NULL;
  yyjson_val *pm;
  yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(ldap), "policyMappings"), i, max, pm) {
    const char *pn = yyjson_get_str(yyjson_obj_get(pm, "policy"));
    static const char *const lists[] = {"users", "groups"}, *const kinds[] = {"ldap-user", "ldap-group"};
    for (int t = 0; t < 2; t++) {
      size_t j, jm;
      yyjson_val *dn;
      yyjson_arr_foreach(yyjson_obj_get(pm, lists[t]), j, jm, dn) {
        const char *s = yyjson_get_str(dn);
        if (!s || !strchr(s, '=')) continue; /* LDAP entities are DNs */
        yyjson_mut_val *p = find(f, kinds[t], s);
        if (!p) {
          p = principal(f, kinds[t], s);
          yyjson_mut_obj_add_arr(f->d, p, "policies");
        }
        if (pn) yyjson_mut_arr_add_strcpy(f->d, yyjson_mut_obj_get(p, "policies"), pn);
      }
    }
  }

  /* OpenID: every policy is a role someone may hold; the people seen, and their keys */
  yyjson_doc *oidc = get(&c, "idp/openid/list-access-keys-bulk", "all=true&listType=all", true);
  f->openid = oidc != NULL;
  if (!oidc && c.status == 403) missing(f, "OpenID users");
  yyjson_val *cfg;
  yyjson_arr_foreach(yyjson_doc_get_root(oidc), i, max, cfg) {
    size_t j, jm;
    yyjson_val *u;
    yyjson_arr_foreach(yyjson_obj_get(cfg, "users"), j, jm, u) {
      const char *label = NULL;
      static const char *const names[] = {"displayName", "readableName", "email", "ID"};
      for (size_t n = 0; n < 4 && !(label && *label); n++) label = yyjson_get_str(yyjson_obj_get(u, names[n]));
      const char *id = yyjson_get_str(yyjson_obj_get(u, "minioAccessKey"));
      if (!label || !*label || !id) continue;
      yyjson_mut_val *p = principal(f, "openid-user", label);
      yyjson_mut_obj_add_strcpy(f->d, p, "id", id);
      yyjson_val *roles = yyjson_obj_get(u, "policies");
      yyjson_mut_obj_add_val(f->d, p, "policies", roles ? yyjson_val_mut_copy(f->d, roles) : yyjson_mut_arr(f->d));
      size_t a, am;
      yyjson_val *sk;
      yyjson_arr_foreach(yyjson_obj_get(u, "serviceAccounts"), a, am, sk) {
        const char *ak = yyjson_get_str(yyjson_obj_get(sk, "accessKey"));
        if (ak) add_key(f, &c, ak, id, yyjson_get_bool(yyjson_obj_get(sk, "impliedPolicy")));
      }
    }
  }
  if (f->openid) {
    yyjson_obj_foreach(policies, i, max, k, v) {
      const char *pn = yyjson_get_str(k);
      yyjson_mut_val *p = principal(f, "openid-role", pn);
      yyjson_mut_arr_add_strcpy(f->d, yyjson_mut_obj_add_arr(f->d, p, "policies"), pn);
      yyjson_mut_val *seen = yyjson_mut_obj_add_arr(f->d, p, "seen");
      size_t a, am;
      yyjson_mut_val *op;
      yyjson_mut_arr_foreach(f->principals, a, am, op) {
        if (strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(op, "kind")), "openid-user") != 0) continue;
        size_t b, bm;
        yyjson_mut_val *r;
        yyjson_mut_arr_foreach(yyjson_mut_obj_get(op, "policies"), b, bm, r) {
          if (strcmp(yyjson_mut_get_str(r), pn) == 0)
            yyjson_mut_arr_add_strcpy(f->d, seen, yyjson_mut_get_str(yyjson_mut_obj_get(op, "name")));
        }
      }
    }
  }

  /* access keys of local users and root; an owner that is not a local user is the root user */
  yyjson_doc *keys = get(&c, "list-access-keys-bulk", "all=true&listType=svcacc-only", true);
  if (!keys) missing(f, "access keys");
  yyjson_obj_foreach(yyjson_doc_get_root(keys), i, max, k, v) {
    const char *owner = yyjson_get_str(k);
    if (!find(f, "user", owner)) yyjson_mut_obj_put(root, yyjson_mut_str(f->d, "name"), yyjson_mut_strcpy(f->d, owner));
    size_t j, jm;
    yyjson_val *sk;
    yyjson_arr_foreach(yyjson_obj_get(v, "serviceAccounts"), j, jm, sk) {
      const char *ak = yyjson_get_str(yyjson_obj_get(sk, "accessKey"));
      if (ak) add_key(f, &c, ak, owner, yyjson_get_bool(yyjson_obj_get(sk, "impliedPolicy")));
    }
  }

  /* the bucket's own policy */
  yyjson_mut_val *bp = yyjson_mut_null(f->d);
  if (bucket) {
    buckets_buf path = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&path, "/");
    buckets_url_encode(&path, bucket, false);
    int st = sess->s3_get(sess->ud, path.data, "policy", &out);
    if (st == 200) {
      yyjson_doc *bd = yyjson_read(out.data ? out.data : "", out.len, 0);
      if (yyjson_is_obj(yyjson_doc_get_root(bd))) bp = yyjson_val_mut_copy(f->d, yyjson_doc_get_root(bd));
      yyjson_doc_free(bd);
    } else if (st != 404) {
      missing(f, "the bucket policy");
    }
    buckets_buf_free(&path);
    buckets_buf_free(&out);
  }
  yyjson_mut_obj_add_val(f->d, f->root, "bucketPolicy", bp);
  yyjson_mut_obj_add_val(f->d, f->root, "missing", f->missing);
  yyjson_doc_free(pol);
  yyjson_doc_free(users);
  yyjson_doc_free(groups);
  yyjson_doc_free(ldap);
  yyjson_doc_free(oidc);
  yyjson_doc_free(keys);
  buckets_buf_free(&c.body);
}

/* ---- the endpoints ------------------------------------------------------------------------------- */

static bool gathered(facts *f, buckets_http_response *resp) {
  if (f->policies_status == 200) return true;
  fail(resp, f->policies_status == 403 ? 403 : 502, f->policies_status == 403 ? "AccessDenied" : "ServerError",
       f->policies_status == 403 ? "The access review needs to read the policies (admin:ListUserPolicies)."
                                 : "The servers did not list the policies.");
  yyjson_mut_doc_free(f->d);
  return false;
}

static void handle_bucket(const buckets_console_access_session *sess, const char *bucket, const char *level,
                          buckets_http_response *resp) {
  facts f = {0};
  gather(&f, sess, bucket);
  if (!gathered(&f, resp)) return;
  yyjson_doc *fi = yyjson_mut_doc_imut_copy(f.d, NULL);
  yyjson_mut_doc_free(f.d);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *r = buckets_access_bucket(d, yyjson_doc_get_root(fi), bucket, level);
  yyjson_doc_free(fi);
  if (!r) {
    yyjson_mut_doc_free(d);
    fail(resp, 400, "InvalidLevel", "The level is one of read, write, delete, manage and any");
    return;
  }
  yyjson_mut_obj_add_int(d, r, "at", (int64_t)time(NULL));
  yyjson_mut_doc_set_root(d, r);
  reply(resp, 200, d);
}

static void handle_check(const buckets_console_access_session *sess, yyjson_val *body,
                         buckets_http_response *resp) {
  yyjson_val *who = yyjson_obj_get(body, "who");
  const char *action = yyjson_get_str(yyjson_obj_get(body, "action"));
  const char *bucket = yyjson_get_str(yyjson_obj_get(body, "bucket"));
  const char *object = yyjson_get_str(yyjson_obj_get(body, "object"));
  if (!yyjson_is_obj(who) || !action || !*action || !bucket || !*bucket) {
    fail(resp, 400, "InvalidRequest", "Give who, an action and a bucket");
    return;
  }
  facts f = {0};
  gather(&f, sess, bucket);
  if (!gathered(&f, resp)) return;
  yyjson_doc *fi = yyjson_mut_doc_imut_copy(f.d, NULL);
  yyjson_mut_doc_free(f.d);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *r = buckets_access_check(d, yyjson_doc_get_root(fi), who, action, bucket, object ? object : "",
                                           yyjson_obj_get(body, "conds"));
  if (r) {
    yyjson_val *ms = yyjson_obj_get(yyjson_doc_get_root(fi), "missing");
    yyjson_mut_obj_add_val(d, r, "missing", yyjson_val_mut_copy(d, ms));
  }
  yyjson_doc_free(fi);
  if (!r) {
    yyjson_mut_doc_free(d);
    fail(resp, 404, "NoSuchPrincipal", "There is no such user, group, LDAP entity or access key");
    return;
  }
  yyjson_mut_doc_set_root(d, r);
  reply(resp, 200, d);
}

static void handle_principals(const buckets_console_access_session *sess, buckets_http_response *resp) {
  facts f = {0};
  gather(&f, sess, NULL);
  if (!gathered(&f, resp)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d), *arr = yyjson_mut_obj_add_arr(d, o, "principals");
  yyjson_mut_doc_set_root(d, o);
  size_t i, max;
  yyjson_mut_val *p;
  yyjson_mut_arr_foreach(f.principals, i, max, p) {
    const char *kind = yyjson_mut_get_str(yyjson_mut_obj_get(p, "kind"));
    if (strcmp(kind, "openid-role") == 0 || strcmp(kind, "openid-user") == 0) continue; /* roles are typed in */
    yyjson_mut_val *q = yyjson_mut_arr_add_obj(d, arr);
    static const char *const keep[] = {"kind", "name", "owner", "status"};
    for (size_t k = 0; k < 4; k++) {
      yyjson_mut_val *v = yyjson_mut_obj_get(p, keep[k]);
      if (v) yyjson_mut_obj_add_strcpy(d, q, keep[k], yyjson_mut_get_str(v));
    }
  }
  yyjson_mut_obj_add_bool(d, o, "openid", f.openid);
  yyjson_mut_obj_add_bool(d, o, "ldap", f.ldap);
  yyjson_mut_obj_add_val(d, o, "missing", yyjson_mut_val_mut_copy(d, f.missing));
  yyjson_mut_doc_free(f.d);
  reply(resp, 200, d);
}

static void handle_local_users(const buckets_console_access_session *sess, buckets_http_response *resp) {
  facts f = {0};
  gather(&f, sess, NULL);
  if (!gathered(&f, resp)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  if (f.openid) yyjson_mut_obj_add_str(d, o, "provider", "OpenID");
  else if (f.ldap) yyjson_mut_obj_add_str(d, o, "provider", "LDAP");
  else yyjson_mut_obj_add_null(d, o, "provider");
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "users");
  size_t i, max;
  yyjson_mut_val *p;
  yyjson_mut_arr_foreach(f.principals, i, max, p) {
    if (strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(p, "kind")), "user") != 0) continue;
    const char *name = yyjson_mut_get_str(yyjson_mut_obj_get(p, "name"));
    yyjson_mut_val *u = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, u, "name", name);
    yyjson_mut_obj_add_strcpy(d, u, "status", yyjson_mut_get_str(yyjson_mut_obj_get(p, "status")));
    yyjson_mut_obj_add_val(d, u, "policies", yyjson_mut_val_mut_copy(d, yyjson_mut_obj_get(p, "policies")));
    yyjson_mut_obj_add_val(d, u, "groups", yyjson_mut_val_mut_copy(d, yyjson_mut_obj_get(p, "groups")));
    int keys = 0;
    size_t j, jm;
    yyjson_mut_val *kp;
    yyjson_mut_arr_foreach(f.principals, j, jm, kp) {
      yyjson_mut_val *owner = yyjson_mut_obj_get(kp, "owner");
      if (owner && strcmp(yyjson_mut_get_str(owner), name) == 0) keys++;
    }
    yyjson_mut_obj_add_int(d, u, "keys", keys);
  }
  yyjson_mut_obj_add_val(d, o, "missing", yyjson_mut_val_mut_copy(d, f.missing));
  yyjson_mut_doc_free(f.d);
  reply(resp, 200, d);
}

void buckets_console_access_handle(const buckets_http_request *req, const char *sub,
                                   const buckets_console_access_session *sess, buckets_http_response *resp) {
  bool get = buckets_str_eq_c(req->method, "GET"), post = buckets_str_eq_c(req->method, "POST");
  if (get && strncmp(sub, "/bucket/", 8) == 0 && sub[8] && !strchr(sub + 8, '/')) {
    buckets_query q;
    buckets_query_parse(req->query, &q);
    const char *level = buckets_query_get(&q, "level");
    handle_bucket(sess, sub + 8, level && *level ? level : "read", resp);
    buckets_query_free(&q);
  } else if (get && strcmp(sub, "/principals") == 0) {
    handle_principals(sess, resp);
  } else if (get && strcmp(sub, "/local-users") == 0) {
    handle_local_users(sess, resp);
  } else if (post && strcmp(sub, "/check") == 0) {
    if (req->body_len > MAX_BODY || req->body_fd >= 0 || req->pipe) {
      fail(resp, 413, "TooLarge", "request too large");
      return;
    }
    yyjson_doc *bd = yyjson_read(req->body.p ? req->body.p : "", req->body.n, 0);
    if (!yyjson_is_obj(yyjson_doc_get_root(bd))) fail(resp, 400, "InvalidRequest", "expected a JSON object");
    else handle_check(sess, yyjson_doc_get_root(bd), resp);
    yyjson_doc_free(bd);
  } else {
    fail(resp, 404, "NotFound", "unknown API");
  }
}
