/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/access.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "iam/policy.h"

const char *const buckets_access_levels[] = {"read", "write", "delete", "manage", "any", NULL};

#define ARN "arn:aws:s3:::"
/* An object name no narrower pattern than "*" matches: access to it is access to the whole bucket. */
#define PROBE \
  "\x01"      \
  "buckets-access-review"

typedef struct {
  const char *action;
  bool object; /* an object action (else on the bucket) */
} level_action;

static const level_action k_read[] = {{"s3:ListBucket", false}, {"s3:GetObject", true}, {NULL, false}};
static const level_action k_write[] = {{"s3:PutObject", true}, {NULL, false}};
static const level_action k_delete[] = {{"s3:DeleteObject", true}, {NULL, false}};
static const level_action k_manage[] = {{"s3:PutBucketPolicy", false},
                                        {"s3:PutLifecycleConfiguration", false},
                                        {"s3:PutBucketVersioning", false},
                                        {"s3:PutEncryptionConfiguration", false},
                                        {"s3:PutBucketNotification", false},
                                        {"s3:PutBucketObjectLockConfiguration", false},
                                        {"s3:PutReplicationConfiguration", false},
                                        {"s3:DeleteBucket", false},
                                        {NULL, false}};
static const level_action *const k_levels[] = {k_read, k_write, k_delete, k_manage};

/* ---- statements, each a policy of its own ------------------------------------------------- */

typedef struct {
  const char *policy; /* NULL: the bucket policy */
  int index;
  const char *sid;
  bool deny;
  yyjson_val *stmt;
  buckets_policy *stripped; /* Effect Allow, no Condition: does it cover the request? */
  buckets_policy *full;     /* Effect Allow, with its Condition: evaluated when every key has a value */
  char **ckeys;             /* the Condition's keys, short names ("SourceIp") */
  size_t nck;
} entry;

typedef struct {
  entry *v;
  size_t n, cap;
} entries;

static void entries_free(entries *e) {
  for (size_t i = 0; i < e->n; i++) {
    buckets_policy_free(e->v[i].stripped);
    buckets_policy_free(e->v[i].full);
    for (size_t k = 0; k < e->v[i].nck; k++) free(e->v[i].ckeys[k]);
    free(e->v[i].ckeys);
  }
  free(e->v);
  *e = (entries){0};
}

static const char *short_key(const char *k) {
  const char *c = strchr(k, ':');
  return c ? c + 1 : k;
}

/* A one-statement policy from stmt, as an Allow, with or without its Condition (and, for a bucket policy, the
 * Principal "*": principals are matched here, not by the evaluator). */
static buckets_policy *mini(yyjson_val *stmt, const char *version, const char *bucket, bool keep_condition) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *s = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "Version", version && *version ? version : "2012-10-17");
  yyjson_mut_arr_append(yyjson_mut_obj_add_arr(d, root, "Statement"), s);
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(stmt, i, max, k, v) {
    const char *key = yyjson_get_str(k);
    if (strcmp(key, "Effect") == 0 || strcmp(key, "Sid") == 0 || strcmp(key, "Principal") == 0) continue;
    if (strcmp(key, "Condition") == 0 && !keep_condition) continue;
    yyjson_mut_obj_add(s, yyjson_mut_strcpy(d, key), yyjson_val_mut_copy(d, v));
  }
  yyjson_mut_obj_add_str(d, s, "Effect", "Allow");
  if (bucket) yyjson_mut_obj_add_str(d, s, "Principal", "*");
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  buckets_policy *p = NULL;
  char err[256];
  bool ok = bucket ? buckets_bucket_policy_parse(json, n, bucket, &p, err, sizeof(err))
                   : buckets_policy_parse(json, n, &p, err, sizeof(err));
  free(json);
  return ok ? p : NULL;
}

/* Adds doc's statements (policy: its name, NULL for the bucket policy of bucket). */
static void add_policy(entries *e, const char *policy, yyjson_val *doc, const char *bucket) {
  const char *version = yyjson_get_str(yyjson_obj_get(doc, "Version"));
  yyjson_val *stmts = yyjson_obj_get(doc, "Statement");
  size_t count = yyjson_is_obj(stmts) ? 1 : yyjson_arr_size(stmts); /* a single statement may be an object */
  for (size_t i = 0; i < count; i++) {
    yyjson_val *st = yyjson_is_obj(stmts) ? stmts : yyjson_arr_get(stmts, i);
    if (!yyjson_is_obj(st)) continue;
    if (e->n == e->cap) {
      e->cap = e->cap ? e->cap * 2 : 16;
      e->v = buckets_xrealloc(e->v, e->cap * sizeof(*e->v));
    }
    entry *x = &e->v[e->n];
    *x = (entry){.policy = policy, .index = (int)i, .stmt = st};
    x->sid = yyjson_get_str(yyjson_obj_get(st, "Sid"));
    const char *eff = yyjson_get_str(yyjson_obj_get(st, "Effect"));
    x->deny = eff && strcmp(eff, "Deny") == 0;
    x->stripped = mini(st, version, bucket, false);
    if (!x->stripped) continue; /* not a statement the servers would load either */
    yyjson_val *cond = yyjson_obj_get(st, "Condition");
    size_t a, am, b, bm;
    yyjson_val *ck, *cv, *kk, *kv;
    yyjson_obj_foreach(cond, a, am, ck, cv) {
      yyjson_obj_foreach(cv, b, bm, kk, kv) {
        x->ckeys = buckets_xrealloc(x->ckeys, (x->nck + 1) * sizeof(char *));
        x->ckeys[x->nck++] = buckets_xstrdup(short_key(yyjson_get_str(kk)));
      }
    }
    if (x->nck) x->full = mini(st, version, bucket, true);
    e->n++;
  }
}

/* ---- deciding ------------------------------------------------------------------------------- */

typedef enum { M_NO, M_YES, M_MAYBE } match;

typedef struct {
  const char *action, *bucket, *object;
  yyjson_val *conds; /* given condition values */
  const char *user;  /* for ${aws:username} */
} request;

static match matches(const entry *x, const request *r) {
  if (!x->stripped) return M_NO;
  /* condition values: those given, and the user's name */
  size_t n = yyjson_obj_size(r->conds) + 1, k = 0;
  buckets_cond_value *cv = buckets_xcalloc(n, sizeof(*cv));
  const char **vals = buckets_xcalloc(n, sizeof(char *));
  size_t i, max;
  yyjson_val *key, *val;
  yyjson_obj_foreach(r->conds, i, max, key, val) {
    if (!yyjson_is_str(val)) continue;
    vals[k] = yyjson_get_str(val);
    cv[k] = (buckets_cond_value){short_key(yyjson_get_str(key)), &vals[k], 1};
    k++;
  }
  if (r->user && *r->user) {
    vals[k] = r->user;
    cv[k] = (buckets_cond_value){"username", &vals[k], 1};
    k++;
  }
  buckets_policy_args a = {
      .action = r->action, .bucket = r->bucket, .object = r->object, .conds = cv, .nconds = k};
  match m;
  if (!x->nck) {
    m = buckets_policy_allowed(x->stripped, &a) ? M_YES : M_NO;
  } else {
    bool all = x->full != NULL;
    for (size_t c = 0; all && c < x->nck; c++) {
      bool have = false;
      for (size_t j = 0; j < k && !have; j++) have = strcmp(cv[j].key, x->ckeys[c]) == 0;
      all = have;
    }
    if (all)
      m = buckets_policy_allowed(x->full, &a) ? M_YES : M_NO;
    else
      m = buckets_policy_allowed(x->stripped, &a) ? M_MAYBE : M_NO;
  }
  free(cv);
  free(vals);
  return m;
}

typedef enum { D_NONE, D_DENIED, D_ALLOWED, D_CONDITIONAL } decision;

typedef struct {
  decision d;
  const entry **by;
  size_t nby;
} outcome;

static void by_add(outcome *o, const entry *x) {
  o->by = buckets_xrealloc(o->by, (o->nby + 1) * sizeof(*o->by));
  o->by[o->nby++] = x;
}

/* The servers' rule over a set of statements: an explicit Deny wins, then an Allow. Statements whose
 * Condition cannot be decided make the result conditional: an Allow never counts, a Deny could still
 * refuse. */
static outcome decide(const entry *const *xs, size_t n, const request *r) {
  outcome o = {D_NONE, NULL, 0};
  bool deny = false, allow = false, maybe_deny = false, maybe_allow = false;
  match *ms = buckets_xcalloc(n ? n : 1, sizeof(*ms));
  for (size_t i = 0; i < n; i++) {
    ms[i] = matches(xs[i], r);
    if (ms[i] == M_YES) (xs[i]->deny ? &deny : &allow)[0] = true;
    if (ms[i] == M_MAYBE) (xs[i]->deny ? &maybe_deny : &maybe_allow)[0] = true;
  }
  o.d = deny          ? D_DENIED
        : allow       ? (maybe_deny ? D_CONDITIONAL : D_ALLOWED)
        : maybe_allow ? D_CONDITIONAL
                      : D_NONE;
  for (size_t i = 0; i < n; i++) {
    if (ms[i] == M_NO) continue;
    bool show = o.d == D_DENIED    ? (xs[i]->deny && ms[i] == M_YES)
                : o.d == D_ALLOWED ? (!xs[i]->deny && ms[i] == M_YES)
                                   : o.d == D_CONDITIONAL;
    if (show) by_add(&o, xs[i]);
  }
  free(ms);
  return o;
}

static void outcome_free(outcome *o) {
  free(o->by);
  o->by = NULL;
  o->nby = 0;
}

/* ---- principals ------------------------------------------------------------------------------- */

typedef struct {
  yyjson_val *facts;
  entries ident;  /* every named policy's statements */
  entries bucket; /* the bucket policy's */
  entries *keys;  /* each key principal's own policy (by index in principals; may be empty) */
  size_t nprincipals;
} model;

static yyjson_val *principals(const model *m) { return yyjson_obj_get(m->facts, "principals"); }

static yyjson_val *find_principal(const model *m, const char *kind, const char *name) {
  size_t i, max;
  yyjson_val *p;
  yyjson_arr_foreach(principals(m), i, max, p) {
    const char *k = yyjson_get_str(yyjson_obj_get(p, "kind")),
               *nm = yyjson_get_str(yyjson_obj_get(p, "name"));
    if (k && nm && strcmp(k, kind) == 0 && strcmp(nm, name) == 0) return p;
  }
  return NULL;
}

/* A key's owner: a user, LDAP user, OpenID user (by name or id) or the root user. */
static yyjson_val *find_owner(const model *m, const char *owner) {
  if (!owner) return NULL;
  static const char *const kinds[] = {"user", "ldap-user", "openid-user", "root"};
  size_t i, max;
  yyjson_val *p;
  yyjson_arr_foreach(principals(m), i, max, p) {
    const char *k = yyjson_get_str(yyjson_obj_get(p, "kind"));
    const char *n = yyjson_get_str(yyjson_obj_get(p, "name")), *id = yyjson_get_str(yyjson_obj_get(p, "id"));
    bool kind_ok = false;
    for (size_t j = 0; k && j < BUCKETS_ARRAY_LEN(kinds); j++) kind_ok = kind_ok || strcmp(k, kinds[j]) == 0;
    if (kind_ok && ((n && strcmp(n, owner) == 0) || (id && strcmp(id, owner) == 0))) return p;
  }
  return NULL;
}

static void model_init(model *m, yyjson_val *facts, const char *bucket) {
  *m = (model){.facts = facts};
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(yyjson_obj_get(facts, "policies"), i, max, k, v)
      add_policy(&m->ident, yyjson_get_str(k), v, NULL);
  yyjson_val *bp = yyjson_obj_get(facts, "bucketPolicy");
  if (bucket && yyjson_is_obj(bp)) add_policy(&m->bucket, NULL, bp, bucket);
  m->nprincipals = yyjson_arr_size(principals(m));
  m->keys = buckets_xcalloc(m->nprincipals ? m->nprincipals : 1, sizeof(entries));
  yyjson_val *p;
  yyjson_arr_foreach(principals(m), i, max, p) {
    yyjson_val *own = yyjson_obj_get(p, "policy");
    if (yyjson_is_obj(own)) add_policy(&m->keys[i], "(the access key's own policy)", own, NULL);
  }
}

static void model_free(model *m) {
  entries_free(&m->ident);
  entries_free(&m->bucket);
  for (size_t i = 0; i < m->nprincipals; i++) entries_free(&m->keys[i]);
  free(m->keys);
}

typedef struct {
  const entry **v;
  size_t n;
} set;

static void set_add_policy(set *s, const model *m, const char *policy) {
  for (size_t i = 0; i < m->ident.n; i++) {
    if (strcmp(m->ident.v[i].policy, policy) != 0) continue;
    bool dup = false;
    for (size_t j = 0; j < s->n && !dup; j++) dup = s->v[j] == &m->ident.v[i];
    if (dup) continue;
    s->v = buckets_xrealloc(s->v, (s->n + 1) * sizeof(*s->v));
    s->v[s->n++] = &m->ident.v[i];
  }
}

static void set_add_names(set *s, const model *m, yyjson_val *names) {
  size_t i, max;
  yyjson_val *n;
  yyjson_arr_foreach(names, i, max, n) if (yyjson_is_str(n)) set_add_policy(s, m, yyjson_get_str(n));
}

/* The identity-policy statements a principal has: its own, and its groups'. */
static set statements_of(const model *m, yyjson_val *p) {
  set s = {0};
  set_add_names(&s, m, yyjson_obj_get(p, "policies"));
  size_t i, max;
  yyjson_val *g;
  yyjson_arr_foreach(yyjson_obj_get(p, "groups"), i, max, g) {
    yyjson_val *gp = find_principal(m, "group", yyjson_get_str(g));
    if (!gp) gp = find_principal(m, "ldap-group", yyjson_get_str(g));
    const char *status = gp ? yyjson_get_str(yyjson_obj_get(gp, "status")) : NULL;
    if (gp && !(status && strcmp(status, "disabled") == 0))
      set_add_names(&s, m, yyjson_obj_get(gp, "policies"));
  }
  return s;
}

/* Whether a bucket-policy statement names the account (or everyone). */
static bool names_account(const entry *x, const char *account) {
  yyjson_val *pr = yyjson_obj_get(x->stmt, "Principal");
  if (yyjson_is_str(pr)) return strcmp(yyjson_get_str(pr), "*") == 0;
  yyjson_val *aws = yyjson_obj_get(pr, "AWS");
  if (yyjson_is_str(aws))
    return strcmp(yyjson_get_str(aws), "*") == 0 || (account && strcmp(yyjson_get_str(aws), account) == 0);
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(aws, i, max, v) {
    const char *s = yyjson_get_str(v);
    if (s && (strcmp(s, "*") == 0 || (account && strcmp(s, account) == 0))) return true;
  }
  return false;
}

/* Whether a bucket-policy statement names the account itself, not just everyone. */
static bool names_account_exactly(const entry *x, const char *account) {
  yyjson_val *pr = yyjson_obj_get(x->stmt, "Principal");
  yyjson_val *aws = yyjson_obj_get(pr, "AWS");
  if (yyjson_is_str(aws)) return strcmp(yyjson_get_str(aws), account) == 0;
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(aws, i, max,
                     v) if (yyjson_is_str(v) && strcmp(yyjson_get_str(v), account) == 0) return true;
  return false;
}

/* The bucket-policy statements that apply to account (NULL: anonymous, only "*"). Without star_allows, Allows
 * that name everyone are left out: a review's "everyone" row shows them once, not in every person's row. */
static set bucket_statements(const model *m, const char *account, bool star_allows) {
  set s = {0};
  for (size_t i = 0; i < m->bucket.n; i++) {
    if (!names_account(&m->bucket.v[i], account)) continue;
    if (!star_allows && !m->bucket.v[i].deny && !(account && names_account_exactly(&m->bucket.v[i], account)))
      continue;
    s.v = buckets_xrealloc(s.v, (s.n + 1) * sizeof(*s.v));
    s.v[s.n++] = &m->bucket.v[i];
  }
  return s;
}

static set set_join(set a, set b) {
  a.v = buckets_xrealloc(a.v, (a.n + b.n + 1) * sizeof(*a.v));
  for (size_t i = 0; i < b.n; i++) a.v[a.n++] = b.v[i];
  free(b.v);
  return a;
}

/* A principal's decision: its statements and the bucket policy's for it; a key with its own policy also needs
 * that policy to allow. Root may do everything. */
static outcome principal_decides(const model *m, yyjson_val *p, size_t pindex, const request *r,
                                 bool star_allows) {
  const char *kind = yyjson_get_str(yyjson_obj_get(p, "kind"));
  const char *name = yyjson_get_str(yyjson_obj_get(p, "name"));
  if (kind && strcmp(kind, "root") == 0) return (outcome){D_ALLOWED, NULL, 0};
  yyjson_val *subject = p;
  const char *account = name;
  if (kind && strcmp(kind, "key") == 0) { /* the owner's access, narrowed by the key's own policy */
    const char *owner = yyjson_get_str(yyjson_obj_get(p, "owner"));
    yyjson_val *op = find_owner(m, owner);
    if (!op) return (outcome){D_NONE, NULL, 0};
    subject = op;
    account = owner;
  }
  request rr = *r;
  rr.user = account;
  set s = set_join(statements_of(m, subject), bucket_statements(m, account, star_allows));
  outcome o;
  if (subject != p && strcmp(yyjson_get_str(yyjson_obj_get(subject, "kind")), "root") == 0)
    o = (outcome){D_ALLOWED, NULL, 0};
  else
    o = decide(s.v, s.n, &rr);
  free(s.v);
  if (pindex < m->nprincipals && m->keys[pindex].n && o.d != D_DENIED && o.d != D_NONE) {
    set ks = {0};
    for (size_t i = 0; i < m->keys[pindex].n; i++) {
      ks.v = buckets_xrealloc(ks.v, (ks.n + 1) * sizeof(*ks.v));
      ks.v[ks.n++] = &m->keys[pindex].v[i];
    }
    outcome k = decide(ks.v, ks.n, &rr);
    free(ks.v);
    if (k.d == D_DENIED || k.d == D_NONE) {
      outcome_free(&o);
      return k;
    }
    for (size_t i = 0; i < k.nby; i++) by_add(&o, k.by[i]);
    if (k.d == D_CONDITIONAL) o.d = D_CONDITIONAL;
    outcome_free(&k);
  }
  return o;
}

/* ---- output -------------------------------------------------------------------------------------- */

static void add_by(yyjson_mut_doc *d, yyjson_mut_val *arr, const outcome *o) {
  for (size_t i = 0; i < o->nby; i++) {
    const entry *x = o->by[i];
    yyjson_mut_val *b = yyjson_mut_arr_add_obj(d, arr);
    if (x->policy)
      yyjson_mut_obj_add_strcpy(d, b, "policy", x->policy);
    else
      yyjson_mut_obj_add_bool(d, b, "bucketPolicy", true);
    yyjson_mut_obj_add_int(d, b, "statement", x->index);
    if (x->sid && *x->sid) yyjson_mut_obj_add_strcpy(d, b, "sid", x->sid);
    yyjson_mut_obj_add_str(d, b, "effect", x->deny ? "Deny" : "Allow");
    if (x->nck) {
      yyjson_mut_val *c = yyjson_mut_obj_add_arr(d, b, "conditions");
      for (size_t k = 0; k < x->nck; k++) yyjson_mut_arr_add_strcpy(d, c, x->ckeys[k]);
    }
  }
}

static const char *decision_name(decision v) {
  return v == D_ALLOWED ? "allowed" : v == D_DENIED ? "denied" : v == D_CONDITIONAL ? "conditional" : "none";
}

/* Object patterns in bucket that an Allow among s grants action on, though not the whole bucket. */
static void limits(yyjson_mut_doc *d, yyjson_mut_val *out, const model *m, yyjson_val *p, size_t pindex,
                   const set *s, const request *r, bool stand_in, outcome *acc) {
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i]->deny) continue;
    yyjson_val *res = yyjson_obj_get(s->v[i]->stmt, "Resource");
    yyjson_val *one = yyjson_is_str(res) ? res : NULL;
    size_t n = one ? 1 : yyjson_arr_size(res);
    for (size_t j = 0; j < n; j++) {
      const char *arn = yyjson_get_str(one ? one : yyjson_arr_get(res, j));
      if (!arn || strncmp(arn, ARN, strlen(ARN)) != 0) continue;
      const char *bo = arn + strlen(ARN), *slash = strchr(bo, '/');
      if (!slash || strcmp(slash + 1, "*") == 0) continue;
      char bpart[256], sample[1024];
      snprintf(bpart, sizeof(bpart), "%.*s", (int)(slash - bo), bo);
      if (!buckets_wildcard_match(bpart, r->bucket)) continue;
      size_t k = 0;
      for (const char *c = slash + 1; *c && k < sizeof(sample) - 1; c++)
        sample[k++] = (*c == '*' || *c == '?') ? 'x' : *c;
      sample[k] = '\0';
      request rs = *r;
      rs.object = sample;
      outcome o = principal_decides(m, p, pindex, &rs, stand_in);
      bool ok = o.d == D_ALLOWED;
      if (ok)
        for (size_t b = 0; b < o.nby; b++) by_add(acc, o.by[b]);
      outcome_free(&o);
      if (!ok) continue;
      bool dup = false;
      size_t a, am;
      yyjson_mut_val *have;
      yyjson_mut_arr_foreach(out, a, am, have) dup = dup || strcmp(yyjson_mut_get_str(have), slash + 1) == 0;
      if (!dup) yyjson_mut_arr_add_strcpy(d, out, slash + 1);
    }
  }
}

static const level_action *level_of(const char *level, size_t *n_out, level_action *any, size_t cap) {
  for (int i = 0; i < 4; i++) {
    if (strcmp(level, buckets_access_levels[i]) == 0) {
      size_t n = 0;
      while (k_levels[i][n].action) n++;
      *n_out = n;
      return k_levels[i];
    }
  }
  if (strcmp(level, "any") != 0) return NULL;
  size_t n = 0;
  for (int i = 0; i < 4; i++)
    for (const level_action *a = k_levels[i]; a->action && n < cap; a++) any[n++] = *a;
  *n_out = n;
  return any;
}

/* One row: a principal's decisions on the level's actions; NULL when it has no access at all. */
static yyjson_mut_val *row(yyjson_mut_doc *d, const model *m, yyjson_val *p, size_t pindex,
                           const level_action *acts, size_t nacts, const char *bucket, bool stand_in) {
  yyjson_mut_val *r = yyjson_mut_obj(d);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  size_t full = 0, some = 0, cond = 0;
  const char *kind = yyjson_get_str(yyjson_obj_get(p, "kind"));
  bool is_key = kind && strcmp(kind, "key") == 0;
  yyjson_val *subject = p;
  if (is_key) {
    subject = find_owner(m, yyjson_get_str(yyjson_obj_get(p, "owner")));
  }
  set s = subject ? set_join(statements_of(m, subject),
                             bucket_statements(m, yyjson_get_str(yyjson_obj_get(subject, "name")), stand_in))
                  : (set){0};
  for (size_t i = 0; i < nacts; i++) {
    request rq = {acts[i].action, bucket, acts[i].object ? PROBE : "", NULL, NULL};
    outcome o = principal_decides(m, p, pindex, &rq, stand_in);
    yyjson_mut_val *a = yyjson_mut_obj(d);
    yyjson_mut_obj_add_str(d, a, "action", acts[i].action);
    const char *dec = NULL;
    if (o.d == D_ALLOWED) {
      dec = "allowed";
      full++;
    } else if (o.d == D_CONDITIONAL) {
      dec = "conditional";
      cond++;
    } else if (acts[i].object) {
      yyjson_mut_val *lim = yyjson_mut_arr(d);
      limits(d, lim, m, p, pindex, &s, &rq, stand_in, &o);
      if (yyjson_mut_arr_size(lim)) {
        dec = "limited";
        some++;
        yyjson_mut_obj_add_val(d, a, "limits", lim);
      }
    }
    if (dec) {
      yyjson_mut_obj_add_str(d, a, "decision", dec);
      add_by(d, yyjson_mut_obj_add_arr(d, a, "by"), &o);
      yyjson_mut_arr_append(arr, a);
    }
    outcome_free(&o);
  }
  free(s.v);
  if (!full && !some && !cond) return NULL;
  yyjson_mut_obj_add_strcpy(d, r, "kind", kind ? kind : "");
  yyjson_mut_obj_add_strcpy(
      d, r, "name",
      yyjson_get_str(yyjson_obj_get(p, "name")) ? yyjson_get_str(yyjson_obj_get(p, "name")) : "");
  static const char *const copy[] = {"status", "members", "seen", "owner", "groups", "ownerLeft"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(copy); i++) {
    yyjson_val *v = yyjson_obj_get(p, copy[i]);
    if (v) yyjson_mut_obj_add_val(d, r, copy[i], yyjson_val_mut_copy(d, v));
  }
  yyjson_mut_obj_add_str(d, r, "access", full == nacts ? "full" : (full || some) ? "limited" : "conditional");
  yyjson_mut_obj_add_val(d, r, "actions", arr);
  return r;
}

yyjson_mut_val *buckets_access_bucket(yyjson_mut_doc *d, yyjson_val *facts, const char *bucket,
                                      const char *level) {
  level_action any[32];
  size_t nacts = 0;
  const level_action *acts = level_of(level, &nacts, any, BUCKETS_ARRAY_LEN(any));
  if (!acts) return NULL;
  model m;
  model_init(&m, facts, bucket);
  yyjson_mut_val *out = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, out, "bucket", bucket);
  yyjson_mut_obj_add_strcpy(d, out, "level", level);
  yyjson_mut_val *an = yyjson_mut_obj_add_arr(d, out, "actions");
  for (size_t i = 0; i < nacts; i++) yyjson_mut_arr_add_str(d, an, acts[i].action);
  yyjson_mut_val *rows = yyjson_mut_obj_add_arr(d, out, "rows");
  size_t i, max;
  yyjson_val *p;
  yyjson_arr_foreach(principals(&m), i, max, p) {
    const char *kind = yyjson_get_str(yyjson_obj_get(p, "kind"));
    if (kind && strcmp(kind, "key") == 0 && !m.keys[i].n) continue; /* its owner's row covers it */
    if (kind && strcmp(kind, "openid-user") == 0) continue;         /* the role rows name them */
    yyjson_mut_val *r = row(d, &m, p, i, acts, nacts, bucket, false);
    if (r) yyjson_mut_arr_append(rows, r);
  }
  /* the bucket policy's own principals: everyone, and accounts it names that are not principals above */
  yyjson_mut_doc *pd = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *names = yyjson_mut_arr(pd);
  for (size_t j = 0; j < m.bucket.n; j++) {
    yyjson_val *pr = yyjson_obj_get(m.bucket.v[j].stmt, "Principal");
    yyjson_val *aws = yyjson_is_str(pr) ? pr : yyjson_obj_get(pr, "AWS");
    yyjson_val *one = yyjson_is_str(aws) ? aws : NULL;
    size_t n = one ? 1 : yyjson_arr_size(aws);
    for (size_t k = 0; k < n; k++) {
      const char *nm = yyjson_get_str(one ? one : yyjson_arr_get(aws, k));
      if (!nm) continue;
      bool dup = false;
      size_t a, am;
      yyjson_mut_val *have;
      yyjson_mut_arr_foreach(names, a, am, have) dup = dup || strcmp(yyjson_mut_get_str(have), nm) == 0;
      bool known = find_principal(&m, "user", nm) || find_principal(&m, "ldap-user", nm);
      if (!dup && !known) yyjson_mut_arr_add_strcpy(pd, names, nm);
    }
  }
  size_t a, am;
  yyjson_mut_val *nm;
  yyjson_mut_arr_foreach(names, a, am, nm) {
    const char *n = yyjson_mut_get_str(nm);
    bool anyone = strcmp(n, "*") == 0;
    /* a stand-in principal with no policies: only the bucket policy applies to it */
    yyjson_mut_doc *sd = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *so = yyjson_mut_obj(sd);
    yyjson_mut_doc_set_root(sd, so);
    yyjson_mut_obj_add_str(sd, so, "kind", anyone ? "anyone" : "account");
    yyjson_mut_obj_add_strcpy(sd, so, "name", anyone ? "everyone, signed in or not" : n);
    yyjson_doc *si = yyjson_mut_doc_imut_copy(sd, NULL);
    yyjson_mut_doc_free(sd);
    yyjson_val *sp = yyjson_doc_get_root(si);
    yyjson_mut_val *r = NULL;
    r = row(d, &m, sp, (size_t)-1, acts, nacts, bucket, anyone); /* a named account: only what names it */
    if (r) yyjson_mut_arr_append(rows, r);
    yyjson_doc_free(si);
  }
  yyjson_mut_doc_free(pd);
  yyjson_val *missing = yyjson_obj_get(facts, "missing");
  yyjson_mut_obj_add_val(d, out, "missing", missing ? yyjson_val_mut_copy(d, missing) : yyjson_mut_arr(d));
  model_free(&m);
  return out;
}

yyjson_mut_val *buckets_access_check(yyjson_mut_doc *d, yyjson_val *facts, yyjson_val *who,
                                     const char *action, const char *bucket, const char *object,
                                     yyjson_val *conds) {
  model m;
  model_init(&m, facts, bucket);
  const char *kind = yyjson_get_str(yyjson_obj_get(who, "kind"));
  const char *name = yyjson_get_str(yyjson_obj_get(who, "name"));
  request r = {action, bucket, object ? object : "", conds, NULL};
  outcome o = {D_NONE, NULL, 0};
  bool known = true, disabled = false;
  if (kind && strcmp(kind, "openid") == 0) { /* the policies its roles name, and the bucket policy's "*" */
    set s = {0};
    set_add_names(&s, &m, yyjson_obj_get(who, "roles"));
    s = set_join(s, bucket_statements(&m, NULL, true));
    o = decide(s.v, s.n, &r);
    free(s.v);
  } else if (kind && strcmp(kind, "anonymous") == 0) {
    set s = bucket_statements(&m, NULL, true);
    o = decide(s.v, s.n, &r);
    free(s.v);
  } else {
    size_t i, max, at = (size_t)-1;
    yyjson_val *p, *found = NULL;
    yyjson_arr_foreach(principals(&m), i, max, p) {
      const char *k = yyjson_get_str(yyjson_obj_get(p, "kind")),
                 *n = yyjson_get_str(yyjson_obj_get(p, "name"));
      if (kind && name && k && n && strcmp(k, kind) == 0 && strcmp(n, name) == 0) found = p, at = i;
    }
    const char *status = found ? yyjson_get_str(yyjson_obj_get(found, "status")) : NULL;
    if (status && strcmp(status, "disabled") == 0)
      disabled = true;
    else if (found)
      o = principal_decides(&m, found, at, &r, true);
    else
      known = false;
  }
  if (!known) {
    model_free(&m);
    return NULL;
  }
  yyjson_mut_val *out = yyjson_mut_obj(d);
  yyjson_mut_obj_add_str(d, out, "decision", o.d == D_NONE ? "denied" : decision_name(o.d));
  const char *reason =
      o.d == D_ALLOWED  ? (o.nby ? "The statements below allow it." : "The root user may do everything.")
      : o.d == D_DENIED ? "The statements below refuse it, and a Deny wins over any Allow."
      : o.d == D_CONDITIONAL
          ? "The statements below decide it once their condition values are known."
      : disabled ? "The account is disabled."
                 : "No statement allows it.";
  yyjson_mut_obj_add_str(d, out, "reason", reason);
  add_by(d, yyjson_mut_obj_add_arr(d, out, "by"), &o);
  outcome_free(&o);
  model_free(&m);
  return out;
}
