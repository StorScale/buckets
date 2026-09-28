/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/iam.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
#include "core/strmap.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/jwt.h"
#include "crypto/madmin.h"
#include "object/sysconfig.h"

#define IAM_PREFIX "config/iam/"
#define GO_ZERO_SEC (-62135596800LL) /* time.Time{} */
#define MAX_SVC_SESSION_POLICY 4096  /* maxSVCSessionPolicySize */
#define MIN_SVC_EXPIRY_SEC (15 * 60)
#define MAX_SVC_EXPIRY_SEC (365 * 24 * 3600)

static const char *const k_user_dirs[] = {"users/", "service-accounts/", "sts/"};
static const char *const k_policydb_dirs[] = {"policydb/users/", "policydb/service-accounts/", "policydb/sts-users/"};

/* ---- small helpers ---------------------------------------------------------------- */

static buckets_iam_time now_time(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (buckets_iam_time){ts.tv_sec, ts.tv_nsec};
}

/* UTCNow().Round(time.Millisecond), as policy docs record. */
static buckets_iam_time now_ms(void) {
  buckets_iam_time t = now_time();
  long ms = (t.nsec + 500000) / 1000000;
  if (ms >= 1000) {
    t.sec++;
    ms -= 1000;
  }
  t.nsec = ms * 1000000;
  return t;
}

bool buckets_iam_time_is_set(buckets_iam_time t) {
  return !((t.sec == GO_ZERO_SEC || t.sec == 0) && t.nsec == 0);
}

static bool time_before(buckets_iam_time a, buckets_iam_time b) {
  return a.sec < b.sec || (a.sec == b.sec && a.nsec < b.nsec);
}

static void time_fmt(buckets_iam_time t, char out[BUCKETS_TIME_RFC3339_NANO_LEN + 1]) {
  buckets_time_rfc3339_nano(t.sec, t.nsec, out);
}

static buckets_iam_time time_parse(yyjson_val *v) {
  buckets_iam_time t = {GO_ZERO_SEC, 0};
  const char *s = yyjson_get_str(v);
  if (s) buckets_time_parse_rfc3339(s, &t.sec, &t.nsec);
  return t;
}

static char *dupnz(const char *s) { return s && *s ? buckets_xstrdup(s) : NULL; }
static const char *nz(const char *s) { return s ? s : ""; }

static void strv_free(char **v, size_t n) {
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
}

static char **strv_dup(const char *const *v, size_t n) {
  if (!n) return NULL;
  char **o = buckets_xcalloc(n, sizeof(char *));
  for (size_t i = 0; i < n; i++) o[i] = buckets_xstrdup(v[i]);
  return o;
}

static bool strv_has(char *const *v, size_t n, const char *s) {
  for (size_t i = 0; i < n; i++) {
    if (strcmp(v[i], s) == 0) return true;
  }
  return false;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* A de-duplicated, sorted list of names. */
typedef struct {
  char **v;
  size_t n, cap;
} strset;

static void set_add(strset *s, const char *x) {
  if (!x || !*x || strv_has(s->v, s->n, x)) return;
  if (s->n == s->cap) {
    s->cap = s->cap ? s->cap * 2 : 8;
    s->v = buckets_xrealloc(s->v, s->cap * sizeof(char *));
  }
  s->v[s->n++] = buckets_xstrdup(x);
}

/* Adds each comma-separated name (MappedPolicy.toSlice). */
static void set_add_csv(strset *s, const char *csv) {
  if (!csv) return;
  const char *p = csv;
  while (*p) {
    const char *e = strchr(p, ',');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    char *one = buckets_xstrndup(p, n);
    char *a = one, *z = one + strlen(one);
    while (*a == ' ' || *a == '\t') a++;
    while (z > a && (z[-1] == ' ' || z[-1] == '\t')) *--z = '\0';
    set_add(s, a);
    free(one);
    p = e ? e + 1 : p + n;
  }
}

static void set_free(strset *s) {
  strv_free(s->v, s->n);
  memset(s, 0, sizeof(*s));
}

static char *set_join(strset *s) {
  if (s->n) qsort(s->v, s->n, sizeof(char *), cmp_str);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "");
  for (size_t i = 0; i < s->n; i++) {
    if (i) buckets_buf_append_c(&b, ",");
    buckets_buf_append_c(&b, s->v[i]);
  }
  return buckets_buf_detach(&b);
}

/* ---- identities ------------------------------------------------------------------- */

static buckets_iam_ident *ident_new(void) {
  buckets_iam_ident *id = buckets_xcalloc(1, sizeof(*id));
  atomic_init(&id->refs, 1);
  id->expiration = (buckets_iam_time){GO_ZERO_SEC, 0};
  id->updated = (buckets_iam_time){GO_ZERO_SEC, 0};
  return id;
}

static buckets_iam_ident *ident_ref(buckets_iam_ident *id) {
  if (id) atomic_fetch_add(&id->refs, 1);
  return id;
}

void buckets_iam_ident_release(buckets_iam_ident *id) {
  if (!id || atomic_fetch_sub(&id->refs, 1) != 1) return;
  free(id->access_key);
  free(id->secret_key);
  free(id->session_token);
  free(id->parent);
  free(id->name);
  free(id->description);
  strv_free(id->groups, id->ngroups);
  free(id->claims_field);
  yyjson_doc_free(id->claims);
  free(id->session_policy_json);
  buckets_policy_free(id->session_policy);
  free(id);
}

bool buckets_iam_ident_is_expired(const buckets_iam_ident *id) {
  if (!buckets_iam_time_is_set(id->expiration)) return false;
  return time_before(id->expiration, now_time());
}

bool buckets_iam_ident_is_temp(const buckets_iam_ident *id) {
  return id->session_token && *id->session_token && buckets_iam_time_is_set(id->expiration);
}

const char *buckets_iam_ident_claim(const buckets_iam_ident *id, const char *key) {
  if (!id->claims) return NULL;
  return yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(id->claims), key));
}

bool buckets_iam_ident_is_svc(const buckets_iam_ident *id) {
  return id->parent && *id->parent && id->claims &&
         yyjson_obj_get(yyjson_doc_get_root(id->claims), "sa-policy") != NULL;
}

bool buckets_iam_ident_is_valid(const buckets_iam_ident *id) {
  if (strcmp(id->status, "off") == 0) return false;
  return id->access_key && strlen(id->access_key) >= 3 && id->secret_key && strlen(id->secret_key) >= 8 &&
         !buckets_iam_ident_is_expired(id);
}

const char *buckets_iam_condition_user(const buckets_iam_ident *id) {
  if (!id) return "";
  if (buckets_iam_ident_is_temp(id) || buckets_iam_ident_is_svc(id)) return nz(id->parent);
  return nz(id->access_key);
}

/* getClaimsFromTokenWithSecret: verify with secret, else the root secret;
 * then decode the base64 sessionPolicy claim. */
static bool ident_load_claims(buckets_iam_ident *id, const char *secret, const char *root_secret) {
  long long now = (long long)time(NULL);
  yyjson_doc *c = buckets_jwt_verify(id->session_token, secret, now);
  if (!c && strcmp(secret, root_secret) != 0) c = buckets_jwt_verify(id->session_token, root_secret, now);
  if (!c) return false;
  const char *sp = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(c), "sessionPolicy"));
  if (sp) {
    size_t n = strlen(sp);
    uint8_t *dec = buckets_xmalloc(n * 3 / 4 + 4);
    long k = buckets_base64_decode(sp, n, dec);
    if (k < 0) {
      free(dec);
      yyjson_doc_free(c);
      return false;
    }
    dec[k] = '\0';
    id->has_session_policy = true;
    id->session_policy_json = (char *)dec;
    char err[256];
    if (!buckets_policy_parse(id->session_policy_json, (size_t)k, &id->session_policy, err, sizeof(err))) {
      id->session_policy = NULL;
    }
  }
  id->claims = c;
  return true;
}

static void set_status(buckets_iam_ident *id, const char *status) {
  snprintf(id->status, sizeof(id->status), "%s", status && strlen(status) < 4 ? status : "");
}

/* Parses identity.json. Returns NULL when malformed. */
static buckets_iam_ident *ident_parse(const char *json, size_t n, const char *key, buckets_iam_utype type) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) return NULL;
  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *cr = yyjson_obj_get(root, "credentials");
  if (!yyjson_is_obj(cr)) {
    yyjson_doc_free(doc);
    return NULL;
  }
  buckets_iam_ident *id = ident_new();
  id->type = type;
  const char *ak = yyjson_get_str(yyjson_obj_get(cr, "accessKey"));
  id->access_key = buckets_xstrdup(ak && *ak ? ak : key);
  id->secret_key = buckets_xstrdup(nz(yyjson_get_str(yyjson_obj_get(cr, "secretKey"))));
  id->session_token = dupnz(yyjson_get_str(yyjson_obj_get(cr, "sessionToken")));
  id->parent = dupnz(yyjson_get_str(yyjson_obj_get(cr, "parentUser")));
  id->name = dupnz(yyjson_get_str(yyjson_obj_get(cr, "name")));
  id->description = dupnz(yyjson_get_str(yyjson_obj_get(cr, "description")));
  if (!id->description) id->description = dupnz(yyjson_get_str(yyjson_obj_get(cr, "comment")));
  set_status(id, yyjson_get_str(yyjson_obj_get(cr, "status")));
  id->expiration = time_parse(yyjson_obj_get(cr, "expiration"));
  id->updated = time_parse(yyjson_obj_get(root, "updatedAt"));
  yyjson_val *groups = yyjson_obj_get(cr, "groups");
  if (yyjson_is_arr(groups) && yyjson_arr_size(groups)) {
    id->groups = buckets_xcalloc(yyjson_arr_size(groups), sizeof(char *));
    size_t i, max;
    yyjson_val *g;
    yyjson_arr_foreach(groups, i, max, g) {
      if (yyjson_is_str(g)) id->groups[id->ngroups++] = buckets_xstrdup(yyjson_get_str(g));
    }
  }
  yyjson_val *claims = yyjson_obj_get(cr, "claims");
  if (claims && !yyjson_is_null(claims)) id->claims_field = yyjson_val_write(claims, 0, NULL);
  yyjson_doc_free(doc);
  return id;
}

static void ident_to_json(const buckets_iam_ident *id, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_int(d, root, "version", 1);
  yyjson_mut_val *cr = yyjson_mut_obj_add_obj(d, root, "credentials");
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1], us[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  if (id->access_key) yyjson_mut_obj_add_str(d, cr, "accessKey", id->access_key);
  if (id->secret_key && *id->secret_key) yyjson_mut_obj_add_str(d, cr, "secretKey", id->secret_key);
  if (id->session_token) yyjson_mut_obj_add_str(d, cr, "sessionToken", id->session_token);
  time_fmt(id->expiration, ts);
  yyjson_mut_obj_add_str(d, cr, "expiration", ts);
  if (*id->status) yyjson_mut_obj_add_str(d, cr, "status", id->status);
  if (id->parent) yyjson_mut_obj_add_str(d, cr, "parentUser", id->parent);
  if (id->ngroups) {
    yyjson_mut_val *g = yyjson_mut_obj_add_arr(d, cr, "groups");
    for (size_t i = 0; i < id->ngroups; i++) yyjson_mut_arr_add_str(d, g, id->groups[i]);
  }
  yyjson_doc *cf = id->claims_field ? yyjson_read(id->claims_field, strlen(id->claims_field), 0) : NULL;
  if (cf) yyjson_mut_obj_add_val(d, cr, "claims", yyjson_val_mut_copy(d, yyjson_doc_get_root(cf)));
  if (id->name) yyjson_mut_obj_add_str(d, cr, "name", id->name);
  if (id->description) yyjson_mut_obj_add_str(d, cr, "description", id->description);
  time_fmt(id->updated, us);
  yyjson_mut_obj_add_str(d, root, "updatedAt", us);
  size_t len;
  char *s = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(out);
  buckets_buf_append(out, s, len);
  free(s);
  yyjson_doc_free(cf);
  yyjson_mut_doc_free(d);
}

/* ---- the cache -------------------------------------------------------------------- */

typedef struct {
  buckets_policy *p;
  char *json;
  buckets_iam_time created, updated;
} policy_doc;

typedef struct {
  bool enabled;
  char **members;
  size_t n;
  buckets_iam_time updated;
} group_info;

typedef struct {
  char *policies;
  buckets_iam_time updated;
} mapped_policy;

typedef struct {
  buckets_strmap policies;  /* name -> policy_doc */
  buckets_strmap users;     /* access key -> ident (regular and service accounts) */
  buckets_strmap sts;       /* access key -> ident */
  buckets_strmap groups;    /* name -> group_info */
  buckets_strmap pol[3];    /* policydb: indexed by buckets_iam_utype (REG, SVC, STS) */
  buckets_strmap group_pol; /* group -> mapped_policy */
} cache;

static void policy_doc_free(policy_doc *d) {
  if (!d) return;
  buckets_policy_free(d->p);
  free(d->json);
  free(d);
}

static void group_info_free(group_info *g) {
  if (!g) return;
  strv_free(g->members, g->n);
  free(g);
}

static void mapped_free(mapped_policy *m) {
  if (!m) return;
  free(m->policies);
  free(m);
}

static void cache_free(cache *c) {
  size_t it;
  void *v;
  for (it = 0; buckets_strmap_next(&c->policies, &it, NULL, &v);) policy_doc_free(v);
  for (it = 0; buckets_strmap_next(&c->users, &it, NULL, &v);) buckets_iam_ident_release(v);
  for (it = 0; buckets_strmap_next(&c->sts, &it, NULL, &v);) buckets_iam_ident_release(v);
  for (it = 0; buckets_strmap_next(&c->groups, &it, NULL, &v);) group_info_free(v);
  for (int k = 0; k < 3; k++) {
    for (it = 0; buckets_strmap_next(&c->pol[k], &it, NULL, &v);) mapped_free(v);
    buckets_strmap_free(&c->pol[k]);
  }
  for (it = 0; buckets_strmap_next(&c->group_pol, &it, NULL, &v);) mapped_free(v);
  buckets_strmap_free(&c->policies);
  buckets_strmap_free(&c->users);
  buckets_strmap_free(&c->sts);
  buckets_strmap_free(&c->groups);
  buckets_strmap_free(&c->group_pol);
}

struct buckets_iam {
  buckets_iam_ident *root;
  char *root_password; /* "ak:sk", the madmin password for legacy encrypted IAM files */
  buckets_objlayer *layer;
  _Atomic bool ready;
  pthread_rwlock_t lock; /* guards the cache */
  pthread_mutex_t write_mu; /* serializes changes (storage, then cache) */
  cache c;
  buckets_iam_time changed; /* last in-memory change (reloads older than this are discarded) */
  buckets_iam_notify_fn notify;
  void *notify_ud;
  int refresh_sec;
  pthread_t refresher;
  bool refresher_started;
};

const char *buckets_iam_root_access_key(const buckets_iam *iam) { return iam->root->access_key; }
const char *buckets_iam_root_secret_key(const buckets_iam *iam) { return iam->root->secret_key; }

buckets_iam *buckets_iam_new(const char *root_access_key, const char *root_secret_key) {
  buckets_iam *iam = buckets_xcalloc(1, sizeof(*iam));
  iam->root = ident_new();
  iam->root->type = BUCKETS_IAM_ROOT;
  iam->root->access_key = buckets_xstrdup(root_access_key);
  iam->root->secret_key = buckets_xstrdup(root_secret_key);
  set_status(iam->root, "on");
  size_t n = strlen(root_access_key) + strlen(root_secret_key) + 2;
  iam->root_password = buckets_xmalloc(n);
  snprintf(iam->root_password, n, "%s:%s", root_access_key, root_secret_key);
  pthread_rwlock_init(&iam->lock, NULL);
  pthread_mutex_init(&iam->write_mu, NULL);
  return iam;
}

void buckets_iam_free(buckets_iam *iam) {
  if (!iam) return;
  cache_free(&iam->c);
  buckets_iam_ident_release(iam->root);
  free(iam->root_password);
  pthread_rwlock_destroy(&iam->lock);
  pthread_mutex_destroy(&iam->write_mu);
  free(iam);
}

bool buckets_iam_ready(const buckets_iam *iam) { return atomic_load(&iam->ready); }

void buckets_iam_set_notify(buckets_iam *iam, buckets_iam_notify_fn fn, void *ud) {
  iam->notify = fn;
  iam->notify_ud = ud;
}

static void notify(buckets_iam *iam, const char *kind, const char *name) {
  if (iam->notify) iam->notify(iam->notify_ud, kind, name);
}

/* ---- storage ---------------------------------------------------------------------- */

static char *path_of(const char *dir, const char *name, const char *file) {
  size_t n = strlen(IAM_PREFIX) + strlen(dir) + strlen(name) + strlen(file) + 2;
  char *p = buckets_xmalloc(n);
  snprintf(p, n, "%s%s%s%s", IAM_PREFIX, dir, name, file);
  return p;
}

static char *identity_path(const char *ak, buckets_iam_utype t) { return path_of(k_user_dirs[t], ak, "/identity.json"); }
static char *mapped_path(const char *name, buckets_iam_utype t, bool group) {
  return path_of(group ? "policydb/groups/" : k_policydb_dirs[t], name, ".json");
}

static bool utf8_valid(const uint8_t *s, size_t n) {
  for (size_t i = 0; i < n;) {
    uint8_t c = s[i];
    size_t k = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (!k || i + k > n) return false;
    for (size_t j = 1; j < k; j++) {
      if ((s[i + j] & 0xC0) != 0x80) return false;
    }
    i += k;
  }
  return true;
}

/* loadIAMConfig: read, then decryptData (plaintext JSON, or madmin-encrypted
 * with the root credential by older releases). */
static buckets_obj_err iam_read(buckets_iam *iam, const char *path, buckets_buf *out, int64_t *mtime) {
  buckets_obj_err err = buckets_sysconfig_read(iam->layer, path, out, mtime);
  if (err) return err;
  if (utf8_valid((const uint8_t *)out->data, out->len)) return BUCKETS_OBJ_OK;
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (!buckets_madmin_decrypt(iam->root_password, out->data, out->len, &plain)) {
    buckets_buf_free(&plain);
    buckets_log_warn("iam: %s is encrypted with a key this server does not have", path);
    return BUCKETS_OBJ_ERR_CORRUPT;
  }
  buckets_buf_free(out);
  *out = plain;
  return BUCKETS_OBJ_OK;
}

static bool iam_write(buckets_iam *iam, const char *path, const buckets_buf *data) {
  buckets_obj_err err = buckets_sysconfig_write(iam->layer, path, data->data, data->len);
  if (err) buckets_log_warn("iam: saving %s: %s", path, buckets_obj_strerror(err));
  return err == BUCKETS_OBJ_OK;
}

static bool iam_delete(buckets_iam *iam, const char *path) {
  buckets_obj_err err = buckets_sysconfig_delete(iam->layer, path);
  return err == BUCKETS_OBJ_OK || err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
}

/* ---- loading ---------------------------------------------------------------------- */

/* loadUserIdentity: NULL when absent, unreadable, expired (then deleted) or
 * with a session token that does not verify. */
static buckets_iam_ident *load_identity(buckets_iam *iam, const char *ak, buckets_iam_utype t, bool *io_error) {
  char *path = identity_path(ak, t);
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_obj_err err = iam_read(iam, path, &data, NULL);
  buckets_iam_ident *id = NULL;
  if (err) {
    if (io_error && err != BUCKETS_OBJ_ERR_NO_SUCH_KEY) *io_error = true;
    goto out;
  }
  id = ident_parse(data.data, data.len, ak, t);
  if (!id) {
    buckets_log_warn("iam: malformed %s", path);
    goto out;
  }
  if (buckets_iam_ident_is_expired(id)) {
    char *mp = mapped_path(ak, t, false);
    iam_delete(iam, path);
    iam_delete(iam, mp);
    free(mp);
    buckets_iam_ident_release(id);
    id = NULL;
    goto out;
  }
  if (id->session_token && !ident_load_claims(id, id->secret_key, iam->root->secret_key)) {
    if (buckets_iam_ident_is_temp(id)) {
      char *mp = mapped_path(ak, t, false);
      iam_delete(iam, path);
      iam_delete(iam, mp);
      free(mp);
    }
    buckets_iam_ident_release(id);
    id = NULL;
  }
out:
  buckets_buf_free(&data);
  free(path);
  return id;
}

static policy_doc *parse_policy_doc(const char *json, size_t n, int64_t mtime_ns, char *err, size_t errlen) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) {
    snprintf(err, errlen, "malformed JSON");
    return NULL;
  }
  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *pol = root;
  policy_doc *d = buckets_xcalloc(1, sizeof(*d));
  /* PolicyDoc{Version int, Policy, CreateDate, UpdateDate}, or the bare
   * policy of releases before 12/2021 (its string Version fails to decode
   * as an int, which is how MinIO tells them apart). */
  yyjson_val *ver = yyjson_obj_get(root, "Version");
  bool wrapped = yyjson_is_obj(root) && !yyjson_is_str(ver) && yyjson_obj_get(root, "Policy");
  if (wrapped) {
    pol = yyjson_obj_get(root, "Policy");
    d->created = time_parse(yyjson_obj_get(root, "CreateDate"));
    d->updated = time_parse(yyjson_obj_get(root, "UpdateDate"));
  }
  if (!wrapped || yyjson_get_int(ver) == 0) {
    d->created = d->updated = (buckets_iam_time){mtime_ns / 1000000000LL, (long)(mtime_ns % 1000000000LL)};
  }
  d->json = yyjson_val_write(pol, 0, NULL);
  bool ok = d->json && buckets_policy_parse(d->json, strlen(d->json), &d->p, err, errlen);
  yyjson_doc_free(doc);
  if (!ok) {
    policy_doc_free(d);
    return NULL;
  }
  return d;
}

static policy_doc *load_policy(buckets_iam *iam, const char *name) {
  char *path = path_of("policies/", name, "/policy.json");
  buckets_buf data = BUCKETS_BUF_INIT;
  int64_t mtime = 0;
  policy_doc *d = NULL;
  if (iam_read(iam, path, &data, &mtime) == BUCKETS_OBJ_OK) {
    char err[256];
    d = parse_policy_doc(data.data, data.len, mtime, err, sizeof(err));
    if (!d) buckets_log_warn("iam: policy %s: %s", name, err);
  }
  buckets_buf_free(&data);
  free(path);
  return d;
}

static group_info *load_group(buckets_iam *iam, const char *name) {
  char *path = path_of("groups/", name, "/members.json");
  buckets_buf data = BUCKETS_BUF_INIT;
  group_info *g = NULL;
  if (iam_read(iam, path, &data, NULL) == BUCKETS_OBJ_OK) {
    yyjson_doc *doc = yyjson_read(data.data, data.len, 0);
    if (doc) {
      yyjson_val *root = yyjson_doc_get_root(doc);
      g = buckets_xcalloc(1, sizeof(*g));
      const char *st = yyjson_get_str(yyjson_obj_get(root, "status"));
      g->enabled = !st || strcmp(st, "disabled") != 0;
      g->updated = time_parse(yyjson_obj_get(root, "updatedAt"));
      yyjson_val *m = yyjson_obj_get(root, "members");
      if (yyjson_is_arr(m) && yyjson_arr_size(m)) {
        g->members = buckets_xcalloc(yyjson_arr_size(m), sizeof(char *));
        size_t i, max;
        yyjson_val *v;
        yyjson_arr_foreach(m, i, max, v) {
          if (yyjson_is_str(v)) g->members[g->n++] = buckets_xstrdup(yyjson_get_str(v));
        }
      }
      yyjson_doc_free(doc);
    }
  }
  buckets_buf_free(&data);
  free(path);
  return g;
}

static mapped_policy *load_mapped(buckets_iam *iam, const char *name, buckets_iam_utype t, bool group) {
  char *path = mapped_path(name, t, group);
  buckets_buf data = BUCKETS_BUF_INIT;
  mapped_policy *m = NULL;
  if (iam_read(iam, path, &data, NULL) == BUCKETS_OBJ_OK) {
    yyjson_doc *doc = yyjson_read(data.data, data.len, 0);
    if (doc) {
      yyjson_val *root = yyjson_doc_get_root(doc);
      m = buckets_xcalloc(1, sizeof(*m));
      m->policies = buckets_xstrdup(nz(yyjson_get_str(yyjson_obj_get(root, "policy"))));
      m->updated = time_parse(yyjson_obj_get(root, "updatedAt"));
      yyjson_doc_free(doc);
    }
  }
  buckets_buf_free(&data);
  free(path);
  return m;
}

static void add_canned(cache *c) {
  static const char *const names[] = {"readwrite", "readonly", "writeonly", "diagnostics", "consoleAdmin"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(names); i++) {
    if (buckets_strmap_get(&c->policies, names[i])) continue;
    const char *json = buckets_policy_canned(names[i]);
    policy_doc *d = buckets_xcalloc(1, sizeof(*d));
    d->json = buckets_xstrdup(json);
    char err[128];
    if (!buckets_policy_parse(json, strlen(json), &d->p, err, sizeof(err))) abort();
    d->created = d->updated = (buckets_iam_time){GO_ZERO_SEC, 0};
    buckets_strmap_put(&c->policies, names[i], d);
  }
}

/* loadAllFromObjStore into a fresh cache. */
static bool load_all(buckets_iam *iam, cache *c) {
  char **names;
  size_t n;
  bool ok = true;
  if (buckets_sysconfig_list(iam->layer, IAM_PREFIX "policies/", true, &names, &n)) return false;
  for (size_t i = 0; i < n; i++) {
    policy_doc *d = load_policy(iam, names[i]);
    if (d) policy_doc_free(buckets_strmap_put(&c->policies, names[i], d));
  }
  buckets_sysconfig_names_free(names, n);
  add_canned(c);

  for (int t = BUCKETS_IAM_REG; t <= BUCKETS_IAM_STS; t++) {
    char prefix[64];
    snprintf(prefix, sizeof(prefix), IAM_PREFIX "%s", k_user_dirs[t]);
    if (buckets_sysconfig_list(iam->layer, prefix, true, &names, &n)) return false;
    for (size_t i = 0; i < n; i++) {
      bool io = false;
      buckets_iam_ident *id = load_identity(iam, names[i], (buckets_iam_utype)t, &io);
      if (io) ok = false;
      if (!id) continue;
      buckets_strmap *m = t == BUCKETS_IAM_STS ? &c->sts : &c->users;
      buckets_iam_ident_release(buckets_strmap_put(m, names[i], id));
    }
    buckets_sysconfig_names_free(names, n);
  }

  if (buckets_sysconfig_list(iam->layer, IAM_PREFIX "groups/", true, &names, &n)) return false;
  for (size_t i = 0; i < n; i++) {
    group_info *g = load_group(iam, names[i]);
    if (g) group_info_free(buckets_strmap_put(&c->groups, names[i], g));
  }
  buckets_sysconfig_names_free(names, n);

  for (int k = 0; k < 4; k++) {
    bool group = k == 3;
    const char *dir = group ? "policydb/groups/" : k_policydb_dirs[k];
    char prefix[64];
    snprintf(prefix, sizeof(prefix), IAM_PREFIX "%s", dir);
    if (buckets_sysconfig_list(iam->layer, prefix, false, &names, &n)) return false;
    for (size_t i = 0; i < n; i++) {
      size_t len = strlen(names[i]);
      if (len <= 5 || strcmp(names[i] + len - 5, ".json") != 0) continue;
      names[i][len - 5] = '\0';
      mapped_policy *m = load_mapped(iam, names[i], group ? BUCKETS_IAM_REG : (buckets_iam_utype)k, group);
      if (!m) continue;
      buckets_strmap *dst = group ? &c->group_pol : &c->pol[k];
      mapped_free(buckets_strmap_put(dst, names[i], m));
    }
    buckets_sysconfig_names_free(names, n);
  }
  return ok;
}

static bool reload(buckets_iam *iam, bool first) {
  cache fresh = {0};
  pthread_rwlock_rdlock(&iam->lock);
  buckets_iam_time started = now_time();
  pthread_rwlock_unlock(&iam->lock);
  if (!load_all(iam, &fresh) && first) {
    cache_free(&fresh);
    return false;
  }
  pthread_rwlock_wrlock(&iam->lock);
  /* Only replace the cache if nothing changed in memory since loading began. */
  bool apply = first || time_before(iam->changed, started);
  if (apply) {
    cache old = iam->c;
    iam->c = fresh;
    fresh = old;
  }
  pthread_rwlock_unlock(&iam->lock);
  cache_free(&fresh);
  return true;
}

bool buckets_iam_start(buckets_iam *iam, buckets_objlayer *layer) {
  iam->layer = layer;
  /* saveIAMFormat */
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_obj_err err = iam_read(iam, IAM_PREFIX "format.json", &data, NULL);
  int version = 0;
  if (!err) {
    yyjson_doc *doc = yyjson_read(data.data, data.len, 0);
    version = doc ? (int)yyjson_get_int(yyjson_obj_get(yyjson_doc_get_root(doc), "version")) : 0;
    yyjson_doc_free(doc);
  } else if (err != BUCKETS_OBJ_ERR_NO_SUCH_KEY) {
    buckets_buf_free(&data);
    return false;
  }
  if (version < 1) {
    buckets_buf_reset(&data);
    buckets_buf_append_c(&data, "{\"version\":1}");
    if (!iam_write(iam, IAM_PREFIX "format.json", &data)) {
      buckets_buf_free(&data);
      return false;
    }
  }
  buckets_buf_free(&data);
  if (!reload(iam, true)) return false;
  atomic_store(&iam->ready, true);
  pthread_rwlock_rdlock(&iam->lock);
  buckets_log_info("iam: %zu users, %zu service accounts/users, %zu STS, %zu groups, %zu policies",
                   iam->c.pol[BUCKETS_IAM_REG].n, iam->c.users.n, iam->c.sts.n, iam->c.groups.n,
                   iam->c.policies.n);
  pthread_rwlock_unlock(&iam->lock);
  return true;
}

bool buckets_iam_reload(buckets_iam *iam) { return iam->layer && reload(iam, false); }

static void *refresh_main(void *arg) {
  buckets_iam *iam = arg;
  for (;;) {
    sleep((unsigned)iam->refresh_sec);
    if (!buckets_iam_reload(iam)) buckets_log_warn("iam: periodic reload failed");
  }
  return NULL;
}

void buckets_iam_start_refresh(buckets_iam *iam, int interval_sec) {
  if (iam->refresher_started || interval_sec <= 0) return;
  iam->refresh_sec = interval_sec;
  if (pthread_create(&iam->refresher, NULL, refresh_main, iam) == 0) {
    pthread_detach(iam->refresher);
    iam->refresher_started = true;
  }
}

/* Marks an in-memory change; call with the write lock held. */
static void touch(buckets_iam *iam) { iam->changed = now_time(); }

void buckets_iam_on_notify(buckets_iam *iam, const char *kind, const char *name) {
  if (!iam->layer || !name || !*name) return;
  pthread_mutex_lock(&iam->write_mu);
  if (strcmp(kind, "user") == 0 || strcmp(kind, "svc") == 0 || strcmp(kind, "sts") == 0) {
    buckets_iam_utype t = kind[0] == 'u' ? BUCKETS_IAM_REG : kind[1] == 'v' ? BUCKETS_IAM_SVC : BUCKETS_IAM_STS;
    buckets_iam_ident *id = load_identity(iam, name, t, NULL);
    pthread_rwlock_wrlock(&iam->lock);
    buckets_strmap *m = t == BUCKETS_IAM_STS ? &iam->c.sts : &iam->c.users;
    buckets_iam_ident_release(id ? buckets_strmap_put(m, name, id) : buckets_strmap_del(m, name));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
  } else if (strcmp(kind, "group") == 0) {
    group_info *g = load_group(iam, name);
    pthread_rwlock_wrlock(&iam->lock);
    group_info_free(g ? buckets_strmap_put(&iam->c.groups, name, g) : buckets_strmap_del(&iam->c.groups, name));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
  } else if (strcmp(kind, "policy") == 0) {
    policy_doc *d = load_policy(iam, name);
    pthread_rwlock_wrlock(&iam->lock);
    policy_doc_free(d ? buckets_strmap_put(&iam->c.policies, name, d) : buckets_strmap_del(&iam->c.policies, name));
    add_canned(&iam->c);
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
  } else if (strncmp(kind, "policydb-", 9) == 0) {
    const char *w = kind + 9;
    bool group = strcmp(w, "group") == 0;
    buckets_iam_utype t = strcmp(w, "sts") == 0 ? BUCKETS_IAM_STS : strcmp(w, "svc") == 0 ? BUCKETS_IAM_SVC : BUCKETS_IAM_REG;
    mapped_policy *m = load_mapped(iam, name, t, group);
    pthread_rwlock_wrlock(&iam->lock);
    buckets_strmap *dst = group ? &iam->c.group_pol : &iam->c.pol[t];
    mapped_free(m ? buckets_strmap_put(dst, name, m) : buckets_strmap_del(dst, name));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
  }
  pthread_mutex_unlock(&iam->write_mu);
}

/* ---- saving ------------------------------------------------------------------------ */

static bool save_identity(buckets_iam *iam, const buckets_iam_ident *id, buckets_iam_utype t) {
  buckets_buf data = BUCKETS_BUF_INIT;
  ident_to_json(id, &data);
  char *path = identity_path(id->access_key, t);
  bool ok = iam_write(iam, path, &data);
  free(path);
  buckets_buf_free(&data);
  return ok;
}

static bool save_mapped(buckets_iam *iam, const char *name, buckets_iam_utype t, bool group, const mapped_policy *m) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  time_fmt(m->updated, ts);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_int(d, root, "version", 1);
  yyjson_mut_obj_add_str(d, root, "policy", m->policies);
  yyjson_mut_obj_add_str(d, root, "updatedAt", ts);
  size_t len;
  char *s = yyjson_mut_write(d, 0, &len);
  buckets_buf data = {.data = s, .len = len, .cap = len};
  char *path = mapped_path(name, t, group);
  bool ok = iam_write(iam, path, &data);
  free(path);
  free(s);
  yyjson_mut_doc_free(d);
  return ok;
}

static bool save_group(buckets_iam *iam, const char *name, const group_info *g) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  time_fmt(g->updated, ts);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_int(d, root, "version", 1);
  yyjson_mut_obj_add_str(d, root, "status", g->enabled ? "enabled" : "disabled");
  yyjson_mut_val *m = yyjson_mut_obj_add_arr(d, root, "members");
  for (size_t i = 0; i < g->n; i++) yyjson_mut_arr_add_str(d, m, g->members[i]);
  yyjson_mut_obj_add_str(d, root, "updatedAt", ts);
  size_t len;
  char *s = yyjson_mut_write(d, 0, &len);
  buckets_buf data = {.data = s, .len = len, .cap = len};
  char *path = path_of("groups/", name, "/members.json");
  bool ok = iam_write(iam, path, &data);
  free(path);
  free(s);
  yyjson_mut_doc_free(d);
  return ok;
}

static bool save_policy(buckets_iam *iam, const char *name, const policy_doc *pd) {
  char cs[BUCKETS_TIME_RFC3339_NANO_LEN + 1], us[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  time_fmt(pd->created, cs);
  time_fmt(pd->updated, us);
  yyjson_doc *pj = yyjson_read(pd->json, strlen(pd->json), 0);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_int(d, root, "Version", 1);
  yyjson_mut_obj_add_val(d, root, "Policy", yyjson_val_mut_copy(d, yyjson_doc_get_root(pj)));
  yyjson_mut_obj_add_str(d, root, "CreateDate", cs);
  yyjson_mut_obj_add_str(d, root, "UpdateDate", us);
  size_t len;
  char *s = yyjson_mut_write(d, 0, &len);
  buckets_buf data = {.data = s, .len = len, .cap = len};
  char *path = path_of("policies/", name, "/policy.json");
  bool ok = iam_write(iam, path, &data);
  free(path);
  free(s);
  yyjson_mut_doc_free(d);
  yyjson_doc_free(pj);
  return ok;
}

/* ---- lookups ------------------------------------------------------------------------- */

static buckets_iam_ident *cache_user(const cache *c, const char *ak) {
  buckets_iam_ident *id = buckets_strmap_get(&c->users, ak);
  return id ? id : buckets_strmap_get(&c->sts, ak);
}

buckets_iam_ident *buckets_iam_get_ident(buckets_iam *iam, const char *access_key) {
  pthread_rwlock_rdlock(&iam->lock);
  buckets_iam_ident *id = ident_ref(cache_user(&iam->c, access_key));
  pthread_rwlock_unlock(&iam->lock);
  return id;
}

/* LoadUser on a cache miss: another server may have just created it. */
static buckets_iam_ident *load_user_any(buckets_iam *iam, const char *ak) {
  for (int t = BUCKETS_IAM_REG; t <= BUCKETS_IAM_STS; t++) {
    buckets_iam_ident *id = load_identity(iam, ak, (buckets_iam_utype)t, NULL);
    if (!id) continue;
    pthread_rwlock_wrlock(&iam->lock);
    buckets_strmap *m = t == BUCKETS_IAM_STS ? &iam->c.sts : &iam->c.users;
    if (!buckets_strmap_get(m, ak)) {
      buckets_strmap_put(m, ak, ident_ref(id));
      /* The mapping for a new STS credential's parent may be new too. */
      if (t == BUCKETS_IAM_STS && id->parent) {
        mapped_policy *mp = load_mapped(iam, id->parent, BUCKETS_IAM_STS, false);
        if (mp) mapped_free(buckets_strmap_put(&iam->c.pol[BUCKETS_IAM_STS], id->parent, mp));
      }
    }
    pthread_rwlock_unlock(&iam->lock);
    return id;
  }
  return NULL;
}

buckets_iam_key_status buckets_iam_get_key(buckets_iam *iam, const char *access_key, buckets_iam_ident **out) {
  *out = NULL;
  if (strcmp(access_key, iam->root->access_key) == 0) {
    *out = ident_ref(iam->root);
    return BUCKETS_IAM_KEY_OK;
  }
  if (!buckets_iam_ready(iam)) return BUCKETS_IAM_KEY_NOT_READY;
  buckets_iam_ident *id = buckets_iam_get_ident(iam, access_key);
  if (!id && strlen(access_key) >= 3 && !strchr(access_key, '/')) id = load_user_any(iam, access_key);
  if (!id) return BUCKETS_IAM_KEY_UNKNOWN;
  if (!buckets_iam_ident_is_valid(id)) {
    buckets_iam_key_status st = strcmp(id->status, "off") == 0 ? BUCKETS_IAM_KEY_DISABLED : BUCKETS_IAM_KEY_UNKNOWN;
    buckets_iam_ident_release(id);
    return st;
  }
  *out = id;
  return BUCKETS_IAM_KEY_OK;
}

buckets_iam_token_status buckets_iam_check_token(const buckets_iam *iam, const buckets_iam_ident *id,
                                                 const char *token, bool *owner) {
  *owner = false;
  bool has_token = token && *token;
  if (has_token && !id) return BUCKETS_IAM_TOKEN_NO_ACCESS_KEY;
  if (!id) return BUCKETS_IAM_TOKEN_OK;
  bool temp = buckets_iam_ident_is_temp(id), svc = buckets_iam_ident_is_svc(id);
  if (!has_token && temp && !svc) return BUCKETS_IAM_TOKEN_INVALID;
  if (has_token && !temp) return BUCKETS_IAM_TOKEN_INVALID;
  if (!svc && temp) {
    size_t a = strlen(token), b = strlen(id->session_token);
    if (a != b || CRYPTO_memcmp(token, id->session_token, a) != 0) return BUCKETS_IAM_TOKEN_INVALID;
  }
  if (temp && buckets_iam_ident_is_expired(id)) return BUCKETS_IAM_TOKEN_EXPIRED;
  const char *root = iam->root->access_key;
  *owner = strcmp(id->access_key, root) == 0 || (id->parent && strcmp(id->parent, root) == 0);
  if (id->has_session_policy) *owner = false;
  return BUCKETS_IAM_TOKEN_OK;
}

/* ---- authorization ------------------------------------------------------------------ */

/* cache.policyDBGet for a user (MinIO users mode). Returns false when a
 * disabled user or group means "no policies". */
static void policy_db_user(const cache *c, const char *name, strset *out) {
  const buckets_iam_ident *u = buckets_strmap_get(&c->users, name);
  if (u && !buckets_iam_ident_is_valid(u)) return;
  strset acc = {0};
  const mapped_policy *mp = buckets_strmap_get(&c->pol[BUCKETS_IAM_REG], name);
  if (!mp) mp = buckets_strmap_get(&c->pol[BUCKETS_IAM_STS], name);
  if (mp) set_add_csv(&acc, mp->policies);
  for (size_t i = 0; u && i < u->ngroups; i++) {
    const group_info *g = buckets_strmap_get(&c->groups, u->groups[i]);
    if (g && !g->enabled) goto none;
    const mapped_policy *gp = buckets_strmap_get(&c->group_pol, u->groups[i]);
    if (gp) set_add_csv(&acc, gp->policies);
  }
  size_t it = 0;
  const char *gname;
  void *v;
  while (buckets_strmap_next(&c->groups, &it, &gname, &v)) {
    const group_info *g = v;
    if (!strv_has(g->members, g->n, name)) continue;
    if (!g->enabled) goto none;
    const mapped_policy *gp = buckets_strmap_get(&c->group_pol, gname);
    if (gp) set_add_csv(&acc, gp->policies);
  }
  for (size_t i = 0; i < acc.n; i++) set_add(out, acc.v[i]);
none:
  set_free(&acc);
}

/* IAMStoreSys.PolicyDBGet(name, groups...). */
static void policy_db_get(const cache *c, const char *name, char *const *groups, size_t ngroups, strset *out) {
  policy_db_user(c, name, out);
  bool user_present = out->n > 0;
  strset gp = {0};
  for (size_t i = 0; i < ngroups; i++) {
    const group_info *g = buckets_strmap_get(&c->groups, groups[i]);
    if (!g || !g->enabled) continue;
    const mapped_policy *m = buckets_strmap_get(&c->group_pol, groups[i]);
    if (m) set_add_csv(&gp, m->policies);
  }
  (void)user_present;
  for (size_t i = 0; i < gp.n; i++) set_add(out, gp.v[i]);
  set_free(&gp);
}

/* policy.GetPoliciesFromClaims(claims, "policy"): a comma-separated string
 * or an array of them. */
static void policies_from_claims(const buckets_iam_ident *id, strset *out) {
  if (!id->claims) return;
  yyjson_val *v = yyjson_obj_get(yyjson_doc_get_root(id->claims), "policy");
  if (yyjson_is_str(v)) set_add_csv(out, yyjson_get_str(v));
  if (yyjson_is_arr(v)) {
    size_t i, max;
    yyjson_val *e;
    yyjson_arr_foreach(v, i, max, e) {
      if (yyjson_is_str(e)) set_add_csv(out, yyjson_get_str(e));
    }
  }
}

/* Evaluates the named policies that exist (MergePolicies + IsAllowed);
 * false when none of them exist. */
static bool eval_named(const cache *c, const strset *names, const buckets_policy_args *a) {
  const buckets_policy **ps = buckets_xcalloc(names->n ? names->n : 1, sizeof(*ps));
  size_t n = 0;
  for (size_t i = 0; i < names->n; i++) {
    const policy_doc *d = buckets_strmap_get(&c->policies, names->v[i]);
    if (d) ps[n++] = d->p;
  }
  bool ok = n > 0 && buckets_policies_allowed(ps, n, a);
  free(ps);
  return ok;
}

static bool session_policy_allows(const buckets_iam_ident *id, const buckets_policy_args *a) {
  if (!id->session_policy) return false;
  buckets_policy_args sa = *a;
  sa.owner = false;
  sa.deny_only = false;
  return buckets_policy_allowed(id->session_policy, &sa);
}

static bool allowed_sts(buckets_iam *iam, const buckets_iam_ident *id, const buckets_policy_args *a) {
  const char *parent = nz(id->parent);
  bool owner_derived = strcmp(parent, iam->root->access_key) == 0;
  strset names = {0};
  bool combined = true;
  if (!owner_derived) {
    policy_db_get(&iam->c, parent, id->groups, id->ngroups, &names);
    if (!names.n) policies_from_claims(id, &names);
    combined = names.n > 0 && eval_named(&iam->c, &names, a);
    if (!names.n) {
      set_free(&names);
      return false;
    }
  }
  set_free(&names);
  if (id->has_session_policy) {
    /* isAllowedBySessionPolicy: a policy without a Version denies. */
    bool sp_ok = id->session_policy && *buckets_policy_version(id->session_policy) && session_policy_allows(id, a);
    return sp_ok && combined;
  }
  return combined;
}

static bool allowed_svc(buckets_iam *iam, const buckets_iam_ident *id, const buckets_policy_args *a) {
  const char *parent = nz(id->parent);
  const char *claim_parent = buckets_iam_ident_claim(id, "parent");
  if (!claim_parent || strcmp(claim_parent, parent) != 0) return false;
  bool owner_derived = strcmp(parent, iam->root->access_key) == 0;
  bool combined = true;
  if (!owner_derived) {
    strset names = {0};
    policy_db_get(&iam->c, parent, id->groups, id->ngroups, &names);
    if (!names.n) policies_from_claims(id, &names);
    if (!names.n) {
      set_free(&names);
      return false;
    }
    combined = eval_named(&iam->c, &names, a);
    set_free(&names);
  }
  const char *sa = buckets_iam_ident_claim(id, "sa-policy");
  if (!sa) return false;
  if (strcmp(sa, "inherited-policy") == 0) return combined;
  /* isAllowedBySessionPolicyForServiceAccount: a blank policy inherits. */
  if (id->has_session_policy && !(id->session_policy && buckets_policy_is_blank(id->session_policy))) {
    return session_policy_allows(id, a) && combined;
  }
  return combined;
}

bool buckets_iam_is_allowed(buckets_iam *iam, const buckets_iam_ident *id, bool owner, const buckets_policy_args *args) {
  if (owner) return true;
  if (!id || id->type == BUCKETS_IAM_ROOT) return false;
  buckets_policy_args a = *args;
  a.owner = false;
  pthread_rwlock_rdlock(&iam->lock);
  bool ok;
  if (buckets_iam_ident_is_temp(id)) {
    ok = allowed_sts(iam, id, &a);
  } else if (buckets_iam_ident_is_svc(id)) {
    ok = allowed_svc(iam, id, &a);
  } else {
    strset names = {0};
    policy_db_get(&iam->c, id->access_key, id->groups, id->ngroups, &names);
    ok = names.n > 0 && eval_named(&iam->c, &names, &a);
    set_free(&names);
  }
  pthread_rwlock_unlock(&iam->lock);
  return ok;
}

/* ---- users ---------------------------------------------------------------------------- */

const char *buckets_iam_strerror(buckets_iam_err e) {
  switch (e) {
    case BUCKETS_IAM_OK: return "ok";
    case BUCKETS_IAM_ERR_INVALID_ARGUMENT: return "invalid arguments specified";
    case BUCKETS_IAM_ERR_NO_SUCH_USER: return "The specified user does not exist";
    case BUCKETS_IAM_ERR_NO_SUCH_GROUP: return "The specified group does not exist";
    case BUCKETS_IAM_ERR_NO_SUCH_POLICY: return "The canned policy does not exist";
    case BUCKETS_IAM_ERR_NO_SUCH_SVC: return "The specified service account is not found";
    case BUCKETS_IAM_ERR_POLICY_IN_USE: return "The policy cannot be removed, as it is in use";
    case BUCKETS_IAM_ERR_GROUP_NOT_EMPTY: return "Specified group is not empty - cannot remove it";
    case BUCKETS_IAM_ERR_GROUP_DISABLED: return "The specified group is disabled";
    case BUCKETS_IAM_ERR_NOT_ALLOWED: return "Specified IAM action is not allowed";
    case BUCKETS_IAM_ERR_SVC_NOT_ALLOWED: return "Specified service account action is not allowed";
    case BUCKETS_IAM_ERR_NO_POLICY_CHANGE: return "No policy to attach or detach";
    case BUCKETS_IAM_ERR_INVALID_ACCESS_KEY: return "access key length should be between 3 and 20";
    case BUCKETS_IAM_ERR_INVALID_SECRET_KEY: return "secret key length should be between 8 and 40";
    case BUCKETS_IAM_ERR_SESSION_POLICY_TOO_LARGE: return "Session policy should not exceed 2048 characters";
    case BUCKETS_IAM_ERR_INVALID_EXPIRATION: return "invalid service account expiration";
    case BUCKETS_IAM_ERR_MALFORMED_POLICY: return "malformed policy";
    case BUCKETS_IAM_ERR_STORAGE: return "unable to save IAM data";
    case BUCKETS_IAM_ERR_NOT_INITIALIZED: return "Server not initialized, please try again";
  }
  return "unknown error";
}

static buckets_iam_err need_ready(const buckets_iam *iam) {
  return buckets_iam_ready(iam) ? BUCKETS_IAM_OK : BUCKETS_IAM_ERR_NOT_INITIALIZED;
}

static void member_of(const cache *c, const char *user, char ***out, size_t *n) {
  strset s = {0};
  size_t it = 0;
  const char *gname;
  void *v;
  while (buckets_strmap_next(&c->groups, &it, &gname, &v)) {
    const group_info *g = v;
    if (strv_has(g->members, g->n, user)) set_add(&s, gname);
  }
  if (s.n) qsort(s.v, s.n, sizeof(char *), cmp_str);
  *out = s.v;
  *n = s.n;
}

void buckets_iam_user_info_free(buckets_iam_user_info *u, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(u[i].name);
    free(u[i].policy);
    strv_free(u[i].member_of, u[i].nmember_of);
  }
}

static void fill_user_info(const cache *c, const char *name, const buckets_iam_ident *id, buckets_iam_user_info *o) {
  memset(o, 0, sizeof(*o));
  o->name = buckets_xstrdup(name);
  const mapped_policy *mp = buckets_strmap_get(&c->pol[BUCKETS_IAM_REG], name);
  o->policy = buckets_xstrdup(mp ? mp->policies : "");
  o->updated = mp ? mp->updated : (buckets_iam_time){GO_ZERO_SEC, 0};
  o->enabled = buckets_iam_ident_is_valid(id);
  member_of(c, name, &o->member_of, &o->nmember_of);
}

buckets_iam_err buckets_iam_get_user_info(buckets_iam *iam, const char *name, buckets_iam_user_info *out) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!name || !*name) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_rwlock_rdlock(&iam->lock);
  const buckets_iam_ident *id = buckets_strmap_get(&iam->c.users, name);
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (!id) e = BUCKETS_IAM_ERR_NO_SUCH_USER;
  else if (buckets_iam_ident_is_temp(id) || buckets_iam_ident_is_svc(id)) e = BUCKETS_IAM_ERR_NOT_ALLOWED;
  else fill_user_info(&iam->c, name, id, out);
  pthread_rwlock_unlock(&iam->lock);
  return e;
}

void buckets_iam_list_users(buckets_iam *iam, buckets_iam_user_info **out, size_t *n) {
  pthread_rwlock_rdlock(&iam->lock);
  *out = buckets_xcalloc(iam->c.users.n ? iam->c.users.n : 1, sizeof(**out));
  *n = 0;
  size_t it = 0;
  const char *name;
  void *v;
  while (buckets_strmap_next(&iam->c.users, &it, &name, &v)) {
    const buckets_iam_ident *id = v;
    if (buckets_iam_ident_is_temp(id) || buckets_iam_ident_is_svc(id)) continue;
    fill_user_info(&iam->c, name, id, &(*out)[(*n)++]);
  }
  pthread_rwlock_unlock(&iam->lock);
}

static bool status_on(const char *status) {
  return status && (strcmp(status, "enabled") == 0 || strcmp(status, "on") == 0);
}

/* Replaces a regular user's identity in storage and cache. Caller holds write_mu. */
static buckets_iam_err put_user(buckets_iam *iam, buckets_iam_ident *id) {
  if (!save_identity(iam, id, BUCKETS_IAM_REG)) {
    buckets_iam_ident_release(id);
    return BUCKETS_IAM_ERR_STORAGE;
  }
  pthread_rwlock_wrlock(&iam->lock);
  buckets_iam_ident_release(buckets_strmap_put(&iam->c.users, id->access_key, id));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, "user", id->access_key);
  return BUCKETS_IAM_OK;
}

static buckets_iam_ident *new_user_ident(const char *ak, const char *sk, bool on) {
  buckets_iam_ident *id = ident_new();
  id->type = BUCKETS_IAM_REG;
  id->access_key = buckets_xstrdup(ak);
  id->secret_key = buckets_xstrdup(sk);
  set_status(id, on ? "on" : "off");
  id->updated = now_time();
  return id;
}

buckets_iam_err buckets_iam_add_user(buckets_iam *iam, const char *access_key, const char *secret_key,
                                     const char *status) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!access_key || strlen(access_key) < 3 || strpbrk(access_key, "=,")) return BUCKETS_IAM_ERR_INVALID_ACCESS_KEY;
  if (!secret_key || strlen(secret_key) < 8) return BUCKETS_IAM_ERR_INVALID_SECRET_KEY;
  pthread_mutex_lock(&iam->write_mu);
  pthread_rwlock_rdlock(&iam->lock);
  const buckets_iam_ident *cur = cache_user(&iam->c, access_key);
  bool temp = cur && buckets_iam_ident_is_temp(cur);
  pthread_rwlock_unlock(&iam->lock);
  buckets_iam_err e = temp ? BUCKETS_IAM_ERR_NOT_ALLOWED
                           : put_user(iam, new_user_ident(access_key, secret_key, status_on(status)));
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_set_user_status(buckets_iam *iam, const char *access_key, bool enabled) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_ident *cur = buckets_iam_get_ident(iam, access_key);
  buckets_iam_err e;
  if (!cur || cur->type == BUCKETS_IAM_STS) e = BUCKETS_IAM_ERR_NO_SUCH_USER;
  else if (buckets_iam_ident_is_temp(cur) || buckets_iam_ident_is_svc(cur)) e = BUCKETS_IAM_ERR_NOT_ALLOWED;
  else e = put_user(iam, new_user_ident(access_key, cur->secret_key, enabled));
  buckets_iam_ident_release(cur);
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_set_user_secret(buckets_iam *iam, const char *access_key, const char *secret_key) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!secret_key || strlen(secret_key) < 8) return BUCKETS_IAM_ERR_INVALID_SECRET_KEY;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_ident *cur = buckets_iam_get_ident(iam, access_key);
  buckets_iam_err e;
  if (!cur || cur->type != BUCKETS_IAM_REG || buckets_iam_ident_is_svc(cur)) {
    e = BUCKETS_IAM_ERR_NO_SUCH_USER;
  } else {
    buckets_iam_ident *id = new_user_ident(access_key, secret_key, strcmp(cur->status, "off") != 0);
    e = put_user(iam, id);
  }
  buckets_iam_ident_release(cur);
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

/* Removes members from a group in storage and cache. Caller holds write_mu. */
static buckets_iam_err group_remove_locked(buckets_iam *iam, const char *group, const char *const *members, size_t n) {
  pthread_rwlock_rdlock(&iam->lock);
  const group_info *g = buckets_strmap_get(&iam->c.groups, group);
  group_info *ng = NULL;
  if (g) {
    ng = buckets_xcalloc(1, sizeof(*ng));
    ng->enabled = g->enabled;
    ng->members = buckets_xcalloc(g->n ? g->n : 1, sizeof(char *));
    for (size_t i = 0; i < g->n; i++) {
      bool drop = false;
      for (size_t j = 0; j < n && !drop; j++) drop = strcmp(g->members[i], members[j]) == 0;
      if (!drop) ng->members[ng->n++] = buckets_xstrdup(g->members[i]);
    }
    ng->updated = now_time();
  }
  pthread_rwlock_unlock(&iam->lock);
  if (!ng) return BUCKETS_IAM_ERR_NO_SUCH_GROUP;
  if (!save_group(iam, group, ng)) {
    group_info_free(ng);
    return BUCKETS_IAM_ERR_STORAGE;
  }
  pthread_rwlock_wrlock(&iam->lock);
  group_info_free(buckets_strmap_put(&iam->c.groups, group, ng));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, "group", group);
  return BUCKETS_IAM_OK;
}

static void delete_identity(buckets_iam *iam, const char *ak, buckets_iam_utype t) {
  char *path = identity_path(ak, t);
  iam_delete(iam, path);
  free(path);
  pthread_rwlock_wrlock(&iam->lock);
  buckets_iam_ident_release(buckets_strmap_del(t == BUCKETS_IAM_STS ? &iam->c.sts : &iam->c.users, ak));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, t == BUCKETS_IAM_SVC ? "svc" : t == BUCKETS_IAM_STS ? "sts" : "user", ak);
}

static void delete_mapping(buckets_iam *iam, const char *name, buckets_iam_utype t, bool group) {
  char *path = mapped_path(name, t, group);
  iam_delete(iam, path);
  free(path);
  pthread_rwlock_wrlock(&iam->lock);
  mapped_free(buckets_strmap_del(group ? &iam->c.group_pol : &iam->c.pol[t], name));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, group ? "policydb-group" : t == BUCKETS_IAM_STS ? "policydb-sts" : t == BUCKETS_IAM_SVC ? "policydb-svc" : "policydb-user", name);
}

/* Access keys of credentials derived from parent, of the given type. */
static void derived_keys(buckets_iam *iam, const char *parent, strset *svc, strset *sts) {
  pthread_rwlock_rdlock(&iam->lock);
  const buckets_strmap *maps[] = {&iam->c.users, &iam->c.sts};
  for (int k = 0; k < 2; k++) {
    size_t it = 0;
    const char *ak;
    void *v;
    while (buckets_strmap_next(maps[k], &it, &ak, &v)) {
      const buckets_iam_ident *id = v;
      if (!id->parent || strcmp(id->parent, parent) != 0) continue;
      if (buckets_iam_ident_is_svc(id)) set_add(svc, ak);
      else if (buckets_iam_ident_is_temp(id)) set_add(sts, ak);
    }
  }
  pthread_rwlock_unlock(&iam->lock);
}

buckets_iam_err buckets_iam_delete_user(buckets_iam *iam, const char *access_key) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!access_key || !*access_key) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  char **groups;
  size_t ng;
  pthread_rwlock_rdlock(&iam->lock);
  member_of(&iam->c, access_key, &groups, &ng);
  pthread_rwlock_unlock(&iam->lock);
  buckets_iam_err e = BUCKETS_IAM_OK;
  for (size_t i = 0; i < ng && !e; i++) e = group_remove_locked(iam, groups[i], &access_key, 1);
  strv_free(groups, ng);
  if (!e) {
    strset svc = {0}, sts = {0};
    derived_keys(iam, access_key, &svc, &sts);
    for (size_t i = 0; i < svc.n; i++) delete_identity(iam, svc.v[i], BUCKETS_IAM_SVC);
    for (size_t i = 0; i < sts.n; i++) delete_identity(iam, sts.v[i], BUCKETS_IAM_STS);
    set_free(&svc);
    set_free(&sts);
    delete_mapping(iam, access_key, BUCKETS_IAM_REG, false);
    delete_identity(iam, access_key, BUCKETS_IAM_REG);
  }
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

/* ---- groups ------------------------------------------------------------------------------- */

void buckets_iam_group_desc_free(buckets_iam_group_desc *g) {
  free(g->name);
  free(g->status);
  strv_free(g->members, g->nmembers);
  free(g->policy);
  memset(g, 0, sizeof(*g));
}

/* Every member must be an existing regular user. */
static buckets_iam_err check_members(buckets_iam *iam, const char *const *members, size_t n) {
  buckets_iam_err e = BUCKETS_IAM_OK;
  pthread_rwlock_rdlock(&iam->lock);
  for (size_t i = 0; i < n && !e; i++) {
    const buckets_iam_ident *u = buckets_strmap_get(&iam->c.users, members[i]);
    if (!u) e = BUCKETS_IAM_ERR_NO_SUCH_USER;
    else if (buckets_iam_ident_is_temp(u) || buckets_iam_ident_is_svc(u)) e = BUCKETS_IAM_ERR_NOT_ALLOWED;
  }
  pthread_rwlock_unlock(&iam->lock);
  return e;
}

buckets_iam_err buckets_iam_group_add_members(buckets_iam *iam, const char *group, const char *const *members,
                                              size_t n) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!group || !*group) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_err e = check_members(iam, members, n);
  if (e) goto out;
  pthread_rwlock_rdlock(&iam->lock);
  const group_info *g = buckets_strmap_get(&iam->c.groups, group);
  group_info *ng = buckets_xcalloc(1, sizeof(*ng));
  ng->enabled = g ? g->enabled : true;
  strset s = {0};
  for (size_t i = 0; g && i < g->n; i++) set_add(&s, g->members[i]);
  for (size_t i = 0; i < n; i++) set_add(&s, members[i]);
  pthread_rwlock_unlock(&iam->lock);
  ng->members = s.v;
  ng->n = s.n;
  ng->updated = now_time();
  if (!save_group(iam, group, ng)) {
    group_info_free(ng);
    e = BUCKETS_IAM_ERR_STORAGE;
    goto out;
  }
  pthread_rwlock_wrlock(&iam->lock);
  group_info_free(buckets_strmap_put(&iam->c.groups, group, ng));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, "group", group);
out:
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_group_remove_members(buckets_iam *iam, const char *group, const char *const *members,
                                                 size_t n) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!group || !*group) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_err e = check_members(iam, members, n);
  if (e) goto out;
  pthread_rwlock_rdlock(&iam->lock);
  const group_info *g = buckets_strmap_get(&iam->c.groups, group);
  size_t count = g ? g->n : 0;
  pthread_rwlock_unlock(&iam->lock);
  if (!g) {
    e = BUCKETS_IAM_ERR_NO_SUCH_GROUP;
  } else if (n == 0 && count != 0) {
    e = BUCKETS_IAM_ERR_GROUP_NOT_EMPTY;
  } else if (n == 0) {
    delete_mapping(iam, group, BUCKETS_IAM_REG, true);
    char *path = path_of("groups/", group, "/members.json");
    iam_delete(iam, path);
    free(path);
    pthread_rwlock_wrlock(&iam->lock);
    group_info_free(buckets_strmap_del(&iam->c.groups, group));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
    notify(iam, "group", group);
  } else {
    e = group_remove_locked(iam, group, members, n);
  }
out:
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_group_set_status(buckets_iam *iam, const char *group, bool enabled) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!group || !*group) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  pthread_rwlock_rdlock(&iam->lock);
  const group_info *g = buckets_strmap_get(&iam->c.groups, group);
  group_info *ng = NULL;
  if (g) {
    ng = buckets_xcalloc(1, sizeof(*ng));
    ng->enabled = enabled;
    ng->members = strv_dup((const char *const *)g->members, g->n);
    ng->n = g->n;
    ng->updated = now_time();
  }
  pthread_rwlock_unlock(&iam->lock);
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (!ng) {
    e = BUCKETS_IAM_ERR_NO_SUCH_GROUP;
  } else if (!save_group(iam, group, ng)) {
    group_info_free(ng);
    e = BUCKETS_IAM_ERR_STORAGE;
  } else {
    pthread_rwlock_wrlock(&iam->lock);
    group_info_free(buckets_strmap_put(&iam->c.groups, group, ng));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
    notify(iam, "group", group);
  }
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_group_describe(buckets_iam *iam, const char *group, buckets_iam_group_desc *out) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  memset(out, 0, sizeof(*out));
  pthread_rwlock_rdlock(&iam->lock);
  const group_info *g = buckets_strmap_get(&iam->c.groups, group);
  if (g) {
    out->name = buckets_xstrdup(group);
    out->status = buckets_xstrdup(g->enabled ? "enabled" : "disabled");
    out->members = strv_dup((const char *const *)g->members, g->n);
    out->nmembers = g->n;
    const mapped_policy *mp = g->enabled ? buckets_strmap_get(&iam->c.group_pol, group) : NULL;
    strset s = {0};
    if (mp) set_add_csv(&s, mp->policies);
    out->policy = set_join(&s);
    set_free(&s);
    out->updated = g->updated;
  }
  pthread_rwlock_unlock(&iam->lock);
  return g ? BUCKETS_IAM_OK : BUCKETS_IAM_ERR_NO_SUCH_GROUP;
}

void buckets_iam_list_groups(buckets_iam *iam, char ***out, size_t *n) {
  strset s = {0};
  pthread_rwlock_rdlock(&iam->lock);
  size_t it = 0;
  const char *name;
  while (buckets_strmap_next(&iam->c.groups, &it, &name, NULL)) set_add(&s, name);
  it = 0;
  while (buckets_strmap_next(&iam->c.group_pol, &it, &name, NULL)) set_add(&s, name);
  pthread_rwlock_unlock(&iam->lock);
  if (s.n) qsort(s.v, s.n, sizeof(char *), cmp_str);
  *out = s.v;
  *n = s.n;
}

/* ---- policies ------------------------------------------------------------------------------ */

void buckets_iam_policy_doc_free(buckets_iam_policy_doc *d, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(d[i].name);
    free(d[i].json);
  }
}

buckets_iam_err buckets_iam_set_policy(buckets_iam *iam, const char *name, const char *json, size_t len,
                                       char *err, size_t errlen) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!name || !*name || strchr(name, '/') || strchr(name, ',')) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  policy_doc *d = parse_policy_doc(json, len, 0, err, errlen);
  if (!d) return BUCKETS_IAM_ERR_MALFORMED_POLICY;
  if (buckets_policy_is_empty(d->p)) {
    policy_doc_free(d);
    return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  }
  pthread_mutex_lock(&iam->write_mu);
  pthread_rwlock_rdlock(&iam->lock);
  const policy_doc *cur = buckets_strmap_get(&iam->c.policies, name);
  d->updated = now_ms();
  d->created = cur && buckets_iam_time_is_set(cur->created) ? cur->created : d->updated;
  pthread_rwlock_unlock(&iam->lock);
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (!save_policy(iam, name, d)) {
    policy_doc_free(d);
    e = BUCKETS_IAM_ERR_STORAGE;
  } else {
    pthread_rwlock_wrlock(&iam->lock);
    policy_doc_free(buckets_strmap_put(&iam->c.policies, name, d));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
    notify(iam, "policy", name);
  }
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

static bool csv_contains(const char *csv, const char *name) {
  strset s = {0};
  set_add_csv(&s, csv);
  bool has = strv_has(s.v, s.n, name);
  set_free(&s);
  return has;
}

buckets_iam_err buckets_iam_delete_policy(buckets_iam *iam, const char *name) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!name || !*name) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_err e = BUCKETS_IAM_OK;
  pthread_rwlock_rdlock(&iam->lock);
  size_t it = 0;
  const char *k;
  void *v;
  while (!e && buckets_strmap_next(&iam->c.pol[BUCKETS_IAM_REG], &it, &k, &v)) {
    if (buckets_strmap_get(&iam->c.users, k) && csv_contains(((mapped_policy *)v)->policies, name)) {
      e = BUCKETS_IAM_ERR_POLICY_IN_USE;
    }
  }
  it = 0;
  while (!e && buckets_strmap_next(&iam->c.group_pol, &it, &k, &v)) {
    if (csv_contains(((mapped_policy *)v)->policies, name)) e = BUCKETS_IAM_ERR_POLICY_IN_USE;
  }
  pthread_rwlock_unlock(&iam->lock);
  if (!e) {
    char *path = path_of("policies/", name, "/policy.json");
    if (!iam_delete(iam, path)) e = BUCKETS_IAM_ERR_STORAGE;
    free(path);
  }
  if (!e) {
    pthread_rwlock_wrlock(&iam->lock);
    policy_doc_free(buckets_strmap_del(&iam->c.policies, name));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
    notify(iam, "policy", name);
  }
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_get_policy(buckets_iam *iam, const char *name, buckets_iam_policy_doc *out) {
  memset(out, 0, sizeof(*out));
  if (!name || !*name) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_rwlock_rdlock(&iam->lock);
  const policy_doc *d = buckets_strmap_get(&iam->c.policies, name);
  if (d) {
    out->name = buckets_xstrdup(name);
    out->json = buckets_xstrdup(d->json);
    out->created = d->created;
    out->updated = d->updated;
  }
  pthread_rwlock_unlock(&iam->lock);
  return d ? BUCKETS_IAM_OK : BUCKETS_IAM_ERR_NO_SUCH_POLICY;
}

void buckets_iam_list_policies(buckets_iam *iam, buckets_iam_policy_doc **out, size_t *n) {
  pthread_rwlock_rdlock(&iam->lock);
  *out = buckets_xcalloc(iam->c.policies.n ? iam->c.policies.n : 1, sizeof(**out));
  *n = 0;
  size_t it = 0;
  const char *name;
  void *v;
  while (buckets_strmap_next(&iam->c.policies, &it, &name, &v)) {
    const policy_doc *d = v;
    buckets_iam_policy_doc *o = &(*out)[(*n)++];
    o->name = buckets_xstrdup(name);
    o->json = buckets_xstrdup(d->json);
    o->created = d->created;
    o->updated = d->updated;
  }
  pthread_rwlock_unlock(&iam->lock);
}

static buckets_iam_err store_mapping(buckets_iam *iam, const char *name, buckets_iam_utype t, bool group,
                                     const char *policies) {
  mapped_policy *m = buckets_xcalloc(1, sizeof(*m));
  m->policies = buckets_xstrdup(policies);
  m->updated = now_time();
  if (!save_mapped(iam, name, t, group, m)) {
    mapped_free(m);
    return BUCKETS_IAM_ERR_STORAGE;
  }
  pthread_rwlock_wrlock(&iam->lock);
  mapped_free(buckets_strmap_put(group ? &iam->c.group_pol : &iam->c.pol[t], name, m));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, group ? "policydb-group" : t == BUCKETS_IAM_STS ? "policydb-sts" : t == BUCKETS_IAM_SVC ? "policydb-svc" : "policydb-user", name);
  return BUCKETS_IAM_OK;
}

buckets_iam_err buckets_iam_policy_set(buckets_iam *iam, const char *name, bool is_group, buckets_iam_utype type,
                                       const char *policies) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!name || !*name) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (!policies || !*policies) {
    delete_mapping(iam, name, type, is_group);
  } else {
    strset s = {0};
    set_add_csv(&s, policies);
    pthread_rwlock_rdlock(&iam->lock);
    for (size_t i = 0; i < s.n && !e; i++) {
      if (!buckets_strmap_get(&iam->c.policies, s.v[i])) e = BUCKETS_IAM_ERR_NO_SUCH_POLICY;
    }
    pthread_rwlock_unlock(&iam->lock);
    if (!e) e = store_mapping(iam, name, type, is_group, policies);
    set_free(&s);
  }
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_policy_update(buckets_iam *iam, const char *name, bool is_group, bool attach,
                                          const char *const *policies, size_t n, char **changed, char **effective) {
  if (changed) *changed = NULL;
  if (effective) *effective = NULL;
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!name || !*name) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_err e = BUCKETS_IAM_OK;
  strset existing = {0}, update = {0}, result = {0};
  pthread_rwlock_rdlock(&iam->lock);
  if (is_group) {
    const group_info *g = buckets_strmap_get(&iam->c.groups, name);
    if (!g) e = BUCKETS_IAM_ERR_NO_SUCH_GROUP;
    else if (!g->enabled) e = BUCKETS_IAM_ERR_GROUP_DISABLED;
  }
  const mapped_policy *mp = buckets_strmap_get(is_group ? &iam->c.group_pol : &iam->c.pol[BUCKETS_IAM_REG], name);
  if (mp) set_add_csv(&existing, mp->policies);
  for (size_t i = 0; i < n; i++) set_add_csv(&update, policies[i]);
  strset delta = {0};
  for (size_t i = 0; i < update.n; i++) {
    bool has = strv_has(existing.v, existing.n, update.v[i]);
    if (attach && !has) {
      if (!buckets_strmap_get(&iam->c.policies, update.v[i]) && !e) e = BUCKETS_IAM_ERR_NO_SUCH_POLICY;
      set_add(&delta, update.v[i]);
    } else if (!attach && has) {
      set_add(&delta, update.v[i]);
    }
  }
  pthread_rwlock_unlock(&iam->lock);
  if (!e && !delta.n) e = BUCKETS_IAM_ERR_NO_POLICY_CHANGE;
  if (!e) {
    for (size_t i = 0; i < existing.n; i++) {
      if (attach || !strv_has(delta.v, delta.n, existing.v[i])) set_add(&result, existing.v[i]);
    }
    if (attach) {
      for (size_t i = 0; i < delta.n; i++) set_add(&result, delta.v[i]);
    }
    char *joined = set_join(&result);
    if (!result.n) delete_mapping(iam, name, BUCKETS_IAM_REG, is_group);
    else e = store_mapping(iam, name, BUCKETS_IAM_REG, is_group, joined);
    if (!e && effective) *effective = joined;
    else free(joined);
    if (!e && changed) *changed = set_join(&delta);
  }
  set_free(&existing);
  set_free(&update);
  set_free(&result);
  set_free(&delta);
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

char *buckets_iam_mapped_policies(buckets_iam *iam, const char *name, bool is_group) {
  strset s = {0};
  pthread_rwlock_rdlock(&iam->lock);
  if (is_group) {
    const mapped_policy *mp = buckets_strmap_get(&iam->c.group_pol, name);
    if (mp) set_add_csv(&s, mp->policies);
  } else {
    policy_db_get(&iam->c, name, NULL, 0, &s);
  }
  pthread_rwlock_unlock(&iam->lock);
  char *r = set_join(&s);
  set_free(&s);
  return r;
}

/* ---- service accounts ------------------------------------------------------------------------ */

void buckets_iam_generate_credentials(char ak[21], char sk[41]) {
  static const char alnum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  uint8_t r[20], s[30];
  if (RAND_bytes(r, sizeof(r)) != 1 || RAND_bytes(s, sizeof(s)) != 1) abort();
  for (int i = 0; i < 20; i++) ak[i] = alnum[r[i] % 36];
  ak[20] = '\0';
  /* base64.RawStdEncoding of DecodedLen(40) = 30 bytes, with '/' -> '+'. */
  char b64[41 + 4];
  buckets_base64_encode(s, sizeof(s), b64);
  for (int i = 0; i < 40; i++) sk[i] = b64[i] == '/' ? '+' : b64[i];
  sk[40] = '\0';
}

static buckets_iam_err check_svc_expiry(const buckets_iam_time *exp) {
  if (!exp || !buckets_iam_time_is_set(*exp)) return BUCKETS_IAM_OK;
  long long now = (long long)time(NULL);
  if (exp->sec < now + MIN_SVC_EXPIRY_SEC || exp->sec > now + MAX_SVC_EXPIRY_SEC) {
    return BUCKETS_IAM_ERR_INVALID_EXPIRATION;
  }
  return BUCKETS_IAM_OK;
}

/* Validates a session policy and returns its minified JSON (NULL: none). */
static buckets_iam_err prepare_session_policy(const char *json, char **out, bool *blank, char *err, size_t errlen) {
  *out = NULL;
  *blank = true;
  if (!json || !*json) return BUCKETS_IAM_OK;
  buckets_policy *p;
  if (!buckets_policy_parse(json, strlen(json), &p, err, errlen)) return BUCKETS_IAM_ERR_MALFORMED_POLICY;
  /* UpdateServiceAccount: Version "" and no statements means "remove". */
  *blank = !*buckets_policy_version(p) && buckets_policy_is_empty(p);
  buckets_policy_free(p);
  yyjson_doc *d = yyjson_read(json, strlen(json), 0);
  if (!d) return BUCKETS_IAM_ERR_MALFORMED_POLICY;
  *out = yyjson_write(d, 0, NULL);
  yyjson_doc_free(d);
  if (strlen(*out) > MAX_SVC_SESSION_POLICY) {
    free(*out);
    *out = NULL;
    return BUCKETS_IAM_ERR_SESSION_POLICY_TOO_LARGE;
  }
  return BUCKETS_IAM_OK;
}

/* Signs claims (with accessKey set) into id->session_token and loads them. */
static bool sign_token(buckets_iam_ident *id, yyjson_mut_doc *claims, const char *key, const char *root_secret) {
  yyjson_mut_val *root = yyjson_mut_doc_get_root(claims);
  yyjson_mut_obj_remove_key(root, "accessKey");
  yyjson_mut_obj_add_strcpy(claims, root, "accessKey", id->access_key);
  size_t len;
  char *json = yyjson_mut_write(claims, 0, &len);
  buckets_buf tok = BUCKETS_BUF_INIT;
  buckets_jwt_sign(json, len, key, &tok);
  free(json);
  free(id->session_token);
  id->session_token = buckets_buf_detach(&tok);
  yyjson_doc_free(id->claims);
  id->claims = NULL;
  free(id->session_policy_json);
  id->session_policy_json = NULL;
  buckets_policy_free(id->session_policy);
  id->session_policy = NULL;
  id->has_session_policy = false;
  return ident_load_claims(id, key, root_secret);
}

buckets_iam_err buckets_iam_add_svc(buckets_iam *iam, const buckets_iam_svc_opts *o, buckets_iam_ident **out,
                                    char *err, size_t errlen) {
  if (out) *out = NULL;
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!o->parent || !*o->parent) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  bool has_ak = o->access_key && *o->access_key, has_sk = o->secret_key && *o->secret_key;
  if (has_ak != has_sk) return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  char gak[21], gsk[41];
  const char *ak = o->access_key, *sk = o->secret_key;
  if (!has_ak) {
    buckets_iam_generate_credentials(gak, gsk);
    ak = gak;
    sk = gsk;
  }
  if (strlen(ak) < 3 || strlen(ak) > 20 || strpbrk(ak, "=,")) return BUCKETS_IAM_ERR_INVALID_ACCESS_KEY;
  if (strlen(sk) < 8 || strlen(sk) > 40) return BUCKETS_IAM_ERR_INVALID_SECRET_KEY;
  if (strcmp(o->parent, ak) == 0 || strcmp(ak, iam->root->access_key) == 0) return BUCKETS_IAM_ERR_NOT_ALLOWED;
  buckets_iam_err e = check_svc_expiry(o->expiration);
  if (e) return e;
  char *sp;
  bool blank;
  if ((e = prepare_session_policy(o->session_policy, &sp, &blank, err, errlen))) return e;

  buckets_iam_ident *id = ident_new();
  id->type = BUCKETS_IAM_SVC;
  id->access_key = buckets_xstrdup(ak);
  id->secret_key = buckets_xstrdup(sk);
  id->parent = buckets_xstrdup(o->parent);
  id->groups = strv_dup(o->groups, o->ngroups);
  id->ngroups = o->ngroups;
  id->name = dupnz(o->name);
  id->description = dupnz(o->description);
  set_status(id, "on");
  id->expiration = o->expiration && buckets_iam_time_is_set(*o->expiration) ? *o->expiration
                                                                             : (buckets_iam_time){0, 0};
  id->updated = now_time();
  yyjson_mut_doc *claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  yyjson_mut_obj_add_strcpy(claims, root, "parent", o->parent);
  if (sp) {
    size_t n = strlen(sp);
    char *b64 = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
    buckets_base64_encode((const uint8_t *)sp, n, b64);
    yyjson_mut_obj_add_strcpy(claims, root, "sessionPolicy", b64);
    yyjson_mut_obj_add_str(claims, root, "sa-policy", "embedded-policy");
    free(b64);
  } else {
    yyjson_mut_obj_add_str(claims, root, "sa-policy", "inherited-policy");
  }
  free(sp);
  /* The requestor's own claims carry over, without replacing ours. */
  yyjson_doc *extra = o->claims_json ? yyjson_read(o->claims_json, strlen(o->claims_json), 0) : NULL;
  if (extra && yyjson_is_obj(yyjson_doc_get_root(extra))) {
    size_t idx, max;
    yyjson_val *k, *v;
    yyjson_obj_foreach(yyjson_doc_get_root(extra), idx, max, k, v) {
      const char *name = yyjson_get_str(k);
      if (strcmp(name, "exp") == 0 || yyjson_mut_obj_get(root, name)) continue;
      yyjson_mut_obj_add(root, yyjson_mut_strcpy(claims, name), yyjson_val_mut_copy(claims, v));
    }
  }
  yyjson_doc_free(extra);
  bool signed_ok = sign_token(id, claims, id->secret_key, iam->root->secret_key);
  yyjson_mut_doc_free(claims);
  if (!signed_ok) {
    buckets_iam_ident_release(id);
    return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  }

  pthread_mutex_lock(&iam->write_mu);
  pthread_rwlock_rdlock(&iam->lock);
  const buckets_iam_ident *taken = cache_user(&iam->c, ak);
  const buckets_iam_ident *pu = buckets_strmap_get(&iam->c.users, o->parent);
  if (taken || (pu && buckets_iam_ident_is_svc(pu))) e = BUCKETS_IAM_ERR_SVC_NOT_ALLOWED;
  pthread_rwlock_unlock(&iam->lock);
  if (!e && !save_identity(iam, id, BUCKETS_IAM_SVC)) e = BUCKETS_IAM_ERR_STORAGE;
  if (!e) {
    pthread_rwlock_wrlock(&iam->lock);
    buckets_iam_ident_release(buckets_strmap_put(&iam->c.users, ak, ident_ref(id)));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
    notify(iam, "svc", ak);
  }
  pthread_mutex_unlock(&iam->write_mu);
  if (e || !out) buckets_iam_ident_release(id);
  else *out = id;
  return e;
}

buckets_iam_err buckets_iam_update_svc(buckets_iam *iam, const char *access_key, const buckets_iam_svc_update *u,
                                       char *err, size_t errlen) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_ident *cur = buckets_iam_get_ident(iam, access_key);
  buckets_iam_err e = BUCKETS_IAM_OK;
  buckets_iam_ident *id = NULL;
  if (!cur || !buckets_iam_ident_is_svc(cur)) {
    e = BUCKETS_IAM_ERR_NO_SUCH_SVC;
    goto out;
  }
  id = ident_new();
  id->type = BUCKETS_IAM_SVC;
  id->access_key = buckets_xstrdup(cur->access_key);
  id->secret_key = buckets_xstrdup(cur->secret_key);
  id->parent = dupnz(cur->parent);
  id->groups = strv_dup((const char *const *)cur->groups, cur->ngroups);
  id->ngroups = cur->ngroups;
  id->name = dupnz(cur->name);
  id->description = dupnz(cur->description);
  id->claims_field = dupnz(cur->claims_field);
  memcpy(id->status, cur->status, sizeof(id->status));
  id->expiration = cur->expiration;
  if (u->secret_key && *u->secret_key) {
    if (strlen(u->secret_key) < 8) {
      e = BUCKETS_IAM_ERR_INVALID_SECRET_KEY;
      goto out;
    }
    free(id->secret_key);
    id->secret_key = buckets_xstrdup(u->secret_key);
  }
  if (u->name && *u->name) {
    free(id->name);
    id->name = buckets_xstrdup(u->name);
  }
  if (u->description && *u->description) {
    free(id->description);
    id->description = buckets_xstrdup(u->description);
  }
  if (u->expiration) {
    if ((e = check_svc_expiry(u->expiration))) goto out;
    id->expiration = *u->expiration;
  }
  const char *st = u->status ? u->status : "";
  if (!*st) {
  } else if (strcmp(st, "enabled") == 0 || strcmp(st, "on") == 0) {
    set_status(id, "on");
  } else if (strcmp(st, "disabled") == 0 || strcmp(st, "off") == 0) {
    set_status(id, "off");
  } else {
    e = BUCKETS_IAM_ERR_INVALID_ARGUMENT;
    goto out;
  }
  /* Re-sign the existing claims, updating the session policy. */
  yyjson_mut_doc *claims = yyjson_doc_mut_copy(cur->claims, NULL);
  yyjson_mut_val *root = yyjson_mut_doc_get_root(claims);
  char *sp = NULL;
  bool blank = true;
  if (u->set_policy && (e = prepare_session_policy(u->session_policy, &sp, &blank, err, errlen))) {
    yyjson_mut_doc_free(claims);
    goto out;
  }
  bool nosp = !u->set_policy || blank;
  if (yyjson_mut_obj_get(root, "sessionPolicy") && nosp) {
    yyjson_mut_obj_remove_key(root, "sessionPolicy");
    yyjson_mut_obj_remove_key(root, "sa-policy");
    yyjson_mut_obj_add_str(claims, root, "sa-policy", "inherited-policy");
  }
  if (u->set_policy && sp && !blank) {
    size_t n = strlen(sp);
    char *b64 = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
    buckets_base64_encode((const uint8_t *)sp, n, b64);
    yyjson_mut_obj_remove_key(root, "sessionPolicy");
    yyjson_mut_obj_remove_key(root, "sa-policy");
    yyjson_mut_obj_add_strcpy(claims, root, "sessionPolicy", b64);
    yyjson_mut_obj_add_str(claims, root, "sa-policy", "embedded-policy");
    free(b64);
  }
  free(sp);
  bool ok = sign_token(id, claims, id->secret_key, iam->root->secret_key);
  yyjson_mut_doc_free(claims);
  if (!ok) {
    e = BUCKETS_IAM_ERR_INVALID_ARGUMENT;
    goto out;
  }
  id->updated = now_time();
  if (!save_identity(iam, id, BUCKETS_IAM_SVC)) {
    e = BUCKETS_IAM_ERR_STORAGE;
    goto out;
  }
  pthread_rwlock_wrlock(&iam->lock);
  buckets_iam_ident_release(buckets_strmap_put(&iam->c.users, id->access_key, ident_ref(id)));
  touch(iam);
  pthread_rwlock_unlock(&iam->lock);
  notify(iam, "svc", id->access_key);
out:
  buckets_iam_ident_release(id);
  buckets_iam_ident_release(cur);
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

buckets_iam_err buckets_iam_delete_svc(buckets_iam *iam, const char *access_key) {
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_ident *cur = buckets_iam_get_ident(iam, access_key);
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (!cur || !buckets_iam_ident_is_svc(cur)) {
    e = BUCKETS_IAM_ERR_NO_SUCH_SVC;
  } else {
    delete_mapping(iam, access_key, BUCKETS_IAM_SVC, false);
    delete_identity(iam, access_key, BUCKETS_IAM_SVC);
  }
  buckets_iam_ident_release(cur);
  pthread_mutex_unlock(&iam->write_mu);
  return e;
}

void buckets_iam_list_derived(buckets_iam *iam, const char *parent, buckets_iam_utype type, buckets_iam_ident ***out,
                              size_t *n) {
  pthread_rwlock_rdlock(&iam->lock);
  const buckets_strmap *m = type == BUCKETS_IAM_STS ? &iam->c.sts : &iam->c.users;
  *out = buckets_xcalloc(m->n ? m->n : 1, sizeof(**out));
  *n = 0;
  size_t it = 0;
  void *v;
  while (buckets_strmap_next(m, &it, NULL, &v)) {
    buckets_iam_ident *id = v;
    if (!id->parent || (parent && strcmp(id->parent, parent) != 0)) continue;
    bool want = type == BUCKETS_IAM_STS ? buckets_iam_ident_is_temp(id) : buckets_iam_ident_is_svc(id);
    if (want) (*out)[(*n)++] = ident_ref(id);
  }
  pthread_rwlock_unlock(&iam->lock);
}

/* ---- STS ------------------------------------------------------------------------------------ */

buckets_iam_err buckets_iam_set_temp_user(buckets_iam *iam, const char *access_key, const char *secret_key,
                                          const char *parent, const char *const *groups, size_t ngroups,
                                          buckets_iam_time expiration, const char *claims_json,
                                          const char *policy, buckets_iam_ident **out) {
  if (out) *out = NULL;
  if (need_ready(iam)) return BUCKETS_IAM_ERR_NOT_INITIALIZED;
  if (!access_key || !*access_key || !parent || !*parent || !buckets_iam_time_is_set(expiration)) {
    return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  }
  buckets_iam_ident *id = ident_new();
  id->type = BUCKETS_IAM_STS;
  id->access_key = buckets_xstrdup(access_key);
  id->secret_key = buckets_xstrdup(secret_key);
  id->parent = buckets_xstrdup(parent);
  id->groups = strv_dup(groups, ngroups);
  id->ngroups = ngroups;
  id->expiration = expiration;
  set_status(id, "on");
  id->updated = now_time();
  yyjson_doc *cd = yyjson_read(claims_json, strlen(claims_json), 0);
  yyjson_mut_doc *claims = cd ? yyjson_doc_mut_copy(cd, NULL) : NULL;
  yyjson_doc_free(cd);
  bool ok = claims && yyjson_mut_is_obj(yyjson_mut_doc_get_root(claims)) &&
            sign_token(id, claims, iam->root->secret_key, iam->root->secret_key);
  yyjson_mut_doc_free(claims);
  if (!ok || buckets_iam_ident_is_expired(id)) {
    buckets_iam_ident_release(id);
    return BUCKETS_IAM_ERR_INVALID_ARGUMENT;
  }
  pthread_mutex_lock(&iam->write_mu);
  buckets_iam_err e = BUCKETS_IAM_OK;
  if (policy && *policy) {
    strset s = {0};
    set_add_csv(&s, policy);
    bool found = false;
    pthread_rwlock_rdlock(&iam->lock);
    for (size_t i = 0; i < s.n; i++) found |= buckets_strmap_get(&iam->c.policies, s.v[i]) != NULL;
    pthread_rwlock_unlock(&iam->lock);
    set_free(&s);
    e = found ? store_mapping(iam, parent, BUCKETS_IAM_STS, false, policy) : BUCKETS_IAM_ERR_NO_SUCH_POLICY;
  }
  if (!e && !save_identity(iam, id, BUCKETS_IAM_STS)) e = BUCKETS_IAM_ERR_STORAGE;
  if (!e) {
    pthread_rwlock_wrlock(&iam->lock);
    buckets_iam_ident_release(buckets_strmap_put(&iam->c.sts, access_key, ident_ref(id)));
    touch(iam);
    pthread_rwlock_unlock(&iam->lock);
    notify(iam, "sts", access_key);
  }
  pthread_mutex_unlock(&iam->write_mu);
  if (e || !out) buckets_iam_ident_release(id);
  else *out = id;
  return e;
}

/* ---- policy entities ------------------------------------------------------------------ */

static void add_sorted(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, strset *s) {
  if (s->n) qsort(s->v, s->n, sizeof(char *), cmp_str);
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, key);
  for (size_t i = 0; i < s->n; i++) yyjson_mut_arr_add_strcpy(d, a, s->v[i]);
}

static yyjson_mut_val *group_mappings(yyjson_mut_doc *d, const cache *c, const strset *only) {
  strset names = {0};
  size_t it = 0;
  const char *g;
  while (buckets_strmap_next(&c->group_pol, &it, &g, NULL)) {
    if (only && only->n && !strv_has(only->v, only->n, g)) continue;
    set_add(&names, g);
  }
  if (names.n) qsort(names.v, names.n, sizeof(char *), cmp_str);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  for (size_t i = 0; i < names.n; i++) {
    const mapped_policy *m = buckets_strmap_get(&c->group_pol, names.v[i]);
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "group", names.v[i]);
    strset ps = {0};
    set_add_csv(&ps, m->policies);
    add_sorted(d, o, "policies", &ps);
    set_free(&ps);
  }
  set_free(&names);
  return arr;
}

char *buckets_iam_policy_entities_json(buckets_iam *iam, const char *const *users, size_t nu,
                                       const char *const *groups, size_t ng, const char *const *policies, size_t np) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  time_fmt(now_time(), ts);
  yyjson_mut_obj_add_strcpy(d, root, "timestamp", ts);
  pthread_rwlock_rdlock(&iam->lock);
  const cache *c = &iam->c;
  bool all = !nu && !ng && !np;

  if (nu) {
    /* listUserPolicyMappings: each queried user's own mapping (regular,
     * else STS) and the mappings of the groups it belongs to. */
    strset us = {0};
    for (size_t i = 0; i < nu; i++) set_add(&us, users[i]);
    qsort(us.v, us.n, sizeof(char *), cmp_str);
    yyjson_mut_val *arr = yyjson_mut_arr(d);
    for (size_t i = 0; i < us.n; i++) {
      const mapped_policy *m = buckets_strmap_get(&c->pol[BUCKETS_IAM_REG], us.v[i]);
      if (!m) m = buckets_strmap_get(&c->pol[BUCKETS_IAM_STS], us.v[i]);
      char **mof;
      size_t nmof;
      member_of(c, us.v[i], &mof, &nmof);
      strset gset = {mof, nmof, nmof};
      if (!m && !nmof) {
        set_free(&gset);
        continue;
      }
      yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
      yyjson_mut_obj_add_strcpy(d, o, "user", us.v[i]);
      strset ps = {0};
      if (m) set_add_csv(&ps, m->policies);
      if (m) add_sorted(d, o, "policies", &ps);
      else yyjson_mut_obj_add_null(d, o, "policies");
      set_free(&ps);
      if (nmof) {
        yyjson_mut_val *gm = group_mappings(d, c, &gset);
        if (yyjson_mut_arr_size(gm)) yyjson_mut_obj_add_val(d, o, "memberOfMappings", gm);
      }
      set_free(&gset);
    }
    if (yyjson_mut_arr_size(arr)) yyjson_mut_obj_add_val(d, root, "userMappings", arr);
  }
  if (ng) {
    strset gs = {0};
    for (size_t i = 0; i < ng; i++) set_add(&gs, groups[i]);
    yyjson_mut_val *arr = group_mappings(d, c, &gs);
    if (yyjson_mut_arr_size(arr)) yyjson_mut_obj_add_val(d, root, "groupMappings", arr);
    set_free(&gs);
  }
  if (np || all) {
    /* listPolicyMappings: policy -> users (regular and STS parents) and groups. */
    strset q = {0};
    for (size_t i = 0; i < np; i++) set_add(&q, policies[i]);
    buckets_strmap by_user = BUCKETS_STRMAP_INIT, by_group = BUCKETS_STRMAP_INIT;
    const buckets_strmap *umaps[] = {&c->pol[BUCKETS_IAM_REG], &c->pol[BUCKETS_IAM_STS], &c->group_pol};
    for (int k = 0; k < 3; k++) {
      size_t it = 0;
      const char *who;
      void *v;
      while (buckets_strmap_next(umaps[k], &it, &who, &v)) {
        strset ps = {0};
        set_add_csv(&ps, ((mapped_policy *)v)->policies);
        for (size_t i = 0; i < ps.n; i++) {
          if (q.n && !strv_has(q.v, q.n, ps.v[i])) continue;
          buckets_strmap *m = k == 2 ? &by_group : &by_user;
          strset *set = buckets_strmap_get(m, ps.v[i]);
          if (!set) {
            set = buckets_xcalloc(1, sizeof(*set));
            buckets_strmap_put(m, ps.v[i], set);
          }
          set_add(set, who);
        }
        set_free(&ps);
      }
    }
    strset names = {0};
    size_t it = 0;
    const char *pn;
    while (buckets_strmap_next(&by_user, &it, &pn, NULL)) set_add(&names, pn);
    it = 0;
    while (buckets_strmap_next(&by_group, &it, &pn, NULL)) set_add(&names, pn);
    if (names.n) qsort(names.v, names.n, sizeof(char *), cmp_str);
    yyjson_mut_val *arr = yyjson_mut_arr(d);
    for (size_t i = 0; i < names.n; i++) {
      yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
      yyjson_mut_obj_add_strcpy(d, o, "policy", names.v[i]);
      strset *us = buckets_strmap_get(&by_user, names.v[i]), *gs = buckets_strmap_get(&by_group, names.v[i]);
      if (us) add_sorted(d, o, "users", us);
      else yyjson_mut_obj_add_null(d, o, "users");
      if (gs) add_sorted(d, o, "groups", gs);
      else yyjson_mut_obj_add_null(d, o, "groups");
    }
    if (yyjson_mut_arr_size(arr)) yyjson_mut_obj_add_val(d, root, "policyMappings", arr);
    set_free(&names);
    void *v;
    it = 0;
    while (buckets_strmap_next(&by_user, &it, NULL, &v)) {
      set_free(v);
      free(v);
    }
    it = 0;
    while (buckets_strmap_next(&by_group, &it, NULL, &v)) {
      set_free(v);
      free(v);
    }
    buckets_strmap_free(&by_user);
    buckets_strmap_free(&by_group);
    set_free(&q);
  }
  pthread_rwlock_unlock(&iam->lock);
  char *json = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  return json;
}
