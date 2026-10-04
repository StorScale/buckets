/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* BucketsUser, BucketsPolicy and Bucket: declarative IAM and buckets,
 * applied to their BucketsCluster through its admin and S3 APIs. */
#include "iam.h"
#include "config/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/log.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "manifests.h"
#include "s3client.h"

#define GROUP_PATH "/apis/buckets.io/v1alpha1"
#define FINALIZER "buckets.io/cleanup"
#define ENDPOINT_ANNOTATION "buckets.io/endpoint"

static const char *get_str(yyjson_val *o, const char *path) {
  char key[128];
  const char *p = path;
  while (o && *p) {
    const char *dot = strchr(p, '.');
    size_t n = dot ? (size_t)(dot - p) : strlen(p);
    snprintf(key, sizeof(key), "%.*s", (int)n, p);
    o = yyjson_obj_get(o, key);
    p = dot ? dot + 1 : p + n;
  }
  return yyjson_get_str(o);
}

/* ---- the cluster connection ------------------------------------------------------ */

typedef struct {
  s3c *c;
  char *ca_file;
} conn;

static void conn_free(conn *cn) {
  s3c_free(cn->c);
  if (cn->ca_file) unlink(cn->ca_file);
  free(cn->ca_file);
}

/* A Secret's data[key], decoded; NULL if absent. */
static char *secret_value(yyjson_val *secret, const char *key) {
  const char *b64 = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(secret, "data"), key));
  if (!b64) return NULL;
  size_t n = strlen(b64);
  char *out = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64_decode(b64, n, (uint8_t *)out);
  if (k < 0) {
    free(out);
    return NULL;
  }
  out[k] = '\0';
  return out;
}

/* The root credentials in a MinIO-style config.env, as bucketsd reads them:
 * BUCKETS_ROOT_* over MINIO_ROOT_*, a later line over an earlier one. */
static void config_env_creds(const char *env, char **ak, char **sk) {
  char *bu = NULL, *bp = NULL, *mu = NULL, *mp = NULL;
  const char *p = env;
  while (*p) {
    size_t n = strcspn(p, "\n");
    char *line = strndup(p, n);
    char *k, *v;
    bool skip;
    if (buckets_config_env_line(line, &k, &v, &skip) && !skip) {
      char **slot = !strcmp(k, "BUCKETS_ROOT_USER")       ? &bu
                    : !strcmp(k, "BUCKETS_ROOT_PASSWORD") ? &bp
                    : !strcmp(k, "MINIO_ROOT_USER")       ? &mu
                    : !strcmp(k, "MINIO_ROOT_PASSWORD")   ? &mp
                                                          : NULL;
      if (slot) {
        free(*slot);
        *slot = v;
        v = NULL;
      }
    }
    free(k);
    free(v);
    free(line);
    p += n + (p[n] == '\n');
  }
  if (bu && *bu) {
    *ak = bu;
    free(mu);
  } else {
    *ak = mu;
    free(bu);
  }
  if (bp && *bp) {
    *sk = bp;
    free(mp);
  } else {
    *sk = mp;
    free(bp);
  }
}

static yyjson_doc *get_secret(op_ctx *o, const char *ns, const char *name) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "/api/v1/namespaces/%s/secrets/%s", ns, name);
  yyjson_doc *d = NULL;
  int st = kube_get(o->k, p.data, &d);
  buckets_buf_free(&p);
  if (st != 200) {
    yyjson_doc_free(d);
    return NULL;
  }
  return d;
}

/* Connects to a BucketsCluster as root. err explains a failure. */
static bool cluster_connect(op_ctx *o, yyjson_val *bc, conn *cn, char *err, size_t errlen) {
  memset(cn, 0, sizeof(*cn));
  bc_spec s;
  if (!bc_parse(bc, o->cluster_domain, &s, err, errlen)) return false;
  char secret_name[128];
  bc_creds_secret_name(&s, secret_name, sizeof(secret_name));
  yyjson_doc *sd = get_secret(o, s.ns, secret_name);
  char *ak = NULL, *sk = NULL;
  if (sd && s.config_secret) {
    char *env = secret_value(yyjson_doc_get_root(sd), "config.env");
    if (env) config_env_creds(env, &ak, &sk);
    free(env);
  } else if (sd) {
    ak = secret_value(yyjson_doc_get_root(sd), "rootUser");
    sk = secret_value(yyjson_doc_get_root(sd), "rootPassword");
  }
  yyjson_doc_free(sd);
  if (!ak || !sk) {
    snprintf(err, errlen, "root credentials Secret %s is missing or incomplete", secret_name);
    free(ak);
    free(sk);
    return false;
  }
  /* The CA for a TLS cluster: its CA Secret, else the TLS Secret's ca.crt. */
  if (s.tls_secret) {
    yyjson_doc *cad = get_secret(o, s.ns, s.ca_secret ? s.ca_secret : s.tls_secret);
    char *ca = cad ? secret_value(yyjson_doc_get_root(cad), "ca.crt") : NULL;
    if (!ca && cad) ca = secret_value(yyjson_doc_get_root(cad), "tls.crt");
    yyjson_doc_free(cad);
    if (ca) {
      char path[] = "/tmp/buckets-operator-ca-XXXXXX";
      int fd = mkstemp(path);
      if (fd >= 0) {
        ssize_t w = write(fd, ca, strlen(ca));
        close(fd);
        if (w == (ssize_t)strlen(ca)) cn->ca_file = buckets_xstrdup(path);
        else unlink(path);
      }
      free(ca);
    }
  }
  const char *override = yyjson_get_str(
      yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(bc, "metadata"), "annotations"), ENDPOINT_ANNOTATION));
  char url[512];
  if (override) snprintf(url, sizeof(url), "%s", override);
  else snprintf(url, sizeof(url), "%s://%s.%s.svc.%s:%d", s.tls_secret ? "https" : "http", s.name, s.ns,
                s.cluster_domain, BC_S3_PORT);
  cn->c = s3c_new(url, cn->ca_file, ak, sk, err, errlen);
  free(ak);
  free(sk);
  if (!cn->c) conn_free(cn);
  return cn->c != NULL;
}

struct op_admin {
  conn cn;
};

op_admin *op_cluster_admin(op_ctx *o, yyjson_val *bc, char *err, size_t errlen) {
  op_admin *a = buckets_xcalloc(1, sizeof(*a));
  if (!cluster_connect(o, bc, &a->cn, err, errlen)) {
    free(a);
    return NULL;
  }
  return a;
}

struct s3c *op_admin_client(op_admin *a) { return a ? a->cn.c : NULL; }

void op_cluster_admin_free(op_admin *a) {
  if (!a) return;
  conn_free(&a->cn);
  free(a);
}

/* ---- object helpers ---------------------------------------------------------------- */

static void object_path(buckets_buf *p, yyjson_val *obj, const char *plural, const char *sub) {
  buckets_buf_appendf(p, GROUP_PATH "/namespaces/%s/%s/%s%s", get_str(obj, "metadata.namespace"), plural,
                      get_str(obj, "metadata.name"), sub ? sub : "");
}

static yyjson_mut_val *skeleton(yyjson_mut_doc *d, yyjson_val *obj, const char *kind) {
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "apiVersion", BC_API_VERSION);
  yyjson_mut_obj_add_strcpy(d, root, "kind", kind);
  yyjson_mut_val *meta = yyjson_mut_obj_add_obj(d, root, "metadata");
  yyjson_mut_obj_add_strcpy(d, meta, "name", get_str(obj, "metadata.name"));
  yyjson_mut_obj_add_strcpy(d, meta, "namespace", get_str(obj, "metadata.namespace"));
  return root;
}

/* Owns (or releases) our finalizer on the object. */
static void set_finalizer(op_ctx *o, yyjson_val *obj, const char *plural, const char *kind, bool present) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = skeleton(d, obj, kind);
  yyjson_mut_val *fin = yyjson_mut_obj_add_arr(d, yyjson_mut_obj_get(root, "metadata"), "finalizers");
  if (present) yyjson_mut_arr_add_str(d, fin, FINALIZER);
  buckets_buf p = BUCKETS_BUF_INIT;
  object_path(&p, obj, plural, NULL);
  yyjson_doc *resp;
  int st = kube_apply(o->k, p.data, d, &resp);
  if (st / 100 != 2 && st != 404) buckets_log_warn("finalizer on %s: %d %s", p.data, st, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&p);
  yyjson_mut_doc_free(d);
}

static bool has_finalizer(yyjson_val *obj) {
  size_t i, max;
  yyjson_val *f;
  yyjson_arr_foreach(yyjson_obj_get(yyjson_obj_get(obj, "metadata"), "finalizers"), i, max, f) {
    if (yyjson_equals_str(f, FINALIZER)) return true;
  }
  return false;
}

typedef struct {
  const char *phase, *message, *hash, *access_key;
  const char *const *groups;
  size_t ngroups;
} status_fields;

static void write_status(op_ctx *o, yyjson_val *obj, const char *plural, const char *kind, const status_fields *f) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = skeleton(d, obj, kind);
  yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, root, "status");
  yyjson_mut_obj_add_str(d, st, "phase", f->phase);
  yyjson_mut_obj_add_strcpy(d, st, "message", f->message ? f->message : "");
  yyjson_mut_obj_add_int(d, st, "observedGeneration",
                         yyjson_get_sint(yyjson_obj_get(yyjson_obj_get(obj, "metadata"), "generation")));
  if (f->hash) yyjson_mut_obj_add_strcpy(d, st, "appliedHash", f->hash);
  if (f->access_key) yyjson_mut_obj_add_strcpy(d, st, "accessKey", f->access_key);
  if (f->groups) {
    yyjson_mut_val *g = yyjson_mut_obj_add_arr(d, st, "groups");
    for (size_t i = 0; i < f->ngroups; i++) yyjson_mut_arr_add_strcpy(d, g, f->groups[i]);
  }
  buckets_buf p = BUCKETS_BUF_INIT;
  object_path(&p, obj, plural, "/status");
  yyjson_doc *resp;
  int code = kube_apply(o->k, p.data, d, &resp);
  if (code / 100 != 2 && code != 404) buckets_log_warn("status of %s: %d %s", p.data, code, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&p);
  yyjson_mut_doc_free(d);
}

static void hash_hex(const char *s, char out[17]) {
  uint8_t sum[32];
  buckets_sha256(s, strlen(s), sum);
  buckets_hex_encode(sum, 8, out);
}

/* "Code: message" from a failed call. */
static void call_error(const char *what, int status, const buckets_buf *body, char *msg, size_t cap) {
  char code[128];
  s3c_error_code(body, code, sizeof(code));
  if (!status) snprintf(msg, cap, "%s: cluster unreachable", what);
  else snprintf(msg, cap, "%s failed (%d%s%s)", what, status, *code ? " " : "", code);
}

/* ---- BucketsPolicy -------------------------------------------------------------------- */

static void reconcile_policy(op_ctx *o, yyjson_val *obj, conn *cn) {
  const char *name = get_str(obj, "metadata.name");
  bool deleting = get_str(obj, "metadata.deletionTimestamp") != NULL;
  buckets_buf body = BUCKETS_BUF_INIT;
  char msg[512];
  if (deleting) {
    if (!has_finalizer(obj)) return;
    char q[300];
    snprintf(q, sizeof(q), "name=%s", name);
    int st = s3c_admin(cn->c, "DELETE", "remove-canned-policy", q, NULL, 0, false, false, &body);
    char code[64];
    s3c_error_code(&body, code, sizeof(code));
    if (st == 200 || strcmp(code, "XMinioAdminNoSuchPolicy") == 0) {
      set_finalizer(o, obj, "bucketspolicies", "BucketsPolicy", false);
    } else {
      call_error("removing the policy", st, &body, msg, sizeof(msg));
      write_status(o, obj, "bucketspolicies", "BucketsPolicy", &(status_fields){.phase = "Deleting", .message = msg});
    }
    buckets_buf_free(&body);
    return;
  }
  if (!has_finalizer(obj)) set_finalizer(o, obj, "bucketspolicies", "BucketsPolicy", true);
  yyjson_val *pol = yyjson_obj_get(yyjson_obj_get(obj, "spec"), "policy");
  char *json = pol ? yyjson_val_write(pol, 0, NULL) : NULL;
  char hash[17];
  hash_hex(json ? json : "", hash);
  const char *applied = get_str(obj, "status.appliedHash"), *phase = get_str(obj, "status.phase");
  if (applied && strcmp(applied, hash) == 0 && phase && strcmp(phase, "Ready") == 0) {
    free(json);
    return;
  }
  char q[300];
  snprintf(q, sizeof(q), "name=%s", name);
  int st = json ? s3c_admin(cn->c, "PUT", "add-canned-policy", q, json, strlen(json), false, false, &body) : 0;
  if (st == 200) {
    write_status(o, obj, "bucketspolicies", "BucketsPolicy",
                 &(status_fields){.phase = "Ready", .message = "policy applied", .hash = hash});
  } else {
    call_error("applying the policy", st, &body, msg, sizeof(msg));
    write_status(o, obj, "bucketspolicies", "BucketsPolicy", &(status_fields){.phase = "Error", .message = msg});
  }
  free(json);
  buckets_buf_free(&body);
}

/* ---- BucketsUser ------------------------------------------------------------------------ */

static void set_membership(conn *cn, const char *group, const char *user, bool remove) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "group", group);
  yyjson_mut_val *m = yyjson_mut_obj_add_arr(d, root, "members");
  yyjson_mut_arr_add_strcpy(d, m, user);
  yyjson_mut_obj_add_bool(d, root, "isRemove", remove);
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  s3c_admin(cn->c, "PUT", "update-group-members", NULL, json, n, false, false, NULL);
  free(json);
  yyjson_mut_doc_free(d);
}

static void reconcile_user(op_ctx *o, yyjson_val *obj, conn *cn) {
  const char *ns = get_str(obj, "metadata.namespace");
  bool deleting = get_str(obj, "metadata.deletionTimestamp") != NULL;
  const char *status_ak = get_str(obj, "status.accessKey");
  buckets_buf body = BUCKETS_BUF_INIT;
  char msg[512];
  if (deleting) {
    if (!has_finalizer(obj)) return;
    if (status_ak) {
      buckets_buf q = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&q, "accessKey=");
      buckets_url_encode(&q, status_ak, false);
      int st = s3c_admin(cn->c, "DELETE", "remove-user", q.data, NULL, 0, false, false, &body);
      buckets_buf_free(&q);
      char code[64];
      s3c_error_code(&body, code, sizeof(code));
      if (st != 200 && strcmp(code, "XMinioAdminNoSuchUser") != 0) {
        call_error("removing the user", st, &body, msg, sizeof(msg));
        write_status(o, obj, "bucketsusers", "BucketsUser",
                     &(status_fields){.phase = "Deleting", .message = msg, .access_key = status_ak});
        buckets_buf_free(&body);
        return;
      }
    }
    set_finalizer(o, obj, "bucketsusers", "BucketsUser", false);
    buckets_buf_free(&body);
    return;
  }
  if (!has_finalizer(obj)) set_finalizer(o, obj, "bucketsusers", "BucketsUser", true);

  const char *secret = get_str(obj, "spec.credsSecret.name");
  yyjson_doc *sd = secret ? get_secret(o, ns, secret) : NULL;
  char *ak = sd ? secret_value(yyjson_doc_get_root(sd), "accessKey") : NULL;
  char *sk = sd ? secret_value(yyjson_doc_get_root(sd), "secretKey") : NULL;
  yyjson_doc_free(sd);
  if (!ak || !sk) {
    snprintf(msg, sizeof(msg), "Secret %s needs keys accessKey and secretKey", secret ? secret : "(unset)");
    write_status(o, obj, "bucketsusers", "BucketsUser",
                 &(status_fields){.phase = "Pending", .message = msg, .access_key = status_ak});
    free(ak);
    free(sk);
    return;
  }

  /* Desired policies and groups; skip everything when nothing changed. */
  yyjson_val *spec = yyjson_obj_get(obj, "spec");
  buckets_buf policies = BUCKETS_BUF_INIT, fp = BUCKETS_BUF_INIT;
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(yyjson_obj_get(spec, "policies"), i, max, v) {
    if (!yyjson_is_str(v)) continue;
    if (policies.len) buckets_buf_append_c(&policies, ",");
    buckets_buf_append_c(&policies, yyjson_get_str(v));
  }
  yyjson_val *gv = yyjson_obj_get(spec, "groups");
  size_t ng = yyjson_is_arr(gv) ? yyjson_arr_size(gv) : 0;
  const char **groups = buckets_xcalloc(ng ? ng : 1, sizeof(char *));
  size_t k = 0;
  yyjson_arr_foreach(gv, i, max, v) {
    if (yyjson_is_str(v)) groups[k++] = yyjson_get_str(v);
  }
  ng = k;
  buckets_buf_appendf(&fp, "%s\n%s\n%s\n", ak, sk, policies.data ? policies.data : "");
  for (size_t g = 0; g < ng; g++) buckets_buf_appendf(&fp, "%s,", groups[g]);
  char hash[17];
  hash_hex(fp.data, hash);
  const char *applied = get_str(obj, "status.appliedHash"), *phase = get_str(obj, "status.phase");
  bool unchanged = applied && strcmp(applied, hash) == 0 && phase && strcmp(phase, "Ready") == 0;
  int st = 0;
  if (!unchanged) {
    /* The user (idempotent), its policies (replaced), then its groups. */
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_strcpy(d, root, "secretKey", sk);
    yyjson_mut_obj_add_str(d, root, "status", "enabled");
    size_t n;
    char *json = yyjson_mut_write(d, 0, &n);
    yyjson_mut_doc_free(d);
    buckets_buf q = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&q, "accessKey=");
    buckets_url_encode(&q, ak, false);
    st = s3c_admin(cn->c, "PUT", "add-user", q.data, json, n, true, false, &body);
    free(json);
    if (st == 200) {
      buckets_buf_reset(&q);
      buckets_buf_append_c(&q, "policyName=");
      buckets_url_encode(&q, policies.data ? policies.data : "", false);
      buckets_buf_append_c(&q, "&userOrGroup=");
      buckets_url_encode(&q, ak, false);
      buckets_buf_append_c(&q, "&isGroup=false");
      st = s3c_admin(cn->c, "PUT", "set-user-or-group-policy", q.data, NULL, 0, false, false, &body);
    }
    if (st == 200) {
      for (size_t g = 0; g < ng; g++) set_membership(cn, groups[g], ak, false);
      /* Leave groups dropped from the spec. */
      yyjson_arr_foreach(yyjson_obj_get(yyjson_obj_get(obj, "status"), "groups"), i, max, v) {
        bool keep = false;
        for (size_t g = 0; g < ng && !keep; g++) keep = yyjson_equals_str(v, groups[g]);
        if (!keep && yyjson_is_str(v)) set_membership(cn, yyjson_get_str(v), ak, true);
      }
    }
    buckets_buf_free(&q);
    if (st == 200) {
      write_status(o, obj, "bucketsusers", "BucketsUser",
                   &(status_fields){.phase = "Ready", .message = "user applied", .hash = hash, .access_key = ak,
                                    .groups = groups, .ngroups = ng});
    } else {
      call_error("applying the user", st, &body, msg, sizeof(msg));
      write_status(o, obj, "bucketsusers", "BucketsUser",
                   &(status_fields){.phase = "Error", .message = msg, .access_key = status_ak});
    }
  }
  free(groups);
  buckets_buf_free(&policies);
  buckets_buf_free(&fp);
  buckets_buf_free(&body);
  free(ak);
  free(sk);
}

/* ---- Bucket ---------------------------------------------------------------------------------- */

static void reconcile_bucket(op_ctx *o, yyjson_val *obj, conn *cn) {
  if (get_str(obj, "metadata.deletionTimestamp")) return; /* the data stays: deleting buckets is left to people */
  const char *phase = get_str(obj, "status.phase");
  if (phase && strcmp(phase, "Ready") == 0) return;
  yyjson_val *spec = yyjson_obj_get(obj, "spec");
  const char *name = get_str(spec, "name");
  if (!name) name = get_str(obj, "metadata.name");
  buckets_buf path = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&path, "/");
  buckets_url_encode(&path, name, false);
  int st = s3c_request(cn->c, "PUT", path.data, NULL, NULL, NULL, 0, &body);
  char code[64], msg[512];
  s3c_error_code(&body, code, sizeof(code));
  if (st == 200 || strcmp(code, "BucketAlreadyOwnedByYou") == 0) {
    bool extras = yyjson_get_bool(yyjson_obj_get(spec, "versioning")) ||
                  yyjson_get_bool(yyjson_obj_get(spec, "objectLock")) || get_str(spec, "quota");
    snprintf(msg, sizeof(msg), "bucket %s exists%s", name,
             extras ? "; versioning, object lock and quota are not applied yet" : "");
    write_status(o, obj, "buckets", "Bucket", &(status_fields){.phase = "Ready", .message = msg});
  } else {
    call_error("creating the bucket", st, &body, msg, sizeof(msg));
    write_status(o, obj, "buckets", "Bucket", &(status_fields){.phase = "Error", .message = msg});
  }
  buckets_buf_free(&path);
  buckets_buf_free(&body);
}

/* ---- the pass --------------------------------------------------------------------------------- */

static yyjson_val *find_cluster(yyjson_val *clusters, const char *ns, const char *name) {
  size_t i, max;
  yyjson_val *bc;
  yyjson_arr_foreach(clusters, i, max, bc) {
    const char *bns = get_str(bc, "metadata.namespace"), *bn = get_str(bc, "metadata.name");
    if (bns && bn && strcmp(bns, ns) == 0 && strcmp(bn, name) == 0) return bc;
  }
  return NULL;
}

typedef void (*reconcile_fn)(op_ctx *o, yyjson_val *obj, conn *cn);

static void reconcile_kind(op_ctx *o, yyjson_val *clusters, const char *plural, const char *kind, reconcile_fn fn) {
  buckets_buf path = BUCKETS_BUF_INIT;
  if (o->namespace) buckets_buf_appendf(&path, GROUP_PATH "/namespaces/%s/%s", o->namespace, plural);
  else buckets_buf_appendf(&path, GROUP_PATH "/%s", plural);
  yyjson_doc *doc = NULL;
  if (kube_get(o->k, path.data, &doc) == 200) {
    size_t i, max;
    yyjson_val *it;
    yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(doc), "items"), i, max, it) {
      const char *ns = get_str(it, "metadata.namespace"), *cname = get_str(it, "spec.cluster");
      yyjson_val *bc = cname ? find_cluster(clusters, ns, cname) : NULL;
      if (!bc) {
        if (get_str(it, "metadata.deletionTimestamp") && has_finalizer(it)) {
          /* The cluster is gone, and the user or policy with it. */
          set_finalizer(o, it, plural, kind, false);
          continue;
        }
        char msg[300];
        snprintf(msg, sizeof(msg), "BucketsCluster %s not found in namespace %s", cname ? cname : "(unset)", ns);
        write_status(o, it, plural, kind, &(status_fields){.phase = "Pending", .message = msg});
        continue;
      }
      conn cn;
      char err[512];
      if (!cluster_connect(o, bc, &cn, err, sizeof(err))) {
        write_status(o, it, plural, kind, &(status_fields){.phase = "Pending", .message = err});
        continue;
      }
      fn(o, it, &cn);
      conn_free(&cn);
    }
  }
  yyjson_doc_free(doc);
  buckets_buf_free(&path);
}

void op_reconcile_iam(op_ctx *o, yyjson_val *clusters) {
  /* Policies first: users refer to them. */
  reconcile_kind(o, clusters, "bucketspolicies", "BucketsPolicy", reconcile_policy);
  reconcile_kind(o, clusters, "bucketsusers", "BucketsUser", reconcile_user);
  reconcile_kind(o, clusters, "buckets", "Bucket", reconcile_bucket);
}
