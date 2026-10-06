/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* BucketsSiteReplication: site replication between BucketsClusters (and
 * other sites), set up through the first site's admin API as `mc admin
 * replicate add` does (docs/design/declarative-buckets.md). Sites added to
 * the list are added and sites taken out are removed; a list of one site
 * stops the replication. Deleting the resource leaves it in place. */
#include "sitereplication.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "iam.h"
#include "manifests.h"

#define GROUP_PATH "/apis/buckets.io/v1alpha1"
#define PLURAL "bucketssitereplications"
#define KIND "BucketsSiteReplication"
#define DATA_SITE_ERROR "please send your request to the cluster containing data/buckets: "

typedef struct {
  char name[128], url[512];
  char *ak, *sk;
  op_admin *adm; /* a BucketsCluster */
  s3c *c;        /* another site */
} site;

static const char *str_at(yyjson_val *o, const char *a, const char *b) {
  yyjson_val *v = yyjson_obj_get(o, a);
  return yyjson_get_str(b ? yyjson_obj_get(v, b) : v);
}

static s3c *client(site *s) { return s->adm ? op_admin_client(s->adm) : s->c; }

static void sites_free(site *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (s[i].sk) memset(s[i].sk, 0, strlen(s[i].sk));
    free(s[i].ak);
    free(s[i].sk);
    op_cluster_admin_free(s[i].adm);
    s3c_free(s[i].c);
  }
  free(s);
}

/* Each site's name, URL, root credentials and admin client. */
static bool resolve(op_ctx *o, yyjson_val *clusters, const char *ns, yyjson_val *list, site **out,
                    size_t *nout, char *msg, size_t cap) {
  size_t n = yyjson_arr_size(list), i, max;
  site *s = buckets_xcalloc(n ? n : 1, sizeof(*s));
  *out = s;
  *nout = n;
  yyjson_val *v;
  yyjson_arr_foreach(list, i, max, v) {
    const char *cl = str_at(v, "cluster", NULL), *ep = str_at(v, "endpoint", NULL);
    if (cl) {
      yyjson_val *bc = op_find_cluster(clusters, ns, cl);
      if (!bc) {
        snprintf(msg, cap, "BucketsCluster %s not found in namespace %s", cl, ns);
        return false;
      }
      snprintf(s[i].name, sizeof(s[i].name), "%s", str_at(v, "name", NULL) ? str_at(v, "name", NULL) : cl);
      char err[512];
      if (!op_cluster_peer(o, bc, s[i].url, sizeof(s[i].url), &s[i].ak, &s[i].sk, err, sizeof(err)) ||
          !(s[i].adm = op_cluster_admin(o, bc, err, sizeof(err)))) {
        snprintf(msg, cap, "site %s: %s", cl, err);
        return false;
      }
    } else {
      const char *secret = str_at(v, "credsSecret", "name");
      snprintf(s[i].name, sizeof(s[i].name), "%s", str_at(v, "name", NULL));
      snprintf(s[i].url, sizeof(s[i].url), "%s", ep);
      char *data[2] = {NULL, NULL};
      if (!op_secret_pair(o, ns, secret, "accessKey", "secretKey", &data[0], &data[1])) {
        snprintf(msg, cap, "site %s: Secret %s needs accessKey and secretKey", s[i].name,
                 secret ? secret : "");
        return false;
      }
      s[i].ak = data[0], s[i].sk = data[1];
      char err[512];
      if (!(s[i].c = s3c_new(ep, NULL, s[i].ak, s[i].sk, err, sizeof(err)))) {
        snprintf(msg, cap, "site %s: %s", s[i].name, err);
        return false;
      }
    }
  }
  return true;
}

/* Checks the list; false and why. */
static bool check(yyjson_val *list, char *msg, size_t cap) {
  if (!yyjson_arr_size(list)) {
    snprintf(msg, cap, "sites needs at least one site (one alone stops the replication through it)");
    return false;
  }
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(list, i, max, v) {
    const char *cl = str_at(v, "cluster", NULL), *ep = str_at(v, "endpoint", NULL),
               *name = str_at(v, "name", NULL);
    if (!cl == !ep) {
      snprintf(msg, cap, "site %zu is {cluster} or {name, endpoint, credsSecret}", i + 1);
      return false;
    }
    if (ep && (!name || !str_at(v, "credsSecret", "name"))) {
      snprintf(msg, cap, "site %zu: an endpoint needs a name and credsSecret", i + 1);
      return false;
    }
    const char *mine = name ? name : cl;
    for (size_t j = 0; j < i; j++) {
      yyjson_val *w = yyjson_arr_get(list, j);
      const char *other = str_at(w, "name", NULL) ? str_at(w, "name", NULL) : str_at(w, "cluster", NULL);
      if (other && strcmp(other, mine) == 0) {
        snprintf(msg, cap, "site name %s is used twice", mine);
        return false;
      }
    }
  }
  return true;
}

/* site-replication/add through via, with every site's credentials (encrypted with via's secret key). */
static int add_sites(site *via, site *s, size_t n, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, arr);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *p = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, p, "name", s[i].name);
    yyjson_mut_obj_add_strcpy(d, p, "endpoints", s[i].url);
    yyjson_mut_obj_add_strcpy(d, p, "accessKey", s[i].ak);
    yyjson_mut_obj_add_strcpy(d, p, "secretKey", s[i].sk);
  }
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  yyjson_mut_doc_free(d);
  int st = s3c_admin(client(via), "PUT", "site-replication/add", NULL, json, len, true, false, out);
  if (json) memset(json, 0, len);
  free(json);
  return st;
}

static void error_message(const char *what, int st, const buckets_buf *body, char *msg, size_t cap) {
  if (!st) {
    snprintf(msg, cap, "%s: site unreachable", what);
    return;
  }
  yyjson_doc *d = yyjson_read(body->data ? body->data : "", body->len, 0);
  const char *m = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "Message"));
  char code[128];
  s3c_error_code(body, code, sizeof(code));
  snprintf(msg, cap, "%s failed (%d %s): %s", what, st, code, m ? m : "");
  yyjson_doc_free(d);
}

static void write_status(op_ctx *o, yyjson_val *obj, const char *phase, const char *message, const char *hash,
                         const char *checked_at, site *s, size_t n) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "apiVersion", BC_API_VERSION);
  yyjson_mut_obj_add_str(d, root, "kind", KIND);
  yyjson_mut_val *meta = yyjson_mut_obj_add_obj(d, root, "metadata");
  const char *name = str_at(obj, "metadata", "name"), *ns = str_at(obj, "metadata", "namespace");
  yyjson_mut_obj_add_strcpy(d, meta, "name", name);
  yyjson_mut_obj_add_strcpy(d, meta, "namespace", ns);
  yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, root, "status");
  yyjson_mut_obj_add_str(d, st, "phase", phase);
  yyjson_mut_obj_add_strcpy(d, st, "message", message);
  yyjson_mut_obj_add_int(d, st, "observedGeneration",
                         yyjson_get_sint(yyjson_obj_get(yyjson_obj_get(obj, "metadata"), "generation")));
  if (hash) yyjson_mut_obj_add_strcpy(d, st, "appliedHash", hash);
  if (checked_at) yyjson_mut_obj_add_strcpy(d, st, "checkedAt", checked_at);
  if (s && n > 1) {
    yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, st, "sites");
    for (size_t i = 0; i < n; i++) yyjson_mut_arr_add_strcpy(d, a, s[i].name);
  }
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, GROUP_PATH "/namespaces/%s/" PLURAL "/%s/status", ns, name);
  yyjson_doc *resp = NULL;
  int code = kube_apply(o->k, p.data, d, &resp);
  if (code / 100 != 2 && code != 404)
    buckets_log_warn("status of %s: %d %s", p.data, code, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&p);
  yyjson_mut_doc_free(d);
}

static void spec_hash(yyjson_val *spec, char out[17]) {
  size_t n;
  char *j = yyjson_val_write(spec, 0, &n);
  uint8_t h[32];
  buckets_sha256(j ? j : "", j ? n : 0, h);
  free(j);
  buckets_hex_encode(h, 8, out);
  out[16] = '\0';
}

static bool due(yyjson_val *obj, const char *hash) {
  const char *phase = str_at(obj, "status", "phase"), *applied = str_at(obj, "status", "appliedHash"),
             *checked = str_at(obj, "status", "checkedAt");
  long long sec;
  long nsec;
  if (!phase || strcmp(phase, "Ready") != 0 || !applied || strcmp(applied, hash) != 0 || !checked ||
      !buckets_time_parse_rfc3339(checked, &sec, &nsec))
    return true;
  return ((long long)time(NULL) - sec) * 1000 >= op_drift_interval_ms();
}

/* How many of the sites a site-replication/info reply has. */
static size_t present(yyjson_val *info, const site *s, size_t n) {
  if (!yyjson_get_bool(yyjson_obj_get(info, "enabled"))) return 0;
  size_t have = 0, i, max;
  yyjson_val *v;
  yyjson_arr_foreach(yyjson_obj_get(info, "sites"), i, max, v) {
    const char *name = str_at(v, "name", NULL);
    for (size_t k = 0; k < n; k++) have += name && strcmp(name, s[k].name) == 0;
  }
  return have;
}

static void reconcile_one(op_ctx *o, yyjson_val *obj, yyjson_val *clusters) {
  if (str_at(obj, "metadata", "deletionTimestamp")) return; /* the replication stays */
  yyjson_val *spec = yyjson_obj_get(obj, "spec"), *list = yyjson_obj_get(spec, "sites");
  char hash[17], msg[1024] = "", now[32];
  spec_hash(spec, hash);
  if (!due(obj, hash)) return;
  buckets_time_iso8601(time(NULL), now);
  if (!check(list, msg, sizeof(msg))) {
    write_status(o, obj, "Error", msg, NULL, NULL, NULL, 0);
    return;
  }
  site *s = NULL;
  size_t n = 0;
  buckets_buf body = BUCKETS_BUF_INIT;
  const char *phase = "Error";
  yyjson_doc *info = NULL;
  if (!resolve(o, clusters, str_at(obj, "metadata", "namespace"), list, &s, &n, msg, sizeof(msg))) {
    phase = "Pending";
    goto out;
  }
  /* what the first site has */
  int st = s3c_admin(client(&s[0]), "GET", "site-replication/info", NULL, NULL, 0, false, false, &body);
  info = st == 200 ? yyjson_read(body.data, body.len, 0) : NULL;
  if (!info) {
    error_message("reading site replication", st, &body, msg, sizeof(msg));
    goto out;
  }
  yyjson_val *iroot = yyjson_doc_get_root(info), *cur = yyjson_obj_get(iroot, "sites");
  bool enabled = yyjson_get_bool(yyjson_obj_get(iroot, "enabled"));
  size_t i, max;
  yyjson_val *v;

  /* sites taken out of the list (all of them when one is left) */
  yyjson_mut_doc *rd = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *rroot = yyjson_mut_obj(rd), *gone = yyjson_mut_obj_add_arr(rd, rroot, "sites");
  yyjson_mut_doc_set_root(rd, rroot);
  if (enabled && n == 1) {
    yyjson_mut_obj_add_bool(rd, rroot, "all", true);
  } else if (enabled) {
    yyjson_arr_foreach(cur, i, max, v) {
      const char *cn = str_at(v, "name", NULL);
      bool keep = false;
      for (size_t k = 0; k < n && !keep; k++) keep = cn && strcmp(cn, s[k].name) == 0;
      if (!keep && cn) yyjson_mut_arr_add_strcpy(rd, gone, cn);
    }
    yyjson_mut_obj_add_bool(rd, rroot, "all", false);
  }
  bool remove = enabled && (n == 1 || yyjson_mut_arr_size(gone));
  if (remove) {
    size_t len;
    char *j = yyjson_mut_write(rd, 0, &len);
    st = s3c_admin(client(&s[0]), "PUT", "site-replication/remove", NULL, j, len, false, false, &body);
    free(j);
    if (st != 200) {
      yyjson_mut_doc_free(rd);
      error_message("removing sites", st, &body, msg, sizeof(msg));
      goto out;
    }
    buckets_log_info("site replication %s: %s", str_at(obj, "metadata", "name"),
                     n == 1 ? "stopped" : "sites removed");
  }
  yyjson_mut_doc_free(rd);
  if (n == 1) {
    snprintf(msg, sizeof(msg), "one site: no site replication");
    phase = "Ready";
    goto out;
  }

  /* sites missing from it: add them all, as the add call takes the whole list */
  if (remove) { /* what is left */
    yyjson_doc_free(info);
    st = s3c_admin(client(&s[0]), "GET", "site-replication/info", NULL, NULL, 0, false, false, &body);
    info = st == 200 ? yyjson_read(body.data, body.len, 0) : NULL;
  }
  size_t have = present(yyjson_doc_get_root(info), s, n);
  if (have != n) {
    site *via = &s[0];
    st = add_sites(via, s, n, &body);
    if (st != 200) { /* the add must go through the one site with buckets */
      char m[1024];
      error_message("adding sites", st, &body, m, sizeof(m));
      const char *p = strstr(m, DATA_SITE_ERROR);
      for (size_t k = 1; p && k < n && via == &s[0]; k++)
        if (strcmp(p + strlen(DATA_SITE_ERROR), s[k].name) == 0) via = &s[k];
      if (via != &s[0]) st = add_sites(via, s, n, &body);
      if (st != 200) {
        error_message("adding sites", st, &body, msg, sizeof(msg));
        goto out;
      }
    }
    buckets_log_info("site replication %s: %zu sites", str_at(obj, "metadata", "name"), n);
  }
  buckets_buf names = BUCKETS_BUF_INIT;
  for (size_t k = 0; k < n; k++) buckets_buf_appendf(&names, "%s%s", k ? ", " : "", s[k].name);
  snprintf(msg, sizeof(msg), "%zu sites replicate: %s", n, names.data);
  buckets_buf_free(&names);
  phase = "Ready";

out:
  write_status(o, obj, phase, msg, strcmp(phase, "Ready") == 0 ? hash : NULL,
               strcmp(phase, "Ready") == 0 ? now : NULL, s, n);
  yyjson_doc_free(info);
  buckets_buf_free(&body);
  sites_free(s, n);
}

void op_reconcile_site_replication(op_ctx *o, yyjson_val *clusters) {
  buckets_buf path = BUCKETS_BUF_INIT;
  if (o->namespace)
    buckets_buf_appendf(&path, GROUP_PATH "/namespaces/%s/" PLURAL, o->namespace);
  else
    buckets_buf_appendf(&path, GROUP_PATH "/" PLURAL);
  yyjson_doc *doc = NULL;
  if (kube_get(o->k, path.data, &doc) == 200) {
    size_t i, max;
    yyjson_val *it;
    yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(doc), "items"), i, max, it)
        reconcile_one(o, it, clusters);
  }
  yyjson_doc_free(doc);
  buckets_buf_free(&path);
}
