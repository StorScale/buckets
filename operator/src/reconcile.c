/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "reconcile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "iam.h"
#include "manifests.h"

#define GROUP_PATH "/apis/buckets.io/v1alpha1"

static void rfc3339_now(char out[32]) {
  time_t t = time(NULL);
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static const char *get_str(yyjson_val *o, const char *path) {
  /* path: dot-separated keys */
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

/* metadata.labels / metadata.annotations entries (their keys contain dots). */
static const char *meta_map(yyjson_val *obj, const char *map, const char *key) {
  return yyjson_get_str(yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(obj, "metadata"), map), key));
}

/* ---- credentials ------------------------------------------------------------ */

static void random_token(char *out, size_t n, bool upper_only) {
  static const char full[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const char *set = upper_only ? upper : full;
  size_t m = strlen(set);
  uint8_t r[64];
  buckets_random_bytes(r, n);
  for (size_t i = 0; i < n; i++) out[i] = set[r[i] % m];
  out[n] = '\0';
}

/* Makes sure the root credentials exist. Returns false (why in msg) if not. */
static bool ensure_creds(op_ctx *o, const bc_spec *s, char *msg, size_t cap) {
  char name[128];
  bc_creds_secret_name(s, name, sizeof(name));
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/api/v1/namespaces/%s/secrets/%s", s->ns, name);
  yyjson_doc *got = NULL;
  int st = kube_get(o->k, path.data, s->config_secret ? &got : NULL);
  bool ok = st == 200;
  if (ok && s->config_secret &&
      !yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(got), "data"), "config.env")) {
    snprintf(msg, cap, "configuration Secret %s has no config.env", name);
    ok = false;
  }
  yyjson_doc_free(got);
  if (st == 404 && !s->creds_secret && !s->config_secret) {
    char user[21], pass[41];
    random_token(user, 20, true); /* MinIO operator's shapes: 20 and 40 characters */
    random_token(pass, 40, false);
    yyjson_mut_doc *d = bc_root_secret(s, user, pass);
    buckets_buf coll = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&coll, "/api/v1/namespaces/%s/secrets", s->ns);
    yyjson_doc *resp;
    st = kube_create(o->k, coll.data, d, &resp);
    ok = st == 201 || st == 409;
    if (ok && st == 201) buckets_log_info("%s/%s: generated root credentials in Secret %s", s->ns, s->name, name);
    if (!ok) snprintf(msg, cap, "creating Secret %s failed (%d): %s", name, st, kube_error_message(resp));
    yyjson_doc_free(resp);
    yyjson_mut_doc_free(d);
    buckets_buf_free(&coll);
  } else if (!ok) {
    snprintf(msg, cap, "credentials Secret %s: %s", name, st == 404 ? "not found" : "cannot be read");
  }
  buckets_buf_free(&path);
  return ok;
}

/* The console's cookie key: random, created once, kept across restarts so
 * sessions survive them (and are shared by the console's replicas). */
static bool ensure_console_secret(op_ctx *o, const bc_spec *s, char *msg, size_t cap) {
  char name[128];
  bc_console_secret_name(s, name, sizeof(name));
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/api/v1/namespaces/%s/secrets/%s", s->ns, name);
  int st = kube_get(o->k, path.data, NULL);
  bool ok = st == 200;
  if (st == 404) {
    char pass[48], salt[24];
    random_token(pass, 40, false);
    random_token(salt, 16, false);
    yyjson_mut_doc *d = bc_console_secret(s, pass, salt);
    buckets_buf coll = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&coll, "/api/v1/namespaces/%s/secrets", s->ns);
    yyjson_doc *resp;
    st = kube_create(o->k, coll.data, d, &resp);
    ok = st == 201 || st == 409;
    if (!ok) snprintf(msg, cap, "creating Secret %s failed (%d): %s", name, st, kube_error_message(resp));
    yyjson_doc_free(resp);
    yyjson_mut_doc_free(d);
    buckets_buf_free(&coll);
  } else if (!ok) {
    snprintf(msg, cap, "console Secret %s cannot be read (%d)", name, st);
  }
  buckets_buf_free(&path);
  return ok;
}

/* ---- pods: coordinated restarts ------------------------------------------------ */

static bool pod_ready(yyjson_val *pod) {
  yyjson_val *conds = yyjson_obj_get(yyjson_obj_get(pod, "status"), "conditions");
  size_t i, max;
  yyjson_val *c;
  yyjson_arr_foreach(conds, i, max, c) {
    const char *t = get_str(c, "type"), *st = get_str(c, "status");
    if (t && st && strcmp(t, "Ready") == 0) return strcmp(st, "True") == 0;
  }
  return false;
}

/* Deletes pods whose spec is out of date. A topology change (endpoints,
 * erasure settings) restarts every pod at once: nodes that disagree on the
 * topology cannot form a cluster. Anything else rolls one pod at a time, and
 * only while all pods are ready. Returns how many pods were deleted. */
static int restart_pods(op_ctx *o, const bc_spec *s, const char *topology, yyjson_val **sts, size_t nsts,
                        size_t *outdated) {
  *outdated = 0;
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/api/v1/namespaces/%s/pods?labelSelector=buckets.io%%2Fcluster%%3D%s", s->ns, s->name);
  yyjson_doc *doc;
  int st = kube_get(o->k, path.data, &doc);
  buckets_buf_free(&path);
  if (st != 200) {
    yyjson_doc_free(doc);
    return 0;
  }
  yyjson_val *items = yyjson_obj_get(yyjson_doc_get_root(doc), "items");
  size_t i, max, total = 0, ready = 0, stale = 0;
  yyjson_val *pod;
  yyjson_arr_foreach(items, i, max, pod) {
    total++;
    ready += pod_ready(pod);
    const char *t = meta_map(pod, "annotations", "buckets.io/topology");
    if (!t || strcmp(t, topology) != 0) stale++;
  }
  int deleted = 0;
  /* Pods behind their StatefulSet's revision (an image or spec change). */
  yyjson_arr_foreach(items, i, max, pod) {
    const char *pool = meta_map(pod, "labels", "buckets.io/pool");
    const char *rev = meta_map(pod, "labels", "controller-revision-hash");
    for (size_t k = 0; pool && rev && k < nsts; k++) {
      const char *sp = meta_map(sts[k], "labels", "buckets.io/pool");
      const char *want = get_str(sts[k], "status.updateRevision");
      if (sp && strcmp(sp, pool) == 0 && want && strcmp(want, rev) != 0) (*outdated)++;
    }
  }
  *outdated += stale;
  if (stale) {
    buckets_log_info("%s/%s: topology changed; restarting %zu pod%s together", s->ns, s->name, stale,
                     stale == 1 ? "" : "s");
    yyjson_arr_foreach(items, i, max, pod) {
      const char *t = meta_map(pod, "annotations", "buckets.io/topology");
      if (t && strcmp(t, topology) == 0) continue;
      buckets_buf p = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&p, "/api/v1/namespaces/%s/pods/%s", s->ns, get_str(pod, "metadata.name"));
      if (kube_delete(o->k, p.data) / 100 == 2) deleted++;
      buckets_buf_free(&p);
    }
  } else {
    size_t servers = 0;
    for (size_t p = 0; p < s->npools; p++) servers += (size_t)s->pools[p].servers;
    if (total == servers && ready == total) {
      /* Roll the first out-of-date pod (StatefulSet revision label vs. the set's updateRevision). */
      yyjson_arr_foreach(items, i, max, pod) {
        const char *pool = meta_map(pod, "labels", "buckets.io/pool");
        const char *rev = meta_map(pod, "labels", "controller-revision-hash");
        for (size_t k = 0; pool && rev && k < nsts; k++) {
          const char *sp = meta_map(sts[k], "labels", "buckets.io/pool");
          const char *want = get_str(sts[k], "status.updateRevision");
          if (!sp || strcmp(sp, pool) != 0 || !want || strcmp(want, rev) == 0) continue;
          buckets_log_info("%s/%s: rolling pod %s to revision %s", s->ns, s->name, get_str(pod, "metadata.name"), want);
          buckets_buf p = BUCKETS_BUF_INIT;
          buckets_buf_appendf(&p, "/api/v1/namespaces/%s/pods/%s", s->ns, get_str(pod, "metadata.name"));
          if (kube_delete(o->k, p.data) / 100 == 2) deleted++;
          buckets_buf_free(&p);
          goto done;
        }
      }
    }
  }
done:
  yyjson_doc_free(doc);
  return deleted;
}

/* ---- status ------------------------------------------------------------------- */

static void write_status(op_ctx *o, yyjson_val *bc, const bc_spec *s, const char *phase, bool ready, const char *reason,
                         const char *message, const char *topology, yyjson_val **sts, size_t nsts) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "apiVersion", BC_API_VERSION);
  yyjson_mut_obj_add_str(d, root, "kind", BC_KIND);
  yyjson_mut_val *meta = yyjson_mut_obj_add_obj(d, root, "metadata");
  yyjson_mut_obj_add_strcpy(d, meta, "name", get_str(bc, "metadata.name"));
  yyjson_mut_obj_add_strcpy(d, meta, "namespace", get_str(bc, "metadata.namespace"));
  yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, root, "status");
  yyjson_mut_obj_add_strcpy(d, st, "phase", phase);
  yyjson_mut_obj_add_int(d, st, "observedGeneration", yyjson_get_sint(yyjson_obj_get(yyjson_obj_get(bc, "metadata"), "generation")));
  long long servers = 0, readyn = 0;
  if (s) {
    yyjson_mut_val *pools = yyjson_mut_obj_add_arr(d, st, "pools");
    for (size_t p = 0; p < s->npools; p++) {
      char name[128];
      bc_statefulset_name(s, p, name, sizeof(name));
      long long rr = 0;
      for (size_t k = 0; k < nsts; k++) {
        const char *n = get_str(sts[k], "metadata.name");
        if (n && strcmp(n, name) == 0) rr = yyjson_get_sint(yyjson_obj_get(yyjson_obj_get(sts[k], "status"), "readyReplicas"));
      }
      yyjson_mut_val *pe = yyjson_mut_arr_add_obj(d, pools);
      yyjson_mut_obj_add_strcpy(d, pe, "name", s->pools[p].name);
      yyjson_mut_obj_add_strcpy(d, pe, "statefulSet", name);
      yyjson_mut_obj_add_int(d, pe, "replicas", s->pools[p].servers);
      yyjson_mut_obj_add_int(d, pe, "readyReplicas", rr);
      servers += s->pools[p].servers;
      readyn += rr;
    }
    char creds[128];
    bc_creds_secret_name(s, creds, sizeof(creds));
    yyjson_mut_obj_add_strcpy(d, st, "credsSecret", creds);
  }
  yyjson_mut_obj_add_int(d, st, "servers", servers);
  yyjson_mut_obj_add_int(d, st, "readyServers", readyn);
  char text[32];
  snprintf(text, sizeof(text), "%lld/%lld", readyn, servers);
  yyjson_mut_obj_add_strcpy(d, st, "readyServersText", text);
  if (topology) yyjson_mut_obj_add_strcpy(d, st, "topology", topology);
  /* Ready condition; its transition time only moves when the status flips. */
  const char *want = ready ? "True" : "False";
  char when[32];
  rfc3339_now(when);
  yyjson_val *old = yyjson_obj_get(yyjson_obj_get(bc, "status"), "conditions");
  size_t i, max;
  yyjson_val *c;
  yyjson_arr_foreach(old, i, max, c) {
    const char *t = get_str(c, "type"), *os = get_str(c, "status"), *lt = get_str(c, "lastTransitionTime");
    if (t && strcmp(t, "Ready") == 0 && os && strcmp(os, want) == 0 && lt) snprintf(when, sizeof(when), "%s", lt);
  }
  yyjson_mut_val *cond = yyjson_mut_arr_add_obj(d, yyjson_mut_obj_add_arr(d, st, "conditions"));
  yyjson_mut_obj_add_str(d, cond, "type", "Ready");
  yyjson_mut_obj_add_str(d, cond, "status", want);
  yyjson_mut_obj_add_strcpy(d, cond, "reason", reason);
  yyjson_mut_obj_add_strcpy(d, cond, "message", message);
  yyjson_mut_obj_add_strcpy(d, cond, "lastTransitionTime", when);
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, GROUP_PATH "/namespaces/%s/bucketsclusters/%s/status", get_str(bc, "metadata.namespace"),
                      get_str(bc, "metadata.name"));
  yyjson_doc *resp;
  int code = kube_apply(o->k, path.data, d, &resp);
  if (code / 100 != 2) buckets_log_warn("status of %s: %d %s", path.data, code, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&path);
  yyjson_mut_doc_free(d);
}

/* ---- one cluster ---------------------------------------------------------------- */

static void reconcile_cluster(op_ctx *o, yyjson_val *bc) {
  bc_spec s;
  char err[512];
  if (!bc_parse(bc, o->cluster_domain, &s, err, sizeof(err))) {
    buckets_log_warn("%s/%s: invalid spec: %s", get_str(bc, "metadata.namespace"), get_str(bc, "metadata.name"), err);
    write_status(o, bc, NULL, "Invalid", false, "InvalidSpec", err, NULL, NULL, 0);
    return;
  }
  if (!ensure_creds(o, &s, err, sizeof(err))) {
    write_status(o, bc, &s, "Pending", false, "Credentials", err, NULL, NULL, 0);
    return;
  }
  if (s.console.enabled && !ensure_console_secret(o, &s, err, sizeof(err))) {
    write_status(o, bc, &s, "Pending", false, "ConsoleSecret", err, NULL, NULL, 0);
    return;
  }
  char topo[17];
  bc_topology(&s, topo);
  bc_object *objs;
  size_t n = bc_desired(&s, &objs);
  yyjson_doc *applied[2 * BC_MAX_POOLS + 5] = {0};
  yyjson_val *sts[BC_MAX_POOLS];
  size_t nsts = 0;
  bool failed = false;
  for (size_t i = 0; i < n; i++) {
    int code = kube_apply(o->k, objs[i].path, objs[i].doc, &applied[i]);
    if (code / 100 != 2) {
      snprintf(err, sizeof(err), "applying %s failed (%d): %s", objs[i].path, code, kube_error_message(applied[i]));
      buckets_log_warn("%s/%s: %s", s.ns, s.name, err);
      failed = true;
      break;
    }
    yyjson_val *r = yyjson_doc_get_root(applied[i]);
    const char *kind = get_str(r, "kind");
    if (kind && strcmp(kind, "StatefulSet") == 0 && nsts < BC_MAX_POOLS) sts[nsts++] = r;
  }
  if (failed) {
    write_status(o, bc, &s, "Error", false, "ApplyFailed", err, topo, sts, nsts);
  } else {
    size_t outdated = 0;
    int restarted = restart_pods(o, &s, topo, sts, nsts, &outdated);
    long long servers = 0, ready = 0;
    for (size_t p = 0; p < s.npools; p++) servers += s.pools[p].servers;
    for (size_t k = 0; k < nsts; k++) ready += yyjson_get_sint(yyjson_obj_get(yyjson_obj_get(sts[k], "status"), "readyReplicas"));
    const char *phase = restarted && outdated == (size_t)restarted && ready == 0 ? "Restarting"
                        : outdated                                              ? "Updating"
                        : ready == servers                                      ? "Ready"
                                                                                : "Provisioning";
    char msg[128];
    snprintf(msg, sizeof(msg), "%lld of %lld servers ready", ready, servers);
    const char *reason = outdated ? "Updating" : ready == servers ? "AllServersReady" : "ServersNotReady";
    write_status(o, bc, &s, phase, !outdated && ready == servers, reason, msg, topo, sts, nsts);
  }
  for (size_t i = 0; i < n; i++) yyjson_doc_free(applied[i]);
  /* A disabled console (or Ingress) goes away. */
  char **stale;
  size_t ns = bc_console_stale(&s, &stale);
  for (size_t i = 0; i < ns; i++) {
    int code = kube_delete(o->k, stale[i]);
    if (code / 100 == 2) buckets_log_info("%s/%s: deleted %s", s.ns, s.name, stale[i]);
    free(stale[i]);
  }
  free(stale);
  bc_objects_free(objs, n);
}

void op_reconcile_all(op_ctx *o) {
  buckets_buf path = BUCKETS_BUF_INIT;
  if (o->namespace) buckets_buf_appendf(&path, GROUP_PATH "/namespaces/%s/bucketsclusters", o->namespace);
  else buckets_buf_append_c(&path, GROUP_PATH "/bucketsclusters");
  yyjson_doc *doc;
  int st = kube_get(o->k, path.data, &doc);
  if (st != 200) {
    buckets_log_warn("list %s: %d %s", path.data, st, kube_error_message(doc));
  } else {
    size_t i, max;
    yyjson_val *bc;
    yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(doc), "items"), i, max, bc) {
      if (get_str(bc, "metadata.deletionTimestamp")) continue; /* garbage collection removes the rest */
      reconcile_cluster(o, bc);
    }
    op_reconcile_iam(o, yyjson_obj_get(yyjson_doc_get_root(doc), "items"));
  }
  yyjson_doc_free(doc);
  buckets_buf_free(&path);
}
