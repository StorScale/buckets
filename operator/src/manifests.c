/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "manifests.h"

#include <ctype.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "kms/kesutil.h"

/* ---- parsing ------------------------------------------------------------------ */

static const char *str_at(yyjson_val *o, const char *k) { return yyjson_get_str(yyjson_obj_get(o, k)); }

static bool valid_dns_label(const char *s) {
  size_t n = strlen(s);
  if (!n || n > 63 || s[0] == '-' || s[n - 1] == '-') return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  return true;
}

/* A drive path goes into BUCKETS_VOLUMES' ellipsis syntax: keep it plain. */
static bool drive_path_ok(const char *p, bool may_be_empty) {
  if (!*p) return may_be_empty;
  if (p[0] != '/' || strstr(p, "//") || strstr(p, "..")) return false;
  for (; *p; p++)
    if (!isalnum((unsigned char)*p) && !strchr("._-/", *p)) return false;
  return true;
}

/* A user or group ID; 65532 (nonroot) when absent, -1 when not a number. */
static long long id_at(yyjson_val *o, const char *key) {
  yyjson_val *v = yyjson_obj_get(o, key);
  if (!v) return 65532;
  return yyjson_is_int(v) ? yyjson_get_sint(v) : -1;
}

bool bc_parse(yyjson_val *obj, const char *cluster_domain, bc_spec *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  yyjson_val *meta = yyjson_obj_get(obj, "metadata"), *spec = yyjson_obj_get(obj, "spec");
  out->name = str_at(meta, "name");
  out->ns = str_at(meta, "namespace");
  out->uid = str_at(meta, "uid");
  out->generation = yyjson_get_sint(yyjson_obj_get(meta, "generation"));
  out->cluster_domain = cluster_domain && *cluster_domain ? cluster_domain : "cluster.local";
  if (!out->name || !out->ns || !out->uid || !spec) {
    snprintf(err, errlen, "object lacks metadata or spec");
    return false;
  }
  if (!valid_dns_label(out->name) || strlen(out->name) > 40) {
    snprintf(err, errlen, "name %s must be a DNS label of at most 40 characters", out->name);
    return false;
  }
  out->image = str_at(spec, "image");
  if (!out->image) out->image = "ghcr.io/buckets-io/bucketsd:1.0.0";
  out->pull_policy = str_at(spec, "imagePullPolicy");
  if (!out->pull_policy) out->pull_policy = "IfNotPresent";
  out->pull_secrets = yyjson_obj_get(spec, "imagePullSecrets");
  out->env = yyjson_obj_get(spec, "env");
  out->creds_secret = str_at(yyjson_obj_get(spec, "credsSecret"), "name");
  out->config_secret = str_at(yyjson_obj_get(spec, "configuration"), "name");
  if (out->creds_secret && out->config_secret) {
    snprintf(err, errlen, "set spec.credsSecret or spec.configuration (whose config.env holds the root credentials), not both");
    return false;
  }
  yyjson_val *drives = yyjson_obj_get(spec, "drives");
  out->mount_path = str_at(drives, "mountPath");
  if (!out->mount_path) out->mount_path = "/data";
  out->sub_path = str_at(drives, "subPath");
  if (!out->sub_path) out->sub_path = "";
  if (!drive_path_ok(out->mount_path, false) || !drive_path_ok(out->sub_path, true)) {
    snprintf(err, errlen, "spec.drives: mountPath must be an absolute path and subPath empty or absolute, "
                          "of letters, digits and . _ - / only");
    return false;
  }
  yyjson_val *sc = yyjson_obj_get(spec, "securityContext");
  out->run_as_user = id_at(sc, "runAsUser");
  out->run_as_group = id_at(sc, "runAsGroup");
  out->fs_group = id_at(sc, "fsGroup");
  if (out->run_as_user == 0 || out->run_as_group < 0 || out->run_as_user < 0 || out->fs_group < 0) {
    snprintf(err, errlen, "spec.securityContext: runAsUser must be a non-root user ID, and the group IDs 0 or more");
    return false;
  }
  out->service_port = BC_S3_PORT;
  if (yyjson_obj_get(spec, "servicePort")) {
    long long sp = yyjson_get_sint(yyjson_obj_get(spec, "servicePort"));
    if (sp < 1 || sp > 65535) {
      snprintf(err, errlen, "spec.servicePort must be a port number");
      return false;
    }
    out->service_port = (int)sp;
  }
  out->volumes = yyjson_obj_get(spec, "volumes");
  out->volume_mounts = yyjson_obj_get(spec, "volumeMounts");
  out->parity = (int)yyjson_get_int(yyjson_obj_get(spec, "parity"));
  out->set_drive_count = (int)yyjson_get_int(yyjson_obj_get(spec, "erasureSetDriveCount"));
  yyjson_val *tls = yyjson_obj_get(spec, "tls");
  out->tls_secret = str_at(yyjson_obj_get(tls, "certSecret"), "name");
  out->ca_secret = str_at(yyjson_obj_get(tls, "caSecret"), "name");
  out->service_type = str_at(spec, "serviceType");
  if (!out->service_type) out->service_type = "ClusterIP";
  yyjson_val *con = yyjson_obj_get(spec, "console");
  out->console.enabled = yyjson_get_bool(yyjson_obj_get(con, "enabled"));
  out->console.replicas = (int)yyjson_get_int(yyjson_obj_get(con, "replicas"));
  if (out->console.replicas < 1) out->console.replicas = 1;
  out->console.image = str_at(con, "image");
  if (!out->console.image) out->console.image = BC_CONSOLE_IMAGE;
  out->console.service_type = str_at(con, "serviceType");
  if (!out->console.service_type) out->console.service_type = "ClusterIP";
  yyjson_val *ing = yyjson_obj_get(con, "ingress");
  out->console.ingress_host = str_at(ing, "host");
  out->console.ingress_class = str_at(ing, "ingressClassName");
  out->console.ingress_tls_secret = str_at(yyjson_obj_get(ing, "tlsSecret"), "name");
  out->console.annotations = yyjson_obj_get(ing, "annotations");
  out->console.resources = yyjson_obj_get(con, "resources");
  out->console.env = yyjson_obj_get(con, "env");
  out->console.s3_url = str_at(con, "s3URL");
  out->console.tls_secret = str_at(yyjson_obj_get(yyjson_obj_get(con, "tls"), "certSecret"), "name");
  yyjson_val *kes = yyjson_obj_get(yyjson_obj_get(spec, "kms"), "kes");
  out->kes.enabled = yyjson_is_obj(kes);
  out->kes.replicas = (int)yyjson_get_int(yyjson_obj_get(kes, "replicas"));
  if (out->kes.replicas < 1) out->kes.replicas = 2;
  out->kes.image = str_at(kes, "image");
  if (!out->kes.image) out->kes.image = getenv("BUCKETS_KES_IMAGE") && *getenv("BUCKETS_KES_IMAGE") ? getenv("BUCKETS_KES_IMAGE") : BC_KES_IMAGE;
  out->kes.key_name = str_at(kes, "keyName");
  if (!out->kes.key_name || !*out->kes.key_name) out->kes.key_name = BC_KES_DEFAULT_KEY;
  out->kes.resources = yyjson_obj_get(kes, "resources");
  out->kes.node_selector = yyjson_obj_get(kes, "nodeSelector");
  out->kes.tolerations = yyjson_obj_get(kes, "tolerations");
  out->kes.affinity = yyjson_obj_get(kes, "affinity");
  out->kes.name = str_at(kes, "name");
  if (out->kes.name && !*out->kes.name) out->kes.name = NULL;
  out->kes.service_account = str_at(kes, "serviceAccountName");
  if (out->kes.service_account && !*out->kes.service_account) out->kes.service_account = NULL;
  yyjson_val *ck = yyjson_obj_get(kes, "createKey");
  out->kes.create_key = !yyjson_is_bool(ck) || yyjson_get_bool(ck);
  if (out->kes.enabled) { /* one KMS: KES configured here, not in the environment as well */
    size_t ki, kmax;
    yyjson_val *ev;
    yyjson_arr_foreach(out->env, ki, kmax, ev) {
      const char *en = str_at(ev, "name");
      if (en && (strncmp(en, "MINIO_KMS_", 10) == 0 || strncmp(en, "BUCKETS_KMS_", 12) == 0)) {
        snprintf(err, errlen, "spec.kms.kes runs the cluster's KMS: remove %s from spec.env", en);
        return false;
      }
    }
  }

  yyjson_val *pools = yyjson_obj_get(spec, "pools");
  size_t n = yyjson_arr_size(pools);
  if (!n || n > BC_MAX_POOLS) {
    snprintf(err, errlen, "spec.pools needs 1 to %d pools", BC_MAX_POOLS);
    return false;
  }
  size_t idx, max;
  yyjson_val *p;
  yyjson_arr_foreach(pools, idx, max, p) {
    bc_pool *bp = &out->pools[idx];
    const char *pn = str_at(p, "name");
    if (pn) snprintf(bp->name, sizeof(bp->name), "%s", pn);
    else snprintf(bp->name, sizeof(bp->name), "pool-%zu", idx);
    if (!valid_dns_label(bp->name)) {
      snprintf(err, errlen, "pool name %s is not a DNS label", bp->name);
      return false;
    }
    for (size_t j = 0; j < idx; j++) {
      if (strcmp(out->pools[j].name, bp->name) == 0) {
        snprintf(err, errlen, "pool name %s is used twice", bp->name);
        return false;
      }
    }
    bp->servers = (int)yyjson_get_int(yyjson_obj_get(p, "servers"));
    bp->volumes = (int)yyjson_get_int(yyjson_obj_get(p, "volumesPerServer"));
    if (bp->servers < 1 || bp->volumes < 1) {
      snprintf(err, errlen, "pool %s: servers and volumesPerServer must be at least 1", bp->name);
      return false;
    }
    if (bp->servers * bp->volumes < 2) {
      snprintf(err, errlen, "pool %s: a pool needs at least 2 drives (servers x volumesPerServer)", bp->name);
      return false;
    }
    bp->volume_claim_template = yyjson_obj_get(p, "volumeClaimTemplate");
    bp->resources = yyjson_obj_get(p, "resources");
    bp->node_selector = yyjson_obj_get(p, "nodeSelector");
    bp->tolerations = yyjson_obj_get(p, "tolerations");
    bp->affinity = yyjson_obj_get(p, "affinity");
  }
  out->npools = n;
  return true;
}

/* ---- names -------------------------------------------------------------------- */

void bc_root_secret_name(const bc_spec *s, char *out, size_t cap) { snprintf(out, cap, "%s-root", s->name); }
void bc_creds_secret_name(const bc_spec *s, char *out, size_t cap) {
  if (s->config_secret) snprintf(out, cap, "%s", s->config_secret);
  else if (s->creds_secret) snprintf(out, cap, "%s", s->creds_secret);
  else bc_root_secret_name(s, out, cap);
}
void bc_statefulset_name(const bc_spec *s, size_t pool, char *out, size_t cap) {
  snprintf(out, cap, "%s-%s", s->name, s->pools[pool].name);
}
void bc_headless_name(const bc_spec *s, char *out, size_t cap) { snprintf(out, cap, "%s-hl", s->name); }

static const char *creds_name(const bc_spec *s, char *buf, size_t cap) {
  if (s->creds_secret) return s->creds_secret;
  bc_root_secret_name(s, buf, cap);
  return buf;
}

char *bc_volumes(const bc_spec *s) {
  buckets_buf b = BUCKETS_BUF_INIT;
  char hl[128], sts[128];
  bc_headless_name(s, hl, sizeof(hl));
  for (size_t p = 0; p < s->npools; p++) {
    const bc_pool *bp = &s->pools[p];
    bc_statefulset_name(s, p, sts, sizeof(sts));
    if (p) buckets_buf_append_char(&b, ' ');
    buckets_buf_appendf(&b, "%s://%s-", s->tls_secret ? "https" : "http", sts);
    if (bp->servers > 1) buckets_buf_appendf(&b, "{0...%d}", bp->servers - 1);
    else buckets_buf_append_char(&b, '0');
    buckets_buf_appendf(&b, ".%s.%s.svc.%s:%d%s", hl, s->ns, s->cluster_domain, BC_S3_PORT, s->mount_path);
    if (bp->volumes > 1) buckets_buf_appendf(&b, "{0...%d}", bp->volumes - 1);
    else buckets_buf_append_char(&b, '0');
    buckets_buf_append_c(&b, s->sub_path);
  }
  return b.data;
}

void bc_topology(const bc_spec *s, char out[17]) {
  char *v = bc_volumes(s);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "%s|parity=%d|sdc=%d", v, s->parity, s->set_drive_count);
  uint8_t h[32];
  buckets_sha256(b.data, b.len, h);
  buckets_hex_encode(h, 8, out);
  out[16] = '\0';
  buckets_buf_free(&b);
  free(v);
}

/* ---- object builders ---------------------------------------------------------- */

typedef yyjson_mut_doc mdoc;
typedef yyjson_mut_val mval;

#define ADD_STR(d, o, k, v) yyjson_mut_obj_add_strcpy(d, o, k, v)
#define ADD_INT(d, o, k, v) yyjson_mut_obj_add_int(d, o, k, v)
#define ADD_BOOL(d, o, k, v) yyjson_mut_obj_add_bool(d, o, k, v)
#define ADD_OBJ(d, o, k) yyjson_mut_obj_add_obj(d, o, k)
#define ADD_ARR(d, o, k) yyjson_mut_obj_add_arr(d, o, k)

static void labels(mdoc *d, mval *obj, const bc_spec *s, const char *pool) {
  ADD_STR(d, obj, "app.kubernetes.io/name", "buckets");
  ADD_STR(d, obj, "app.kubernetes.io/instance", s->name);
  ADD_STR(d, obj, "app.kubernetes.io/managed-by", "buckets-operator");
  ADD_STR(d, obj, "buckets.io/cluster", s->name);
  if (pool) ADD_STR(d, obj, "buckets.io/pool", pool);
}

static mval *object(mdoc *d, const char *api, const char *kind, const bc_spec *s, const char *name, const char *pool) {
  mval *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  ADD_STR(d, root, "apiVersion", api);
  ADD_STR(d, root, "kind", kind);
  mval *meta = ADD_OBJ(d, root, "metadata");
  ADD_STR(d, meta, "name", name);
  ADD_STR(d, meta, "namespace", s->ns);
  labels(d, ADD_OBJ(d, meta, "labels"), s, pool);
  mval *owners = ADD_ARR(d, meta, "ownerReferences");
  mval *o = yyjson_mut_arr_add_obj(d, owners);
  ADD_STR(d, o, "apiVersion", BC_API_VERSION);
  ADD_STR(d, o, "kind", BC_KIND);
  ADD_STR(d, o, "name", s->name);
  ADD_STR(d, o, "uid", s->uid);
  ADD_BOOL(d, o, "controller", true);
  ADD_BOOL(d, o, "blockOwnerDeletion", true);
  return root;
}

static char *path_of(const char *prefix, const bc_spec *s, const char *resource, const char *name) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "%s/namespaces/%s/%s/%s", prefix, s->ns, resource, name);
  return b.data;
}

static bc_object service(const bc_spec *s, bool headless) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  if (headless) bc_headless_name(s, name, sizeof(name));
  else snprintf(name, sizeof(name), "%s", s->name);
  mval *root = object(d, "v1", "Service", s, name, NULL);
  mval *spec = ADD_OBJ(d, root, "spec");
  if (headless) {
    ADD_STR(d, spec, "clusterIP", "None");
    /* Peers must find each other before they are ready: bootstrap needs them. */
    ADD_BOOL(d, spec, "publishNotReadyAddresses", true);
  } else {
    ADD_STR(d, spec, "type", s->service_type);
  }
  mval *sel = ADD_OBJ(d, spec, "selector");
  ADD_STR(d, sel, "buckets.io/cluster", s->name);
  mval *port = yyjson_mut_arr_add_obj(d, ADD_ARR(d, spec, "ports"));
  ADD_STR(d, port, "name", s->tls_secret ? "https-s3" : "http-s3");
  ADD_INT(d, port, "port", headless ? BC_S3_PORT : s->service_port);
  ADD_INT(d, port, "targetPort", BC_S3_PORT);
  ADD_STR(d, port, "protocol", "TCP");
  return (bc_object){path_of("/api/v1", s, "services", name), d};
}

static void env_value(mdoc *d, mval *env, const char *name, const char *value) {
  mval *e = yyjson_mut_arr_add_obj(d, env);
  ADD_STR(d, e, "name", name);
  ADD_STR(d, e, "value", value);
}

static void env_secret(mdoc *d, mval *env, const char *name, const char *secret, const char *key) {
  mval *e = yyjson_mut_arr_add_obj(d, env);
  ADD_STR(d, e, "name", name);
  mval *ref = ADD_OBJ(d, ADD_OBJ(d, e, "valueFrom"), "secretKeyRef");
  ADD_STR(d, ref, "name", secret);
  ADD_STR(d, ref, "key", key);
}

static void probe(mdoc *d, mval *c, const char *key, const char *path, bool https, int period, int failures,
                  int initial) {
  mval *p = ADD_OBJ(d, c, key);
  mval *get = ADD_OBJ(d, p, "httpGet");
  ADD_STR(d, get, "path", path);
  ADD_INT(d, get, "port", BC_S3_PORT);
  ADD_STR(d, get, "scheme", https ? "HTTPS" : "HTTP");
  ADD_INT(d, p, "periodSeconds", period);
  ADD_INT(d, p, "failureThreshold", failures);
  if (initial) ADD_INT(d, p, "initialDelaySeconds", initial);
}

static bc_object statefulset(const bc_spec *s, size_t pi, const char *volumes, const char *topology) {
  const bc_pool *bp = &s->pools[pi];
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128], hl[128], creds[128];
  bc_statefulset_name(s, pi, name, sizeof(name));
  bc_headless_name(s, hl, sizeof(hl));
  mval *root = object(d, "apps/v1", "StatefulSet", s, name, bp->name);
  mval *spec = ADD_OBJ(d, root, "spec");
  ADD_STR(d, spec, "serviceName", hl);
  ADD_INT(d, spec, "replicas", bp->servers);
  /* All pods start at once: bootstrap needs every peer. The operator decides
   * when pods restart (a topology change restarts all of them together). */
  ADD_STR(d, spec, "podManagementPolicy", "Parallel");
  ADD_STR(d, ADD_OBJ(d, spec, "updateStrategy"), "type", "OnDelete");
  mval *match = ADD_OBJ(d, ADD_OBJ(d, spec, "selector"), "matchLabels");
  ADD_STR(d, match, "buckets.io/cluster", s->name);
  ADD_STR(d, match, "buckets.io/pool", bp->name);

  mval *tmpl = ADD_OBJ(d, spec, "template");
  mval *tmeta = ADD_OBJ(d, tmpl, "metadata");
  labels(d, ADD_OBJ(d, tmeta, "labels"), s, bp->name);
  ADD_STR(d, ADD_OBJ(d, tmeta, "annotations"), "buckets.io/topology", topology);
  mval *pod = ADD_OBJ(d, tmpl, "spec");
  mval *sec = ADD_OBJ(d, pod, "securityContext");
  ADD_INT(d, sec, "runAsUser", s->run_as_user);
  ADD_INT(d, sec, "runAsGroup", s->run_as_group);
  ADD_INT(d, sec, "fsGroup", s->fs_group);
  ADD_BOOL(d, sec, "runAsNonRoot", true);
  ADD_STR(d, sec, "fsGroupChangePolicy", "OnRootMismatch");
  ADD_INT(d, pod, "terminationGracePeriodSeconds", 30);
  if (s->pull_secrets) yyjson_mut_obj_add_val(d, pod, "imagePullSecrets", yyjson_val_mut_copy(d, s->pull_secrets));
  if (bp->node_selector) yyjson_mut_obj_add_val(d, pod, "nodeSelector", yyjson_val_mut_copy(d, bp->node_selector));
  if (bp->tolerations) yyjson_mut_obj_add_val(d, pod, "tolerations", yyjson_val_mut_copy(d, bp->tolerations));
  if (bp->affinity) {
    yyjson_mut_obj_add_val(d, pod, "affinity", yyjson_val_mut_copy(d, bp->affinity));
  } else { /* spread a pool's servers over nodes when possible */
    mval *pref = ADD_ARR(d, ADD_OBJ(d, ADD_OBJ(d, pod, "affinity"), "podAntiAffinity"),
                         "preferredDuringSchedulingIgnoredDuringExecution");
    mval *term = yyjson_mut_arr_add_obj(d, pref);
    ADD_INT(d, term, "weight", 100);
    mval *pat = ADD_OBJ(d, term, "podAffinityTerm");
    ADD_STR(d, pat, "topologyKey", "kubernetes.io/hostname");
    mval *ml = ADD_OBJ(d, ADD_OBJ(d, pat, "labelSelector"), "matchLabels");
    ADD_STR(d, ml, "buckets.io/cluster", s->name);
    ADD_STR(d, ml, "buckets.io/pool", bp->name);
  }

  mval *c = yyjson_mut_arr_add_obj(d, ADD_ARR(d, pod, "containers"));
  ADD_STR(d, c, "name", "bucketsd");
  ADD_STR(d, c, "image", s->image);
  ADD_STR(d, c, "imagePullPolicy", s->pull_policy);
  mval *args = ADD_ARR(d, c, "args");
  yyjson_mut_arr_add_str(d, args, "server");
  yyjson_mut_arr_add_str(d, args, "--address");
  yyjson_mut_arr_add_str(d, args, ":9000");
  if (s->tls_secret) {
    yyjson_mut_arr_add_str(d, args, "--certs-dir");
    yyjson_mut_arr_add_str(d, args, "/etc/buckets/certs");
  }
  mval *env = ADD_ARR(d, c, "env");
  env_value(d, env, "BUCKETS_VOLUMES", volumes);
  if (s->config_secret) { /* the root credentials come with config.env */
    env_value(d, env, "BUCKETS_CONFIG_ENV_FILE", "/etc/buckets/config/config.env");
  } else {
    const char *cn = creds_name(s, creds, sizeof(creds));
    env_secret(d, env, "BUCKETS_ROOT_USER", cn, "rootUser");
    env_secret(d, env, "BUCKETS_ROOT_PASSWORD", cn, "rootPassword");
  }
  if (s->parity) {
    char ec[16];
    snprintf(ec, sizeof(ec), "EC:%d", s->parity);
    env_value(d, env, "BUCKETS_STORAGE_CLASS_STANDARD", ec);
  }
  if (s->set_drive_count) {
    char n[16];
    snprintf(n, sizeof(n), "%d", s->set_drive_count);
    env_value(d, env, "BUCKETS_ERASURE_SET_DRIVE_COUNT", n);
  }
  if (s->kes.active) {
    char ep[512], idn[128];
    bc_kes_endpoint(s, false, ep, sizeof(ep));
    bc_kes_identity_secret_name(s, idn, sizeof(idn));
    env_value(d, env, "MINIO_KMS_KES_ENDPOINT", ep);
    env_value(d, env, "MINIO_KMS_KES_KEY_NAME", s->kes.key_name);
    env_secret(d, env, "MINIO_KMS_KES_API_KEY", idn, "client");
    env_value(d, env, "MINIO_KMS_KES_CAPATH", "/etc/buckets/kes/ca.crt");
  }
  size_t ei, emax;
  yyjson_val *ev;
  yyjson_arr_foreach(s->env, ei, emax, ev) yyjson_mut_arr_append(env, yyjson_val_mut_copy(d, ev));
  mval *port = yyjson_mut_arr_add_obj(d, ADD_ARR(d, c, "ports"));
  ADD_STR(d, port, "name", "s3");
  ADD_INT(d, port, "containerPort", BC_S3_PORT);
  probe(d, c, "readinessProbe", "/minio/health/ready", s->tls_secret != NULL, 5, 3, 0);
  probe(d, c, "livenessProbe", "/minio/health/live", s->tls_secret != NULL, 10, 6, 10);
  if (bp->resources) yyjson_mut_obj_add_val(d, c, "resources", yyjson_val_mut_copy(d, bp->resources));
  mval *csec = ADD_OBJ(d, c, "securityContext");
  ADD_BOOL(d, csec, "allowPrivilegeEscalation", false);
  ADD_BOOL(d, csec, "readOnlyRootFilesystem", true);
  yyjson_mut_arr_add_str(d, ADD_ARR(d, ADD_OBJ(d, csec, "capabilities"), "drop"), "ALL");

  mval *mounts = ADD_ARR(d, c, "volumeMounts"), *vols = ADD_ARR(d, pod, "volumes");
  for (int v = 0; v < bp->volumes; v++) {
    char vn[16], mp[256];
    snprintf(vn, sizeof(vn), "data%d", v);
    snprintf(mp, sizeof(mp), "%s%d", s->mount_path, v);
    mval *m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", vn);
    ADD_STR(d, m, "mountPath", mp);
  }
  if (s->tls_secret) {
    mval *m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", "certs");
    ADD_STR(d, m, "mountPath", "/etc/buckets/certs");
    ADD_BOOL(d, m, "readOnly", true);
    /* A projected volume lays the Secret out the way bucketsd expects:
     * public.crt, private.key, and CAs/ca.crt for internode trust. */
    mval *vol = yyjson_mut_arr_add_obj(d, vols);
    ADD_STR(d, vol, "name", "certs");
    mval *sources = ADD_ARR(d, ADD_OBJ(d, vol, "projected"), "sources");
    mval *src = ADD_OBJ(d, yyjson_mut_arr_add_obj(d, sources), "secret");
    ADD_STR(d, src, "name", s->tls_secret);
    mval *items = ADD_ARR(d, src, "items");
    const char *map[][2] = {{"tls.crt", "public.crt"}, {"tls.key", "private.key"}};
    for (int i = 0; i < 2; i++) {
      mval *it = yyjson_mut_arr_add_obj(d, items);
      ADD_STR(d, it, "key", map[i][0]);
      ADD_STR(d, it, "path", map[i][1]);
    }
    mval *ca = ADD_OBJ(d, yyjson_mut_arr_add_obj(d, sources), "secret");
    ADD_STR(d, ca, "name", s->ca_secret ? s->ca_secret : s->tls_secret);
    mval *ci = yyjson_mut_arr_add_obj(d, ADD_ARR(d, ca, "items"));
    ADD_STR(d, ci, "key", "ca.crt");
    ADD_STR(d, ci, "path", "CAs/ca.crt");
  }
  if (s->config_secret) {
    mval *m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", "config");
    ADD_STR(d, m, "mountPath", "/etc/buckets/config");
    ADD_BOOL(d, m, "readOnly", true);
    mval *vol = yyjson_mut_arr_add_obj(d, vols);
    ADD_STR(d, vol, "name", "config");
    mval *src = ADD_OBJ(d, vol, "secret");
    ADD_STR(d, src, "secretName", s->config_secret);
    mval *it = yyjson_mut_arr_add_obj(d, ADD_ARR(d, src, "items"));
    ADD_STR(d, it, "key", "config.env");
    ADD_STR(d, it, "path", "config.env");
  }
  if (s->kes.active) { /* KES's certificate, its own CA */
    char tn[128];
    bc_kes_tls_secret_name(s, tn, sizeof(tn));
    mval *m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", "kes-ca");
    ADD_STR(d, m, "mountPath", "/etc/buckets/kes");
    ADD_BOOL(d, m, "readOnly", true);
    mval *vol = yyjson_mut_arr_add_obj(d, vols);
    ADD_STR(d, vol, "name", "kes-ca");
    mval *src = ADD_OBJ(d, vol, "secret");
    ADD_STR(d, src, "secretName", tn);
    mval *it = yyjson_mut_arr_add_obj(d, ADD_ARR(d, src, "items"));
    ADD_STR(d, it, "key", "tls.crt");
    ADD_STR(d, it, "path", "ca.crt");
  }
  size_t xi, xmax;
  yyjson_val *xv;
  yyjson_arr_foreach(s->volumes, xi, xmax, xv) yyjson_mut_arr_append(vols, yyjson_val_mut_copy(d, xv));
  yyjson_arr_foreach(s->volume_mounts, xi, xmax, xv) yyjson_mut_arr_append(mounts, yyjson_val_mut_copy(d, xv));
  if (!yyjson_mut_arr_size(vols)) yyjson_mut_obj_remove_key(pod, "volumes"); /* as before: none without TLS */

  mval *claims = ADD_ARR(d, spec, "volumeClaimTemplates");
  for (int v = 0; v < bp->volumes; v++) {
    char vn[16];
    snprintf(vn, sizeof(vn), "data%d", v);
    mval *pvc = yyjson_mut_arr_add_obj(d, claims);
    mval *pm = ADD_OBJ(d, pvc, "metadata");
    ADD_STR(d, pm, "name", vn);
    labels(d, ADD_OBJ(d, pm, "labels"), s, bp->name);
    mval *pspec;
    if (bp->volume_claim_template) {
      pspec = yyjson_val_mut_copy(d, bp->volume_claim_template);
      yyjson_mut_obj_add_val(d, pvc, "spec", pspec);
    } else {
      pspec = ADD_OBJ(d, pvc, "spec");
    }
    if (!yyjson_mut_obj_get(pspec, "accessModes")) {
      yyjson_mut_arr_add_str(d, ADD_ARR(d, pspec, "accessModes"), "ReadWriteOnce");
    }
    if (!yyjson_mut_obj_get(pspec, "resources")) {
      ADD_STR(d, ADD_OBJ(d, ADD_OBJ(d, pspec, "resources"), "requests"), "storage", "10Gi");
    }
  }
  return (bc_object){path_of("/apis/apps/v1", s, "statefulsets", name), d};
}

static bc_object pdb(const bc_spec *s, size_t pi) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_statefulset_name(s, pi, name, sizeof(name));
  mval *root = object(d, "policy/v1", "PodDisruptionBudget", s, name, s->pools[pi].name);
  mval *spec = ADD_OBJ(d, root, "spec");
  /* One server at a time: enough to drain nodes, never enough to lose quorum. */
  ADD_INT(d, spec, "maxUnavailable", 1);
  mval *ml = ADD_OBJ(d, ADD_OBJ(d, spec, "selector"), "matchLabels");
  ADD_STR(d, ml, "buckets.io/cluster", s->name);
  ADD_STR(d, ml, "buckets.io/pool", s->pools[pi].name);
  return (bc_object){path_of("/apis/policy/v1", s, "poddisruptionbudgets", name), d};
}

/* ---- the console ------------------------------------------------------------------ */

void bc_console_secret_name(const bc_spec *s, char *out, size_t cap) { snprintf(out, cap, "%s-console", s->name); }

/* Console pods carry their own labels: the storage Service selects
 * buckets.io/cluster, and must never send S3 traffic to them. */
static void console_labels(mdoc *d, mval *obj, const bc_spec *s) {
  ADD_STR(d, obj, "app.kubernetes.io/name", "buckets-console");
  ADD_STR(d, obj, "app.kubernetes.io/instance", s->name);
  ADD_STR(d, obj, "app.kubernetes.io/managed-by", "buckets-operator");
  ADD_STR(d, obj, "buckets.io/console", s->name);
}

static mval *console_object(mdoc *d, const char *api, const char *kind, const bc_spec *s, const char *name) {
  mval *root = object(d, api, kind, s, name, NULL);
  mval *meta = yyjson_mut_obj_get(root, "metadata");
  yyjson_mut_obj_remove_key(meta, "labels");
  console_labels(d, ADD_OBJ(d, meta, "labels"), s);
  return root;
}

static bc_object console_service(const bc_spec *s) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_console_secret_name(s, name, sizeof(name));
  mval *root = console_object(d, "v1", "Service", s, name);
  mval *spec = ADD_OBJ(d, root, "spec");
  ADD_STR(d, spec, "type", s->console.service_type);
  ADD_STR(d, ADD_OBJ(d, spec, "selector"), "buckets.io/console", s->name);
  mval *port = yyjson_mut_arr_add_obj(d, ADD_ARR(d, spec, "ports"));
  ADD_STR(d, port, "name", s->console.tls_secret ? "https-console" : "http-console");
  ADD_INT(d, port, "port", BC_CONSOLE_PORT);
  ADD_INT(d, port, "targetPort", BC_CONSOLE_PORT);
  ADD_STR(d, port, "protocol", "TCP");
  return (bc_object){path_of("/api/v1", s, "services", name), d};
}

static bc_object console_deployment(const bc_spec *s) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_console_secret_name(s, name, sizeof(name));
  mval *root = console_object(d, "apps/v1", "Deployment", s, name);
  mval *spec = ADD_OBJ(d, root, "spec");
  ADD_INT(d, spec, "replicas", s->console.replicas);
  ADD_STR(d, ADD_OBJ(d, ADD_OBJ(d, spec, "selector"), "matchLabels"), "buckets.io/console", s->name);
  mval *tmpl = ADD_OBJ(d, spec, "template");
  console_labels(d, ADD_OBJ(d, ADD_OBJ(d, tmpl, "metadata"), "labels"), s);
  mval *pod = ADD_OBJ(d, tmpl, "spec");
  /* its own account: it may read and change its cluster's KMS settings, nothing else */
  ADD_STR(d, pod, "serviceAccountName", name);
  ADD_BOOL(d, pod, "automountServiceAccountToken", true);
  mval *sec = ADD_OBJ(d, pod, "securityContext");
  ADD_INT(d, sec, "runAsUser", 65532);
  ADD_INT(d, sec, "runAsGroup", 65532);
  ADD_BOOL(d, sec, "runAsNonRoot", true);
  if (s->pull_secrets) yyjson_mut_obj_add_val(d, pod, "imagePullSecrets", yyjson_val_mut_copy(d, s->pull_secrets));
  mval *c = yyjson_mut_arr_add_obj(d, ADD_ARR(d, pod, "containers"));
  ADD_STR(d, c, "name", "console");
  ADD_STR(d, c, "image", s->console.image);
  ADD_STR(d, c, "imagePullPolicy", s->pull_policy);
  mval *args = ADD_ARR(d, c, "args");
  yyjson_mut_arr_add_str(d, args, "--address");
  yyjson_mut_arr_add_str(d, args, ":9090");
  yyjson_mut_arr_add_str(d, args, "--web-dir");
  yyjson_mut_arr_add_str(d, args, "/usr/share/buckets-console");
  if (s->console.tls_secret) {
    yyjson_mut_arr_add_str(d, args, "--certs-dir");
    yyjson_mut_arr_add_str(d, args, "/etc/buckets/console-certs");
  }
  mval *port = yyjson_mut_arr_add_obj(d, ADD_ARR(d, c, "ports"));
  ADD_STR(d, port, "name", s->console.tls_secret ? "https" : "http");
  ADD_INT(d, port, "containerPort", BC_CONSOLE_PORT);
  mval *env = ADD_ARR(d, c, "env");
  char url[512];
  snprintf(url, sizeof(url), "%s://%s.%s.svc.%s:%d", s->tls_secret ? "https" : "http", s->name, s->ns, s->cluster_domain,
           BC_S3_PORT);
  env_value(d, env, "BUCKETS_CONSOLE_SERVER", url);
  env_secret(d, env, "BUCKETS_CONSOLE_PBKDF_PASSPHRASE", name, "passphrase");
  env_secret(d, env, "BUCKETS_CONSOLE_PBKDF_SALT", name, "salt");
  if (s->console.ingress_tls_secret) env_value(d, env, "BUCKETS_CONSOLE_SECURE_COOKIE", "on");
  if (s->tls_secret) env_value(d, env, "BUCKETS_CONSOLE_CA_DIR", "/etc/buckets/ca");
  if (s->console.s3_url) env_value(d, env, "BUCKETS_CONSOLE_S3_URL", s->console.s3_url);
  env_value(d, env, "BUCKETS_CONSOLE_CLUSTER", s->name);
  mval *nse = yyjson_mut_arr_add_obj(d, env);
  ADD_STR(d, nse, "name", "BUCKETS_CONSOLE_NAMESPACE");
  ADD_STR(d, ADD_OBJ(d, ADD_OBJ(d, nse, "valueFrom"), "fieldRef"), "fieldPath", "metadata.namespace");
  size_t ei, emax;
  yyjson_val *ev;
  yyjson_arr_foreach(s->console.env, ei, emax, ev) yyjson_mut_arr_append(env, yyjson_val_mut_copy(d, ev));
  for (int i = 0; i < 2; i++) {
    mval *p = ADD_OBJ(d, c, i ? "livenessProbe" : "readinessProbe");
    mval *get = ADD_OBJ(d, p, "httpGet");
    ADD_STR(d, get, "path", "/healthz");
    ADD_INT(d, get, "port", BC_CONSOLE_PORT);
    ADD_STR(d, get, "scheme", s->console.tls_secret ? "HTTPS" : "HTTP");
    ADD_INT(d, p, "periodSeconds", i ? 20 : 5);
  }
  if (s->console.resources) yyjson_mut_obj_add_val(d, c, "resources", yyjson_val_mut_copy(d, s->console.resources));
  else {
    mval *r = ADD_OBJ(d, c, "resources");
    mval *req = ADD_OBJ(d, r, "requests");
    ADD_STR(d, req, "cpu", "50m");
    ADD_STR(d, req, "memory", "64Mi");
    ADD_STR(d, ADD_OBJ(d, r, "limits"), "memory", "256Mi");
  }
  mval *csec = ADD_OBJ(d, c, "securityContext");
  ADD_BOOL(d, csec, "allowPrivilegeEscalation", false);
  ADD_BOOL(d, csec, "readOnlyRootFilesystem", true);
  yyjson_mut_arr_add_str(d, ADD_ARR(d, ADD_OBJ(d, csec, "capabilities"), "drop"), "ALL");
  mval *mounts = ADD_ARR(d, c, "volumeMounts"), *vols = ADD_ARR(d, pod, "volumes");
  /* Large uploads spool to /tmp. */
  mval *m = yyjson_mut_arr_add_obj(d, mounts);
  ADD_STR(d, m, "name", "tmp");
  ADD_STR(d, m, "mountPath", "/tmp");
  mval *v = yyjson_mut_arr_add_obj(d, vols);
  ADD_STR(d, v, "name", "tmp");
  ADD_OBJ(d, v, "emptyDir");
  if (s->tls_secret) { /* trust the cluster's CA, as bucketsd's peers do */
    m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", "ca");
    ADD_STR(d, m, "mountPath", "/etc/buckets/ca");
    ADD_BOOL(d, m, "readOnly", true);
    v = yyjson_mut_arr_add_obj(d, vols);
    ADD_STR(d, v, "name", "ca");
    mval *src = ADD_OBJ(d, v, "secret");
    ADD_STR(d, src, "secretName", s->ca_secret ? s->ca_secret : s->tls_secret);
    mval *it = yyjson_mut_arr_add_obj(d, ADD_ARR(d, src, "items"));
    ADD_STR(d, it, "key", "ca.crt");
    ADD_STR(d, it, "path", "ca.crt");
  }
  if (s->console.tls_secret) { /* consoled's own HTTPS: public.crt and private.key, as bucketsd lays them out */
    m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", "console-certs");
    ADD_STR(d, m, "mountPath", "/etc/buckets/console-certs");
    ADD_BOOL(d, m, "readOnly", true);
    v = yyjson_mut_arr_add_obj(d, vols);
    ADD_STR(d, v, "name", "console-certs");
    mval *src = ADD_OBJ(d, v, "secret");
    ADD_STR(d, src, "secretName", s->console.tls_secret);
    mval *items = ADD_ARR(d, src, "items");
    const char *map[][2] = {{"tls.crt", "public.crt"}, {"tls.key", "private.key"}};
    for (int i = 0; i < 2; i++) {
      mval *it = yyjson_mut_arr_add_obj(d, items);
      ADD_STR(d, it, "key", map[i][0]);
      ADD_STR(d, it, "path", map[i][1]);
    }
  }
  return (bc_object){path_of("/apis/apps/v1", s, "deployments", name), d};
}

static bc_object console_ingress(const bc_spec *s) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_console_secret_name(s, name, sizeof(name));
  mval *root = console_object(d, "networking.k8s.io/v1", "Ingress", s, name);
  mval *ann = NULL;
  if (s->console.annotations) {
    ann = yyjson_val_mut_copy(d, s->console.annotations);
    yyjson_mut_obj_add_val(d, yyjson_mut_obj_get(root, "metadata"), "annotations", ann);
  }
  /* consoled on HTTPS: ingress-nginx must speak HTTPS to it too */
  if (s->console.tls_secret && !yyjson_mut_obj_get(ann, "nginx.ingress.kubernetes.io/backend-protocol")) {
    if (!ann) ann = ADD_OBJ(d, yyjson_mut_obj_get(root, "metadata"), "annotations");
    ADD_STR(d, ann, "nginx.ingress.kubernetes.io/backend-protocol", "HTTPS");
  }
  mval *spec = ADD_OBJ(d, root, "spec");
  if (s->console.ingress_class) ADD_STR(d, spec, "ingressClassName", s->console.ingress_class);
  if (s->console.ingress_tls_secret) {
    mval *t = yyjson_mut_arr_add_obj(d, ADD_ARR(d, spec, "tls"));
    yyjson_mut_arr_add_str(d, ADD_ARR(d, t, "hosts"), s->console.ingress_host);
    ADD_STR(d, t, "secretName", s->console.ingress_tls_secret);
  }
  mval *rule = yyjson_mut_arr_add_obj(d, ADD_ARR(d, spec, "rules"));
  ADD_STR(d, rule, "host", s->console.ingress_host);
  mval *path = yyjson_mut_arr_add_obj(d, ADD_ARR(d, ADD_OBJ(d, rule, "http"), "paths"));
  ADD_STR(d, path, "path", "/");
  ADD_STR(d, path, "pathType", "Prefix");
  mval *svc = ADD_OBJ(d, ADD_OBJ(d, path, "backend"), "service");
  ADD_STR(d, svc, "name", name);
  ADD_INT(d, ADD_OBJ(d, svc, "port"), "number", BC_CONSOLE_PORT);
  return (bc_object){path_of("/apis/networking.k8s.io/v1", s, "ingresses", name), d};
}

size_t bc_console_stale(const bc_spec *s, char ***paths) {
  char name[128];
  bc_console_secret_name(s, name, sizeof(name));
  char **p = buckets_xcalloc(6, sizeof(char *));
  size_t n = 0;
  if (!s->console.enabled) {
    p[n++] = path_of("/apis/apps/v1", s, "deployments", name);
    p[n++] = path_of("/api/v1", s, "services", name);
    p[n++] = path_of("/apis/rbac.authorization.k8s.io/v1", s, "rolebindings", name);
    p[n++] = path_of("/apis/rbac.authorization.k8s.io/v1", s, "roles", name);
    p[n++] = path_of("/api/v1", s, "serviceaccounts", name);
  }
  if (!s->console.enabled || !s->console.ingress_host) p[n++] = path_of("/apis/networking.k8s.io/v1", s, "ingresses", name);
  *paths = p;
  return n;
}

yyjson_mut_doc *bc_console_secret(const bc_spec *s, const char *passphrase, const char *salt) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_console_secret_name(s, name, sizeof(name));
  mval *root = console_object(d, "v1", "Secret", s, name);
  ADD_STR(d, root, "type", "Opaque");
  mval *data = ADD_OBJ(d, root, "stringData");
  ADD_STR(d, data, "passphrase", passphrase);
  ADD_STR(d, data, "salt", salt);
  return d;
}

static size_t console_rbac(const bc_spec *s, bc_object *o);

size_t bc_desired(const bc_spec *s, bc_object **out) {
  size_t n = 2 + 2 * s->npools + 6, k = 0;
  bc_object *o = buckets_xcalloc(n, sizeof(*o));
  char *vols = bc_volumes(s);
  char topo[17];
  bc_topology(s, topo);
  o[k++] = service(s, true);
  o[k++] = service(s, false);
  for (size_t p = 0; p < s->npools; p++) o[k++] = statefulset(s, p, vols, topo);
  for (size_t p = 0; p < s->npools; p++) o[k++] = pdb(s, p);
  if (s->console.enabled) {
    k += console_rbac(s, o + k); /* before the Deployment that runs as it */
    o[k++] = console_service(s);
    o[k++] = console_deployment(s);
    if (s->console.ingress_host) o[k++] = console_ingress(s);
  }
  free(vols);
  *out = o;
  return k;
}

void bc_objects_free(bc_object *o, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(o[i].path);
    yyjson_mut_doc_free(o[i].doc);
  }
  free(o);
}

yyjson_mut_doc *bc_root_secret(const bc_spec *s, const char *user, const char *password) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_root_secret_name(s, name, sizeof(name));
  mval *root = object(d, "v1", "Secret", s, name, NULL);
  /* Not owned by the cluster: the PVCs outlive a deleted BucketsCluster, and
   * so must the credentials that open them. */
  yyjson_mut_obj_remove_key(yyjson_mut_obj_get(root, "metadata"), "ownerReferences");
  ADD_STR(d, root, "type", "Opaque");
  mval *data = ADD_OBJ(d, root, "stringData");
  ADD_STR(d, data, "rootUser", user);
  ADD_STR(d, data, "rootPassword", password);
  return d;
}

/* ---- KES ------------------------------------------------------------------------- */

/* spec.kms.kes.name, or <cluster>-kes: an adopted MinIO tenant's own KES objects
 * (<tenant>-kes, <tenant>-kes-tls) keep their names */
static void kes_base(const bc_spec *s, char *out, size_t cap) {
  if (s->kes.name) snprintf(out, cap, "%s", s->kes.name);
  else snprintf(out, cap, "%s-kes", s->name);
}
void bc_kes_name(const bc_spec *s, bool trial, char *out, size_t cap) {
  char b[128];
  kes_base(s, b, sizeof(b));
  snprintf(out, cap, "%s%s", b, trial ? "-test" : "");
}
void bc_kes_endpoint(const bc_spec *s, bool trial, char *out, size_t cap) {
  char n[128];
  bc_kes_name(s, trial, n, sizeof(n));
  snprintf(out, cap, "https://%s.%s.svc.%s:%d", n, s->ns, s->cluster_domain, BC_KES_PORT);
}
void bc_kms_settings_secret_name(const bc_spec *s, char *out, size_t cap) { snprintf(out, cap, "%s-kms", s->name); }
void bc_kms_candidate_secret_name(const bc_spec *s, char *out, size_t cap) {
  snprintf(out, cap, "%s-kms-candidate", s->name);
}
void bc_kes_tls_secret_name(const bc_spec *s, char *out, size_t cap) {
  char b[128];
  kes_base(s, b, sizeof(b));
  snprintf(out, cap, "%s-tls", b);
}
void bc_kes_identity_secret_name(const bc_spec *s, char *out, size_t cap) {
  char b[128];
  kes_base(s, b, sizeof(b));
  snprintf(out, cap, "%s-identity", b);
}

#define KES_CA_PATH "/etc/kes/config/keystore-ca.pem"

char *bc_kes_config(const bc_spec *s, yyjson_val *settings, const char *admin_identity, const char *client_identity,
                    char **ca_pem, char *err, size_t errlen) {
  (void)s;
  *ca_pem = NULL;
  mdoc *d = yyjson_mut_doc_new(NULL);
  mval *ks = buckets_kes_keystore(d, settings, KES_CA_PATH, err, errlen);
  if (!ks) {
    yyjson_mut_doc_free(d);
    return NULL;
  }
  mval *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  ADD_STR(d, root, "version", "v1");
  ADD_STR(d, root, "address", "0.0.0.0:7373");
  ADD_STR(d, ADD_OBJ(d, root, "admin"), "identity", admin_identity);
  mval *tls = ADD_OBJ(d, root, "tls");
  ADD_STR(d, tls, "key", "/etc/kes/tls/tls.key");
  ADD_STR(d, tls, "cert", "/etc/kes/tls/tls.crt");
  /* bucketsd's identity: what MinIO's KES guide grants, and deleting keys */
  mval *pol = ADD_OBJ(d, ADD_OBJ(d, root, "policy"), "buckets");
  mval *allow = ADD_ARR(d, pol, "allow");
  static const char *const paths[] = {"/v1/key/create/*", "/v1/key/generate/*", "/v1/key/decrypt/*",
                                      "/v1/key/bulk/decrypt", "/v1/key/list/*",     "/v1/key/delete/*",
                                      "/v1/status",          "/v1/metrics",        "/v1/api",
                                      "/v1/log/audit",       "/v1/log/error",      NULL};
  for (const char *const *p = paths; *p; p++) yyjson_mut_arr_add_str(d, allow, *p);
  yyjson_mut_arr_add_strcpy(d, ADD_ARR(d, pol, "identities"), client_identity);
  /* the kubelet's readiness probe has no identity */
  mval *ready = ADD_OBJ(d, ADD_OBJ(d, root, "api"), "/v1/ready");
  ADD_BOOL(d, ready, "skip_auth", true);
  ADD_STR(d, ready, "timeout", "15s");
  yyjson_mut_obj_add_val(d, root, "keystore", ks);
  const char *ca = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(settings, "vault"), "caCert"));
  const char *backend = yyjson_get_str(yyjson_obj_get(settings, "backend"));
  if (ca && *ca && backend && strcmp(backend, "vault") == 0) *ca_pem = buckets_xstrdup(ca);
  char *out = yyjson_mut_write(d, YYJSON_WRITE_PRETTY, NULL);
  yyjson_mut_doc_free(d);
  return out;
}

/* KES pods carry labels of their own: the S3 Service selects buckets.io/cluster */
static void kes_labels(mdoc *d, mval *obj, const bc_spec *s, const char *name) {
  ADD_STR(d, obj, "app.kubernetes.io/name", "buckets-kes");
  ADD_STR(d, obj, "app.kubernetes.io/instance", s->name);
  ADD_STR(d, obj, "app.kubernetes.io/managed-by", "buckets-operator");
  ADD_STR(d, obj, "buckets.io/kes", name);
}

static mval *kes_object(mdoc *d, const char *api, const char *kind, const bc_spec *s, const char *name,
                        const char *kes) {
  mval *root = object(d, api, kind, s, name, NULL);
  mval *meta = yyjson_mut_obj_get(root, "metadata");
  yyjson_mut_obj_remove_key(meta, "labels");
  kes_labels(d, ADD_OBJ(d, meta, "labels"), s, kes);
  return root;
}

size_t bc_kes_objects(const bc_spec *s, bool trial, const char *config, const char *ca_pem, bc_object **out) {
  bc_object *o = buckets_xcalloc(4, sizeof(*o));
  size_t k = 0;
  char kes[128], cfg[160], tlsn[128], sa[128];
  bc_kes_name(s, trial, kes, sizeof(kes));
  snprintf(cfg, sizeof(cfg), "%s-config", kes);
  bc_kes_tls_secret_name(s, tlsn, sizeof(tlsn));
  /* the trial signs in to Vault as the live one would */
  if (s->kes.service_account) snprintf(sa, sizeof(sa), "%s", s->kes.service_account);
  else bc_kes_name(s, false, sa, sizeof(sa));

  if (!s->kes.service_account) { /* the live server's own, which a trial uses too */
    mdoc *d = yyjson_mut_doc_new(NULL);
    kes_object(d, "v1", "ServiceAccount", s, sa, sa);
    o[k++] = (bc_object){path_of("/api/v1", s, "serviceaccounts", sa), d};
  }

  mdoc *d = yyjson_mut_doc_new(NULL);
  mval *root = kes_object(d, "v1", "Secret", s, cfg, kes);
  ADD_STR(d, root, "type", "Opaque");
  mval *data = ADD_OBJ(d, root, "stringData");
  ADD_STR(d, data, "config.yaml", config);
  if (ca_pem) ADD_STR(d, data, "keystore-ca.pem", ca_pem);
  o[k++] = (bc_object){path_of("/api/v1", s, "secrets", cfg), d};

  /* a new configuration restarts KES: its hash is in the pod template */
  buckets_buf hb = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&hb, "%s\n%s", config, ca_pem ? ca_pem : "");
  uint8_t h[32];
  char hash[17];
  buckets_sha256(hb.data, hb.len, h);
  buckets_hex_encode(h, 8, hash);
  hash[16] = '\0';
  buckets_buf_free(&hb);

  d = yyjson_mut_doc_new(NULL);
  root = kes_object(d, "apps/v1", "Deployment", s, kes, kes);
  mval *spec = ADD_OBJ(d, root, "spec");
  ADD_INT(d, spec, "replicas", trial ? 1 : s->kes.replicas);
  ADD_STR(d, ADD_OBJ(d, ADD_OBJ(d, spec, "selector"), "matchLabels"), "buckets.io/kes", kes);
  mval *tmpl = ADD_OBJ(d, spec, "template");
  mval *tmeta = ADD_OBJ(d, tmpl, "metadata");
  kes_labels(d, ADD_OBJ(d, tmeta, "labels"), s, kes);
  ADD_STR(d, ADD_OBJ(d, tmeta, "annotations"), "buckets.io/config-hash", hash);
  mval *pod = ADD_OBJ(d, tmpl, "spec");
  ADD_STR(d, pod, "serviceAccountName", sa);
  ADD_BOOL(d, pod, "automountServiceAccountToken", true); /* Vault's Kubernetes sign-in */
  mval *sec = ADD_OBJ(d, pod, "securityContext");
  ADD_INT(d, sec, "runAsUser", 65532);
  ADD_INT(d, sec, "runAsGroup", 65532);
  ADD_BOOL(d, sec, "runAsNonRoot", true);
  if (s->pull_secrets) yyjson_mut_obj_add_val(d, pod, "imagePullSecrets", yyjson_val_mut_copy(d, s->pull_secrets));
  if (s->kes.node_selector) yyjson_mut_obj_add_val(d, pod, "nodeSelector", yyjson_val_mut_copy(d, s->kes.node_selector));
  if (s->kes.tolerations) yyjson_mut_obj_add_val(d, pod, "tolerations", yyjson_val_mut_copy(d, s->kes.tolerations));
  if (s->kes.affinity) {
    yyjson_mut_obj_add_val(d, pod, "affinity", yyjson_val_mut_copy(d, s->kes.affinity));
  } else if (!trial) { /* replicas on different nodes when possible */
    mval *pref = ADD_ARR(d, ADD_OBJ(d, ADD_OBJ(d, pod, "affinity"), "podAntiAffinity"),
                         "preferredDuringSchedulingIgnoredDuringExecution");
    mval *term = yyjson_mut_arr_add_obj(d, pref);
    ADD_INT(d, term, "weight", 100);
    mval *pat = ADD_OBJ(d, term, "podAffinityTerm");
    ADD_STR(d, pat, "topologyKey", "kubernetes.io/hostname");
    ADD_STR(d, ADD_OBJ(d, ADD_OBJ(d, pat, "labelSelector"), "matchLabels"), "buckets.io/kes", kes);
  }
  mval *c = yyjson_mut_arr_add_obj(d, ADD_ARR(d, pod, "containers"));
  ADD_STR(d, c, "name", "kes");
  ADD_STR(d, c, "image", s->kes.image);
  ADD_STR(d, c, "imagePullPolicy", s->pull_policy);
  mval *args = ADD_ARR(d, c, "args");
  yyjson_mut_arr_add_str(d, args, "server");
  yyjson_mut_arr_add_str(d, args, "--config");
  yyjson_mut_arr_add_str(d, args, "/etc/kes/config/config.yaml");
  mval *port = yyjson_mut_arr_add_obj(d, ADD_ARR(d, c, "ports"));
  ADD_STR(d, port, "name", "https-kes");
  ADD_INT(d, port, "containerPort", BC_KES_PORT);
  mval *rp = ADD_OBJ(d, c, "readinessProbe");
  mval *get = ADD_OBJ(d, rp, "httpGet");
  ADD_STR(d, get, "path", "/v1/ready");
  ADD_INT(d, get, "port", BC_KES_PORT);
  ADD_STR(d, get, "scheme", "HTTPS");
  ADD_INT(d, rp, "periodSeconds", trial ? 2 : 5);
  /* /version needs no identity on either KES (a bare TCP probe fills its log with handshake errors) */
  mval *lp = ADD_OBJ(d, c, "livenessProbe");
  mval *lget = ADD_OBJ(d, lp, "httpGet");
  ADD_STR(d, lget, "path", "/version");
  ADD_INT(d, lget, "port", BC_KES_PORT);
  ADD_STR(d, lget, "scheme", "HTTPS");
  ADD_INT(d, lp, "initialDelaySeconds", 10);
  ADD_INT(d, lp, "periodSeconds", 20);
  if (s->kes.resources) {
    yyjson_mut_obj_add_val(d, c, "resources", yyjson_val_mut_copy(d, s->kes.resources));
  } else {
    mval *r = ADD_OBJ(d, c, "resources");
    mval *req = ADD_OBJ(d, r, "requests");
    ADD_STR(d, req, "cpu", "50m");
    ADD_STR(d, req, "memory", "64Mi");
    ADD_STR(d, ADD_OBJ(d, r, "limits"), "memory", "256Mi");
  }
  mval *csec = ADD_OBJ(d, c, "securityContext");
  ADD_BOOL(d, csec, "allowPrivilegeEscalation", false);
  ADD_BOOL(d, csec, "readOnlyRootFilesystem", true);
  yyjson_mut_arr_add_str(d, ADD_ARR(d, ADD_OBJ(d, csec, "capabilities"), "drop"), "ALL");
  mval *mounts = ADD_ARR(d, c, "volumeMounts"), *vols = ADD_ARR(d, pod, "volumes");
  const char *mv[][3] = {{"config", "/etc/kes/config", cfg}, {"tls", "/etc/kes/tls", tlsn}};
  for (int i = 0; i < 2; i++) {
    mval *m = yyjson_mut_arr_add_obj(d, mounts);
    ADD_STR(d, m, "name", mv[i][0]);
    ADD_STR(d, m, "mountPath", mv[i][1]);
    ADD_BOOL(d, m, "readOnly", true);
    mval *v = yyjson_mut_arr_add_obj(d, vols);
    ADD_STR(d, v, "name", mv[i][0]);
    ADD_STR(d, ADD_OBJ(d, v, "secret"), "secretName", mv[i][2]);
  }
  o[k++] = (bc_object){path_of("/apis/apps/v1", s, "deployments", kes), d};

  d = yyjson_mut_doc_new(NULL);
  root = kes_object(d, "v1", "Service", s, kes, kes);
  spec = ADD_OBJ(d, root, "spec");
  ADD_STR(d, ADD_OBJ(d, spec, "selector"), "buckets.io/kes", kes);
  port = yyjson_mut_arr_add_obj(d, ADD_ARR(d, spec, "ports"));
  ADD_STR(d, port, "name", "https-kes");
  ADD_INT(d, port, "port", BC_KES_PORT);
  ADD_INT(d, port, "targetPort", BC_KES_PORT);
  ADD_STR(d, port, "protocol", "TCP");
  o[k++] = (bc_object){path_of("/api/v1", s, "services", kes), d};
  *out = o;
  return k;
}

size_t bc_kes_paths(const bc_spec *s, bool trial, char ***paths) {
  char kes[128], cfg[160];
  bc_kes_name(s, trial, kes, sizeof(kes));
  snprintf(cfg, sizeof(cfg), "%s-config", kes);
  char **p = buckets_xcalloc(4, sizeof(char *));
  size_t n = 0;
  p[n++] = path_of("/apis/apps/v1", s, "deployments", kes);
  p[n++] = path_of("/api/v1", s, "services", kes);
  p[n++] = path_of("/api/v1", s, "secrets", cfg);
  if (!trial) p[n++] = path_of("/api/v1", s, "serviceaccounts", kes);
  *paths = p;
  return n;
}

yyjson_mut_doc *bc_kms_empty_secret(const bc_spec *s, const char *name) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  mval *root = object(d, "v1", "Secret", s, name, NULL);
  yyjson_mut_obj_remove_key(yyjson_mut_obj_get(root, "metadata"), "ownerReferences");
  ADD_STR(d, root, "type", "Opaque");
  return d;
}

yyjson_mut_doc *bc_kes_tls_secret(const bc_spec *s, const char *cert, const char *key) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_kes_tls_secret_name(s, name, sizeof(name));
  mval *root = kes_object(d, "v1", "Secret", s, name, name);
  ADD_STR(d, root, "type", "kubernetes.io/tls");
  mval *data = ADD_OBJ(d, root, "stringData");
  ADD_STR(d, data, "tls.crt", cert);
  ADD_STR(d, data, "tls.key", key);
  return d;
}

yyjson_mut_doc *bc_kes_identity_secret(const bc_spec *s, const char *admin, const char *client) {
  mdoc *d = yyjson_mut_doc_new(NULL);
  char name[128];
  bc_kes_identity_secret_name(s, name, sizeof(name));
  mval *root = kes_object(d, "v1", "Secret", s, name, name);
  ADD_STR(d, root, "type", "Opaque");
  mval *data = ADD_OBJ(d, root, "stringData");
  ADD_STR(d, data, "admin", admin);
  ADD_STR(d, data, "client", client);
  return d;
}

/* The console's ServiceAccount and what it may do: read and change its own
 * cluster (the KMS settings' spec.kms, the test annotation) and the two KMS
 * settings Secrets. */
static size_t console_rbac(const bc_spec *s, bc_object *o) {
  char name[128], kms[128], cand[128];
  bc_console_secret_name(s, name, sizeof(name));
  bc_kms_settings_secret_name(s, kms, sizeof(kms));
  bc_kms_candidate_secret_name(s, cand, sizeof(cand));
  size_t k = 0;
  mdoc *d = yyjson_mut_doc_new(NULL);
  console_object(d, "v1", "ServiceAccount", s, name);
  o[k++] = (bc_object){path_of("/api/v1", s, "serviceaccounts", name), d};

  d = yyjson_mut_doc_new(NULL);
  mval *root = console_object(d, "rbac.authorization.k8s.io/v1", "Role", s, name);
  mval *rules = ADD_ARR(d, root, "rules");
  mval *r = yyjson_mut_arr_add_obj(d, rules);
  yyjson_mut_arr_add_str(d, ADD_ARR(d, r, "apiGroups"), "buckets.io");
  yyjson_mut_arr_add_str(d, ADD_ARR(d, r, "resources"), "bucketsclusters");
  yyjson_mut_arr_add_strcpy(d, ADD_ARR(d, r, "resourceNames"), s->name);
  mval *verbs = ADD_ARR(d, r, "verbs");
  yyjson_mut_arr_add_str(d, verbs, "get");
  yyjson_mut_arr_add_str(d, verbs, "patch");
  r = yyjson_mut_arr_add_obj(d, rules);
  yyjson_mut_arr_add_str(d, ADD_ARR(d, r, "apiGroups"), "");
  yyjson_mut_arr_add_str(d, ADD_ARR(d, r, "resources"), "secrets");
  mval *names = ADD_ARR(d, r, "resourceNames");
  yyjson_mut_arr_add_strcpy(d, names, kms);
  yyjson_mut_arr_add_strcpy(d, names, cand);
  verbs = ADD_ARR(d, r, "verbs");
  yyjson_mut_arr_add_str(d, verbs, "get");
  yyjson_mut_arr_add_str(d, verbs, "update");
  o[k++] = (bc_object){path_of("/apis/rbac.authorization.k8s.io/v1", s, "roles", name), d};

  d = yyjson_mut_doc_new(NULL);
  root = console_object(d, "rbac.authorization.k8s.io/v1", "RoleBinding", s, name);
  mval *ref = ADD_OBJ(d, root, "roleRef");
  ADD_STR(d, ref, "apiGroup", "rbac.authorization.k8s.io");
  ADD_STR(d, ref, "kind", "Role");
  ADD_STR(d, ref, "name", name);
  mval *sub = yyjson_mut_arr_add_obj(d, ADD_ARR(d, root, "subjects"));
  ADD_STR(d, sub, "kind", "ServiceAccount");
  ADD_STR(d, sub, "name", name);
  ADD_STR(d, sub, "namespace", s->ns);
  o[k++] = (bc_object){path_of("/apis/rbac.authorization.k8s.io/v1", s, "rolebindings", name), d};
  return k;
}
