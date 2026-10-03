/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "kms.h"
#include "manifests.h"

static const char *k_cluster =
    "{\"apiVersion\":\"buckets.io/v1alpha1\",\"kind\":\"BucketsCluster\","
    "\"metadata\":{\"name\":\"store\",\"namespace\":\"data\",\"uid\":\"u-1\",\"generation\":3},"
    "\"spec\":{\"image\":\"bucketsd:test\",\"parity\":2,"
    "\"pools\":[{\"servers\":4,\"volumesPerServer\":2,"
    "\"volumeClaimTemplate\":{\"storageClassName\":\"fast\",\"resources\":{\"requests\":{\"storage\":\"1Ti\"}}}},"
    "{\"name\":\"expansion\",\"servers\":2,\"volumesPerServer\":1}]}}";

static yyjson_doc *parse(const char *json, bc_spec *s, bool expect_ok) {
  yyjson_doc *d = yyjson_read(json, strlen(json), 0);
  assert_non_null(d);
  char err[256] = "";
  bool ok = bc_parse(yyjson_doc_get_root(d), NULL, s, err, sizeof(err));
  if (ok != expect_ok) fail_msg("bc_parse: %s", err);
  return d;
}

static yyjson_mut_val *path(yyjson_mut_val *v, const char *const *keys) {
  for (; *keys && v; keys++) v = yyjson_mut_obj_get(v, *keys);
  return v;
}
#define AT(v, ...) path(v, (const char *const[]){__VA_ARGS__, NULL})

static void test_volumes_and_topology(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_cluster, &s, true);
  char *v = bc_volumes(&s);
  assert_string_equal(v, "http://store-pool-0-{0...3}.store-hl.data.svc.cluster.local:9000/data{0...1} "
                         "http://store-expansion-{0...1}.store-hl.data.svc.cluster.local:9000/data0");
  free(v);
  char t1[17], t2[17];
  bc_topology(&s, t1);
  bc_topology(&s, t2);
  assert_string_equal(t1, t2);
  s.pools[1].servers = 3; /* a topology change changes the hash */
  bc_topology(&s, t2);
  assert_string_not_equal(t1, t2);
  yyjson_doc_free(d);
}

static void test_desired_objects(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_cluster, &s, true);
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  assert_int_equal(n, 6); /* 2 services, 2 statefulsets, 2 PDBs */
  assert_string_equal(o[0].path, "/api/v1/namespaces/data/services/store-hl");
  assert_string_equal(o[1].path, "/api/v1/namespaces/data/services/store");
  assert_string_equal(o[2].path, "/apis/apps/v1/namespaces/data/statefulsets/store-pool-0");
  assert_string_equal(o[5].path, "/apis/policy/v1/namespaces/data/poddisruptionbudgets/store-expansion");

  yyjson_mut_val *hl = yyjson_mut_doc_get_root(o[0].doc);
  assert_true(yyjson_mut_get_bool(AT(hl, "spec", "publishNotReadyAddresses")));
  assert_string_equal(yyjson_mut_get_str(AT(hl, "spec", "clusterIP")), "None");

  yyjson_mut_val *sts = yyjson_mut_doc_get_root(o[2].doc);
  assert_int_equal(yyjson_mut_get_int(AT(sts, "spec", "replicas")), 4);
  assert_string_equal(yyjson_mut_get_str(AT(sts, "spec", "podManagementPolicy")), "Parallel");
  assert_string_equal(yyjson_mut_get_str(AT(sts, "spec", "updateStrategy", "type")), "OnDelete");
  yyjson_mut_val *owner = yyjson_mut_arr_get_first(AT(sts, "metadata", "ownerReferences"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(owner, "uid")), "u-1");
  yyjson_mut_val *c = yyjson_mut_arr_get_first(AT(sts, "spec", "template", "spec", "containers"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(c, "image")), "bucketsd:test");
  bool saw_volumes = false, saw_parity = false;
  size_t i, max;
  yyjson_mut_val *e;
  yyjson_mut_arr_foreach(yyjson_mut_obj_get(c, "env"), i, max, e) {
    const char *name = yyjson_mut_get_str(yyjson_mut_obj_get(e, "name"));
    const char *val = yyjson_mut_get_str(yyjson_mut_obj_get(e, "value"));
    if (strcmp(name, "BUCKETS_VOLUMES") == 0) saw_volumes = val && strstr(val, "store-expansion-{0...1}");
    if (strcmp(name, "BUCKETS_STORAGE_CLASS_STANDARD") == 0) saw_parity = val && strcmp(val, "EC:2") == 0;
    if (strcmp(name, "BUCKETS_ROOT_USER") == 0) {
      assert_string_equal(yyjson_mut_get_str(AT(e, "valueFrom", "secretKeyRef", "name")), "store-root");
    }
  }
  assert_true(saw_volumes);
  assert_true(saw_parity);
  assert_int_equal(yyjson_mut_arr_size(AT(sts, "spec", "volumeClaimTemplates")), 2);
  yyjson_mut_val *pvc = yyjson_mut_arr_get_first(AT(sts, "spec", "volumeClaimTemplates"));
  assert_string_equal(yyjson_mut_get_str(AT(pvc, "spec", "storageClassName")), "fast");
  assert_string_equal(yyjson_mut_get_str(AT(pvc, "spec", "resources", "requests", "storage")), "1Ti");
  assert_non_null(AT(pvc, "spec", "accessModes"));
  char topo[17];
  bc_topology(&s, topo);
  assert_string_equal(yyjson_mut_get_str(AT(sts, "spec", "template", "metadata", "annotations", "buckets.io/topology")), topo);

  yyjson_mut_val *exp = yyjson_mut_doc_get_root(o[3].doc);
  yyjson_mut_val *epvc = yyjson_mut_arr_get_first(AT(exp, "spec", "volumeClaimTemplates"));
  assert_string_equal(yyjson_mut_get_str(AT(epvc, "spec", "resources", "requests", "storage")), "10Gi");
  bc_objects_free(o, n);
  yyjson_doc_free(d);
}

static void test_tls(void **state) {
  (void)state;
  const char *json = "{\"metadata\":{\"name\":\"sec\",\"namespace\":\"ns\",\"uid\":\"u\"},"
                     "\"spec\":{\"tls\":{\"certSecret\":{\"name\":\"sec-tls\"}},"
                     "\"pools\":[{\"servers\":2,\"volumesPerServer\":2}]}}";
  bc_spec s;
  yyjson_doc *d = parse(json, &s, true);
  char *v = bc_volumes(&s);
  assert_non_null(strstr(v, "https://sec-pool-0-{0...1}."));
  free(v);
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  yyjson_mut_val *sts = yyjson_mut_doc_get_root(o[2].doc);
  yyjson_mut_val *c = yyjson_mut_arr_get_first(AT(sts, "spec", "template", "spec", "containers"));
  assert_string_equal(yyjson_mut_get_str(AT(c, "readinessProbe", "httpGet", "scheme")), "HTTPS");
  yyjson_mut_val *vol = yyjson_mut_arr_get_first(AT(sts, "spec", "template", "spec", "volumes"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(vol, "name")), "certs");
  bc_objects_free(o, n);
  yyjson_doc_free(d);
}

static void test_root_secret_not_owned(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_cluster, &s, true);
  yyjson_mut_doc *sec = bc_root_secret(&s, "USER", "PASS");
  yyjson_mut_val *r = yyjson_mut_doc_get_root(sec);
  assert_null(AT(r, "metadata", "ownerReferences"));
  assert_string_equal(yyjson_mut_get_str(AT(r, "stringData", "rootUser")), "USER");
  yyjson_mut_doc_free(sec);
  yyjson_doc_free(d);
}

static void test_invalid(void **state) {
  (void)state;
  bc_spec s;
  const char *bad[] = {
      "{\"metadata\":{\"name\":\"x\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"pools\":[]}}",
      "{\"metadata\":{\"name\":\"x\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"pools\":[{\"servers\":1,\"volumesPerServer\":1}]}}",
      "{\"metadata\":{\"name\":\"Bad_Name\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"pools\":[{\"servers\":2,\"volumesPerServer\":2}]}}",
      "{\"metadata\":{\"name\":\"x\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"pools\":[{\"name\":\"a\",\"servers\":2,\"volumesPerServer\":2},{\"name\":\"a\",\"servers\":2,\"volumesPerServer\":2}]}}",
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) yyjson_doc_free(parse(bad[i], &s, false));
}

static const char *k_console =
    "{\"apiVersion\":\"buckets.io/v1alpha1\",\"kind\":\"BucketsCluster\","
    "\"metadata\":{\"name\":\"store\",\"namespace\":\"data\",\"uid\":\"u-1\",\"generation\":3},"
    "\"spec\":{\"tls\":{\"certSecret\":{\"name\":\"store-tls\"}},\"pools\":[{\"servers\":4,\"volumesPerServer\":1}],"
    "\"console\":{\"enabled\":true,\"replicas\":2,\"image\":\"console:test\",\"s3URL\":\"https://s3.example.com\","
    "\"ingress\":{\"host\":\"console.example.com\",\"ingressClassName\":\"nginx\",\"tlsSecret\":{\"name\":\"web-tls\"}}}}}";

static void test_console(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_cluster, &s, true);
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  assert_int_equal(n, 6); /* disabled: nothing of the console */
  bc_objects_free(o, n);
  char **stale;
  size_t ns = bc_console_stale(&s, &stale);
  assert_int_equal(ns, 6);
  assert_string_equal(stale[0], "/apis/apps/v1/namespaces/data/deployments/store-console");
  assert_string_equal(stale[4], "/api/v1/namespaces/data/serviceaccounts/store-console");
  for (size_t i = 0; i < ns; i++) free(stale[i]);
  free(stale);
  yyjson_doc_free(d);

  d = parse(k_console, &s, true);
  n = bc_desired(&s, &o);
  assert_int_equal(n, 2 + 2 + 3 + 3); /* + its ServiceAccount, Role, RoleBinding */
  assert_string_equal(o[7].path, "/api/v1/namespaces/data/services/store-console");
  assert_string_equal(o[8].path, "/apis/apps/v1/namespaces/data/deployments/store-console");
  assert_string_equal(o[9].path, "/apis/networking.k8s.io/v1/namespaces/data/ingresses/store-console");
  yyjson_mut_val *dep = yyjson_mut_doc_get_root(o[8].doc);
  assert_int_equal(yyjson_mut_get_int(AT(dep, "spec", "replicas")), 2);
  /* console pods never match the storage Service's selector */
  yyjson_mut_val *pl = AT(dep, "spec", "template", "metadata", "labels");
  assert_null(yyjson_mut_obj_get(pl, "buckets.io/cluster"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(pl, "buckets.io/console")), "store");
  assert_string_equal(yyjson_mut_get_str(AT(yyjson_mut_doc_get_root(o[7].doc), "spec", "selector", "buckets.io/console")), "store");
  yyjson_mut_val *c = yyjson_mut_arr_get_first(AT(dep, "spec", "template", "spec", "containers"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(c, "image")), "console:test");
  yyjson_mut_val *env = yyjson_mut_obj_get(c, "env");
  bool server = false, ca = false, secure = false, pass = false, s3 = false;
  size_t i, max;
  yyjson_mut_val *e;
  yyjson_mut_arr_foreach(env, i, max, e) {
    const char *nm = yyjson_mut_get_str(yyjson_mut_obj_get(e, "name"));
    const char *v = yyjson_mut_get_str(yyjson_mut_obj_get(e, "value"));
    if (!strcmp(nm, "BUCKETS_CONSOLE_SERVER")) server = !strcmp(v, "https://store.data.svc.cluster.local:9000");
    if (!strcmp(nm, "BUCKETS_CONSOLE_CA_DIR")) ca = true;
    if (!strcmp(nm, "BUCKETS_CONSOLE_SECURE_COOKIE")) secure = true;
    if (!strcmp(nm, "BUCKETS_CONSOLE_S3_URL")) s3 = !strcmp(v, "https://s3.example.com");
    if (!strcmp(nm, "BUCKETS_CONSOLE_PBKDF_PASSPHRASE"))
      pass = !strcmp(yyjson_mut_get_str(AT(e, "valueFrom", "secretKeyRef", "name")), "store-console");
  }
  assert_true(server && ca && secure && pass && s3);
  yyjson_mut_val *ing = yyjson_mut_doc_get_root(o[9].doc);
  assert_string_equal(yyjson_mut_get_str(AT(ing, "spec", "ingressClassName")), "nginx");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(yyjson_mut_arr_get_first(AT(ing, "spec", "rules")), "host")), "console.example.com");
  bc_objects_free(o, n);
  ns = bc_console_stale(&s, &stale);
  assert_int_equal(ns, 0);
  free(stale);
  yyjson_mut_doc *sec = bc_console_secret(&s, "p", "s");
  assert_string_equal(yyjson_mut_get_str(AT(yyjson_mut_doc_get_root(sec), "stringData", "passphrase")), "p");
  yyjson_mut_doc_free(sec);
  yyjson_doc_free(d);
}

static void test_console_tls(void **state) {
  (void)state;
  const char *json = "{\"metadata\":{\"name\":\"store\",\"namespace\":\"data\",\"uid\":\"u\"},"
                     "\"spec\":{\"pools\":[{\"servers\":2,\"volumesPerServer\":2}],"
                     "\"console\":{\"enabled\":true,\"tls\":{\"certSecret\":{\"name\":\"console-tls\"}},"
                     "\"ingress\":{\"host\":\"console.example.com\"}}}}";
  bc_spec s;
  yyjson_doc *d = parse(json, &s, true);
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  assert_int_equal(n, 2 + 2 + 3 + 3); /* + its ServiceAccount, Role, RoleBinding */
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(
                          yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[7].doc), "spec", "ports")), "name")),
                      "https-console");
  yyjson_mut_val *pod = AT(yyjson_mut_doc_get_root(o[8].doc), "spec", "template", "spec");
  yyjson_mut_val *c = yyjson_mut_arr_get_first(yyjson_mut_obj_get(pod, "containers"));
  yyjson_mut_val *args = yyjson_mut_obj_get(c, "args");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_arr_get(args, 4)), "--certs-dir");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_arr_get(args, 5)), "/etc/buckets/console-certs");
  assert_string_equal(yyjson_mut_get_str(AT(c, "readinessProbe", "httpGet", "scheme")), "HTTPS");
  assert_string_equal(yyjson_mut_get_str(AT(c, "livenessProbe", "httpGet", "scheme")), "HTTPS");
  yyjson_mut_val *vol = yyjson_mut_arr_get_last(yyjson_mut_obj_get(pod, "volumes"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(vol, "name")), "console-certs");
  assert_string_equal(yyjson_mut_get_str(AT(vol, "secret", "secretName")), "console-tls");
  yyjson_mut_val *key = yyjson_mut_arr_get(AT(vol, "secret", "items"), 1);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(key, "path")), "private.key");
  yyjson_mut_val *ing = yyjson_mut_doc_get_root(o[9].doc);
  assert_string_equal(
      yyjson_mut_get_str(AT(ing, "metadata", "annotations", "nginx.ingress.kubernetes.io/backend-protocol")), "HTTPS");
  bc_objects_free(o, n);
  yyjson_doc_free(d);

  /* without console TLS: plain HTTP, as before */
  d = parse(k_console, &s, true);
  n = bc_desired(&s, &o);
  c = yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[8].doc), "spec", "template", "spec", "containers"));
  assert_int_equal(yyjson_mut_arr_size(yyjson_mut_obj_get(c, "args")), 4);
  assert_string_equal(yyjson_mut_get_str(AT(c, "readinessProbe", "httpGet", "scheme")), "HTTP");
  assert_null(AT(yyjson_mut_doc_get_root(o[9].doc), "metadata", "annotations"));
  bc_objects_free(o, n);
  yyjson_doc_free(d);
}

static void test_console_env(void **state) {
  (void)state;
  const char *json = "{\"metadata\":{\"name\":\"store\",\"namespace\":\"data\",\"uid\":\"u\"},"
                     "\"spec\":{\"pools\":[{\"servers\":2,\"volumesPerServer\":2}],"
                     "\"console\":{\"enabled\":true,\"env\":["
                     "{\"name\":\"BUCKETS_CONSOLE_OIDC_CLIENT_ID\",\"value\":\"app-1\"},"
                     "{\"name\":\"BUCKETS_CONSOLE_OIDC_CLIENT_SECRET\","
                     "\"valueFrom\":{\"secretKeyRef\":{\"name\":\"entra\",\"key\":\"secret\"}}}]}}}";
  bc_spec s;
  yyjson_doc *d = parse(json, &s, true);
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  yyjson_mut_val *c = yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[8].doc), "spec", "template", "spec", "containers"));
  yyjson_mut_val *env = yyjson_mut_obj_get(c, "env");
  /* the operator's own first, then the spec's, as given */
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(yyjson_mut_arr_get_first(env), "name")), "BUCKETS_CONSOLE_SERVER");
  size_t len = yyjson_mut_arr_size(env);
  yyjson_mut_val *id = yyjson_mut_arr_get(env, len - 2), *sec = yyjson_mut_arr_get(env, len - 1);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(id, "value")), "app-1");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(sec, "name")), "BUCKETS_CONSOLE_OIDC_CLIENT_SECRET");
  assert_string_equal(yyjson_mut_get_str(AT(sec, "valueFrom", "secretKeyRef", "key")), "secret");
  bc_objects_free(o, n);
  yyjson_doc_free(d);
}

/* A MinIO Operator tenant's layout, to adopt its volumes in place: the same
 * StatefulSet, headless Service and claim names, its drive paths, user,
 * config.env credentials and Service port. */
static const char *k_tenant =
    "{\"metadata\":{\"name\":\"minio\",\"namespace\":\"data\",\"uid\":\"u\"},"
    "\"spec\":{\"tls\":{\"certSecret\":{\"name\":\"tls-minio\"}},"
    "\"configuration\":{\"name\":\"myminio-env-configuration\"},"
    "\"drives\":{\"mountPath\":\"/export\",\"subPath\":\"/data\"},"
    "\"securityContext\":{\"runAsUser\":1000,\"runAsGroup\":1000,\"fsGroup\":1000},"
    "\"servicePort\":443,"
    "\"volumes\":[{\"name\":\"kes-client\",\"secret\":{\"secretName\":\"minio-kes-tls\"}}],"
    "\"volumeMounts\":[{\"name\":\"kes-client\",\"mountPath\":\"/etc/buckets/kes\"}],"
    "\"pools\":[{\"name\":\"pool-0\",\"servers\":3,\"volumesPerServer\":6}]}}";

static yyjson_mut_val *find_named(yyjson_mut_val *arr, const char *name) {
  size_t i, max;
  yyjson_mut_val *e;
  yyjson_mut_arr_foreach(arr, i, max, e) {
    const char *n = yyjson_mut_get_str(yyjson_mut_obj_get(e, "name"));
    if (n && !strcmp(n, name)) return e;
  }
  return NULL;
}

static void test_minio_tenant_layout(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_tenant, &s, true);
  char *v = bc_volumes(&s);
  assert_string_equal(v, "https://minio-pool-0-{0...2}.minio-hl.data.svc.cluster.local:9000/export{0...5}/data");
  free(v);
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  assert_string_equal(o[0].path, "/api/v1/namespaces/data/services/minio-hl");
  assert_int_equal(yyjson_mut_get_int(yyjson_mut_obj_get(yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[0].doc), "spec", "ports")), "port")), 9000);
  assert_int_equal(yyjson_mut_get_int(yyjson_mut_obj_get(yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[1].doc), "spec", "ports")), "port")), 443);
  assert_string_equal(o[2].path, "/apis/apps/v1/namespaces/data/statefulsets/minio-pool-0");
  yyjson_mut_val *sts = yyjson_mut_doc_get_root(o[2].doc);
  yyjson_mut_val *pod = AT(sts, "spec", "template", "spec");
  assert_int_equal(yyjson_mut_get_int(AT(pod, "securityContext", "runAsUser")), 1000);
  assert_int_equal(yyjson_mut_get_int(AT(pod, "securityContext", "fsGroup")), 1000);
  yyjson_mut_val *c = yyjson_mut_arr_get_first(yyjson_mut_obj_get(pod, "containers"));
  yyjson_mut_val *env = yyjson_mut_obj_get(c, "env");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(find_named(env, "BUCKETS_CONFIG_ENV_FILE"), "value")),
                      "/etc/buckets/config/config.env");
  assert_null(find_named(env, "BUCKETS_ROOT_USER")); /* config.env carries them */
  yyjson_mut_val *mounts = yyjson_mut_obj_get(c, "volumeMounts");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(find_named(mounts, "data5"), "mountPath")), "/export5");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(find_named(mounts, "config"), "mountPath")), "/etc/buckets/config");
  assert_non_null(find_named(mounts, "kes-client"));
  yyjson_mut_val *vols = yyjson_mut_obj_get(pod, "volumes");
  assert_string_equal(yyjson_mut_get_str(AT(find_named(vols, "config"), "secret", "secretName")), "myminio-env-configuration");
  assert_non_null(find_named(vols, "kes-client"));
  assert_non_null(find_named(vols, "certs"));
  yyjson_mut_val *claims = AT(sts, "spec", "volumeClaimTemplates");
  assert_int_equal(yyjson_mut_arr_size(claims), 6); /* data0..data5: PVCs data<n>-minio-pool-0-<i> */
  assert_string_equal(yyjson_mut_get_str(AT(yyjson_mut_arr_get_first(claims), "metadata", "name")), "data0");
  char cn[128];
  bc_creds_secret_name(&s, cn, sizeof(cn));
  assert_string_equal(cn, "myminio-env-configuration");
  bc_objects_free(o, n);
  yyjson_doc_free(d);

  /* defaults are unchanged: nonroot, /data<n>, port 9000, no pod volumes without TLS */
  d = parse(k_cluster, &s, true);
  n = bc_desired(&s, &o);
  pod = AT(yyjson_mut_doc_get_root(o[2].doc), "spec", "template", "spec");
  assert_int_equal(yyjson_mut_get_int(AT(pod, "securityContext", "runAsUser")), 65532);
  assert_null(yyjson_mut_obj_get(pod, "volumes"));
  c = yyjson_mut_arr_get_first(yyjson_mut_obj_get(pod, "containers"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(find_named(yyjson_mut_obj_get(c, "volumeMounts"), "data1"), "mountPath")), "/data1");
  assert_non_null(find_named(yyjson_mut_obj_get(c, "env"), "BUCKETS_ROOT_USER"));
  assert_int_equal(yyjson_mut_get_int(yyjson_mut_obj_get(yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[1].doc), "spec", "ports")), "port")), 9000);
  bc_objects_free(o, n);
  yyjson_doc_free(d);

  const char *bad[] = {
      "{\"metadata\":{\"name\":\"m\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"credsSecret\":{\"name\":\"a\"},"
      "\"configuration\":{\"name\":\"b\"},\"pools\":[{\"servers\":2,\"volumesPerServer\":2}]}}",
      "{\"metadata\":{\"name\":\"m\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"drives\":{\"mountPath\":\"export\"},"
      "\"pools\":[{\"servers\":2,\"volumesPerServer\":2}]}}",
      "{\"metadata\":{\"name\":\"m\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"drives\":{\"mountPath\":\"/e{0...3}\"},"
      "\"pools\":[{\"servers\":2,\"volumesPerServer\":2}]}}",
      "{\"metadata\":{\"name\":\"m\",\"namespace\":\"n\",\"uid\":\"u\"},\"spec\":{\"securityContext\":{\"runAsUser\":0},"
      "\"pools\":[{\"servers\":2,\"volumesPerServer\":2}]}}",
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) yyjson_doc_free(parse(bad[i], &s, false));
}


static const char *k_kes =
    "{\"apiVersion\":\"buckets.io/v1alpha1\",\"kind\":\"BucketsCluster\","
    "\"metadata\":{\"name\":\"store\",\"namespace\":\"data\",\"uid\":\"u-1\"},"
    "\"spec\":{\"image\":\"bucketsd:test\",\"console\":{\"enabled\":true},\"kms\":{\"kes\":{\"image\":\"kes:test\"}},"
    "\"pools\":[{\"servers\":4,\"volumesPerServer\":1}]}}";

static const char *env_value_of(yyjson_mut_val *c, const char *name) {
  size_t i, max;
  yyjson_mut_val *e;
  yyjson_mut_arr_foreach(yyjson_mut_obj_get(c, "env"), i, max, e) {
    if (!strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(e, "name")), name)) {
      const char *v = yyjson_mut_get_str(yyjson_mut_obj_get(e, "value"));
      return v ? v : "(from a Secret)";
    }
  }
  return NULL;
}

static void test_kes_spec(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_kes, &s, true);
  assert_true(s.kes.enabled);
  assert_int_equal(s.kes.replicas, 2);
  assert_string_equal(s.kes.key_name, BC_KES_DEFAULT_KEY);
  assert_string_equal(s.kes.image, "kes:test");
  char ep[256];
  bc_kes_endpoint(&s, false, ep, sizeof(ep));
  assert_string_equal(ep, "https://store-kes.data.svc.cluster.local:7373");
  bc_kes_endpoint(&s, true, ep, sizeof(ep));
  assert_string_equal(ep, "https://store-kes-test.data.svc.cluster.local:7373");

  /* bucketsd uses KES only once the reconciler says it may */
  bc_object *o;
  size_t n = bc_desired(&s, &o);
  yyjson_mut_val *c = yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[2].doc), "spec", "template", "spec", "containers"));
  assert_null(env_value_of(c, "MINIO_KMS_KES_ENDPOINT"));
  bc_objects_free(o, n);
  s.kes.active = true;
  n = bc_desired(&s, &o);
  yyjson_mut_val *pod = AT(yyjson_mut_doc_get_root(o[2].doc), "spec", "template", "spec");
  c = yyjson_mut_arr_get_first(yyjson_mut_obj_get(pod, "containers"));
  assert_string_equal(env_value_of(c, "MINIO_KMS_KES_ENDPOINT"), "https://store-kes.data.svc.cluster.local:7373");
  assert_string_equal(env_value_of(c, "MINIO_KMS_KES_KEY_NAME"), BC_KES_DEFAULT_KEY);
  assert_string_equal(env_value_of(c, "MINIO_KMS_KES_API_KEY"), "(from a Secret)");
  assert_string_equal(env_value_of(c, "MINIO_KMS_KES_CAPATH"), "/etc/buckets/kes/ca.crt");
  bool vol = false;
  size_t i, max;
  yyjson_mut_val *v;
  yyjson_mut_arr_foreach(yyjson_mut_obj_get(pod, "volumes"), i, max, v) {
    if (!strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(v, "name")), "kes-ca"))
      vol = !strcmp(yyjson_mut_get_str(AT(v, "secret", "secretName")), "store-kes-tls");
  }
  assert_true(vol);
  /* the console runs as its own account, which may touch its cluster and the KMS Secrets only */
  yyjson_mut_val *role = NULL;
  for (size_t k = 0; k < n; k++)
    if (strstr(o[k].path, "/roles/store-console")) role = yyjson_mut_doc_get_root(o[k].doc);
  assert_non_null(role);
  yyjson_mut_val *r0 = yyjson_mut_arr_get(yyjson_mut_obj_get(role, "rules"), 0);
  yyjson_mut_val *r1 = yyjson_mut_arr_get(yyjson_mut_obj_get(role, "rules"), 1);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_arr_get_first(yyjson_mut_obj_get(r0, "resourceNames"))), "store");
  assert_int_equal(yyjson_mut_arr_size(yyjson_mut_obj_get(r1, "resourceNames")), 2);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_arr_get(yyjson_mut_obj_get(r1, "resourceNames"), 1)), "store-kms-candidate");
  for (size_t k = 0; k < n; k++) {
    if (!strstr(o[k].path, "/deployments/store-console")) continue;
    yyjson_mut_val *cp = AT(yyjson_mut_doc_get_root(o[k].doc), "spec", "template", "spec");
    assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(cp, "serviceAccountName")), "store-console");
    assert_string_equal(env_value_of(yyjson_mut_arr_get_first(yyjson_mut_obj_get(cp, "containers")), "BUCKETS_CONSOLE_CLUSTER"), "store");
  }
  bc_objects_free(o, n);
  yyjson_doc_free(d);

  /* KMS settings in two places is a mistake */
  d = parse("{\"metadata\":{\"name\":\"store\",\"namespace\":\"data\",\"uid\":\"u\"},\"spec\":{\"kms\":{\"kes\":{}},"
            "\"env\":[{\"name\":\"MINIO_KMS_SECRET_KEY\",\"value\":\"k:x\"}],\"pools\":[{\"servers\":4,\"volumesPerServer\":1}]}}",
            &s, false);
  yyjson_doc_free(d);
}

static void test_kes_objects(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse(k_kes, &s, true);
  const char *settings = "{\"backend\":\"vault\",\"vault\":{\"endpoint\":\"https://vault:8200\",\"approle\":{\"id\":\"r\","
                         "\"secret\":\"x\"},\"caCert\":\"-----BEGIN CERTIFICATE-----\\nA\\n-----END CERTIFICATE-----\\n\"}}";
  yyjson_doc *sd = yyjson_read(settings, strlen(settings), 0);
  char *ca = NULL, err[256];
  char *config = bc_kes_config(&s, yyjson_doc_get_root(sd), "aaaa", "bbbb", &ca, err, sizeof(err));
  assert_non_null(config);
  assert_non_null(ca);
  yyjson_doc *cd = yyjson_read(config, strlen(config), 0);
  yyjson_val *cr = yyjson_doc_get_root(cd);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_obj_get(cr, "admin"), "identity")), "aaaa");
  yyjson_val *pol = yyjson_obj_get(yyjson_obj_get(cr, "policy"), "buckets");
  assert_string_equal(yyjson_get_str(yyjson_arr_get_first(yyjson_obj_get(pol, "identities"))), "bbbb");
  assert_true(yyjson_get_bool(yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(cr, "api"), "/v1/ready"), "skip_auth")));
  yyjson_val *vault = yyjson_obj_get(yyjson_obj_get(cr, "keystore"), "vault");
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_obj_get(vault, "tls"), "ca")), "/etc/kes/config/keystore-ca.pem");
  yyjson_doc_free(cd);

  bc_object *o;
  size_t n = bc_kes_objects(&s, false, config, ca, &o);
  assert_int_equal(n, 4);
  assert_string_equal(o[0].path, "/api/v1/namespaces/data/serviceaccounts/store-kes");
  assert_string_equal(o[1].path, "/api/v1/namespaces/data/secrets/store-kes-config");
  assert_string_equal(o[2].path, "/apis/apps/v1/namespaces/data/deployments/store-kes");
  assert_string_equal(o[3].path, "/api/v1/namespaces/data/services/store-kes");
  yyjson_mut_val *dep = yyjson_mut_doc_get_root(o[2].doc);
  assert_int_equal(yyjson_mut_get_int(AT(dep, "spec", "replicas")), 2);
  yyjson_mut_val *labels = AT(dep, "spec", "template", "metadata", "labels");
  assert_null(yyjson_mut_obj_get(labels, "buckets.io/cluster")); /* never behind the S3 Service */
  const char *hash = yyjson_mut_get_str(AT(dep, "spec", "template", "metadata", "annotations", "buckets.io/config-hash"));
  char h1[17];
  snprintf(h1, sizeof(h1), "%s", hash);
  yyjson_mut_val *c = yyjson_mut_arr_get_first(AT(dep, "spec", "template", "spec", "containers"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(c, "image")), "kes:test");
  assert_string_equal(yyjson_mut_get_str(AT(c, "readinessProbe", "httpGet", "path")), "/v1/ready");
  assert_string_equal(yyjson_mut_get_str(AT(c, "livenessProbe", "httpGet", "path")), "/version");
  assert_string_equal(yyjson_mut_get_str(AT(dep, "spec", "template", "spec", "serviceAccountName")), "store-kes");
  assert_non_null(AT(yyjson_mut_doc_get_root(o[1].doc), "stringData", "keystore-ca.pem"));
  bc_objects_free(o, n);

  /* a trial: one replica of its own, the live account; new settings, a new hash */
  n = bc_kes_objects(&s, true, "{\"other\":1}", NULL, &o);
  assert_string_equal(o[2].path, "/apis/apps/v1/namespaces/data/deployments/store-kes-test");
  dep = yyjson_mut_doc_get_root(o[2].doc);
  assert_int_equal(yyjson_mut_get_int(AT(dep, "spec", "replicas")), 1);
  assert_string_equal(yyjson_mut_get_str(AT(dep, "spec", "template", "spec", "serviceAccountName")), "store-kes");
  assert_string_not_equal(yyjson_mut_get_str(AT(dep, "spec", "template", "metadata", "annotations", "buckets.io/config-hash")), h1);
  bc_objects_free(o, n);
  char **paths;
  n = bc_kes_paths(&s, true, &paths);
  assert_int_equal(n, 3); /* a trial's cleanup leaves the live account */
  for (size_t i = 0; i < n; i++) free(paths[i]);
  free(paths);
  free(config);
  free(ca);
  yyjson_doc_free(sd);

  /* settings that do not hold up say why */
  const char *bad = "{\"backend\":\"vault\",\"vault\":{}}";
  sd = yyjson_read(bad, strlen(bad), 0);
  assert_null(bc_kes_config(&s, yyjson_doc_get_root(sd), "a", "b", &ca, err, sizeof(err)));
  assert_non_null(strstr(err, "Vault server's address"));
  yyjson_doc_free(sd);
  yyjson_doc_free(d);
}

/* an adopted tenant's KES: its account, its keys (none made) */
static void test_kes_adopted(void **state) {
  (void)state;
  bc_spec s;
  yyjson_doc *d = parse("{\"metadata\":{\"name\":\"minio\",\"namespace\":\"lake\",\"uid\":\"u\"},\"spec\":{\"kms\":{\"kes\":"
                        "{\"keyName\":\"minio-key\",\"createKey\":false,\"serviceAccountName\":\"minio-kes-sa\","
                        "\"name\":\"minio-buckets-kes\","
                        "\"tolerations\":[{\"key\":\"storage\",\"operator\":\"Exists\"}]}},"
                        "\"pools\":[{\"servers\":4,\"volumesPerServer\":1}]}}",
                        &s, true);
  assert_false(s.kes.create_key);
  assert_string_equal(s.kes.service_account, "minio-kes-sa");
  assert_string_equal(s.kes.key_name, "minio-key");
  char nm[160];
  bc_kes_name(&s, false, nm, sizeof(nm));
  assert_string_equal(nm, "minio-buckets-kes"); /* the tenant's minio-kes objects keep their names */
  bc_kes_name(&s, true, nm, sizeof(nm));
  assert_string_equal(nm, "minio-buckets-kes-test");
  bc_kes_tls_secret_name(&s, nm, sizeof(nm));
  assert_string_equal(nm, "minio-buckets-kes-tls");
  bc_kes_identity_secret_name(&s, nm, sizeof(nm));
  assert_string_equal(nm, "minio-buckets-kes-identity");
  bc_kes_endpoint(&s, false, nm, sizeof(nm));
  assert_non_null(strstr(nm, "https://minio-buckets-kes.lake.svc."));
  bc_object *o;
  size_t n = bc_kes_objects(&s, false, "{}", NULL, &o);
  assert_int_equal(n, 3); /* no ServiceAccount of its own */
  for (size_t i = 0; i < n; i++) assert_null(strstr(o[i].path, "/serviceaccounts/"));
  assert_string_equal(yyjson_mut_get_str(AT(yyjson_mut_doc_get_root(o[1].doc), "spec", "template", "spec", "serviceAccountName")),
                      "minio-kes-sa");
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(yyjson_mut_arr_get_first(AT(yyjson_mut_doc_get_root(o[1].doc), "spec",
                                                                                  "template", "spec", "tolerations")), "key")),
                      "storage");
  bc_objects_free(o, n);
  yyjson_doc_free(d);
  d = parse(k_kes, &s, true);
  assert_true(s.kes.create_key); /* the default */
  assert_null(s.kes.service_account);
  bc_kes_tls_secret_name(&s, nm, sizeof(nm));
  assert_string_equal(nm, "store-kes-tls");
  yyjson_doc_free(d);
}

/* what KES 2024-09-11 prints, as captured */
static void test_kes_log_reason(void **state) {
  (void)state;
  char r[300];
  op_kes_log_reason("Version  <unknown>\n\nError: Error making API request.\n\nURL: PUT http://v:8200/v1/auth/approle/login\n"
                    "Code: 400. Errors:\n\n* invalid role or secret ID\n",
                    r, sizeof(r));
  assert_string_equal(r, "Error making API request. URL: PUT http://v:8200/v1/auth/approle/login Code: 400. Errors: * "
                         "invalid role or secret ID");
  op_kes_log_reason("Error: Put \"http://127.0.0.1:18299/v1/auth/approle/login\": dial tcp 127.0.0.1:18299: connect: "
                    "connection refused\n",
                    r, sizeof(r));
  assert_string_equal(r, "Put \"http://127.0.0.1:18299/v1/auth/approle/login\": dial tcp 127.0.0.1:18299: connect: connection refused");
  op_kes_log_reason("=> Server is up and running...\n"
                    "time=2026-10-02T14:43:01.187-05:00 level=ERROR msg=\"vault: failed to create 'kv/data/buckets/x/t1': "
                    "Error making API request.\\n\\nURL: GET http://v/v1/kv/data/buckets/x/t1\\nCode: 403. Errors:\\n\\n* 1 "
                    "error occurred:\\n\\t* permission denied\\n\\n\" req.method=POST req.path=/v1/key/create/t1\n",
                    r, sizeof(r));
  assert_string_equal(r, "vault: failed to create 'kv/data/buckets/x/t1': Error making API request. URL: GET "
                         "http://v/v1/kv/data/buckets/x/t1 Code: 403. Errors: * 1 error occurred: * permission denied");
  /* buckets-kes's own log lines */
  op_kes_log_reason("{\"level\":\"INFO\",\"msg\":\"listening\"}\n{\"level\":\"ERROR\",\"time\":\"t\",\"msg\":\"vault: "
                    "failed to create key: permission denied (403)\"}\n",
                    r, sizeof(r));
  assert_string_equal(r, "vault: failed to create key: permission denied (403)");
  op_kes_log_reason("=> Server is up and running...\n", r, sizeof(r));
  assert_string_equal(r, "");
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_volumes_and_topology), cmocka_unit_test(test_desired_objects), cmocka_unit_test(test_tls),
      cmocka_unit_test(test_root_secret_not_owned), cmocka_unit_test(test_invalid),
      cmocka_unit_test(test_console), cmocka_unit_test(test_console_tls), cmocka_unit_test(test_console_env),
      cmocka_unit_test(test_minio_tenant_layout), cmocka_unit_test(test_kes_spec), cmocka_unit_test(test_kes_objects), cmocka_unit_test(test_kes_log_reason), cmocka_unit_test(test_kes_adopted),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
