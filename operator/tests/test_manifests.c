/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

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
  assert_int_equal(ns, 3);
  assert_string_equal(stale[0], "/apis/apps/v1/namespaces/data/deployments/store-console");
  for (size_t i = 0; i < ns; i++) free(stale[i]);
  free(stale);
  yyjson_doc_free(d);

  d = parse(k_console, &s, true);
  n = bc_desired(&s, &o);
  assert_int_equal(n, 2 + 2 + 3);
  assert_string_equal(o[4].path, "/api/v1/namespaces/data/services/store-console");
  assert_string_equal(o[5].path, "/apis/apps/v1/namespaces/data/deployments/store-console");
  assert_string_equal(o[6].path, "/apis/networking.k8s.io/v1/namespaces/data/ingresses/store-console");
  yyjson_mut_val *dep = yyjson_mut_doc_get_root(o[5].doc);
  assert_int_equal(yyjson_mut_get_int(AT(dep, "spec", "replicas")), 2);
  /* console pods never match the storage Service's selector */
  yyjson_mut_val *pl = AT(dep, "spec", "template", "metadata", "labels");
  assert_null(yyjson_mut_obj_get(pl, "buckets.io/cluster"));
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(pl, "buckets.io/console")), "store");
  assert_string_equal(yyjson_mut_get_str(AT(yyjson_mut_doc_get_root(o[4].doc), "spec", "selector", "buckets.io/console")), "store");
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
  yyjson_mut_val *ing = yyjson_mut_doc_get_root(o[6].doc);
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

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_volumes_and_topology), cmocka_unit_test(test_desired_objects), cmocka_unit_test(test_tls),
      cmocka_unit_test(test_root_secret_not_owned), cmocka_unit_test(test_invalid),
      cmocka_unit_test(test_console),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
