/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_MANIFESTS_H
#define BUCKETS_OPERATOR_MANIFESTS_H

#include <yyjson.h>

#include "core/common.h"

/* Pure functions from a BucketsCluster to the objects it should own. No I/O,
 * so they are unit tested directly (operator/tests/test_manifests.c). */

#define BC_API_VERSION "buckets.io/v1alpha1"
#define BC_KIND "BucketsCluster"
#define BC_S3_PORT 9000
#define BC_MAX_POOLS 32

typedef struct {
  char name[32];
  int servers, volumes;
  yyjson_val *volume_claim_template, *resources, *node_selector, *tolerations, *affinity;
} bc_pool;

typedef struct {
  const char *name, *ns, *uid;
  long long generation;
  const char *image, *pull_policy;
  yyjson_val *pull_secrets, *env;
  const char *creds_secret; /* NULL: operator-managed <name>-root */
  bc_pool pools[BC_MAX_POOLS];
  size_t npools;
  int parity, set_drive_count; /* 0: default */
  const char *tls_secret, *ca_secret;
  const char *service_type;
  const char *cluster_domain; /* e.g. cluster.local */
} bc_spec;

/* Reads and validates a BucketsCluster; strings point into the document. */
bool bc_parse(yyjson_val *obj, const char *cluster_domain, bc_spec *out, char *err, size_t errlen);

/* Names. */
void bc_root_secret_name(const bc_spec *s, char *out, size_t cap);
void bc_statefulset_name(const bc_spec *s, size_t pool, char *out, size_t cap);
void bc_headless_name(const bc_spec *s, char *out, size_t cap);

/* BUCKETS_VOLUMES: one ellipsis argument per pool, over the pods' stable DNS
 * names, e.g. http://c-pool-0-{0...3}.c-hl.ns.svc.cluster.local:9000/data{0...3}.
 * Caller frees. */
char *bc_volumes(const bc_spec *s);
/* A short hash of everything every node must agree on (endpoints, erasure
 * settings). A change means the whole cluster restarts together. */
void bc_topology(const bc_spec *s, char out[17]);

typedef struct {
  char *path;           /* the object's API URL */
  yyjson_mut_doc *doc;  /* desired object, for server-side apply */
} bc_object;

/* Services, one StatefulSet and one PodDisruptionBudget per pool, in apply
 * order. Caller frees with bc_objects_free. */
size_t bc_desired(const bc_spec *s, bc_object **out);
void bc_objects_free(bc_object *o, size_t n);

/* The operator-managed root credentials Secret (deliberately not owned by the
 * cluster, so it outlives it like the data does). */
yyjson_mut_doc *bc_root_secret(const bc_spec *s, const char *user, const char *password);

#endif
