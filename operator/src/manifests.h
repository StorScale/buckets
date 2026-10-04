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
#define BC_CONSOLE_PORT 9090
#define BC_CONSOLE_IMAGE "ghcr.io/storscale/buckets-console:1.0.0"
#define BC_MAX_POOLS 32
#define BC_KES_PORT 7373
/* buckets-kes, Buckets' own KES-compatible server; BUCKETS_KES_IMAGE (the
 * operator's environment) or spec.kms.kes.image point elsewhere: a registry
 * mirror, or MinIO's KES, which reads the same configuration and keys. */
#define BC_KES_IMAGE "ghcr.io/storscale/buckets-kes:1.0.0"
#define BC_KES_DEFAULT_KEY "buckets-default"

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
  /* MinIO Operator compatibility, for adopting a tenant's volumes in place:
   * config_secret = a Secret whose config.env (export KEY=value lines, root
   * credentials included) bucketsd reads; drive mounts at <mount_path><n>
   * with data under <mount_path><n><sub_path>; the pods' user and groups;
   * the S3 Service's port; extra pod volumes and container mounts. */
  const char *config_secret;
  const char *mount_path, *sub_path; /* "/data", "" */
  long long run_as_user, run_as_group, fs_group; /* 65532 */
  int service_port;                              /* BC_S3_PORT */
  yyjson_val *volumes, *volume_mounts;
  bc_pool pools[BC_MAX_POOLS];
  size_t npools;
  int parity, set_drive_count; /* 0: default */
  const char *tls_secret, *ca_secret;
  const char *service_type;
  const char *cluster_domain; /* e.g. cluster.local */
  struct {
    bool enabled;
    int replicas;
    const char *image, *service_type;
    const char *ingress_host, *ingress_class, *ingress_tls_secret; /* host NULL: no Ingress */
    const char *s3_url; /* S3 as browsers reach it, for share links (NULL: none) */
    const char *tls_secret; /* consoled serves HTTPS with it (NULL: HTTP) */
    yyjson_val *resources, *annotations;
    yyjson_val *env; /* extra environment for consoled, e.g. its OpenID sign-in */
  } console;
  /* spec.kms.kes: a KES server the operator runs for the cluster, its key
   * store settings in Secret <name>-kms (settings.json, written by the
   * console; see kms/kesutil.h). */
  struct {
    bool enabled;
    int replicas;
    const char *image, *key_name;
    yyjson_val *resources;
    /* an existing ServiceAccount KES runs as (an adopted tenant's, which a
     * Vault Kubernetes role names); NULL: the operator's own <name>-kes */
    const char *name; /* the KES servers' and their Secrets' base name (default <cluster>-kes) */
    const char *service_account;
    yyjson_val *node_selector, *tolerations, *affinity; /* where KES runs (trials too) */
    bool create_key; /* make the default key when missing (false: a missing key is an error) */
    bool active; /* set by the reconciler once KES serves the default key: bucketsd uses it */
  } kes;
} bc_spec;

/* Reads and validates a BucketsCluster; strings point into the document. */
bool bc_parse(yyjson_val *obj, const char *cluster_domain, bc_spec *out, char *err, size_t errlen);

/* Names. */
void bc_root_secret_name(const bc_spec *s, char *out, size_t cap);
/* Where the root credentials are: spec.configuration, spec.credsSecret, else <name>-root. */
void bc_creds_secret_name(const bc_spec *s, char *out, size_t cap);
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

/* Services, one StatefulSet and one PodDisruptionBudget per pool, then the
 * console's Service, Deployment and Ingress when it is enabled, in apply
 * order. Caller frees with bc_objects_free. */
size_t bc_desired(const bc_spec *s, bc_object **out);
void bc_objects_free(bc_object *o, size_t n);

/* The console's objects (paths only) to delete when it is disabled, or its
 * Ingress when that is not wanted. Caller frees each and the array. */
size_t bc_console_stale(const bc_spec *s, char ***paths);
/* The console's cookie-key Secret (<name>-console), owned by the cluster. */
void bc_console_secret_name(const bc_spec *s, char *out, size_t cap);
yyjson_mut_doc *bc_console_secret(const bc_spec *s, const char *passphrase, const char *salt);

/* ---- KES ------------------------------------------------------------------------- */

/* <name>-kes, or <name>-kes-test for a trial of new settings. */
void bc_kes_name(const bc_spec *s, bool trial, char *out, size_t cap);
void bc_kes_endpoint(const bc_spec *s, bool trial, char *out, size_t cap);
/* <name>-kms: the key store settings in use (settings.json); <name>-kms-candidate:
 * settings to try (candidate.json: {"settings", "keyName", "createKey",
 * "requiredKeys"}). Neither owned by the cluster: they outlive it, as the root
 * credentials do. */
void bc_kms_settings_secret_name(const bc_spec *s, char *out, size_t cap);
void bc_kms_candidate_secret_name(const bc_spec *s, char *out, size_t cap);
/* <name>-kes-tls (tls.crt, tls.key: KES's certificate, its own CA) and
 * <name>-kes-identity (admin, client: API keys), owned by the cluster. */
void bc_kes_tls_secret_name(const bc_spec *s, char *out, size_t cap);
void bc_kes_identity_secret_name(const bc_spec *s, char *out, size_t cap);

/* KES's configuration (JSON, which KES reads as YAML) for key store settings;
 * NULL and why on settings that do not hold up. Caller frees. ca_pem gets the
 * Vault CA certificate to mount beside it, if any (caller frees). */
char *bc_kes_config(const bc_spec *s, yyjson_val *settings, const char *admin_identity, const char *client_identity,
                    char **ca_pem, char *err, size_t errlen);
/* A KES server's objects for a configuration: the live server's
 * ServiceAccount (which Vault's Kubernetes sign-in names; a trial runs as it
 * too; none when spec.kms.kes.serviceAccountName names one), its config
 * Secret, Deployment and Service. */
size_t bc_kes_objects(const bc_spec *s, bool trial, const char *config, const char *ca_pem, bc_object **out);
/* Paths of a KES server's objects, to delete them. Caller frees each and the array. */
size_t bc_kes_paths(const bc_spec *s, bool trial, char ***paths);
/* An empty Secret the console fills in (not owned), and the operator's own KES Secrets. */
yyjson_mut_doc *bc_kms_empty_secret(const bc_spec *s, const char *name);
yyjson_mut_doc *bc_kes_tls_secret(const bc_spec *s, const char *cert, const char *key);
yyjson_mut_doc *bc_kes_identity_secret(const bc_spec *s, const char *admin, const char *client);

/* The operator-managed root credentials Secret (deliberately not owned by the
 * cluster, so it outlives it like the data does). */
yyjson_mut_doc *bc_root_secret(const bc_spec *s, const char *user, const char *password);

#endif
