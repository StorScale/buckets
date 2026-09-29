/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_PLUGINS_H
#define BUCKETS_IAM_PLUGINS_H

#include <yyjson.h>

#include "config/config.h"
#include "iam/policy.h"

/* The HTTP plugins MinIO supports:
 *  - policy_plugin (and the older policy_opa): every authorization decision
 *    is delegated to an HTTP endpoint (MinIO's AuthZPlugin);
 *  - identity_plugin: AssumeRoleWithCustomToken asks an HTTP endpoint who a
 *    token belongs to (MinIO's AuthNPlugin).
 * Reference counted; a config change builds a new one. */
typedef struct buckets_plugins buckets_plugins;

/* NULL (err set) for an invalid config. With probe, endpoints must answer. */
buckets_plugins *buckets_plugins_build(const buckets_config *cfg, const char *region, bool probe, char *err,
                                       size_t errlen);
buckets_plugins *buckets_plugins_ref(buckets_plugins *p);
void buckets_plugins_release(buckets_plugins *p);

bool buckets_authz_plugin_enabled(const buckets_plugins *p);
/* AuthZPlugin.IsAllowed: false on any error. claims_json may be NULL. */
bool buckets_authz_plugin_allowed(buckets_plugins *p, const char *account, char *const *groups, size_t ngroups,
                                  bool owner, const buckets_policy_args *a, const char *claims_json);

bool buckets_idp_plugin_enabled(const buckets_plugins *p);
const char *buckets_idp_plugin_role_arn(const buckets_plugins *p);
const char *buckets_idp_plugin_role_policy(const buckets_plugins *p);

typedef struct {
  char *user;             /* success */
  int max_validity;
  yyjson_doc *claims;     /* success, may be NULL */
  char *reason;           /* a 403 from the plugin */
} buckets_idp_result;
void buckets_idp_result_free(buckets_idp_result *r);

/* AuthNPlugin.Metrics: reachability and the last whole minute's calls. */
typedef struct {
  double last_reachable_secs, last_unreachable_secs;
  uint64_t total_requests, failed_requests;
  double avg_rtt_ms, max_rtt_ms;
} buckets_idp_plugin_metrics;
void buckets_idp_plugin_metrics_get(buckets_plugins *p, buckets_idp_plugin_metrics *out);
/* AuthNPlugin.Authenticate: false (err set) on transport/protocol errors. */
bool buckets_idp_plugin_authenticate(buckets_plugins *p, const char *role_arn, const char *token,
                                     buckets_idp_result *out, char *err, size_t errlen);

#endif
