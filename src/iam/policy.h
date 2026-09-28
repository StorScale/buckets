/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_POLICY_H
#define BUCKETS_IAM_POLICY_H

#include <stddef.h>

#include "core/common.h"

/* IAM policy documents: parsing, validation and evaluation, ported from
 * github.com/minio/pkg/v3/policy (v3.1.3). Action and condition-key tables
 * are generated from that package (tools/policygen), and its own evaluator
 * produced the golden vectors in tests/unit/policy_vectors.inc. */

typedef struct buckets_policy buckets_policy;

/* ParseConfig + Validate. On failure returns false with a message in err. */
bool buckets_policy_parse(const char *json, size_t len, buckets_policy **out, char *err, size_t errlen);
void buckets_policy_free(buckets_policy *p);
/* The policy has no statements (e.g. "{}"). */
bool buckets_policy_is_empty(const buckets_policy *p);
/* The Version field ("" when absent). */
const char *buckets_policy_version(const buckets_policy *p);
/* No Version, ID or statements: "null", "{}" (service-account policies
 * treat these as "inherit the parent's policy"). */
bool buckets_policy_is_blank(const buckets_policy *p);

/* A request's condition values (MinIO's getConditionValues), keyed by the
 * short names MinIO uses: "SourceIp", "username", "prefix", ... */
typedef struct {
  const char *key;
  const char *const *values;
  size_t n;
} buckets_cond_value;

typedef struct {
  const char *action; /* e.g. "s3:GetObject", "admin:ServerInfo" */
  const char *bucket;
  const char *object;
  bool owner;     /* the account owns everything: only Deny statements apply */
  bool deny_only; /* check Deny statements only */
  const buckets_cond_value *conds;
  size_t nconds;
} buckets_policy_args;

bool buckets_policy_allowed(const buckets_policy *p, const buckets_policy_args *a);
/* The same as evaluating buckets_policy_merge(ps, n), without building it.
 * NULL entries are skipped. */
bool buckets_policies_allowed(const buckets_policy *const *ps, size_t n, const buckets_policy_args *a);

/* Merges several policies into one (MinIO's MergePolicies): the union of
 * their statements. The inputs stay owned by the caller. */
buckets_policy *buckets_policy_merge(const buckets_policy *const *ps, size_t n);

/* wildcard.Match from minio/pkg: '*' any run, '?' exactly one byte. */
bool buckets_wildcard_match(const char *pattern, const char *name);

/* Canned policies MinIO ships: readwrite, readonly, writeonly, diagnostics,
 * consoleAdmin. NULL when name is not one of them. */
const char *buckets_policy_canned(const char *name);

#endif
