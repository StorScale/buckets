/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_ACCESS_H
#define BUCKETS_IAM_ACCESS_H

/* The access review (docs/design/access-review.md): who can reach a bucket and
 * why, and whether a principal would be allowed an action. It works on facts
 * gathered from the admin APIs, and every match goes through the servers'
 * policy evaluator (iam/policy.h): each statement is evaluated on its own, its
 * Condition set aside, to learn whether it covers an action and resource; an
 * explicit Deny then wins over any Allow, as on the servers.
 *
 * Facts, as JSON:
 *   {"policies":     {"<name>": <policy document>, ...},
 *    "principals":   [{"kind": "root" | "user" | "group" | "ldap-user" | "ldap-group" | "openid-role" | "key",
 *                      "name",
 *                      "policies": [names],          attached (an openid-role: [its own name])
 *                      "groups": [names],            a user's groups, whose policies it also has
 *                      "members": [names],           a group's
 *                      "status": "enabled" | "disabled",
 *                      "owner",                      a key's owner (a user's name)
 *                      "policy": <document>,         a key's own policy, narrowing its owner's (absent: the owner's)
 *                      "seen": [names]}],            an openid-role: people seen signing in with it
 *    "bucketPolicy": <bucket policy document> | null,
 *    "missing":      ["access keys", ...]}           facts the reviewer could not read
 */

#include <stdbool.h>
#include <yyjson.h>

/* The levels a bucket is reviewed at, NULL-terminated: "read", "write", "delete", "manage", "any". */
extern const char *const buckets_access_levels[];

/* Who can reach bucket at level, into d:
 *   {"bucket", "level", "actions": [...],
 *    "rows": [{"kind", "name", "status"?, "members"?, "seen"?, "owner"?,
 *              "access": "full" | "limited" | "conditional",
 *              "actions": [{"action", "decision": "allowed" | "limited" | "conditional",
 *                           "limits": [object patterns]?, "conditions": [keys]?,
 *                           "by": [{"policy" | "bucketPolicy": true, "statement": index, "sid"?, "effect"}]}]}],
 *    "missing": [...]}
 * Rows only for principals with some access; a key only when it has a policy of its own (otherwise it is its
 * owner's). Bucket-policy principals appear as kind "anyone" (Principal "*": every request, signed or not) or
 * "account". NULL on an unknown level. */
yyjson_mut_val *buckets_access_bucket(yyjson_mut_doc *d, yyjson_val *facts, const char *bucket, const char *level);

/* Whether who ({"kind", "name"} of a principal in facts, or {"kind": "openid", "roles": [...]}, or
 * {"kind": "anonymous"}) may do action on bucket (and object, "" for bucket actions), into d:
 *   {"decision": "allowed" | "denied" | "conditional", "reason": words,
 *    "by": [{"policy" | "bucketPolicy", "statement", "sid"?, "effect", "conditions"?}]}
 * conds: optional condition values ({"SourceIp": "10.0.0.1", "SecureTransport": "true", ...}). A statement
 * with a Condition whose keys are not all given is "conditional": never counted as allowing, and, for a Deny,
 * reported as what could still refuse. NULL when who is not in facts. */
yyjson_mut_val *buckets_access_check(yyjson_mut_doc *d, yyjson_val *facts, yyjson_val *who, const char *action,
                                     const char *bucket, const char *object, yyjson_val *conds);

#endif
