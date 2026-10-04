/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_TEAMS_H
#define BUCKETS_IAM_TEAMS_H

/* Teams (docs/design/teams.md): a name and a set of buckets, turned into
 * ordinary IAM policies team-<name>-ro, -rw and -admin. A team is stored in
 * nothing but those policies: each statement's Sid names the team and level
 * ("buckets-team:v1:<name>:<level>[:objects|:create]"), and the buckets are
 * its Resource ARNs, so teams read back from the policies alone and survive a
 * MinIO round trip.
 *
 * As JSON:
 *   {"name":     "finance",                 [a-z0-9-], 1 to 40, starting with a letter or digit
 *    "buckets":  ["finance-reports", ...],  existing or future bucket names
 *    "prefixes": ["finance-", ...],         every bucket whose name starts with one
 *    "levels":   ["ro", "rw", "admin"]}     the policies to have; at least one
 * At least one bucket or prefix. */

#include <stdbool.h>
#include <stddef.h>
#include <yyjson.h>

#include "core/buf.h"

#define BUCKETS_TEAM_NAME_MAX 40

/* "ro", "rw", "admin", NULL-terminated, in order of access. */
extern const char *const buckets_team_levels[];

/* Checks a team. On error, false and why, in words for the person who filled
 * it in. */
bool buckets_team_check(yyjson_val *team, char *err, size_t errlen);

/* "team-<name>-<level>" into out. */
void buckets_team_policy_name(const char *name, const char *level, char *out, size_t cap);

/* The policy document for one of a checked team's levels, appended to out as
 * JSON. */
void buckets_team_policy(yyjson_val *team, const char *level, buckets_buf *out);

/* The teams in a set of policies, as list-canned-policies returns them
 * ({"<policy name>": <document>, ...}), into d as an array sorted by name:
 *   [{"name", "buckets", "prefixes", "levels",
 *     "edited": [levels whose policy differs from what the Teams page would write]}]
 * A level's policy belongs to a team when it is named team-<name>-<level> and
 * its first statement's Sid is buckets-team:v1:<name>:<level>. A team's
 * buckets and prefixes are read from its first level that is not edited. */
yyjson_mut_val *buckets_teams_from_policies(yyjson_mut_doc *d, yyjson_val *policies);

/* Whether a checked team's prefixes overlap another team's in teams (an array
 * as from buckets_teams_from_policies; the team's own entry is skipped). On
 * overlap, true and which, in words. */
bool buckets_team_overlaps(yyjson_val *team, yyjson_val *teams, char *err, size_t errlen);

#endif
