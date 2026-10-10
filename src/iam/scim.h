/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_IAM_SCIM_H
#define BUCKETS_IAM_SCIM_H

/* SCIM 2.0 Users (RFC 7643, 7644), for providers that push changes (docs/design/scim.md): Entra ID's and Okta's
 * provisioning tell Buckets who is assigned, turned off or deleted. A person is matched to credentials by
 * externalId, which holds the ID in their sign-in token (Entra's oid, Okta's user ID = sub); identity sync
 * (iam/idsync.h) then removes and restores as it does for a provider's API answers. This part is pure: the
 * resources, the providers' patch forms, filters and the store's JSON. The endpoint is s3/scimhandlers.c.
 *
 * The store: .minio.sys/buckets/scim/users.json, {"rev", "users": [{"id", "externalId", "userName",
 * "displayName", "active", "deleted", "created", "modified"}]}. */

#include <stdbool.h>
#include <stddef.h>
#include <yyjson.h>

#include "core/buf.h"
#include "iam/idsync.h"

#define BUCKETS_SCIM_PATH "buckets/scim/users.json"
#define BUCKETS_SCIM_PREFIX "/minio/scim/v2"

typedef struct {
  char id[40]; /* Buckets' UUID */
  char *external_id, *user_name, *display_name;
  bool active;
  bool deleted;                /* DELETE /Users/{id}: kept for the grace period */
  long long created, modified; /* unix seconds */
} buckets_scim_user;

/* A group (roles kept current, docs/design/roles-current.md): its members are users' Buckets IDs. */
typedef struct {
  char id[40];
  char *display_name, *external_id;
  char **members;
  size_t nmembers;
  long long created, modified;
} buckets_scim_group;

typedef struct {
  long long rev; /* bumped by every change: the sync runs when it moves */
  buckets_scim_user *u;
  size_t n;
  buckets_scim_group *g;
  size_t ng;
} buckets_scim_store;

void buckets_scim_user_free(buckets_scim_user *u);
void buckets_scim_store_free(buckets_scim_store *s);
/* An empty or missing document is an empty store; false when it doesn't parse. */
bool buckets_scim_store_parse(const char *json, size_t len, buckets_scim_store *out);
void buckets_scim_store_json(const buckets_scim_store *s, buckets_buf *out);
/* Drops deleted people deleted more than keep_s ago. */
void buckets_scim_store_prune(buckets_scim_store *s, long long now, long long keep_s);

buckets_scim_user *buckets_scim_find_id(buckets_scim_store *s, const char *id);
/* A person not deleted with this externalId (case-sensitive) or userName (case-insensitive), or NULL. */
buckets_scim_user *buckets_scim_find_external(buckets_scim_store *s, const char *external_id);
buckets_scim_user *buckets_scim_find_user_name(buckets_scim_store *s, const char *user_name);

/* What identity sync makes of a person, by their token's ID: active, disabled (active false), gone (deleted), or
 * UNKNOWN when SCIM never mentioned them. */
buckets_idsync_state buckets_scim_state_of(const buckets_scim_store *s, const char *person);

/* The person a POST or PUT body describes (userName is required). false, an HTTP status and why when not. */
bool buckets_scim_user_from_json(yyjson_val *body, buckets_scim_user *out, int *status, char *err,
                                 size_t errlen);
/* Applies a PatchOp body to u: add, replace and remove (any case), with a path or a value object; booleans as
 * JSON or as "True"/"False" strings (Entra). Paths it doesn't keep are ignored. */
bool buckets_scim_patch(buckets_scim_user *u, yyjson_val *body, int *status, char *err, size_t errlen);

/* A filter: attr eq "value", for userName or externalId; "" is every person. false: one it can't do. */
typedef struct {
  char attr[16]; /* "userName", "externalId", or "" */
  char value[512];
} buckets_scim_filter;
bool buckets_scim_filter_parse(const char *s, buckets_scim_filter *out);
bool buckets_scim_filter_match(const buckets_scim_filter *f, const buckets_scim_user *u);

/* Groups: from a POST or PUT body (displayName required; members' value are user IDs), a PatchOp (members added,
 * removed, by a filter such as members[value eq "id"], or replaced; displayName and externalId; Entra's and Okta's
 * forms), the resource as JSON, and lookups. */
void buckets_scim_group_free(buckets_scim_group *g);
bool buckets_scim_group_from_json(yyjson_val *body, buckets_scim_group *out, int *status, char *err, size_t errlen);
bool buckets_scim_group_patch(buckets_scim_group *g, yyjson_val *body, int *status, char *err, size_t errlen);
void buckets_scim_group_json(const buckets_scim_group *g, const char *base, buckets_buf *out);
buckets_scim_group *buckets_scim_find_group(buckets_scim_store *s, const char *id);
/* A group filter: displayName or externalId eq "value"; "" every group. */
bool buckets_scim_group_filter_match(const buckets_scim_filter *f, const buckets_scim_group *g);
/* The groups a person (by their token's ID: a user record's externalId) is a member of, as their token would name
 * them: each group's externalId (Entra: the group's object ID) when by_external, else its displayName (Okta).
 * Sorted, malloc'd; free with buckets_scim_values_free. */
size_t buckets_scim_values_of(const buckets_scim_store *s, const char *person, bool by_external, char ***out);
void buckets_scim_values_free(char **v, size_t n);

/* The User resource, as JSON; base is the endpoint's URL for meta.location ("" leaves it out). */
void buckets_scim_user_json(const buckets_scim_user *u, const char *base, buckets_buf *out);
/* An error response: {"schemas": [Error], "status": "404", "scimType", "detail"}. */
void buckets_scim_error_json(int status, const char *scim_type, const char *detail, buckets_buf *out);
/* ServiceProviderConfig, ResourceTypes, Schemas. */
void buckets_scim_service_provider_config(buckets_buf *out);
void buckets_scim_resource_types(const char *base, buckets_buf *out);
void buckets_scim_schemas(buckets_buf *out);

#endif
