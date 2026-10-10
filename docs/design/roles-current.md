# Design: keeping roles current

Status: built (unreleased). Roadmap: Phase 2, "Automatic provisioning and removal". This is step 2 of
[identity-sync.md](identity-sync.md), "Roles kept current", and it brings the groups that
[scim.md](scim.md) left for later.

## The problem

With OpenID sign-in, a person's access comes from a claim in their token: their app roles (Entra ID's
`roles`, Keycloak's) or their groups (Okta's `groups`, a Keycloak group mapper). Each value names a Buckets
policy, directly or through a team (1.3.0).

The claim is read when they sign in, and it is **copied into everything they make**:
- **Temporary credentials** (STS) keep the roles of that sign-in until they expire, within hours.
- **Access keys** made by the person carry the same claim inside their own signed token, for as long as the
  key lives, which is often for years.

So someone moved out of a role in the provider keeps it on every access key they made:
- An engineer who moves teams keeps write access to the old team's buckets through a script's key.
- A contractor reduced to read-only keeps their read-write keys.

Identity sync (1.9.0) and SCIM (1.17.0) remove the access of people who **leave**. Nothing yet follows people
who **stay but change roles**. For LDAP this is already done: the hourly LDAP sync updates each user's groups,
as MinIO's does.

## What it does

Each identity sync run (hourly), and each SCIM change, also learns each person's **current** roles or groups.
Where they differ from what a credential carries, the credential is updated.

**What the person has now** is asked for in the form their token carries it, so the values mean the same:

| Provider | Claim | Asked |
| --- | --- | --- |
| Entra ID | `roles` (app roles) | Once per sync, the sign-in app's roles and who holds them: `GET /servicePrincipals(appId='{client}')` (`appRoles`) and `.../appRoleAssignedTo` (users and groups). Then for each person, their own assignments and those of groups they're a direct member of (`GET /users/{oid}/memberOf`), as Entra issues the claim. |
| Entra ID | `groups` | `GET /users/{oid}/transitiveMemberOf/microsoft.graph.group?$select=id` (group IDs, as the token has them) |
| Okta | `groups` | `GET /api/v1/users/{id}/groups`, by profile name, filtered by the authorization server's groups claim filter where one is set in the settings |
| Keycloak | realm or client roles, or groups | `role-mappings/realm/composite`, `role-mappings/clients/{id}/composite`, or `groups`, per the claim's mapper as set in the sign-in settings |
| SCIM | `groups` | the groups pushed to `/Groups`, with their members (below) |

**What is updated:**
- **Access keys:** their token is signed again with the new value of the policy claim. Everything else stays:
  the key's ID, secret, expiry, its own session policy (which can only narrow it), and its status. The stored
  form is the one MinIO writes, so MinIO reads it after a rollback.
- **Temporary credentials:** the same, so a console session gets the new access at its next request, not after
  it expires.
- **Someone left with no roles at all** keeps their credentials, which then allow nothing. A role given back
  makes them work again. Removal stays a matter of leaving, decided as today.

**Logged and audited:** "roles of <person> changed: +team-data-rw −team-ops-admin; 3 access keys and 1 session
updated". The audit log entry is `IdentitySyncRoles`. The access review shows the current roles, since that
is what the credentials now carry.

**Safety:** a provider answering wrongly, for example with every role mapping missing after a misconfiguration,
must not strip everyone. If one run would **remove** roles from more people than `BUCKETS_OPENID_REMOVE_MAX`, it
removes none, logs why and raises `BucketsIdentitySyncHeld`, as for removals. Roles **added** are not held.

**A provider that can't be asked** (an error or a timeout) changes nothing for that person, as for removal.

### Groups by SCIM

SCIM's `/Groups` endpoint stops answering "not supported". The provider then pushes groups and their members:
- `POST`, `PUT` and `PATCH /Groups`, with `members` adds, removes and replaces;
- `DELETE /Groups/{id}`.

A group's value for the claim is what the token carries: Okta's group name (`displayName`), Entra's group ID
(`externalId`, mapped from `objectId` as for users). A change acts within seconds through the same run as
pushed users.

SCIM groups replace asking the API for groups only where SCIM is the only source (SCIM alone). With both, the
API's answer is kept for people SCIM's groups don't name.

## Setting it up

Under **Identity → Sign-in → People who leave**, a new option, **Keep their roles current**, appears beside
removal. It is on by default for new settings and off for existing ones until turned on. It shows what the
provider app needs:
- **Entra ID:** `User.Read.All` (already there for removal) reads memberships, for both the `groups` claim and
  app roles given through groups. App roles also need **`Application.Read.All`**, which reads app registrations
  and who is assigned to them. Asking each user instead (`/users/{id}/appRoleAssignments`) would need
  `Directory.Read.All`, Graph's least privilege for that call, and that reads the whole directory.
- **Okta:** the read-only API token reads groups.
- **Keycloak:** `view-users` reads role mappings and groups.

**Look up a person** then also shows their current roles, and the Buckets policies those map to.

For SCIM, the Entra and Okta guides gain the step to provision groups.

## Code

- **`src/iam/idsync.{c,h}`:**
  - `buckets_idsync_client_values`: the person's current values, per `roles_from`;
  - `buckets_idsync_roles_decide`: which changes go ahead, with the safety count.
- **`src/iam/iam.c`:** `buckets_iam_set_person_policies` stores the person's mapping and re-signs the claim of each
  of their access keys and temporary credentials that differs.
- **`src/s3/server.c`:** `idsync_roles`, in each sync run.
- **`src/iam/scim.{c,h}`, `src/s3/scimhandlers.c`:** Groups: the resource, members' patch forms, and the store
  (beside the users, in the same file and revision).
- **Settings and operator:** `openid.removal.roles` and `rolesFrom`, to `BUCKETS_OPENID_SYNC_ROLES` and `_ROLES_FROM`.
- **Console:** the option, the permissions it needs, the lookup's roles, and SCIM's group steps.

## Tests

- **Unit:**
  - each provider's answers mapped to values, from recorded responses;
  - the plan's role changes and their limit;
  - re-signing keeps everything but the claim;
  - SCIM group patches (Entra's and Okta's forms).
- **Integration:**
  - the stand-in provider moves a person between app roles and groups;
  - their access key and console session lose the old bucket and gain the new one within a sync;
  - roles removed from too many at once are held;
  - an access key with roles changed is read by MinIO after a rollback (the stored token still verifies);
  - SCIM groups: a member removed loses the group's policy within seconds.
- **Cluster:** the real Keycloak of `tests/e2e-k8s/identity.sh`: a user moved between realm roles.

## Open questions, with a recommendation each

1. **Update credentials in place, or revoke them so the person signs in again?** Revoking access keys would break
   every script on a role change. **Recommended: update in place,** keys and sessions alike.
2. **Someone with no roles left: keep their credentials (allowing nothing), or disable them as for leavers?**
   Being moved to no role is often brief, in the middle of a reorganisation. **Recommended: keep them;** leaving
   stays what removes access.
3. **On by default?** It changes what existing keys can do. **Recommended: on for new settings, off for existing
   ones until an admin turns it on,** with the console saying so.
4. **SCIM groups now?** **Recommended: yes,** for Okta's group names and Entra's group IDs, since without them
   SCIM alone can't keep roles current.

## Decisions

1. **Credentials are updated in place,** access keys and sessions alike.
2. **Someone left with no roles keeps their credentials,** which then allow nothing.
3. **On for new settings, off for existing ones** until an admin turns it on.
4. **SCIM groups now,** for Okta's group names and Entra's group IDs.
5. **Entra app roles are read from the app's side** (`appRoleAssignedTo`, `Application.Read.All`), not each user's
   (`Directory.Read.All`), checked against Microsoft's permission reference.
