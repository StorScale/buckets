# Design: removing people who leave (SCIM and identity sync)

Status: agreed, being built. Roadmap: Phase 2, "Automatic provisioning and
removal (SCIM)". It is Phase 2's last item: "People who leave lose access and
their access keys without manual cleanup."

## The problem

With OpenID sign-in (Entra ID, Okta, Keycloak), Buckets keeps no list of
people. A person gets access when they sign in, from the roles or groups in
their token. Turning them off in the provider stops new sign-ins, but three
things stay behind:

- **Access keys they made** (service accounts whose parent is the person).
  These never expire unless the person set an expiry. **This is the real
  gap:** a leaver's scripts and tools keep working.
- **Temporary credentials** (STS), and the console sessions built on them.
  These run until they expire, by default within hours.
- **Roles changed in the provider.** An access key keeps the roles its owner
  had when it was made, so someone moved out of a role keeps it on their keys.

LDAP is already covered. `bucketsd`'s LDAP sync (`src/s3/server.c`, hourly,
`BUCKETS_LDAP_SYNC_INTERVAL`) removes the credentials of users no longer in
the directory and updates their groups. Nothing does the same for OpenID.

**Provisioning is already covered too.** With OpenID, nobody has to be created
in Buckets before signing in: their roles or groups, mapped by teams (1.3.0),
decide their access. What's missing is removal, plus keeping roles current.

## Two ways to learn that someone left

| | SCIM (the provider pushes) | Identity sync (Buckets asks) |
| --- | --- | --- |
| How | Buckets serves `/scim/v2/Users`; the provider sends changes | Buckets asks the provider's API about each person holding credentials |
| Speed | Within minutes (Entra provisions every 40 minutes; Okta at once) | Each sync, hourly by default |
| Reachability | **The provider's cloud must reach Buckets over HTTPS.** Entra and Okta call from the internet; an internal-only console (the dev cluster's `*.os.harlandclarke.internal`) needs Entra's on-premises provisioning agent or Okta's | Only outbound HTTPS from Buckets to the provider |
| Keycloak | No SCIM client built in (needs an extension) | Its admin API |
| Permissions in the provider | An enterprise app with provisioning; a bearer token Buckets checks | Read-only: Entra `User.Read.All` (application), an Okta read-only API token, a Keycloak `view-users` client |
| Matching people | SCIM's `externalId` or `userName`, which must be matched to a token claim (Entra's `sub` is per-app and is not in SCIM) | The token's own user ID claim (Entra `oid`, Okta and Keycloak `sub`), used as is |
| Roles kept current | Only with group provisioning as well | The same call can return the person's app roles and groups |

**Recommendation: identity sync first, then SCIM as an option.**
- **Identity sync works everywhere Buckets runs,** including clusters the
  provider can't reach. It needs only read-only permissions, and it matches
  people by an ID already in their token.
- **It follows the LDAP sync** Buckets already has, so OpenID and LDAP behave
  the same.
- **SCIM can come later for faster removal** where the console is reachable
  from the internet. It would act through the same removal code. It is left
  out of this first step because it adds an internet-facing endpoint and a
  token to protect.

## What identity sync does

Each sync (hourly, `BUCKETS_OPENID_SYNC_INTERVAL`) runs on one server at a
time:

1. **Who to check:** every OpenID person who holds access keys or temporary
   credentials, by the user ID claim stored with the credential (`oid` for
   Entra, `sub` otherwise). The parent user is a hash, so the claim is what
   identifies them.
2. **Ask the provider about each one.** Entra:
   `GET /users/{oid}?$select=accountEnabled` and the person's app role
   assignments. Okta: `GET /api/v1/users/{id}` and their groups. Keycloak:
   `GET /admin/realms/{realm}/users/{id}`, with role mappings or groups.
3. **Gone or disabled** (404, `accountEnabled: false`, Okta `DEPROVISIONED`
   or `SUSPENDED`, Keycloak `enabled: false`):
   - Temporary credentials are deleted at once, which ends console sessions.
   - Access keys are **disabled** at once and **deleted after a grace period**
     (`BUCKETS_OPENID_REMOVE_AFTER`, default 30 days). Someone wrongly turned
     off doesn't lose their keys for good, and an owner can still re-key a
     shared tool.
   - Each step is logged and audited, and the access review shows these keys
     as "owner left, deleted on <date>".
4. **Still there, roles or groups changed:** the roles on their credentials
   are updated, as the LDAP sync updates groups.
5. **The provider can't be reached, or answers an error:** nothing is removed
   and the sync is retried next time; `buckets_identity_sync_failures_total`
   and an alert (`BucketsIdentitySyncFailing`) say so. A broken sync must
   never remove anyone.

**Safety limit:** if one sync would remove more than
`BUCKETS_OPENID_REMOVE_MAX` people (default 10, or 25%), it removes no one,
logs why and alerts. Someone confirms in the console, or raises the limit.
This guards against a misconfigured app or a provider outage that answers
404.

## Setting it up

The console's **Identity → Sign-in** page gets a **Removal** step for each
OpenID provider:
- the provider's API credentials (Entra: tenant, client ID and secret, which
  can be the sign-in app's with `User.Read.All` added; Okta: an API token;
  Keycloak: a client with `view-users`);
- a **Test** button that looks up the signed-in admin and one other person,
  as the sign-in test does today;
- what to do on removal (disable, then delete after N days).

The settings are stored and applied the way sign-in settings are. With the
operator, they live in the cluster's identity Secret, so nothing is in a
manifest.

## Code

- **`src/iam/idsync.{c,h}`:** the provider clients (Graph, Okta, Keycloak)
  behind one interface: `lookup(id) -> {gone | disabled | active, roles[]}`.
  It is pure apart from the HTTP calls, and tested against recorded
  responses.
- **`src/s3/server.c`:** an `openid_sync` thread beside `ldap_sync`, using
  the existing `buckets_iam_revoke_tokens`, `buckets_iam_update_svc` (to
  disable), `buckets_iam_delete_svc` and `buckets_iam_set_groups`.
- **Console:** the Removal step, the test endpoint, and "owner left" in the
  access review and on the Access Keys page.
- **Metrics and alert:** sync runs, people checked and removed, and failures,
  with a `BucketsIdentitySyncFailing` rule in the chart.

## Tests

- **Unit:** each provider's answers mapped to gone, disabled or active;
  the safety limit; the grace period.
- **Integration:** a stand-in provider (a small HTTP server answering Graph,
  Okta and Keycloak paths). The tests cover a person disabled, deleted,
  re-enabled within the grace period, and moved out of a role, plus a
  provider outage that removes no one.
- **Cluster:** the real Keycloak already used by `tests/e2e-k8s/identity.sh`.
  A person signs in, makes an access key and is disabled in Keycloak, and the
  key stops working after one sync.

## Decisions

1. **Identity sync first; SCIM later**, as an option acting through the same
   removal code.
2. **Disable at once, delete after 30 days** (`BUCKETS_OPENID_REMOVE_AFTER`,
   in days). The LDAP sync keeps deleting at once, as MinIO's does: changing
   it would surprise people moving from MinIO.
3. **Entra first.** Okta and Keycloak come later behind the same interface.
4. **Removal first.** Keeping roles current comes in a later step.

## How it is built (step 1)

- **Settings are environment variables on the servers.** They are not a
  configuration subsystem, since MinIO would not know one after a rollback.
  The operator sets them from the identity settings, with the secret from a
  Secret it writes, and restarts the servers when they change, as it does for
  LDAP:
  - `BUCKETS_OPENID_SYNC_PROVIDER=entra`
  - `BUCKETS_OPENID_SYNC_TENANT_ID`, `BUCKETS_OPENID_SYNC_CLIENT_ID` and
    `BUCKETS_OPENID_SYNC_CLIENT_SECRET`
  - `BUCKETS_OPENID_SYNC_INTERVAL` (seconds, default 3600)
  - `BUCKETS_OPENID_REMOVE_AFTER` (days, default 30)
  - `BUCKETS_OPENID_REMOVE_MAX` (people per sync, default 10)
- **Who counts as an Entra person:** a credential whose `tid` claim is the
  tenant, identified by its `oid` claim.
- **One server syncs:** the one leading pool 0, set 0, as the scanner does.
- **What the sync disabled is remembered** in
  `.minio.sys/buckets/identity-sync.json`: each key, its owner and when it was
  disabled. A key comes back on if its owner comes back within the grace
  period. A key its owner had turned off themselves is never turned on.
- **The safety limit** holds new removals when more than
  `BUCKETS_OPENID_REMOVE_MAX` people would go in one sync. Raising the limit
  lets them through; a confirmation in the console comes with the console
  step.

## Order

1. ✅ Entra identity sync: removal, with the grace period and safety limit,
   set up from the console's Sign-in page ("People who leave"), with metrics,
   two alerts and docs ([identity.md](../identity.md#people-who-leave)).
   Showing "owner left" in the access review and on the Access Keys page is
   left for later: such keys show as off meanwhile.
2. Roles kept current.
3. Okta and Keycloak.
4. SCIM endpoint (optional), acting through the same removal code.
