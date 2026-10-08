# Design: SCIM, for providers that push changes

Status: proposed. Roadmap: Phase 2, "SCIM, for providers that push changes". It is Phase 2's last item; the rest
of "Automatic provisioning and removal" was done by identity sync (1.9.0, 1.10.0;
[identity-sync.md](identity-sync.md)).

## The problem

Identity sync asks the provider about each person once an hour. So someone who leaves keeps their access keys for
up to an hour, and their temporary credentials until those expire. Identity sync also needs read access to the
provider's API, which some organisations won't grant to an application.

SCIM turns this around. The provider tells Buckets as soon as someone is turned off, deleted, or taken out of the
app:
- **Okta** sends changes at once.
- **Entra ID** sends them on its provisioning cycle, every 40 minutes, or at once with "provision on demand".

Both use the standard SCIM 2.0 protocol (RFC 7643, 7644), set up in the provider's own admin console with a URL
and a bearer token.

The identity sync design chose to do sync first, with SCIM later "as an option acting through the same removal
code". This is that option.

## What it does

**Buckets serves a SCIM 2.0 endpoint for Users.** Each provider's provisioning sends the people assigned to the
Buckets app, and each change to them:

| The provider sends | Buckets does |
| --- | --- |
| A person assigned (`POST /Users`) | Records them: `externalId`, `userName`, `active`. Nothing else: with OpenID sign-in nobody has to be created before they sign in. |
| A person turned off (`PATCH` `active: false`, or `PUT` with it) | Their temporary credentials go at once; their access keys are turned off, and deleted after the grace period. |
| A person deleted or unassigned (`DELETE /Users/{id}`) | The same. |
| A person turned on again within the grace period | The keys that were turned off for them come back on. |
| Lookups (`GET /Users?filter=userName eq "…"` or `externalId eq "…"`, `GET /Users/{id}`) | Answers from what it recorded, as Entra and Okta expect before each create. |

**The same removal as identity sync.** A SCIM change does not remove anything itself. It records the person's
state and starts a sync run for that person at once. The sync's planner then does what it does for an answer
from the provider's API:
- the 30-day grace period (`BUCKETS_OPENID_REMOVE_AFTER`);
- the safety limit (`BUCKETS_OPENID_REMOVE_MAX` people at once, which holds removals and raises
  `BucketsIdentitySyncHeld`);
- the memory of which keys it turned off;
- the same log lines, audit entries and metrics.

A provider whose scoping is changed by mistake, and which then unassigns everyone, hits the safety limit just as
an outage answering 404 would.

**Two ways to use it:**
- **SCIM only** (`BUCKETS_OPENID_SYNC_PROVIDER=scim`): no API credentials for the provider. Buckets acts only on
  what is pushed. Someone SCIM never mentions is never removed.
- **SCIM and sync together** (an API provider, plus SCIM turned on): pushed changes act within seconds, and the
  hourly sync is the backstop for anything a push missed.

## Matching SCIM people to credentials

A credential knows its owner by the claims in their sign-in token: Entra's `tid` and `oid`, or the issuer and
`sub` elsewhere (identity sync matches the same way). A SCIM person is matched by **`externalId`**, which must hold
that same ID:

| Provider | `externalId` | What to set up |
| --- | --- | --- |
| Entra ID | `mailNickname` by default | In the app's provisioning **Attribute mappings**, map **`objectId`** to `externalId`. The console's guide says so, and the test checks it. |
| Okta | Okta's user ID (`00u…`), the same as the token's `sub` | Nothing |
| Keycloak | No SCIM client built in | Use identity sync |

`userName` (an email or sign-in name) is kept and shown, but never used to match. Names get reused when someone
new joins with a leaver's address, and matching on them could remove the wrong person.

The console's **test** looks up the signed-in admin's own record. If SCIM has sent people but none of their
`externalId`s match a token's ID, it says that the mapping is probably wrong.

## Where it is served

Each provider's cloud has to reach the endpoint over HTTPS.

- **On `bucketsd`, at `/minio/scim/v2/`.** Any server answers, since the records are cluster-wide and the sync
  runs on the server leading pool 0, set 0. `/minio/` is already reserved: MinIO and Buckets use it for the admin,
  health and metrics APIs, and no bucket can be called `minio`.
- **An Ingress for SCIM alone,** with the operator. `spec.scim.ingress` (a host, a TLS Secret and an ingress
  class) makes an Ingress that routes **only `/minio/scim/`**. You can open that one path to the provider without
  opening S3 or the console to the internet.
- **Not reachable from the internet at all:**
  - Entra's **provisioning agent** (installed inside the network) delivers SCIM to internal apps;
  - Okta's **On-Prem Provisioning agent** does the same.

  The docs show both. Otherwise, use identity sync, which needs only outbound HTTPS.

## Security

- **A bearer token** that the provider sends with every request (Entra's "Secret Token", Okta's "HTTP Header"
  authentication).
  - The console makes it: 32 random bytes, shown once.
  - The servers keep only its SHA-256 and compare in constant time.
  - A new token replaces the old one; for a brief overlap, both are accepted.
- **Only SCIM:** the token gives access to the SCIM endpoint and nothing else. It isn't an S3 or admin credential.
- **Limits:** request bodies up to 64 KiB, and at most 1,000 people per request page. Failed token checks are counted (`buckets_scim_requests_total{result="unauthorized"}`) and appear in the
  audit log.
- **Every change is audited** as `SCIMCreateUser`, `SCIMUpdateUser` and `SCIMDeleteUser`, with the person, and
  shows in the audit log viewer (1.15.0).

## Groups

Groups are **left out of this step.** The SCIM `/Groups` endpoint answers with SCIM's own "not supported", and
`ServiceProviderConfig` says so. Entra and Okta then skip group provisioning.

Keeping roles current from groups is identity sync's step 2, "Roles kept current", which isn't built yet. Pushed
groups belong with it, so roles change the same way whether they're pushed or fetched.

## API

The SCIM 2.0 service, under `/minio/scim/v2/`:
- `ServiceProviderConfig`: patch is supported, filters `eq` on `userName` and `externalId`, no bulk, no sort, no
  ETags, bearer authentication.
- `ResourceTypes` and `Schemas`: User only.
- `Users`: `GET` with filter, `startIndex` and `count`; `POST`; `GET`, `PUT`, `PATCH` and `DELETE` on
  `/Users/{id}`.

The provider can store and read back the core User attributes (`userName`, `externalId`, `active`, `name`,
`emails`, `displayName`). Attributes Buckets doesn't keep are accepted and ignored, as RFC 7643 allows.

**Providers' quirks,** handled and tested:
- Entra sends `"op": "Replace"`, capitalised.
- Entra sends `"value": "False"` as a string.
- Entra sends a patch with no `path` and a value object.
- Okta sends `PUT` instead of `PATCH` to turn someone off.

**Records:** each person's SCIM record is kept in `.minio.sys/buckets/scim/users.json`:
- `id` (Buckets' UUID);
- `externalId`, `userName` and `active`;
- `deleted`, kept for the grace period so a delete followed by a re-create matches up;
- `meta`.

A change takes the cluster lock on that document, so two servers never lose each other's writes. MinIO doesn't
read the directory, so a rollback loses only the records.

**Settings**, on the servers, set by the operator from the identity Secret as the sync's are:
- `BUCKETS_SCIM` (`on`)
- `BUCKETS_SCIM_TOKEN_SHA256` (or `_FILE`), and `BUCKETS_SCIM_TOKEN_SHA256_PREVIOUS` for the overlap
- `BUCKETS_OPENID_SYNC_PROVIDER=scim` for SCIM only, with `BUCKETS_SCIM_TENANT_ID` (Entra) or
  `BUCKETS_SCIM_ISSUER` (Okta), to say which tokens' IDs `externalId` is

**The console:** **Identity → Sign-in → People who leave** gets a **Provisioning (SCIM)** part. It turns SCIM on,
makes a token and shows it once with the URL, gives a step-by-step guide for Entra and for Okta, and has a
**Test** button. It also lists the people SCIM has sent, with their state.

## Code

- **`src/iam/scim.{c,h}`:**
  - the SCIM resources: parsing, the providers' patch forms, filters, and JSON out;
  - the record store.

  Pure apart from storage, and unit tested against recorded Entra and Okta requests.
- **`src/s3/scimhandlers.c`:** the endpoint, token check, audit, and a nudge to the sync for one person.
- **`src/iam/idsync.c`:** a "scim" provider whose answers come from the records, and a run for one person.
- **Operator:** `spec.scim.ingress`, and the settings from the identity Secret.
- **Console:** the Provisioning part, its test, and the list of people.
- **Metrics:** `buckets_scim_requests_total{op, result}` and `buckets_scim_people{state}`.

## Tests

- **Unit:**
  - each provider's create, lookup, patch and delete, from recorded requests;
  - the patch quirks;
  - the filters;
  - the token check.
- **Integration (`scim.sh`), in a cluster of four:**
  - a fake Entra and a fake Okta run their real sequences: create, look up, turn off, turn on, delete;
  - a turned-off person's access key stops working within seconds, and comes back when they're turned on;
  - everyone unassigned at once hits the safety limit;
  - a wrong token is refused and counted;
  - SCIM only and SCIM with sync both work.
- **Compliance:** Microsoft's SCIM Validator, run by hand against the dev cluster through the SCIM-only Ingress
  before release. Its results go in the docs.
- **Browser:** turning SCIM on, the token shown once, the guide, the test, and the list of people.

## Open questions, with a recommendation each

1. **Where it is served: `bucketsd` or `consoled`?** On `bucketsd`, at `/minio/scim/v2/`, where the identity sync
   and its removal code live, with a SCIM-only Ingress from the operator. `consoled` would need credentials of its
   own to act. **Recommended: `bucketsd`, with the SCIM-only Ingress.**
2. **Match by `externalId` only, or also by `userName`?** Names are reused; IDs aren't. **Recommended:
   `externalId` only,** with Entra's attribute mapping in the guide and checked by the test.
3. **Groups now, or with "roles kept current"?** **Recommended: later, with roles kept current,** so pushed and
   fetched roles change the same way.
4. **The safety limit for pushed removals: the sync's, or none?** A provider can be misconfigured as easily as it
   can fail. **Recommended: the sync's limit and grace period,** one set of rules for both.
