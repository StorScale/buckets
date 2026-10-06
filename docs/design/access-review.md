# Design: access review

Status: agreed, being built. Roadmap: Phase 2, "An access review page" and
"Local-users policy". Phase 2 is done when "an auditor can list everyone with
access to a bucket".

## The problem

Access in Buckets comes from several places at once:

- **Policies attached** to local users, local groups, and LDAP users and
  groups.
- **Policies named by OpenID roles** in a sign-in token. Buckets never sees
  the full list of who holds a role: only the identity provider knows that.
- **Group membership**, which passes a group's policies to its members.
- **Access keys**, which carry their owner's policies, or a narrower policy of
  their own.
- **Bucket policies**, which can grant access to named accounts, or to
  everyone, anonymous requests included.
- **The root user**, which can do everything.

The console shows each of these on its own page, and nothing puts them
together. To answer "who can read `ledger`, and why?", an admin has to read
every policy, work out which ones reach `ledger`, then look up who has each
of them. Nobody can check the answer to "would alice be allowed to delete
`ledger/2026/q3.csv`?" without trying it.

## What it does

A new page, **Identity → Access review**, with two parts. It can also be
reached as an **Access** tab on each bucket.

### 1. Who can reach a bucket

Pick a bucket and an action level (read, write, delete, manage settings).
The page lists every route to that access:

| Who | How they get it | What it allows | Limits |
|---|---|---|---|
| `alice` (local user) | policy `team-finance-rw` | read, write, delete | — |
| group `finance-auditors` (3 members: …) | policy `audit-ro` | read | objects under `reports/` only |
| `cn=devs,ou=groups,…` (LDAP group) | policy `team-finance-rw` | read, write, delete | — |
| anyone with the OpenID role `team-finance-rw` (seen: kcteam, bob@…) | role value = policy | read, write, delete | — |
| access key `AKIA…` (bob's) | bob's policies, narrowed | read | the key's own policy |
| **everyone, without signing in** | bucket policy, statement `PublicRead` | read | — |
| `rootadmin` | root user | everything | — |

Each row expands to show the policy statement that grants the access, and any
statement that denies part of it. The list exports as CSV for an auditor:
bucket, principal, kind, route, policy, statement, actions, limits, and the
time of the review.

### 2. Would this be allowed?

Pick who (a local user, a group, an LDAP DN, an access key, or "someone with
these OpenID roles"), an action, and a bucket or object. The answer is
**Allowed** or **Denied**, with the statements that decided it: the Allow that
grants it, or the explicit Deny that wins, or "no statement allows it". It
uses the same policy evaluator as the servers (`src/iam/policy.c`), with the
same rules for combining policies, groups, access-key policies and bucket
policies.

### 3. Local users while sign-in uses a provider

When OpenID or LDAP sign-in is on, a box at the top lists the local users that
remain, with their policies and access keys, so they can be disabled or
deleted. That covers the roadmap's "Local-users policy" item.

## How it works

### Where it runs: the console

All the facts it needs are already available through admin APIs that MinIO
also has. Those calls are made as the signed-in admin, as the Teams page
does:

| Fact | Admin API |
|---|---|
| Policies | `list-canned-policies` |
| Who has each policy | `idp/builtin/policy-entities`, `idp/ldap/policy-entities` |
| Local users, their groups and status | `list-users` |
| Groups and their members | `groups`, `group` |
| Access keys, with any narrower policy | `list-access-keys-bulk`, `idp/openid/list-access-keys-bulk`, `info-access-key` |
| Bucket policies | S3 `GetBucketPolicy` |

So it needs no new server API, works against the servers as they are, and
only an admin who may read all of this can run it (the servers decide, call by
call).

The analysis is a library, `src/iam/access.c`, shared by the console and
unit tests, like `teams.c`. It takes the facts above as JSON and answers both
questions, using `buckets_policy_allowed` and `buckets_bucket_policy_allowed`
for every decision.

### "Reaches a bucket" when patterns are involved

A policy can name a bucket exactly (`arn:aws:s3:::ledger/*`), by wildcard
(`arn:aws:s3:::*`, `arn:aws:s3:::fin*`) or name only some of its objects
(`arn:aws:s3:::ledger/reports/*`). For each statement, the bucket part of each
resource is matched against the bucket name with the evaluator's own wildcard
match. The object part decides the **Limits** column: `*` means the whole
bucket; anything else is shown as the prefix or pattern it allows. A Deny on a
narrower pattern is shown as a limit on the Allow it cuts into.

### Conditions

Statements with conditions (source IP, secure transport, object tags, time)
cannot be decided without a real request. The list marks such access as
**conditional** and names the condition keys. The "would this be allowed?"
check takes optional values for the common ones (source IP, whether the
request uses TLS, the object's tags) and otherwise treats a condition as not
met for an Allow and met for a Deny, so it never shows more access than the
request would really get.

### OpenID roles

Buckets cannot list everyone the identity provider gives a role. The page
says so plainly: the row is "anyone with role `X`", followed by the people
Buckets has seen with that role (signed in now, or holding access keys, from
`idp/openid/list-access-keys-bulk`), and the step to check in the provider
(Entra: Enterprise applications → the app → Users and groups). Asking the
provider directly (Microsoft Graph, Okta's API) belongs with SCIM, which will
know the provider's users anyway.

## Code

- **`src/iam/access.{c,h}`**: given the facts as JSON, (a) the routes to a
  bucket at an action level, with the deciding statements and limits, and (b)
  the decision for a principal, action and resource, with the statements
  behind it.
- **The console** (`src/console/access.c`): `GET /api/v1/access/bucket/<name>`,
  `POST /api/v1/access/check`, and `GET /api/v1/access/local-users`. Each
  gathers the facts with admin calls made as the signed-in admin, and runs
  the library on them. No caching: a review shows the state at the moment it
  runs, and says when that was.
- **The console page** Identity → Access review, the Access tab on a bucket,
  and the CSV export (built in the browser from the same JSON).

## Tests

- **Unit** (`tests/unit/test_access.c`): routes through each kind of
  principal; wildcard and prefix resources; a Deny cutting into an Allow;
  conditions marked; bucket policies with `*` and named principals;
  access-key policies narrowing their owner's. Every "allowed" or "denied" in
  the check is compared with `buckets_policy_allowed` on the same inputs, so
  the analysis cannot drift from the evaluator.
- **Integration** (`tests/integration/access.sh`): a setup with a local user, a
  group, a team, an access key with its own policy, a public bucket policy and
  an OpenID role. The review lists exactly the expected rows. For each "would
  this be allowed?" answer, the test makes the real request with that
  principal's credentials and checks the servers agree.
- **Playwright**: the page, the bucket tab, the CSV export.
- **Cluster**: extend `tests/e2e-k8s/identity.sh`: the review of the team's
  bucket names the Keycloak role, the LDAP group, and the people seen.

## Decisions

1. **Action levels: read, write, delete, manage settings, and any access.**
   Each is a fixed set of S3 actions, listed on the page. Single actions are
   chosen in the "would this be allowed?" check.
2. **Where it lives: Identity → Access review**, plus an Access tab on each
   bucket that opens the same view for that bucket.
3. **Admins who cannot read everything** see what they may read, and the page
   names the facts it could not get (for example "access keys: not allowed to
   list them"). It does not refuse the whole page.
4. **Local users while a provider is on are reported only.** There is no
   button to disable them all at once.
