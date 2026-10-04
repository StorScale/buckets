# Design: per-team roles

Status: agreed, being built. Roadmap: Phase 2, "Per-bucket and per-team roles".

## The problem

Signing in with Entra ID, Okta, Keycloak or LDAP works, but the only roles
that work without extra effort are the built-in ones: `consoleAdmin`,
`readwrite` and `readonly`, each covering every bucket. To give one team its own
buckets, an admin writes an IAM policy by hand, gets the ARNs and actions
right, names it, and then makes a matching app role, group or LDAP mapping in
the provider. Most people stop at `readwrite`, so everyone can reach everything.

## What it does

A **team** is a name and a set of buckets. Buckets turns it into ordinary IAM
policies, one per access level, and shows exactly what to set up in the
identity provider so the right people get those policies.

```
Team "finance"
  buckets:  finance-reports, ledger        (existing buckets)
            finance-*                       (a prefix: today's and future buckets)
  levels:   team-finance-ro      read
            team-finance-rw      read and write objects
            team-finance-admin   rw + the buckets' settings, and creating/deleting buckets under the prefix
```

People then get a team's level the way they get any policy today:

| Sign-in | How someone gets `team-finance-rw` |
|---|---|
| Entra ID | An app role with the value `team-finance-rw`, assigned to a group |
| Okta | A group named `team-finance-rw`, sent in the `groups` claim |
| Keycloak | A realm role `team-finance-rw` (the `roles` claim mapper) |
| LDAP / AD | A group DN attached to the policy (Buckets does this from the Teams page) |
| Local users and groups | Attached to the policy (Buckets does this from the Teams page) |

Role changes in the provider apply at the next sign-in, as today. Changes to a
team's buckets apply straight away, even to people who are already signed in,
because sessions name their policies and the servers read policies live.

## Access levels

| Level | Actions | On |
|---|---|---|
| `ro` | `s3:GetBucketLocation`, `s3:ListBucket`, `s3:ListBucketVersions`, `s3:ListBucketMultipartUploads`, `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectTagging`, `s3:GetObjectRetention`, `s3:GetObjectLegalHold` | the team's buckets and their objects |
| `rw` | `ro`, plus `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutObjectTagging`, `s3:DeleteObjectTagging`, `s3:AbortMultipartUpload`, `s3:ListMultipartUploadParts` | the same |
| `admin` | `rw`, plus the bucket-configuration actions (versioning, lifecycle, tagging, encryption, notifications, object lock and retention defaults, replication settings) and `s3:CreateBucket` / `s3:DeleteBucket` | the same; creating and deleting only under the team's prefixes |

None of the levels include admin API actions (users, policies, configuration,
KMS). A team admin manages buckets, not people. Anyone who needs more keeps a
built-in policy as well.

Listing buckets needs no extra permission: `ListBuckets` already returns only
the buckets the caller can list or locate, so a team member sees their team's
buckets in the console and in `mc ls`.

## Where teams are stored: in the policies themselves

A team is not stored anywhere new. Each generated policy marks its statements
with a `Sid` naming the team and level, and its buckets and prefixes are its
`Resource` ARNs:

```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "buckets-team:v1:finance:rw", "Effect": "Allow", "Action": ["s3:ListBucket", "..."],
   "Resource": ["arn:aws:s3:::finance-reports", "arn:aws:s3:::ledger", "arn:aws:s3:::finance-*"]},
  {"Sid": "buckets-team:v1:finance:rw:objects", "Effect": "Allow", "Action": ["s3:GetObject", "..."],
   "Resource": ["arn:aws:s3:::finance-reports/*", "arn:aws:s3:::ledger/*", "arn:aws:s3:::finance-*/*"]}]}
```

The Teams page lists the policies whose names start with `team-` and whose
`Sid` carries the marker, and groups them by team. Doing it this way means:

- **No new storage format.** The policies are plain MinIO policies, so the
  MinIO round trip keeps working: MinIO enforces them as they are, and when the
  cluster comes back to Buckets they show up as teams again. See
  [compatibility.md](../compatibility.md).
- **No operator needed.** It works for a bare `bucketsd` with the console, as
  well as on Kubernetes.
- **Nothing to get out of sync.** The policy is the team. A team policy someone
  edits by hand (so the marker no longer matches what Buckets would generate)
  shows up as "edited outside the Teams page". It is left alone until someone
  saves the team again, which asks before overwriting it.

## Code

Following the identity settings (`src/iam/idpsettings.c`), which are shared by
the console and the operator:

- **`src/iam/teams.{c,h}`**: generates the policies for a team (name, buckets,
  prefixes, levels), and reads a team back from its policies. Checks names
  (`[a-z0-9-]`, 1 to 40 characters, so `team-<name>-admin` stays a valid
  provider role value) and bucket names, and refuses a prefix that would cover
  another team's buckets without saying so.
- **The console** (`src/console/teams.c`): `GET/PUT/DELETE
  /api/v1/teams[/<name>]`, using the signed-in admin's own credentials for
  `add-canned-policy`, `remove-canned-policy`, `list-canned-policies` and the
  LDAP and builtin attach/detach calls. No new admin API.
- **Console page** Identity → Teams: a list (name, buckets, levels, LDAP and
  local mappings) and an editor (pick buckets or type prefixes, choose levels).
  It shows the provider-side steps for the sign-in that is set up, with each
  role value ready to copy, the way the Sign-in page does: Entra app roles,
  Okta groups, Keycloak realm roles, LDAP group DNs.
- **Deleting a team** removes its policies, after detaching its LDAP and local
  mappings (the page lists them first). Provider-side roles are left as they
  are: values with no policy are ignored.

Later, and only if people ask for it: a `BucketsTeam` CRD that the operator
reconciles into the same policies, for setups kept in Git (Phase 3). Teams it
manages would be read-only on the Teams page, marked with
`buckets-team:v1:k8s:...`.

## Tests

- **Unit** (`tests/unit/test_teams.c`): the generated policies for each level;
  reading a team back from its policies;
  hand-edited policies detected; name and prefix checks.
- **Integration** (`tests/integration/teams.sh`, local servers, mock OpenID
  provider): create `finance` with `rw`; a token with role `team-finance-rw`
  reads and writes `finance-reports`, cannot see or reach `hr-payroll`, and
  `ListBuckets` shows only its buckets. `admin` creates `finance-q4` under the
  prefix but not `hr-q4`. Changing the team's buckets applies to a session that
  is already signed in. An LDAP group attached from the page gets access.
  Deleting the team cuts access.
- **Playwright**: create, edit and delete a team; the provider steps shown
  match the sign-in that is set up.
- **Cluster** (extending `tests/e2e-k8s/identity.sh`): a Keycloak realm role
  `team-finance-rw` gives a real sign-in exactly the team's buckets.
- **Round trip**: a team survives Buckets → MinIO → Buckets, and MinIO enforces
  it the same way.

## Decisions

1. **Level names: `ro`, `rw` and `admin`.** They become provider role values,
   so they will not change.
2. **No bucket policies for team admins.** `admin` leaves out
   `s3:PutBucketPolicy` and `s3:DeleteBucketPolicy`, so a team cannot share its
   buckets or make them public. An opt-in per team can come later.
3. **No team quotas yet.** They come later, with the per-team usage reports in
   Phase 3.
4. **Entra ID: app roles, not a `groups` claim**, as the Sign-in setup already
   recommends.
