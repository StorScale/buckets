# Design: lifecycle and replication editor

Status: proposed. Roadmap: Phase 4, "A lifecycle and replication editor,
instead of JSON and `mc` commands." It is the last item of Phase 4.

## The problem

**Lifecycle:** a bucket's settings page has one textarea of lifecycle XML.
To expire logs after 30 days you need to know S3's XML. A typo is refused
with S3's error, and nothing shows what the rule will do. A rule that deletes
far more than meant is found out only afterwards. MinIO's own extensions
(`ExpiredObjectAllVersions`, `DelMarkerExpiration`) and transitions to a tier
are harder still.

**Replication:** there is nothing in the console. Setting up one bucket's
replication takes four `mc` steps: versioning on both sides, a remote target
with credentials, the replication rule pointing at the target's ARN, and a
resync for existing objects. When it goes wrong, the only signs are
`mc replicate status` and the metrics.

**Two things to respect:**
- **Buckets declared as `Bucket` resources** (1.8.0) have their lifecycle and
  replication put back every 10 minutes. An edit in the console would
  quietly come undone.
- **Ransomware alerts** (1.14.0) open an incident when a lifecycle rule
  expires noncurrent versions. The editor should say so before saving, not
  afterwards.

## What it does

### Lifecycle (a bucket's settings → Lifecycle)

**A list of rules,** each in a line of words: "Objects under `logs/`:
deleted 30 days after they're written; old versions deleted after 7 days."
Each rule can be turned on or off, edited, or removed.

**The rule form:**
- **Which objects:** the whole bucket, or a prefix, tags, and object size
  (larger than, smaller than).
- **Current versions:** delete after N days or on a date, or move to a tier
  after N days or on a date. The tier is picked from the tiers that exist.
- **Old versions** (on a versioned bucket): delete after N days, keeping the
  newest N; or move to a tier.
- **Clean-up:** remove delete markers left with no versions behind them;
  remove delete markers after N days (`DelMarkerExpiration`); remove
  incomplete multipart uploads after N days.
- **Everything at once** (`ExpiredObjectAllVersions`): delete the object with
  all its versions. Behind a confirmation, since it is the rule that cannot be
  undone.

**What it will do, before saving:** **Preview** asks the server to run the
draft rules over the bucket's current versions, without acting. It answers
with counts and bytes:
- deleted on the next run;
- deleted within 7 and 30 days;
- moved to a tier.

It also gives a few example keys for each. The server stops after 1 million
versions or 30 seconds, and then says "at least". The bucket's size and
object count, from the usage report, are shown beside it.

**Warnings, in words, before saving:**
- A rule that deletes old versions or all versions: "This removes the copies
  that let you recover from an overwrite or ransomware. It will open a
  ransomware alert (protection removed)." (1.14.0)
- On a bucket with object lock: "Versions under retention are kept until
  their date whatever these rules say."
- A rule for old versions on a bucket without versioning: it does nothing.
- Two rules for the same objects with different days: the shortest wins.

**XML is still there:** **Edit as XML** shows the configuration the form
makes, and accepts any S3 or MinIO lifecycle XML. If a configuration has
something the form can't show, the bucket opens in XML with a note, and
saving the form never drops what it didn't show.

### Replication (a bucket's settings → Replication)

**Setting it up is one form:**
1. **Where to:** an S3 endpoint, a bucket there, and an access key and secret
   for it. Another Buckets or MinIO cluster is the usual case. The secret is
   sent to the server once, kept as MinIO keeps it (in the bucket's targets,
   encrypted), and never shown again.
2. **Test** checks that the target answers and that the credentials can
   replicate (`ValidateBucketReplicationCreds`), and that versioning is on at
   both ends. If it isn't on here, the form offers to turn it on. It can't
   change the target's versioning, so it says to turn it on there.
3. **What:** the whole bucket, or a prefix and tags; whether deletes and
   delete markers follow; whether objects already in the bucket are copied
   (existing-object replication); metadata sync for two-way setups; the
   storage class at the target; a bandwidth limit.
4. **Save** creates the remote target (`SetRemoteTarget`), then the rule that
   points at its ARN. If the rule is refused, the target it just made is
   removed again, so a failed save leaves nothing half done.

A bucket can replicate to more than one target. Each target is a card of its
own, in priority order.

**Its state, on the same page, for each target:**
- online or offline;
- objects and bytes waiting, failed in the last hour and day, and the
  replication lag;
- the last error.

These come from the replication metrics (`?replication-metrics=2`).
**Resync** copies everything again (`?replication-reset`), with its progress
shown, for a target that was rebuilt or out of reach for long.

**Reports → Replication** lists every bucket that replicates, with its
targets and state, worst first.

**Alerts:** the operator's rules have none for replication today. Three are
added, with runbooks in `docs/monitoring.md`, each linking to this report:
- `BucketsReplicationTargetOffline`: a target unreachable for 5 minutes;
- `BucketsReplicationFailing`: failures for 15 minutes;
- `BucketsReplicationBacklog`: objects waiting for more than an hour and
  still growing.

**Buckets under site replication** are replicated to every site already.
Their Replication section says so and links to the site replication
settings, rather than offering a second setup that would fight it.

### Buckets declared in Kubernetes

The console reads the cluster's `Bucket` resources. To allow this, the
operator grants each cluster's console `get` and `list` on `buckets.buckets.io`
in its namespace, read-only. If a bucket's resource declares `lifecycle` or
`replication`:
- that section is shown but can't be changed. It says: "Declared in
  Kubernetes (Bucket `reports` in `tenant`): change it there, or the operator
  will put it back within 10 minutes."
- **Copy as YAML** gives the draft as the resource's `lifecycle:` or
  `replication:` block. A team can work out rules in the form, preview them,
  and commit them to Git.

The form can also make the YAML for a bucket that isn't declared yet. Rules
beyond what the `Bucket` resource can say (tags, sizes, transitions) are
named, rather than left out without a word.

Outside Kubernetes, nothing is declared and everything can be edited.

### A fix on the way: incomplete uploads

The `Bucket` resource's `abortIncompleteUploadDays` writes S3's
`AbortIncompleteMultipartUpload`, but the server never reads it. Neither does
MinIO, which only clears every upload after a day (`stale_uploads_expiry`).
The setting does nothing today. The scanner will apply it, removing
incomplete uploads under the rule's prefix after N days. MinIO ignores the
element, so a rollback loses only the setting, not data.

## API

Buckets extensions to the admin API:

```
POST /minio/admin/v3/buckets/lifecycle-preview?bucket=
     body: lifecycle XML (the draft)
     s3:GetLifecycleConfiguration and s3:ListBucketVersions on the bucket
  -> {"scanned", "complete", "actions": [{"rule", "action": "expire|expire-noncurrent|transition|..."
       , "when": "next-run|7d|30d", "objects", "bytes", "examples": [...]}]}

GET  /minio/admin/v3/buckets/replication?bucket=     (or all buckets, for the report)
     s3:GetReplicationConfiguration
  -> {"buckets": [{"bucket", "siteReplication", "targets": [{"arn", "endpoint", "bucket",
       "online", "pending", "failed1h", "failed24h", "lagSeconds", "lastError", "resync"}]}]}
```

Everything else uses the S3 and admin calls that `mc` uses:
- `PutBucketLifecycleConfiguration` and `PutBucketReplicationConfiguration`;
- `SetRemoteTarget`, `RemoveRemoteTarget` and `ListRemoteTargets`;
- `?replication-check` and `?replication-reset`;
- `ListTier`, for the tiers to pick from.

So the console needs no new rights, and a site that rolls back to MinIO keeps
every setting made here.

## Code

- **`src/bucket/lifecycle.c`:** the preview reuses the same evaluation the
  scanner uses (`lifecycle eval`), with a clock moved forward for "within 7
  and 30 days". It gains `AbortIncompleteMultipartUpload`.
- **`src/admin/lifecycle_preview.c`** and **`src/admin/replication.c`:** the
  two endpoints. The preview walks versions with the object layer's listing,
  bounded by count and time.
- **Operator:** the console Role gets read access to `Bucket`.
  The three replication alerts go in `monitoring/rules.yaml`.
- **Console:**
  - `pages/Lifecycle.tsx` and `pages/Replication.tsx`, used by the bucket's
    settings page;
  - `lifecycle.ts`: the XML ⇄ rules model, keeping what it doesn't model;
  - `pages/ReplicationReport.tsx`.

## Tests

- **Unit:** `lifecycle.ts` round trips: every element S3 and MinIO allow,
  unknown elements kept, and the plain-words summaries. The preview's counts
  over a set of versions with set times. `AbortIncompleteMultipartUpload`
  parsed and applied.
- **Integration (`lifecycle-editor.sh`):** the preview against real buckets
  (expiry, old versions, delete markers, transition to a tier, the "at least"
  cap). Incomplete uploads removed after N days.
- **Browser:**
  - a rule made with the form, previewed and saved, then read back with
    `mc ilm rule ls`;
  - the ransomware and object lock warnings;
  - XML with an unknown element kept through a form edit;
  - replication to a second local server: test, save, an object replicated,
    the state shown, a resync, and a failed save leaving no target behind;
  - a declared bucket shown read-only (with the mock Kubernetes API), and
    Copy as YAML.

## Open questions, with a recommendation each

1. **The preview: worth a server endpoint?** It is the part that keeps a rule
   from deleting more than meant, and the scanner's evaluation can be reused.
   **Recommended: yes**, bounded at 1 million versions or 30 seconds.
2. **Declared buckets: read-only, or editable with a warning?** An edit that
   the operator puts back 10 minutes later is worse than none. **Recommended:
   read-only, with Copy as YAML,** which needs read access to `Bucket` for
   the console.
3. **Tiers: pick only, or manage them too?** Transitions need a tier, and
   tiers are set up today with `mc ilm tier add`. **Recommended: pick from
   the existing tiers now,** with a link to how to add one. A tiers page can
   follow; it needs secrets for each cloud, which is a design of its own.
4. **Incomplete uploads: apply `AbortIncompleteMultipartUpload`, or stop
   offering it?** **Recommended: apply it.** It's what S3 users expect, and
   the `Bucket` resource already promises it. MinIO ignores it on rollback.
