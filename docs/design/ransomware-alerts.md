# Design: ransomware alerts

Status: agreed, being built. Roadmap: Phase 4, "Ransomware alerts for
unusual bursts of deletes or overwrites, using the existing event
notifications". Phase 4's gate has passed (1.13.0); this is one of its three
remaining items.

## The problem

Ransomware that reaches object storage, or a stolen or misused credential,
does damage in one of a few ways:

- **Mass deletion:** objects deleted, or delete markers laid over them.
- **Mass overwriting:** each object replaced by an encrypted copy. With
  versioning, the originals stay as noncurrent versions, until lifecycle or
  the attacker removes them.
- **Removing the protection first:** suspending versioning, adding a
  lifecycle rule that expires noncurrent versions, shortening retention with
  a governance bypass, or deleting the bucket.

Today Buckets notices none of this. The per-bucket metrics count requests, so
a `DeleteObjects` call removing 1,000 objects counts once. Nothing compares
today with a normal day, and nothing says which credential did it. An admin
finds out when users report missing data.

## What it does

**Detect** a burst of deletes or overwrites, per bucket and per credential,
against that bucket's normal rate. **Say so at once:** a Prometheus alert, an
event to the bucket's notification targets, and a log line.
Each names the bucket, the credential (and, for an access key or STS session,
the person behind it), and what happened. **Optionally stop it:** turn off the
credential.

**Protection removed** (versioning suspended, an expiry rule for noncurrent
versions added, retention bypassed, a bucket with data deleted) is reported
every time, with no threshold. These changes are rare, and they matter most.

## What is counted

Every server counts, per bucket and per credential (the access key, with its
parent user):

| Count | When |
| --- | --- |
| objects deleted | each object of a `DeleteObject` or `DeleteObjects` call, and each delete marker laid |
| versions destroyed | deletes by version ID: these remove data for good |
| objects overwritten | a PUT, copy or completed multipart upload onto a key that already had a current version |
| protection changes | the changes above, by kind |

Counting per object, not per request, closes the `DeleteObjects` gap.

Overwrites are known without an extra read. Committing a write already reads
the object's existing metadata on every drive, to add the new version beside
the old ones, so whether a current version was there is known at that point.

## Detection

Each server keeps its counts for the last hour, in one-minute slots, for each
bucket and credential seen in that hour.

- **Cluster-wide:** the leader (pool 0, set 0, as for identity sync) asks the
  other servers for their recent counts every 30 seconds. This is one small
  peer call that sends only what changed. A burst spread over servers behind
  a load balancer is seen as a whole.
- **What counts as a burst** over the last 5 minutes, for a bucket or a
  credential:
  - **Deletes and destroyed versions:** more than 1,000 objects, and more than
    10 times the bucket's usual rate.
  - **Overwrites:** the same rule.

  The usual rate comes from the usage history (1.12.0), which keeps daily
  counts for 13 months. Its daily records gain objects deleted and
  overwritten, per hour. The usual rate is the median of the busiest hour of
  each of the 14 days before today, so nightly clean-up jobs don't raise
  alerts, while one unusual day (an attack among them) doesn't move it. A
  bucket with less than a week of history uses the floor alone.
- **Once per incident:** an alert fires once, and again only after the burst
  has been quiet for 15 minutes.
- **Settings:** `BUCKETS_RANSOMWARE_FLOOR` (1000),
  `BUCKETS_RANSOMWARE_FACTOR` (10), `BUCKETS_RANSOMWARE_WINDOW` (5m). A bucket
  can be left out entirely, for example a scratch bucket that is emptied
  every hour.

## What happens

- **Event:** `s3:Buckets:MassDelete`, `s3:Buckets:MassOverwrite` or
  `s3:Buckets:ProtectionRemoved` goes to every notification target set up for
  the bucket that listens for it. `s3:Buckets:*` matches them all, like
  MinIO's own `s3:Scanner:*` events. The record carries the bucket, the
  credential and its parent user, the counts, the usual rate, and the window.
  That fits webhooks, Kafka and the SIEM targets as they are.
- **Log:** a warning in the server log, so it reaches the logger targets (and
  from there Sentinel or Splunk).
- **Metrics:** cumulative counts per bucket:
  - `buckets_bucket_objects_deleted_total`
  - `buckets_bucket_versions_destroyed_total`
  - `buckets_bucket_objects_overwritten_total`
  - `buckets_bucket_protection_changes_total{change}`

  Plus `buckets_ransomware_incidents_total{kind}` from the leader. There is no
  per-credential label, because credentials are unbounded.
- **Alerts** in the operator's rules: `BucketsMassDelete`,
  `BucketsMassOverwrite` and `BucketsProtectionRemoved`, firing on the
  incident counter, with runbooks in `docs/monitoring.md`.
- **Console:** an **Activity** page under Reports. It lists incidents, open
  and past, each with its bucket, credential, person, counts and timeline,
  and buttons to turn the credential off or to mark the incident a false
  alarm. Incidents are kept in `.minio.sys/buckets/incidents.json` for 90
  days.

## Stopping it

With `BUCKETS_RANSOMWARE_RESPONSE=disable`, the leader turns off the
credential behind an incident as it opens it:
- an access key is turned off, as an admin would;
- an STS session is revoked, with its user's other sessions;
- root is never touched: the incident says root did it.

The incident records the action, and the console offers to undo it. Turning
off a key stops a legitimate job too, so this is off by default; the console's
**Turn off credential** does the same by hand. Protection changes are never
acted on by themselves: an admin making a change is the usual case.

## What it doesn't do

- **Inspect content:** checking whether new data looks encrypted would mean
  reading every object written. The overwrite rate is the signal instead.
- **Prevent damage by itself:** versioning with object lock (Compliance or
  Governance retention) is what keeps data unrecoverable-by-attackers. The
  docs lead with that, and the retention report (1.11.0) shows which buckets
  have it. The alerts tell you to act; locking makes acting in time less
  critical.

## API

Buckets extensions to the admin API:

```
GET  /minio/admin/v3/buckets/incidents?state=open|all     admin:ServerInfo
  -> {"incidents": [{"id", "kind", "bucket", "change", "detail",
                     "credentials": [{"accessKey", "user", "type", "count"}],
                     "opened", "lastSeen", "closed", "counts": {...}, "usual",
                     "action": "disabled" | "revoked" | "none" | null, "undone", "falseAlarm"}],
      "rule": {"floor", "factor", "windowMinutes"}, "response": "disable" | "alert"}
POST /minio/admin/v3/buckets/incidents?id=<id>&action=disable|undo|false-alarm   admin:ConfigUpdate
```

## Code

- **`src/s3`:** per-object counting where deletes, delete markers and writes
  over a current version happen, and the protection changes where the bucket
  configurations are set.
- **`src/ransomware/`:** the per-server windows, the leader's cluster view,
  the detection rule (pure, unit tested), incidents and their storage, and
  the response.
- **`src/usage/history.c`:** daily objects deleted and overwritten.
- **Admin endpoints**, events, metrics, the operator's rules and the console
  page.

## Tests

- **Unit:** the detection rule (floor, factor, usual rate from history, a new
  bucket, quiet periods, one incident per burst); per-object counting of
  `DeleteObjects`; overwrites against a first write; window arithmetic.
- **Integration:** a four-server cluster with a webhook target.
  - Thousands of deletes through two servers trigger one `MassDelete`, which
    names the credential.
  - The same number spread over the day doesn't.
  - Overwrites trigger `MassOverwrite`.
  - Suspending versioning triggers `ProtectionRemoved` at once.
  - With the response on, the access key is turned off, and undoing turns it
    back on.
- **Browser:** the Activity page, false alarm, and undo.

## Decisions

1. **The servers detect,** with the leader's cluster-wide view, and the
   per-bucket metrics as well.
2. **Automatic response off by default;** with
   `BUCKETS_RANSOMWARE_RESPONSE=disable`, the credential behind an incident is
   turned off (an access key) or revoked (STS sessions). Root never is.
3. **Defaults:** at least 1,000 objects and 10 times the usual rate over 5
   minutes; the usual rate is the median of the busiest hour of each of the
   14 days before today (not their maximum, so an attack doesn't raise the
   bar for the next).
4. **Protection removed, always:** versioning suspended, an expiry rule for
   noncurrent versions added, retention bypassed, a bucket with data deleted,
   and a bucket policy that lets anyone write or delete.
