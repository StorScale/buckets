# Ransomware alerts

Ransomware that reaches object storage, or a stolen or misused credential,
deletes data, overwrites it with encrypted copies, or first removes what would
let you recover it. Buckets notices each of these as it happens, says which
bucket and which credential, and can turn that credential off.

The design is in [design/ransomware-alerts.md](design/ransomware-alerts.md).

## Protect first

Alerts tell you to act; they don't keep data safe by themselves. What does:

- **Versioning** keeps every overwritten or deleted object as a noncurrent
  version, behind a delete marker, so it can be restored.
- **Object lock** (Governance or Compliance retention) stops those versions from
  being deleted before their date, whoever asks. Compliance mode can't be lifted
  by anyone, root included.

**Reports → Retention** shows which buckets have both.

## What is noticed

| Incident | When |
| --- | --- |
| **Mass delete** | A bucket deletes at least 1,000 objects in 5 minutes, and more than 10 times its usual rate. Each object of a `DeleteObjects` call counts, and each delete marker laid. |
| **Mass overwrite** | The same, for writes onto a key that already had an object. |
| **Protection removed** | At once, whatever the numbers: versioning suspended, a lifecycle rule that expires noncurrent versions (or all versions), Governance retention bypassed, a bucket deleted with its data (`--force`), or a bucket policy letting anyone (no credentials) write or delete. |

A mass delete or overwrite is also noticed for **one credential over several
buckets**, when together they add up to a burst and no single bucket's does.

**The usual rate** is the median, over the 14 days before today, of each day's
busiest hour, from the [usage history](usage-reports.md). So a nightly clean-up
job doesn't raise alerts, and one unusual day, an attack among them, doesn't
raise the bar for the next. A bucket with less than a week of history has a
usual rate of 0, so the 1,000-object floor decides.

The servers count; the one leading the cluster adds up every server's counts
every 30 seconds, so a burst spread over servers behind a load balancer is seen
as one. Replicated deletes and lifecycle expiry are not counted: the site where
a delete started, and your own lifecycle rules, are.

## What happens

Each incident:

- **opens once,** and stays open while the burst goes on. It closes after 15
  quiet minutes. Repeats of a protection change while it is open add to it.
- **goes to the bucket's notification targets** as `s3:Buckets:MassDelete`,
  `s3:Buckets:MassOverwrite` or `s3:Buckets:ProtectionRemoved` (`s3:Buckets:*`
  for all three). The record's `userMetadata` carries:
  - `x-buckets-incident-id`, `x-buckets-incident-kind`;
  - `x-buckets-credential` (the access key), `x-buckets-user` (the person
    behind it), `x-buckets-credential-type` (`access-key`, `user`, `sts`,
    `root` or `anonymous`);
  - `x-buckets-objects`, `x-buckets-usual`, `x-buckets-window`;
  - for a protection change, `x-buckets-change` and `x-buckets-detail`;
  - `x-buckets-action`: what was done to the credential.

  `mc event add` doesn't know these names; set them with
  `PutBucketNotificationConfiguration` (any S3 SDK, or `curl --aws-sigv4`).
- **is logged** as a warning (`ransomware: mass delete in bucket logs: ...`),
  which reaches the log targets (Sentinel, Splunk, ...).
- **raises an alert:** `BucketsMassDelete`, `BucketsMassOverwrite` or
  `BucketsProtectionRemoved` ([runbooks](monitoring.md#bucketsmassdelete)).
- **shows on Reports → Activity,** with the bucket, the credentials, the
  counts and the usual rate. Incidents are kept for 90 days.

## Stopping it

On **Reports → Activity**, **Turn off credential** stops the credential behind an
incident:

- an access key is turned off;
- a user is disabled;
- for temporary (STS) credentials, all of that person's sessions are revoked;
- root is never touched.

**Turn back on** undoes it for an access key or a user. Revoked sessions can't
come back: the person signs in again. **False alarm** marks an incident that
was a legitimate job.

With `BUCKETS_RANSOMWARE_RESPONSE=disable`, the credential behind a mass delete
or mass overwrite is turned off as the incident opens, without waiting for
anyone. It is off by default: a legitimate job stops too. Protection changes
are never acted on by themselves, since an admin making a change is the usual
case.

## Settings

| Setting | Default | |
| --- | --- | --- |
| `BUCKETS_RANSOMWARE_FLOOR` | `1000` | objects in the window, at least |
| `BUCKETS_RANSOMWARE_FACTOR` | `10` | times the usual rate, more than |
| `BUCKETS_RANSOMWARE_WINDOW` | `5` | minutes |
| `BUCKETS_RANSOMWARE_RESPONSE` | (alert only) | `disable`: turn the credential off at once |
| `BUCKETS_RANSOMWARE_EXCLUDE` | | buckets left out, comma-separated (a scratch bucket emptied every hour) |
| `BUCKETS_RANSOMWARE_INTERVAL` | `30` | seconds between the leader's checks |

Set them on every server, for example in the BucketsCluster's `spec.env`.

## For other tools

- **Admin API:**
  - `GET /minio/admin/v3/buckets/incidents?state=open|all` (`admin:ServerInfo`)
    returns the incidents (newest first), the rule and the response setting.
  - `POST /minio/admin/v3/buckets/incidents?id=<id>&action=disable|undo|false-alarm`
    (`admin:ConfigUpdate`).
- **Metrics,** per bucket, counted on each server (sum them):
  - `buckets_bucket_objects_deleted_total`
  - `buckets_bucket_versions_destroyed_total`
  - `buckets_bucket_objects_overwritten_total`
  - `buckets_bucket_protection_changes_total{change}`

  Per server, `buckets_ransomware_incidents_total{kind}` counts the incidents it
  opened while it led.

Incidents are kept in `.minio.sys/buckets/incidents.json`, and the per-hour
counts in the usage history, apart from MinIO's own data, so moving back to
MinIO is unaffected.
