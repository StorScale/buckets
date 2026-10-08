# Lifecycle and replication

A bucket's settings page has an editor for each:
- **lifecycle rules,** which delete or move objects as they age;
- **replication,** which copies a bucket's objects to another cluster.

Everything these editors do goes through the same S3 and admin calls `mc` makes. So the settings work with `mc`,
and stay readable after a rollback to MinIO.

The design is in [design/lifecycle-replication-editor.md](design/lifecycle-replication-editor.md).

## Lifecycle

**The rules** are listed in words, for example: "Objects under `logs/`: deleted 30 days after they're written;
old versions deleted 7 days after they're replaced." Each rule can be edited, turned off or removed.

**A rule's form** has four parts:
- **Which objects:** the whole bucket, or a prefix, tags and object size.
- **Objects:** deleted after N days or on a date, or moved to a tier after N days. The tier is chosen from the
  tiers set up with `mc ilm tier add`.
- **Old versions,** on a bucket that keeps versions: deleted N days after a newer version replaced them, keeping
  the newest N if you like; or moved to a tier.
- **Clean-up:**
  - delete markers left with no versions behind them removed, or every delete marker after N days;
  - incomplete multipart uploads removed after N days;
  - when an object is deleted, every version of it deleted too. This is the one rule that can't be undone, so it
    must be confirmed.

**Preview** shows what the rules would do before you save them. The server runs the draft over the bucket's
versions, exactly as its scanner would, without acting. It answers with, for each rule:
- what would be deleted or moved on the next run, within 7 days and within 30 days;
- how many versions and how much data;
- a few example keys.

It stops after a million versions or 30 seconds; the counts then say "at least". Versions under retention or legal
hold are kept whatever the rules say.

**Warnings** appear before you save:
- **Deleting old versions or all versions** removes what would let you recover from an overwrite or from
  ransomware. Saving such a rule also opens a [ransomware alert](ransomware.md) (protection removed).
- **On a bucket with object lock,** versions under retention stay until their date.
- **On a bucket without versioning,** rules for old versions and delete markers do nothing.
- **On a versioned bucket,** an expired object only gets a delete marker. Its versions stay until a rule deletes
  old versions.
- **Two rules that expire the same objects:** the shorter time wins.

**Edit as XML** shows the configuration behind the rules, and accepts any S3 or MinIO lifecycle XML. If XML
holds something the form can't show, it stays as XML, so a form edit never drops it.

### Incomplete uploads

A multipart upload that was started and never finished keeps its parts on the drives. Each server removes those
on its erasure sets 24 hours after they started. It checks every 6 hours. The `api` settings
`stale_uploads_expiry` and `stale_uploads_cleanup_interval` change this, as in MinIO.

A lifecycle rule with "remove incomplete uploads after N days" (S3's `AbortIncompleteMultipartUpload`) matters
when it's shorter than `stale_uploads_expiry`. It works by prefix only, and applies to uploads started on 1.16.0
or later.

## Replication

**Setting it up** is one form:

1. **Where to:** the endpoint of another Buckets or MinIO cluster (or any S3 service), a bucket there, and an
   access key and secret for it. The servers keep the secret encrypted; it is never shown again.
2. **Test** checks that:
   - the target answers;
   - the bucket is there;
   - the credentials work;
   - the bucket there keeps versions.

   Nothing is saved yet. Replication needs versioning on this bucket too, and the form turns it on with the save.
3. **What:**
   - a prefix, or the whole bucket;
   - whether objects already in the bucket are copied;
   - whether deletes and delete markers follow;
   - two-way metadata sync;
   - a storage class at the target;
   - a bandwidth limit.
4. **Save** creates the remote target, then the rule that sends objects to it. If the rule is refused, the new
   target is removed again, so nothing is left half done.

A bucket can replicate to several targets.

**Each target** shows:
- whether it is online, and the link's latency;
- objects replicated;
- failures in the last hour and since the servers started.

Below the targets, the section shows what is waiting to be sent. Every server keeps its own counts; the page adds
them up.

**Resync** copies every object to the target again, for a target that was rebuilt or out of reach for long.
**Remove** stops replicating; what is already there stays.

**Reports → Replication** lists every bucket that replicates, the worst first.

**Under site replication,** every bucket is replicated to every site already, so the section says so and offers
nothing to set up.

### Alerts

The operator's Prometheus rules ([monitoring.md](monitoring.md)) include:

| Alert | When |
| --- | --- |
| `BucketsReplicationTargetOffline` | A target has been unreachable for 5 minutes. |
| `BucketsReplicationFailing` | A bucket's objects have failed to replicate for 15 minutes. |
| `BucketsReplicationBacklog` | Objects have waited for more than an hour, and the queue is still growing. |

New metrics: `buckets_bucket_replication_pending_count` and `buckets_bucket_replication_pending_bytes`, per bucket
and per server.

## Buckets declared in Kubernetes

Under buckets-operator, a `Bucket` resource can declare a bucket's `lifecycle` and `replication`. The operator puts
them back within 10 minutes if they are changed anywhere else. So when a bucket's resource declares one of them,
the console shows it but doesn't let you change it. It says which resource to change instead.

**Copy as YAML** gives a lifecycle as the resource's `lifecycle:` block. You can work rules out in the form,
preview them, and commit them to Git. A `Bucket` resource can't express everything the form can, such as tags,
sizes, dates, tiers or keeping the newest versions. Copy as YAML names what it leaves out.

For this, the operator gives each cluster's console read-only access (`get`, `list`) to `Bucket` resources in its
namespace.

## For other tools

Buckets extensions to the admin API:

```
POST /minio/admin/v3/buckets/lifecycle-preview?bucket=     body: lifecycle XML
     s3:GetLifecycleConfiguration and s3:ListBucketVersions on the bucket
  -> {"scanned", "complete", "opensIncident", "actions": [{"rule", "action", "when", "objects", "bytes", "examples"}]}

GET  /minio/admin/v3/buckets/replication[?bucket=]
     s3:GetReplicationConfiguration on the bucket, or admin:GetBucketTarget for every bucket
  -> {"siteReplication", "servers", "serversAnswering", "buckets": [{"bucket", "versioned", "configured",
      "pending": {"objects", "bytes"}, "rules", "targets": [{"arn", "endpoint", "bucket", "online", "latencyMs",
      "replicated", "failedLastHour", "failedSinceStart", ...}]}]}

POST /minio/admin/v3/buckets/replication-test?bucket=     body: a madmin-encrypted target, as SetRemoteTarget takes it
     admin:SetBucketTarget
  -> {"ok": true, "sourceVersioned"}, or the error SetRemoteTarget would give
```

`action` is one of:
- `expire`;
- `delete-version`;
- `transition` or `transition-version`;
- `delete-all-versions` or `delete-marker-all-versions`.

`when` is `next-run`, `7d` or `30d`.
