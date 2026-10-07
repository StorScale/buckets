# Design: compliance reports (retention and encryption)

Status: proposed, for review. Roadmap: Phase 4, "WORM compliance reports" and
"Encryption coverage reports". Phase 4 is done when "an auditor can get usage,
access and retention reports from the console, and FIPS mode is documented and
tested". The access review (1.4.0) is the access report. This adds retention
and encryption; usage comes later.

## The problem

An auditor asks two questions the console can't answer today without going
bucket by bucket:

- **Retention (WORM):** which buckets keep their data unchangeable, how, and
  for how long? How much data is under retention or legal hold right now?
- **Encryption:** which buckets encrypt new objects, with which key? How much
  data is still stored unencrypted?

Bucket settings answer half of each question. The other half (how many
versions and bytes are locked or encrypted) is per object, and nothing counts
it today. The encrypt-existing job counts only what it rotates.

## What the page shows

A **Compliance** page, under Monitoring, with two tabs. Each has a table and
**Export CSV**, like the access review, and says when its figures were taken.

### Retention

One row per bucket:

| Column | From |
| --- | --- |
| Object lock | on / off (bucket's object-lock configuration) |
| Default retention | mode (Governance, Compliance) and period, or none |
| Versioning | Enabled / Suspended / off |
| Versions under retention | count and bytes, by mode, with the latest retain-until date |
| Versions under legal hold | count and bytes |
| Lifecycle that expires versions | yes / no, so the auditor sees deletion rules next to retention |

A summary line above the table: buckets with object lock, the data under
Compliance-mode retention (which nobody, not even root, can shorten), and the
furthest retain-until date.

### Encryption

One row per bucket:

| Column | From |
| --- | --- |
| Default encryption | SSE-S3, SSE-KMS with its key, or none |
| Key status | the KMS's answer for that key (exists, can encrypt) |
| Versions encrypted | count and bytes, by kind (SSE-S3, SSE-KMS, SSE-C) |
| Versions unencrypted | count and bytes, with a link to **Encrypt existing objects** |

A summary line: the KMS (online or not), the share of bytes encrypted, and the
buckets with no default encryption.

## Where the per-object figures come from

**The scanner counts them.** The scanner already reads every version's
metadata on every cycle, on the server leading each erasure set. For each
version it adds to per-bucket counters:
- **Encryption:** by the sealed-key metadata, which says SSE-S3, SSE-KMS or
  SSE-C.
- **Retention:** by `x-amz-object-lock-mode` and `retain-until` (only if still
  in the future), and the legal-hold flag.

This adds a few comparisons per version to a walk that already happens.

- **Stored apart from MinIO's data usage:** in
  `.minio.sys/buckets/compliance.json`, at the end of each cycle, with the
  cycle's time. MinIO's `.usage.json` is left exactly as MinIO writes it, so
  the round trip to MinIO is unaffected.
- **As fresh as the last scan.** On a large cluster a cycle can take hours,
  so the page says "as of the scan finished at …". Bucket settings are read
  live.
- **Delete markers** are not counted; there is no data in them.

## API

A Buckets extension to the admin API, like `ownerLeft` (1.10.0) but a new
path, since MinIO has nothing like it:

```
GET /minio/admin/v3/buckets/compliance -> {"scannedAt", "buckets": [{name, versioning, objectLock, ...,
                                            retention: {...}, encryption: {...}}]}
```

It needs `admin:DataUsageInfo`, the permission MinIO's own data-usage call
needs. The console page reads it through the session, so someone without that
permission sees why. The bucket settings in it are read live; the counts come
from `compliance.json`.

## Code

- **`src/scanner`:** per-bucket counters next to usage, written at the cycle's
  end (leader only, as `.usage.json` is). The counting is a pure function of a
  version's metadata, unit tested.
- **`src/admin`:** the endpoint, joining live bucket settings with the counts.
- **Console:** `Compliance.tsx` with the two tabs, CSV export, and links to
  bucket settings and Encrypt existing objects.

## Tests

- **Unit:** each metadata shape counted as MinIO writes it: SSE-S3, SSE-KMS
  with a key, SSE-C, plain, Governance and Compliance retention, expired
  retention, legal hold, delete markers.
- **Integration:** a server with KMS, three buckets (locked with a default
  retention, encrypted by default, plain), objects of each kind, one scanner
  cycle (`MINIO_SCANNER_SPEED`), then the endpoint's figures and the page's
  CSV checked.
- **Browser:** the page, its tabs and export.

## Open questions for review

1. **Per-object counts from the scanner?** The alternative is settings only:
   no counts, but always current and no scanner change. I recommend the
   counts: "how much is unencrypted" is the question auditors ask.
2. **Where in the console:** under Monitoring as proposed, or its own top-level
   **Compliance** section, ready for usage and audit reports later?
3. **Metrics too?** The same counts as Prometheus metrics (for example
   `buckets_bucket_unencrypted_bytes`) would let an alert fire when
   unencrypted data appears in a bucket that should have none. That's cheap
   once counted; I'd add it.
