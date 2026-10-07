# Compliance reports

The console's **Compliance** section answers two questions auditors ask,
bucket by bucket, with **Export CSV** for their files. The access review
(**Identity → Access review**, see [identity.md](identity.md#access-review))
answers the third: who can reach the data.

## Retention

**Compliance → Retention** shows, for each bucket:

- **Object lock:** on or off. It can only be turned on when a bucket is made.
- **Default retention:** Governance or Compliance, and for how long. Governance
  can be shortened by someone allowed to bypass it; Compliance cannot be
  shortened by anyone, root included.
- **Versioning:** object lock keeps versions, so a locked bucket is always
  versioned.
- **Governance, Compliance and Legal hold:** how many versions, and how many
  bytes, are under retention right now (by mode) or on legal hold.
- **Retained until:** the furthest retain-until date in force.
- **Lifecycle expires versions:** whether a lifecycle rule deletes versions,
  so the auditor sees deletion rules next to retention. Retention wins: a
  lifecycle rule never deletes a version still under retention or legal hold.

The summary line gives the buckets with object lock, the data under
Compliance-mode retention, and the furthest date.

## Encryption coverage

**Compliance → Encryption coverage** shows, for each bucket:

- **Default encryption:** SSE-S3, SSE-KMS with its key, or none. A bucket's
  settings page sets it.
- **Key:** for SSE-KMS the bucket's key, for SSE-S3 the KMS's default key. A
  key that no longer works is flagged.
- **SSE-S3, SSE-KMS, SSE-C and Unencrypted:** how many versions, and how many
  bytes, are stored each way. **Encrypt existing objects**, in the bucket's
  settings, encrypts what is left unencrypted in place.

The summary line gives the KMS's state, the share of bytes encrypted, and the
buckets without default encryption.

## How fresh the figures are

Bucket settings are read when the page opens. The counts come from the data
scanner, which reads every version once per cycle; the page says when that
cycle finished. A bucket made since then shows its settings, and its counts
after the next cycle. On a large cluster a cycle can take hours.

Delete markers hold no data and are counted nowhere.

## For other tools

- **Admin API:** `GET /minio/admin/v3/buckets/compliance`, with
  `admin:DataUsageInfo` (the permission MinIO's data usage call needs). It's a
  Buckets extension, and returns JSON (see `src/admin/compliance.c`).
- **Metrics:** the per-bucket endpoint (`/minio/v2/metrics/bucket`) carries
  `buckets_bucket_unencrypted_bytes`, `buckets_bucket_unencrypted_versions`,
  `buckets_bucket_encrypted_bytes{kind}`, `buckets_bucket_retained_bytes{mode}`
  and `buckets_bucket_legal_hold_versions`. For example, this alerts on
  unencrypted data in buckets whose names start with `secure-`:

  ```
  buckets_bucket_unencrypted_bytes{bucket=~"secure-.*"} > 0
  ```

The counts live in `.minio.sys/buckets/compliance.json`, apart from MinIO's own
data usage, so moving back to MinIO is unaffected.
