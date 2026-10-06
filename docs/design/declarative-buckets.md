# Design: buckets, replication and site replication as resources

Status: agreed, being built. Roadmap: Phase 3, "More resources as CRDs".
Phase 3 is done when "a cluster, its buckets, policies and replication are
created from one Git repository".

## The problem

The `Bucket` resource already accepts `versioning`, `objectLock` and `quota`,
but the operator does not apply them. It creates the bucket once, says "not
applied yet", marks itself Ready and never looks again. Lifecycle rules,
default encryption, replication and site replication can't be declared at
all. A setup kept in Git therefore stops at "the bucket exists".

## What it does

### `Bucket`, applied and kept

```yaml
apiVersion: buckets.io/v1alpha1
kind: Bucket
metadata: {name: reports}
spec:
  cluster: store
  versioning: true                 # false after true: suspended
  objectLock: {mode: GOVERNANCE, days: 30}   # or true: enabled, no default retention
  quota: 100Gi                     # a hard quota; removed: no quota
  encryption: {kmsKey: reports-key}          # or {sse: S3}
  lifecycle:
    - id: tmp
      prefix: tmp/
      expireDays: 7
      noncurrentExpireDays: 30
      abortIncompleteUploadDays: 7
      expireDeleteMarkers: true
  replication:
    target: {cluster: dr}          # another BucketsCluster here, or:
    # target: {endpoint: https://s3.dr.example.com, bucket: reports, credsSecret: {name: dr-creds}}
    deletes: true
    deleteMarkers: true
    existingObjects: true
```

**What it does with each field:**
- **Applied when the spec changes.** A hash of the spec is kept in
  `status.appliedHash`.
- **Checked again every 10 minutes.** A setting changed by hand on a declared
  field is put back; `status.drift` says which one and when.
- **Only declared fields are touched.** Leaving `lifecycle` out leaves the
  bucket's rules alone, while `lifecycle: []` removes them. Likewise
  `quota: ""`, `encryption: {}` and `replication: {}`. Not `null`: Kubernetes
  drops a null field from a patch or an apply, which would leave the setting
  unmanaged rather than removed.
- **Object lock only at creation.** S3 allows it only when the bucket is made,
  so declaring it on an existing bucket without lock is an error in the status.
  The default retention (`mode`, `days`) can change later.
- **Deleting the resource leaves the bucket**, its data and settings, as
  today.

**Replication** needs versioning on both sides. `versioning: true` must be
declared, or the status says so.

- **`target.cluster`:** another BucketsCluster in the same namespace. The
  operator:
  - makes a replication user on the target cluster, allowed only that
    bucket's replication actions. Its secret key is an HMAC of its name under
    the target's root key, so no Secret holds it and it follows a root key
    rotation on the next check;
  - creates and versions the target bucket;
  - registers the remote target on the source with that user;
  - writes the replication configuration.
- **`target.endpoint`:** credentials from `credsSecret`. The target bucket
  must already exist and be versioned; the status says so if not.

### `BucketsSiteReplication`

```yaml
apiVersion: buckets.io/v1alpha1
kind: BucketsSiteReplication
metadata: {name: everywhere}
spec:
  sites:
    - cluster: store
    - cluster: dr
    - {name: branch, endpoint: https://s3.branch.example.com, credsSecret: {name: branch-root}}
```

The operator adds the sites through the first site's admin API
(`site-replication add`, with each site's root credentials, as `mc admin
replicate add` does). A site added to the list later is added; a site removed
is removed. The status lists the sites. Deleting the resource leaves the
replication in place, so a GitOps mistake can't tear it down. To stop it,
leave one site in the list: the operator removes the replication through it.
(An empty list would leave no site to talk to.) When the first site is empty
and another holds buckets, the operator sets the replication up through that
one, as `bucketsd` asks.

## Code

- **`operator/src/bucketspec.c`:** pure functions from a Bucket's spec to what
  the APIs take (versioning XML, object-lock XML, lifecycle XML, encryption
  XML, quota JSON, replication XML, the replication user's policy) and a
  canonical hash. Unit tested.
- **`operator/src/iam.c`:** `reconcile_bucket` applies them through the
  cluster's S3 and admin APIs, using the connection the IAM kinds already use.
- **`operator/src/sitereplication.c`:** the new kind.
- **CRDs:** the Bucket schema grows, and a `BucketsSiteReplication` CRD is
  added; the RBAC covers it.

## Tests

- **Unit:** each document, against the shapes MinIO accepts.
- **envtest:** a Bucket's settings applied to a stand-in `bucketsd` and read
  back, changed, drifted by hand and put back. Replication between two
  stand-in servers; site replication between three.
- **Cluster:** two BucketsClusters on the shared cluster. A bucket replicated
  from one to the other carries an object across; site replication carries a
  bucket, a policy and a user across.

## Order

1. ✅ `Bucket`: versioning, object lock, quota, encryption, lifecycle, with drift
   correction.
2. ✅ `Bucket.replication`.
3. ✅ `BucketsSiteReplication`.
4. The exportable-manifests layout (docs and an example repository tree),
   which then covers all of it.
