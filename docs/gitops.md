# A Buckets setup in Git

Everything the operator manages is a Kubernetes resource, so a whole setup
can live in one repository and be applied by `kubectl apply -k`, Argo CD or
Flux:

| Resource | What it holds |
| --- | --- |
| `BucketsCluster` | The servers, their drives, TLS, the KMS, sign-in, the console, monitoring |
| `BucketsPolicy` | An IAM policy document |
| `BucketsUser` | A user, its policies and groups; its keys come from a Secret |
| `Bucket` | A bucket: versioning, object lock, quota, default encryption, lifecycle rules, replication |
| `BucketsSiteReplication` | Site replication between clusters |

`operator/examples/gitops` is a repository laid out this way:

```
kustomization.yaml
clusters/store.yaml        BucketsCluster: the main cluster, TLS from company-ca, a KMS
clusters/dr.yaml           BucketsCluster: the disaster-recovery copy
policies/reports-rw.yaml   BucketsPolicy
policies/reports-ro.yaml   BucketsPolicy
users/etl.yaml             BucketsUser (its Secret comes from your secret store)
buckets/reports.yaml       Bucket: versioned, locked, quota, SSE-S3, lifecycle, replicated to dr
buckets/raw.yaml           Bucket: a landing area that expires
```

```sh
kubectl create namespace storage
kubectl apply -k operator/examples/gitops -n storage
kubectl -n storage get bucketsclusters,buckets,bucketspolicies,bucketsusers,bsr
```

## How the operator treats what is in Git

- **Spec is yours, status is the operator's.** The operator never writes a
  resource's `spec`, so Argo CD and Flux see no difference to correct. It
  reports in `status`: `phase` (`Ready`, `Pending`, `Error`), a `message`,
  and for buckets `checkedAt` and `drift`.
- **Changes made by hand are put back.** A `Bucket`'s settings, and the sites
  of a `BucketsSiteReplication`, are read back every 10 minutes
  (`BUCKETS_OPERATOR_DRIFT_MS` on the operator). Anything changed outside Git
  is put back, and `status.drift` names the setting and when.
- **What isn't declared isn't touched.** Leave `lifecycle` out of a Bucket
  and its rules are left alone, so people can still manage them in the
  console. To remove a setting, declare it empty: `quota: ""`,
  `encryption: {}`, `lifecycle: []`, `replication: {}`. (Not `null`:
  Kubernetes drops a null field, which leaves the setting unmanaged.)
- **Deleting is cautious.** Deleting a `Bucket` leaves the bucket and its
  data. Deleting a `BucketsSiteReplication` leaves the replication running;
  to stop it, leave one site in the list. Deleting a `BucketsUser` or
  `BucketsPolicy` removes the user or policy from the cluster.
- **Secrets stay out of Git.** Root credentials are generated into a Secret
  when a cluster is made, and replication users get keys derived from the
  target's root key. Only `BucketsUser` credentials and other sites' root
  credentials need Secrets of yours: create them from your secret store,
  for example with External Secrets or Sealed Secrets.

## Argo CD

The resources need no special handling to sync. For Argo CD to show their
health, add a health check that reads `status.phase`:

```yaml
# argocd-cm
data:
  resource.customizations.health.buckets.io_Bucket: |
    hs = {status = "Progressing", message = "Waiting for the operator"}
    if obj.status ~= nil and obj.status.phase ~= nil then
      if obj.status.phase == "Ready" then hs.status = "Healthy" end
      if obj.status.phase == "Error" then hs.status = "Degraded" end
      hs.message = obj.status.message
    end
    return hs
```

The same check works for `buckets.io_BucketsUser`, `buckets.io_BucketsPolicy`
and `buckets.io_BucketsSiteReplication`.

## Order

The resources can be applied together. Until what a resource refers to is
there, such as its cluster's servers, a user's Secret or a replication target,
its status says what is missing (`Pending` or `Error`). It is tried again on
every pass and turns `Ready` once it can be applied.

## Replication and TLS

A bucket replicating into another cluster reaches it over that cluster's
Service. The source's servers trust the CA in their own certificate's
`ca.crt` (or `tls.caSecret`). With TLS, issue both clusters' certificates from
one issuer, as the example does. Otherwise, give the source a `tls.caSecret`
whose `ca.crt` holds both its own CA and the target's: it replaces the
source's own CA trust, which its servers need to reach each other.

Bucket replication and site replication don't mix on one cluster:
`bucketsd`, like MinIO, refuses new bucket replication targets once site
replication is on.
