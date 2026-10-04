# Moving from MinIO to Buckets

Buckets takes over a MinIO deployment's drives in place. There's no data copy: the same PersistentVolumeClaims, StatefulSet names and Service names, with bucketsd in place of MinIO. Users, policies, buckets, versions, object lock, lifecycle rules and encrypted objects carry over, because Buckets uses MinIO's on-disk format. The move can be undone: `scripts/rollback-to-minio.sh` hands the same drives back to MinIO.

This guide covers MinIO on Kubernetes, either a MinIO Operator Tenant or StatefulSets laid out the way the MinIO Operator lays them out. It's tested end to end in `tests/e2e-k8s/adopt-minio.sh`, which moves a tenant with data to Buckets and back, with and without KES (see [Tested](#tested)).

## Before you start

**1. Mirror MinIO's images.** MinIO no longer publishes images or binaries: quay.io and Docker Hub return errors for `minio/*`. A cluster that loses a node can't pull MinIO again, and a rollback needs a MinIO image the cluster can pull. Before anything else, copy the images the tenant runs to a registry you control:

- MinIO itself, at the tenant's exact release;
- KES, if the tenant uses it;
- the MinIO Operator, and any CSI driver (DirectPV) the drives depend on.

If the images are only in the nodes' container caches, push them from a node (`ctr -n k8s.io images export`, then import and push), and check that the digests match.

Then point the Tenant (and the MinIO Operator) at the mirror before adopting. Adoption itself doesn't need MinIO's images, but rollback restores the Tenant exactly as it was saved: if it still names quay.io or Docker Hub, MinIO can only start again on nodes that still have the image cached.

**2. Back up what can't be rebuilt.**

- The key store (Vault, AWS, Azure or Google), if objects are encrypted. **Keys are the data:** a lost key makes every object encrypted with it unreadable, for MinIO and Buckets alike. Adoption never moves or changes keys, but the key store is outside both.
- The Tenant, its Secrets and its `config.env`. The adoption saves the objects it deletes in its state directory (see below), but a copy of your own costs nothing.

**3. Install the operator.** Install buckets-operator from its published Helm chart, which brings the CRDs, so that it watches the tenant's namespace:

```bash
helm install buckets-operator oci://ghcr.io/storscale/charts/buckets-operator \
  --version 1.2.0 -n buckets-system --create-namespace \
  --set watchNamespace=<namespace>          # leave out to watch every namespace
```

The chart and Buckets' images (`bucketsd`, `buckets-operator`, `buckets-console`, `buckets-kes`) are public on `ghcr.io/storscale` and signed; the README shows how to verify them. If the cluster can't pull from ghcr.io, mirror them as you did MinIO's, and point the chart's `image.repository` and `kesImage` at the mirror, pass `--image` to the adoption below, and set `spec.console.image` if you enable the console. From a checkout, the same chart is in `operator/helm/buckets-operator`.

**4. Know the outage.** The servers stop and start once: MinIO's pods are deleted, then Buckets' pods start on the same drives. Expect S3 to be unavailable for a few minutes, and longer with large pools or slow volume attachment.

## What carries over

| What | How |
|---|---|
| Objects, versions, delete markers, tags, metadata, object lock | On the drives, in MinIO's format |
| Buckets and their settings (versioning, lifecycle, replication, notifications, quotas, policies) | On the drives |
| Users, groups, policies, service accounts, STS settings | On the drives (IAM is stored in `.minio.sys`) |
| Server configuration set with `mc admin config set` | On the drives (`config.json`), read by Buckets |
| `config.env` (root credentials and every `MINIO_*` setting in it) | The BucketsCluster's `spec.configuration` names the same Secret |
| TLS certificate | `spec.tls.certSecret`: the Tenant's `externalCertSecret`, or the Secret mounted at `--certs-dir` |
| Pools, servers, drives per server, volume claim templates | `spec.pools` |
| Where the pods run (node selector, tolerations, affinity) | Each pool, and KES |
| Security context (user, group, fsGroup) | `spec.securityContext` |
| The S3 Service's name and port | `spec.servicePort`; the Service names (`<tenant>`, `<tenant>-hl`) stay the same, so clients keep their endpoint |
| KES and its keys | See [KES](#kes) |

Not carried over:

- **The Tenant's `spec.env`.** Environment variables set on the Tenant (rather than in `config.env`) aren't copied. Move them to the BucketsCluster's `spec.env` after adoption, or to `config.env` before it. Identity settings (`MINIO_IDENTITY_*`) are the ones that matter most; see [Identity](#identity).
- **The MinIO console.** The adoption deletes Service `<tenant>-console` and doesn't enable the Buckets console. Enable it afterwards (see [The console](#the-console)).
- **Bucket DNS** (`MINIO_DNS_WEBHOOK_ENDPOINT`, the Tenant's `features.bucketDNS`). The plan says so in its notes.
- **The MinIO Operator's automatic certificate** (`requestAutoCert`). The adoption refuses such a tenant: give it an `externalCertSecret` first.
- **A certificate Secret with only `public.crt` and `private.key`.** Buckets needs `tls.crt` and `tls.key` (see [TLS](#tls)).

## The move

The script runs from a machine with `kubectl` and Python 3 (PyYAML too, if the tenant uses KES). Always pass the context explicitly.

### 1. Dry run

```bash
scripts/adopt-minio.sh --context <ctx> -n <namespace> -t <tenant> --state ./adopt-<tenant>
```

The servers run the operator's default image, `ghcr.io/storscale/bucketsd` at its version. To run a mirrored or pinned image, add `--image <registry>/bucketsd:1.2.0`, here and when applying.

Without `--apply`, nothing changes. The script reads the Tenant (or the StatefulSets), its PVCs and PVs, and prints:

- the pools and drives it found;
- how many PVs would be deleted with their PVC (the adoption sets them to `Retain` first);
- notes: what it adjusts, or won't carry over;
- problems, which stop the adoption: for example a PVC that isn't Bound or that something else owns, a missing `config.env`, or a KES setup it can't carry over;
- the BucketsCluster it would create.

Read the BucketsCluster before going on. With KES, add `--check-kes` (see [KES](#kes)).

MinIO releases before `RELEASE.2024-10-29` can't read the newest `xl.meta` version. For those, the plan sets `BUCKETS_XL_META_VERSION=2`, so that a rollback can read what Buckets writes. Remove it once there's no going back.

### 2. Apply

```bash
scripts/adopt-minio.sh --context <ctx> -n <namespace> -t <tenant> --state ./adopt-<tenant> --apply
```

In order:

1. **KES check** (with KES only): buckets-kes reads the default key with the tenant's own KES configuration, in a one-off pod. If it can't, nothing has changed and the script stops.
2. **Save.** The Tenant (or the StatefulSets and Services), the plan and the PVs' reclaim policies go to the state directory. Keep it: rollback needs it.
3. **Retain.** Every drive's PV is set to `Retain`, so no later step can delete data.
4. **Stop MinIO.** The Tenant is deleted (or its StatefulSets and Services). The PVCs stay; the script never deletes a PVC.
5. **Start Buckets.** The BucketsCluster is created, with the same names, on the same claims. The script waits until it's Ready (`--timeout`, default 900 seconds).

### 3. Check

```bash
kubectl --context <ctx> -n <namespace> get bc <tenant>
mc ls <alias>/<bucket>                 # the same endpoint and credentials as before
mc admin info <alias>
```

Read back objects you know, including an encrypted one if there are any. The S3 endpoint, credentials and certificate are the same as before, so clients need no change.

## KES

A tenant that encrypts with KES keeps its keys where they are. buckets-kes, Buckets' own KES-compatible key server, reads them in place: it stores keys exactly as MinIO's KES does.

What the adoption does:

- **Settings.** It reads the tenant's KES StatefulSet (`<tenant>-kes`) as it runs, including the Secrets it mounts and the environment its `${VAR}`s refer to. Where the keys are and how to sign in become Secret `<tenant>-kms`. The credentials never appear in the plan, the state directory or the output.
- **The cluster's KES.** `spec.kms.kes` names the tenant's default key with `createKey: false`, so a missing key is an error rather than a new, empty key. It runs as the tenant's KES ServiceAccount, so a Vault Kubernetes role bound to that account keeps working, and where the tenant's KES pods ran. Its objects are named `<tenant>-buckets-kes`, so the tenant's own `<tenant>-kes` objects and certificate Secret stay as they are.
- **The check.** `--check-kes` runs the KES check during a dry run as well. The one-off pod is the only change it makes.
- **`config.env`.** If it sets `MINIO_KMS_*`, Buckets reads a copy without those lines (Secret `<tenant>-buckets-config`). MinIO's own stays as it was.
- **Start.** The storage servers wait until buckets-kes serves the default key. Until then, the BucketsCluster's phase is `WaitingForKMS`, and `status.kms.message` says what KES is waiting for.

Supported key stores: HashiCorp Vault (KV v1 or v2, Transit, AppRole or Kubernetes sign-in), AWS Secrets Manager, Azure Key Vault and Google Secret Manager. The adoption refuses, before changing anything:

- KES's `fs` key store (keys in files on KES's own pods): move the keys to a key store first;
- Vault sign-in with a client certificate;
- a Kubernetes JWT written into the configuration instead of the pod's token;
- Google workload identity through `gcpCredentialSecretName`.

After adoption, the console's **Encryption** page shows the KMS and its keys, and can change the settings later. See `docs/encryption.md`.

## Identity

Users, groups, policies and service accounts are on the drives, so access keys keep working without any step.

Sign-in through an identity provider needs its settings on the Buckets servers:

- **Settings in `config.env`** or stored with `mc admin config set` carry over by themselves.
- **Settings in the Tenant's `spec.env`** don't: copy the `MINIO_IDENTITY_OPENID_*` or `MINIO_IDENTITY_LDAP_*` variables to the BucketsCluster's `spec.env`, with secrets as `valueFrom` references. The servers restart one at a time.

The Buckets console has its own sign-in settings (`BUCKETS_CONSOLE_OIDC_*`, or `CONSOLE_LDAP_ENABLED`), separate from the servers'. MinIO's console settings don't apply to it.

`docs/identity.md` sets up Microsoft Entra ID with app roles: each role in the token's `roles` claim names a Buckets policy. The same setup works with any OpenID Connect provider that puts roles in a claim, Okta included, though only Entra ID is in use today. If MinIO mapped a claim to policies (`MINIO_IDENTITY_OPENID_CLAIM_NAME`), the same mapping works in Buckets.

## TLS

The adoption carries the tenant's certificate Secret over (`spec.tls.certSecret`). The certificate keeps covering the right hosts, because the Service names don't change.

The Secret must hold `tls.crt` and `tls.key`, as a `kubernetes.io/tls` Secret or cert-manager's does. MinIO also accepts `public.crt` and `private.key`; if the tenant's Secret uses only those names, the dry run reports it. Add `tls.crt` and `tls.key` with the same certificate and key, or name another Secret with `--tls`.

Certificates the MinIO Operator generated (`requestAutoCert`) aren't carried over: before adopting, give the tenant a certificate of your own (`externalCertSecret`), from cert-manager or your CA.

## The console

Enable the Buckets console after adoption:

```yaml
spec:
  console:
    enabled: true
    tls: {certSecret: {name: <console cert>}}   # optional
```

It runs as its own Deployment and Service, `<tenant>-console` on port 9090, so an Ingress that pointed at MinIO's console Service keeps its backend name. Check the port: MinIO's console listened on 9090, or on 9443 with TLS.

## Monitoring

- **Metrics.** Buckets serves MinIO's metrics endpoints (`/minio/v2/metrics/{cluster,node,bucket,resource}` and `/minio/metrics/v3`) with MinIO's metric names, so dashboards and alerts keep working. Bearer tokens (`mc admin prometheus generate`) and `MINIO_PROMETHEUS_AUTH_TYPE=public` work as before.
- **Scrape targets.** Prometheus configurations that reach the Service by name keep working. Ones that select pods or Services by the MinIO Operator's labels (`v1.min.io/tenant`) need Buckets' label instead: `buckets.io/cluster: <tenant>`.
- **Health.** `/minio/health/live`, `/minio/health/ready` and `/minio/health/cluster` are served as before.
- **Status.** The BucketsCluster's status reports the phase, ready servers per pool and, with KES, `status.kms`.

## Rollback

```bash
scripts/rollback-to-minio.sh --context <ctx> -n <namespace> -t <tenant> --state ./adopt-<tenant>            # check
scripts/rollback-to-minio.sh --context <ctx> -n <namespace> -t <tenant> --state ./adopt-<tenant> --apply
```

It checks that every PVC is still there, deletes the BucketsCluster (the PVCs stay), and restores the Tenant, or the StatefulSets and Services, from the state directory. MinIO starts on the same drives, with its own KES if it had one. The PVs stay `Retain` unless you add `--restore-reclaim`.

What Buckets wrote in the meantime stays readable by MinIO: objects, versions, users and policies, and objects encrypted with the tenant's keys. That's why the plan sets `BUCKETS_XL_META_VERSION=2` for older MinIO releases.

Rollback needs the MinIO image (and the KES image) the saved Tenant names. If you didn't point the Tenant at a mirror before adopting, change the images in the saved `tenant.json` (or `statefulsets.json`) in the state directory before rolling back.

## Afterwards

- Remove `BUCKETS_XL_META_VERSION` from `spec.env` once there's no going back to an older MinIO.
- Set the PVs' reclaim policy back if you want `Delete` again; the adoption left them `Retain`.
- Keep or delete the state directory. It holds the saved Tenant (or StatefulSets) and the plan. The adoption writes no credentials there, though a Tenant with secrets written directly into its `spec.env` would carry them.
- Uninstall the MinIO Operator once nothing else uses it.

## Tested

`tests/e2e-k8s/adopt-minio.sh` runs on a real cluster:

1. A MinIO tenant (StatefulSets as the MinIO Operator lays them out, TLS, `config.env`) gets data: many small objects, a multipart object, metadata and tags, versions, and an encrypted object.
2. `scripts/adopt-minio.sh` adopts it, and every object reads back identical.
3. Buckets writes new objects.
4. `scripts/rollback-to-minio.sh` hands it back, and MinIO reads both its own objects and Buckets'.

With `KES=1`, the tenant encrypts with MinIO's own KES on Vault. The adoption carries it over to buckets-kes, and after rollback MinIO decrypts what Buckets encrypted. Both pass on the shared cluster with MinIO `RELEASE.2024-10-13`, 29/29 without KES and 44/44 with it.
