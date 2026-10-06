# Compatibility promise

Buckets is a successor to MinIO: people move existing deployments onto it and build on it for years. This page says what stays compatible across Buckets releases, what is compatible with MinIO, and which test proves each promise. It applies to every 1.x release.

## Versions

Buckets follows [Semantic Versioning](https://semver.org/):

- **Patch releases** (1.1.0 → 1.1.1) fix bugs and make things faster. They change nothing you configure or call.
- **Minor releases** (1.1 → 1.2) add features. Everything that worked keeps working: new settings, CRD fields and API responses are optional or additive.
- **A major release** (2.0) is the only place a promise below can be broken. Anything removed in 2.0 is deprecated first: marked in the CHANGELOG and, where it is a setting, logged as deprecated at startup, in at least one 1.x minor release before.

Security fixes go into the next release from `main`; only the latest release is supported (see `SECURITY.md`).

## What stays compatible

Each promise holds both across 1.x releases and, where it says so, with MinIO. MinIO here means its last public release, `RELEASE.2025-10-15T17-29-55Z`, which Buckets reimplements, and the older releases an adopted deployment may roll back to.

| Surface | The promise | Proven by |
|---|---|---|
| **On-disk format** | Drives written by any 1.x release are read by every later 1.x release, and by MinIO: `format.json`, `xl.meta`, part files, bucket metadata (`.metadata.bin`), IAM and server configuration under `.minio.sys`. Buckets reads drives MinIO wrote. | `tests/data/minio-ref` (byte-for-byte fixtures); `interop.sh`, `iam-interop.sh`, `sse-interop.sh`, `versioning-interop.sh`, `compress-interop.sh`, `config.sh` (each both ways with MinIO); `tests/e2e-k8s/adopt-minio.sh` |
| **Handing drives back to older MinIO** | Buckets writes `xl.meta` version 3, which MinIO reads from `RELEASE.2024-10-29`. With `BUCKETS_XL_META_VERSION=2` it writes version 2, which older MinIO reads; adoption sets it when the tenant's MinIO is older. | `minio-rollback.sh`; `adopt-minio.sh` (rollback to `RELEASE.2024-10-13`) |
| **S3 API** | Requests, responses, headers and error codes as MinIO answers them; errors byte for byte (MinIO's table of 327 codes). | `s3diff.sh` (scenarios diffed against MinIO); `tests/conformance/minio-go.sh` (minio-go's functional suite); `tests/conformance/s3-tests.sh` (ceph s3-tests) |
| **Clients and SDKs** | `mc`, the AWS SDKs and CLI, and minio-go keep working against every 1.x release, with the same endpoint and credentials as MinIO. | `interop.sh` (mc); `minio-go.sh`; the e2e tests' AWS CLI client |
| **Admin API** (`/minio/admin/v3`) | `mc admin` works as it does with MinIO: users, policies, groups, service accounts, configuration, heal, info, trace, profiling, decommission, rebalance, replication, tiering, batch jobs. Two handlers are dropped on purpose (self-update; see below). | `adminops.sh`, `adminops-dist.sh`, `trace-interop.sh`, `config.sh` |
| **STS and identity** | `AssumeRole`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithLDAPIdentity`, `AssumeRoleWithCertificate`; MinIO's policy documents and claim mapping. | `iam.sh`, `openid.sh`, `ldap.sh`, `certsts.sh`, `iam-interop.sh` |
| **Events, audit and trace** | Bucket notification payloads, audit log entries and trace records have MinIO's shape and fields. | `notify-interop.sh`, `audit-interop.sh`, `trace-interop.sh` (each diffed against MinIO) |
| **Metrics** | The Prometheus metric families and label names of MinIO's v2 and v3 endpoints, so dashboards and alerts keep working; bearer-token and public metrics authentication. New metrics may be added. | `metrics-names.sh` (zero diff against MinIO), `metrics-auth.sh` |
| **Configuration** | Every `BUCKETS_*` setting keeps its name and meaning in 1.x, and the `MINIO_*` name of each setting keeps working beside it. `config.env` files written for MinIO work unchanged. | `config.sh`; the adoption tests (MinIO's `config.env` reused as is) |
| **KES** | bucketsd works with MinIO's KES and with `buckets-kes`. `buckets-kes` speaks KES's API, reads KES's configuration file, and stores keys exactly as MinIO KES does in each key store, so either server reads the other's keys and ciphertexts. | `kes.sh`, `kes-diff.sh` (buckets-kes and MinIO KES, request for request), `buckets-kes.sh`; `adopt-minio.sh` with `KES=1` |
| **Kubernetes resources** | The `buckets.io` CRDs (`BucketsCluster`, `BucketsUser`, `BucketsPolicy`, `Bucket`, `BucketsSiteReplication`) are `v1alpha1`. In 1.x no field is removed or changes meaning, and new fields are optional with defaults that keep today's behaviour. When a later API version arrives it is served beside `v1alpha1`, with conversion, for the rest of 1.x. | `operator/tests/test_manifests.c`, `tests/e2e-k8s/envtest.sh` |
| **Rolling upgrades** | The operator upgrades a cluster one server at a time. Servers of consecutive 1.x releases work together while that is in progress, so S3 stays available. | Every upgrade of the development cluster (1.0.0 → 1.1.0 → 1.1.1, each rolled with S3 serving); not yet a CI test |

## What is not promised

- **Mixed MinIO and Buckets clusters.** The internode protocol is Buckets' own. A cluster is all MinIO or all Buckets; moving between them is done whole, by adoption and rollback, on the same drives.
- **Skipping releases in a rolling upgrade.** Consecutive releases interoperate while servers are mixed. To jump further, upgrade through each minor release, or stop the cluster and start it on the new release.
- **The console's internal API.** The calls between the console's web app and `consoled` change freely; the console talks to the servers only through the S3 and admin APIs above.
- **Log lines.** The server's own log messages and their wording may change in any release. Audit logs and trace records are promised above; ordinary logs are not.
- **Default resource names and tuning.** Thread counts, buffer sizes and other defaults may change in any release when measurements justify it. Settings that set them explicitly keep working.
- **Dropped on purpose.** SUBNET, call-home and self-update (`ServerUpdateHandler`, `ServerUpdateV2Handler`): the operator rolls images, and Buckets reports to no vendor. MinIO's gateway mode, removed from MinIO itself, is not implemented.

## When a promise breaks

A release that breaks a promise above, other than in 2.0, has a bug. Report it as an issue; it is fixed in the next patch release, and the CHANGELOG says what was affected.
