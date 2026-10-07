# Buckets architecture

Buckets is a C17 rewrite of MinIO's last public release (`RELEASE.2025-10-15T17-29-55Z`, archived April 2026). It is built to run natively on Kubernetes, and the web console is a separate deployment from the storage servers.

The MinIO source at that tag is the behavioral spec. Each subsystem below names the Go code it replaces. `docs/parity.md` tracks every API handler.

## Deployables

```
                        ┌──────────────────────────── Kubernetes namespace ───────────────────────────┐
  browser ──Ingress──▶  │ buckets-console (Deployment)            buckets-operator (Deployment)       │
                        │  └─ consoled (C): serves the SPA,        watches BucketsCluster, BucketsUser,│
                        │     sessions, key/LDAP/OpenID sign-in,   BucketsPolicy, Bucket CRs           │
                        │     SigV4-signs S3/admin calls ─┐        reconciles everything below         │
                        │                                 ▼                                            │
  S3 clients ─Ingress─▶ │ Service <cluster>  ──▶  StatefulSet per pool: bucketsd ×N (PVCs per drive)   │
                        │                          headless Service for peer DNS + internode RPC       │
                        │                                 │ SSE-S3/KMS data keys (mTLS)                │
                        │                                 ▼                                            │
                        │ <cluster>-kes (Deployment): buckets-kes ×2 ──▶ Vault / AWS / Azure / Google  │
                        └──────────────────────────────────────────────────────────────────────────────┘
```

- **`bucketsd`** is the storage server. It serves the S3, admin, STS and metrics APIs, internode RPC, the background services (scanner, heal, ILM, replication, notifications), and SFTP/FTP. There is one StatefulSet per server pool.
- **`buckets-operator`** is written in C. It uses the Kubernetes REST API directly (libbuckets' HTTP client, `src/k8s`; it resyncs on an interval rather than watching) and handles:
  - reconciling the `buckets.io/v1alpha1` CRDs
  - pool expansion
  - rolling upgrades paced by `/minio/health/cluster`
  - decommissioning
  - TLS
  - leader election through a Lease
- **`buckets-kes`** is the key server behind SSE-S3 and SSE-KMS (`src/kes`).
  - **API:** KES's, with identities from client certificates and allow/deny policies, so bucketsd talks to it as to MinIO's KES.
  - **Keys:** generated and wrapped in the server and cached, and kept in Vault, AWS Secrets Manager, Azure Key Vault or Google Secret Manager in MinIO KES's layout, so keys move freely between the two.
  - **Run by the operator** for `spec.kms.kes`, with a certificate and API keys it generates. The console's Encryption page sets it up and tests it (see `docs/encryption.md`).
- **`buckets-console`** is stateless and scales independently of storage. It never touches drives: it only talks to `bucketsd` over the S3 and admin APIs, like any other client. `consoled` serves the SPA itself, over HTTPS when `spec.console.tls` gives it a certificate, and signs people in with access keys, LDAP or OpenID Connect (see `docs/identity.md`).

## `bucketsd` layers

```
cmd/bucketsd     argument/env config, signals, graceful drain
s3/              router, SigV4/V2/presign/streaming/POST-policy auth, handlers, XML, error table
admin/ iam/ ...  admin API, IAM/STS, bucket features, ILM, replication, notify, metrics, select
object/          object layer: server pools → erasure sets → quorum reads/writes, multipart, listing
erasure/         Reed-Solomon (ISA-L), bitrot (HighwayHash), xl.meta v2, format.json
storage/         one local drive: volumes, xl.meta + part files, atomic renames, fsync discipline
dist/            internode RPC (HTTP/1.1 + HMAC, pooled, TLS), remote drives, dsync locks, endpoints
net/  core/      HTTP/1.1 server (llhttp), event loop (epoll/kqueue, io_uring planned), buffers, logging
```

## Compatibility contract

The promise for releases, with the test behind each line, is in [compatibility.md](compatibility.md).

| Surface | Compatible with MinIO | Why |
|---|---|---|
| S3 API, error codes | yes, byte-identical errors (`scripts/gen-s3-errors.py`) | SDKs, `mint`, `warp` |
| Admin API (madmin) | yes | `mc admin` keeps working |
| STS, IAM documents | yes | existing identity setups |
| On-disk format (`format.json`, `xl.meta` v2) | yes | adopt existing MinIO drives in place |
| Prometheus metric names | yes | existing dashboards and alerts |
| Env vars | `BUCKETS_*`, with `MINIO_*` fallback | drop-in migration |
| Internode protocol | **no** | mixed MinIO/Buckets clusters are unsupported |
| SUBNET, callhome, self-update, gateway | dropped | not applicable on Kubernetes |

## Current state (1.11.0)

Every build phase below is done: `docs/parity.md` lists 220 of MinIO's 222 API handlers as implemented and 2 as dropped on purpose, and `CHANGELOG.md` records what each release added. What comes next is in `docs/roadmap.md`.

The rest of this section describes the S3 core and the operator as they were verified at 0.3.0 (Phases 1 to 3); later phases are described in the sections after it.

### The S3 core at 0.3.0

The S3 core runs on one drive, many drives, several pools, or a cluster of nodes, in MinIO's on-disk format. At 0.3.0 it was verified these ways:
- **Conformance:** minio-go's functional suite (the Go suite inside MinIO's `mint`) gives 78 pass, 0 fail. The other 24 tests need later-phase features.
- **On-disk compatibility:** a real MinIO build (`tests/integration/interop.sh`) reads what Buckets wrote, and Buckets reads what MinIO wrote. That covers single PUT, streaming PUT, multipart, checksums, folder objects, metadata and bucket creation times.
- **Byte-level fixtures:** `tests/data/minio-ref` holds files written by MinIO, and `xl.meta` and `.metadata.bin` round-trip byte for byte.
- **Clusters:** minio-go gives the same 78/0 against a 4-node cluster (`CLUSTER=1`), and 80/0 over HTTPS. `tests/integration/cluster.sh` covers node loss and rejoin, and a real 4-node MinIO cluster reads the drives a Buckets cluster wrote.

**Implemented:**
- **Auth:**
  - SigV4 headers, presigned URLs and aws-chunked streaming (signed chunks, signed and unsigned trailers)
  - SigV2 headers and presigned URLs
  - POST policy (V4 and V2)
- **Objects:**
  - Put, Get (ranges, `partNumber`, preconditions, `response-*` overrides), Head, Delete, DeleteObjects, Copy
  - GetObjectAttributes
  - canned-private ACLs
- **Multipart:** create, upload part, copy part (with ranges), list parts, complete, abort, list uploads.
- **Checksums:** CRC32, CRC32C, CRC64NVME, SHA1 and SHA256 via headers, trailers or form fields. Multipart uploads get composite and full-object checksums (merged with CRC combination).
- **Listing:** v1, v2 and v2-with-metadata, with prefix, delimiter, marker, continuation token and url encoding.
- **Storage:**
  - `format.json`, `xl.meta` v2 with MinIO's signatures, and inline data under 128 KiB
  - bitrot-framed part files
  - `__XLDIR__` folder objects
  - MinIO's multipart staging layout
  - `.metadata.bin` bucket metadata

**Phase 2 (erasure, pools, distribution) ✅:**
- **Erasure coding:**
  - a Reed-Solomon codec
  - ellipsis drive syntax and set sizing identical to MinIO
  - SipHash set selection and `hashOrder` shard placement
  - read/write quorum, bitrot detection and parity reconstruction
- **Format:** `format.json` negotiation across drives, pools and nodes. It heals a replaced drive into its slot.
- **Server pools:** MinIO-compatible placement across pools.
- **Distributed mode:**
  - drives given as `http(s)://host:port/path` URLs, and a node recognizes its own drives by port and interface address
  - peers' drives are reached over our own internode RPC: HTTP/1.1 with HMAC auth and pooled connections, TLS optional, on a separate worker pool
  - dsync locks with quorum, refresh and expiry
  - bootstrap waits for peers, and only a pool's first node formats it
- **Concurrency:**
  - a drive I/O thread pool
  - request handlers on worker threads
  - namespace locks, cluster-wide in distributed mode
- **Healing:**
  - object heal with MinIO's dangling-object rules
  - an MRF queue for heal-on-read and partial writes
  - background healing of replaced drives
  - a scanner that finds objects nobody reads
- **HTTPS:** SNI and hot certificate reload.
- **Health:** `/minio/health/cluster` reports per-set write and read quorum.

**Phase 3 (Kubernetes):**
- **CRDs:**
  - `BucketsCluster` has pools, image, credentials, parity, TLS, env and service type, with a status subresource and printer columns.
  - `BucketsUser`, `BucketsPolicy` and `Bucket` are defined, and reconcile once the admin API exists.
- **Operator:** `buckets-operator` (C, `operator/src`) server-side-applies per cluster:
  - a headless Service (publishing unready pods, which bootstrap needs) and the S3 Service
  - one StatefulSet per pool (`Parallel`, `OnDelete`, and `BUCKETS_VOLUMES` naming every pool's pods)
  - PodDisruptionBudgets
  - generated root credentials, which deliberately outlive the cluster
  - with `spec.kms.kes`, `buckets-kes` for SSE-S3/KMS, whose key store the console sets up and tests first (see `docs/encryption.md`)
- **Restarts:** a topology change (pools, erasure settings) restarts every server together. Any other template change rolls one server at a time, only while all are ready.
- **Status:** phase, servers ready, and a `Ready` condition.
- **Leader election:** on a Lease.
- **Server awareness:** bucketsd reads `BUCKETS_VOLUMES`, takes credentials from `*_FILE` secrets, and recognizes its own endpoints by pod hostname before cluster DNS publishes it.
- **Verified here:** manifest unit tests, and the operator against a real kube-apiserver and etcd (`tests/e2e-k8s/envtest.sh`, 34 checks, running as its own ServiceAccount under the shipped RBAC).
- **On kind:** `tests/e2e-k8s/kind.sh` (17 checks) applies a 4-server `BucketsCluster` and keeps serving S3 through its Service while a pod is killed, a drive's PVC is replaced and healed, a pool is added and the image is rolled; then the console comes up as its own Deployment and its Playwright suite passes against the cluster. The images build on Debian trixie, whose OpenSSL (3.5) has the Argon2id that madmin's encrypted admin payloads need.

**Interim choices that remain:**
- The operator resyncs on an interval (`BUCKETS_OPERATOR_RESYNC_MS`, 5 s by default) instead of watching; it is level-triggered either way.
- The network loops use epoll or kqueue; io_uring is not used yet.

The others listed at 0.3.0 are gone: the HTTP server runs several event loops (`BUCKETS_NET_THREADS`), SHA-256 and MD5 use OpenSSL, IAM and versioning arrived in Phases 4 and 5, and bucket metadata is cached.

## Build phases

Phase 8's gate includes replication between MinIO (RELEASE.2025-10-15) and Buckets, run with a local MinIO binary:

1. ✅ Bucket replication MinIO → Buckets and Buckets → MinIO: active-active, deletes and delete markers, existing-object replication, resync, and SSE-C objects (`tests/integration/replication.sh`).
2. ✅ Three-site replication mixing MinIO and Buckets sites: users, policies and bucket settings created on any site appear on all of them (`tests/integration/siterepl.sh`, groups set up from either kind of site).
3. ✅ Handing a MinIO site's work over to a Buckets site (migration): a Buckets site joins a MinIO group, is resynced, and the MinIO sites leave (`siterepl.sh`).
4. ✅ The same on Kubernetes (`tests/e2e-k8s/multisite.sh`, 48 checks): two operator-run Buckets clusters and a MinIO site, each in its own namespace and reaching the others by Service DNS. It covers active-active bucket replication between Buckets and MinIO (multipart, metadata, delete markers, resync of existing objects), a three-site group (Buckets, MinIO, Buckets) set up from a Buckets site with changes made on every site, and a decommission on a multi-server site that is started and followed through servers that forward to the pool's owner.

Site replication (`src/siterepl/`) speaks MinIO's admin protocol between sites, so a group can mix both. Each site keeps `config/site-replication/state.json`; hooks in the S3 and admin handlers push changes to peers as they happen, and the cluster leader's heal routine (every 30s) compares the sites' `metainfo` reports and repairs what a site missed while it was away. Deleted buckets leave a `.minio.sys/buckets/.deleted/<bucket>` marker until every site agrees, as MinIO does. ILM expiry-rule replication (`--replicate-ilm-expiry`) is accepted but its rules are not yet compared or healed.

Tiering (`src/tier/`, `src/s3/tiering.c`) keeps MinIO's formats end to end: tiers live in `.minio.sys/config/tier-config.bin` (msgp, SSE-S3-sealed when a KMS exists), transitioned versions keep their `xl.meta` entry with MinIO's `x-minio-internal-transition-*` keys and no data dir, and the bytes go to the warm backend as stored, under MinIO's remote object names. So either server reads, restores and deletes what the other transitioned. The warm backends are S3/MinIO (through the internal S3 client), Azure Blob and GCS, over their REST APIs. Transition workers are fed by the scanner and by writes. Deleting or overwriting a transitioned version either removes the remote copy right away or leaves a free version for the scanner to sweep. The scanner also keeps MinIO's per-tier usage for `mc admin tier info`.

Batch jobs (`src/batch/` for the job model, `src/s3/batch.c` for running them, `src/admin/batch.c` for the API) keep MinIO's files: definitions in `.minio.sys/batch-jobs/<id>` and progress reports under `batch-jobs/reports/`, both in MinIO's msgp. Definitions are YAML, parsed with libyaml into a tree that resolves tags and reports errors as yaml.v3 does. `mc batch describe` prints them with a writer that follows yaml.v3's layout. Each job runs on its own thread with a small worker pool, walks the bucket's versions (oldest first for replicate and keyrotate, newest first for expire), and saves its report every ten seconds and at the end, so a restarted server resumes where it left off. Replication pushes reuse bucket replication's request building. Pulls list the remote with MinIO's `metadata=true` extension and write through the object layer, keeping version IDs and modification times. MinIO pushes small objects as snowball tar archives, which the PUT handler unpacks (`PutObjectExtract`).

Decommission and rebalance (`src/s3/datamove.c`) move versions between pools below the S3 layer. The object layer can read a version's full record from one pool and import it into another. The import re-encodes the stored bytes, still encrypted or compressed, for the destination set's erasure layout, and keeps the version ID, time, ETag and metadata. Delete markers and remote-tier versions move as metadata only. Once every version of an object has moved, the object is removed from its old pool in one step. Pools being decommissioned or rebalanced out are skipped when new objects are placed. Progress is kept in MinIO's `pool.bin` and `rebalance.bin`, and each operation runs on the node that holds the pool's first drive.

S3 Select (`src/select/`) follows MinIO's `internal/s3select` closely enough to be checked against it query by query. The SQL is MinIO's participle grammar, parsed by a backtracking recursive-descent parser that tries alternatives in the same order, so the same queries parse into the same tree; analysis, evaluation, value inference and the Go number and time formatting follow MinIO's code. Inputs are pulled through a streaming decompressor (`src/compress/stream.c`) and read as CSV (the csvparser rules, as one stream), JSON (jstream's reading) or Parquet (a Thrift-compact footer reader and page decoder written for this). The response is an AWS event stream produced as the HTTP layer pulls it, so a query holds no thread while the client reads. Where MinIO is plainly wrong the deviations are listed in `docs/parity.md`.

| Phase | Deliverable | Exit gate |
|---|---|---|
| 0 ✅ | Repo, build, core runtime, HTTP server, CI script, Dockerfile | `ctest` green, fuzz corpora replay, ASan/UBSan clean |
| 1 ✅ | Single-node S3 core: streaming bodies, xl.meta v2, objects, multipart, listing, checksums, SigV2, POST policy | minio-go functional suite at 0 failures; MinIO interop both ways |
| 2 ✅ | Erasure coding, multi-drive, distributed (RPC, dsync, pools, heal, scanner, MRF), TLS | Drive and node loss with no data loss; reads MinIO-written drives |
| 3 ✅ | Operator and CRDs, K8s-aware server, kind e2e | `kubectl apply` gives a healthy 4×4 cluster; pod and PVC loss heals |
| 4 ✅ | IAM, STS, policy, LDAP, OIDC, plugins, admin API core | `mc admin user/policy/svcacct`; mint IAM |
| 5 ✅ | Versioning, object lock, tagging, CORS, quota, lifecycle, SSE-S3/KMS/C, compression | Full mint pass; ceph s3-tests at or above the MinIO baseline |
| 6 ✅ | Console (web + consoled) as its own Deployment | Playwright e2e on kind |
| 7 ✅ | Notifications (10 targets), audit, metrics v2/v3 | Target integration tests; zero metric-name diff against MinIO |
| 8 ✅ | Bucket and site replication, tiering, batch jobs, decommission, rebalance | Two-cluster and three-site e2e; mixed MinIO/Buckets replication (see below) |
| 9 ✅ | S3 Select, object lambda, SFTP/FTP, Veeam SOS, remaining admin | `docs/parity.md` at 100% |
| 10 ✅ | Performance parity (warp), fuzz soak, Helm chart | warp within 10% of MinIO or better |
