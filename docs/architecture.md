# Buckets architecture

Buckets is a C17 rewrite of MinIO's last public release (`RELEASE.2025-10-15T17-29-55Z`, archived April 2026). It is built to run natively on Kubernetes, and the web console is a separate deployment from the storage servers.

The MinIO source at that tag is the behavioral spec. Each subsystem below names the Go code it replaces. `docs/parity.md` tracks every API handler.

## Deployables

```
                        ┌──────────────────────────── Kubernetes namespace ───────────────────────────┐
  browser ──Ingress──▶  │ buckets-console (Deployment)            buckets-operator (Deployment)       │
                        │  ├─ nginx: React SPA                     watches BucketsCluster, BucketsUser,│
                        │  └─ consoled (C BFF): sessions,          BucketsPolicy, Bucket CRs           │
                        │     SigV4-signs S3/admin calls ─┐        reconciles everything below         │
                        │                                 ▼                                            │
  S3 clients ─Ingress─▶ │ Service <cluster>  ──▶  StatefulSet per pool: bucketsd ×N (PVCs per drive)   │
                        │                          headless Service for peer DNS + internode RPC       │
                        └──────────────────────────────────────────────────────────────────────────────┘
```

- **`bucketsd`** is the storage server. It serves the S3, admin, STS and metrics APIs, internode RPC, the background services (scanner, heal, ILM, replication, notifications), and SFTP/FTP. There is one StatefulSet per server pool.
- **`buckets-operator`** is written in C. It uses the Kubernetes REST API directly (libcurl plus watch streams) and handles:
  - reconciling the `buckets.io/v1alpha1` CRDs
  - pool expansion
  - rolling upgrades paced by `/minio/health/cluster`
  - decommissioning
  - TLS
  - leader election through a Lease
- **`buckets-console`** is stateless and scales independently of storage. It never touches drives: it only talks to `bucketsd` over the S3 and admin APIs, like any other client.

## `bucketsd` layers

```
cmd/bucketsd     argument/env config, signals, graceful drain
s3/              router, SigV4/V2/presign/streaming/POST-policy auth, handlers, XML, error table
admin/ iam/ ...  admin API, IAM/STS, bucket features, ILM, replication, notify, metrics, select
object/          object layer: server pools → erasure sets → quorum reads/writes, multipart, listing
erasure/         Reed-Solomon (ISA-L), bitrot (HighwayHash), xl.meta v2, format.json
storage/         one local drive: volumes, xl.meta + part files, atomic renames, fsync discipline
dist/            internode RPC (multiplexed msgpack over TLS), dsync locks, peer notifications
net/  core/      HTTP/1.1 server (llhttp), event loop (epoll/kqueue, io_uring planned), buffers, logging
```

## Compatibility contract

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

## Current state (0.1.0)

**Built:**
- core runtime: buffers, strings, time formats, query parsing, JSON logging, and an epoll/kqueue event loop
- HTTP/1.1 server with keep-alive, pipelining, `Expect: 100-continue`, idle timeouts, and graceful drain on SIGTERM
- SigV4 authentication for signed headers and presigned URLs, verified against AWS's published vectors and curl's independent signer
- payload checks for `Content-MD5` and `x-amz-content-sha256`
- MinIO's full generated error table
- a strict XML reader that refuses DOCTYPE and entities
- single-drive storage with a MinIO-compatible `format.json`
- bucket operations: ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation, and GetBucketVersioning (always unversioned)
- empty ListObjects v1 and v2 responses
- MinIO health endpoints

**Known interim choices, each replaced in a later phase:**
- SHA-256, MD5 and HMAC are portable C. The macOS dev toolchain has no OpenSSL, and TLS arrives with OpenSSL 3 in Phase 2. Payload hashing will then move to multi-buffer SIMD.
- Request bodies are buffered in memory, up to 64 MiB. Streaming bodies come before PutObject and UploadPart.
- Handlers run on the event-loop thread with blocking disk I/O. A disk thread pool, then io_uring, arrives with the object layer.
- Bucket creation time is the directory's mtime, as in MinIO's `StatVol`. `.metadata.bin` bucket metadata lands with bucket features.
- Only the root credential is accepted. IAM comes in Phase 4.

## Build phases

| Phase | Deliverable | Exit gate |
|---|---|---|
| 0 ✅ | Repo, build, core runtime, HTTP server, CI script, Dockerfile | `ctest` green, fuzz corpora replay, ASan/UBSan clean |
| 1 🚧 | Single-node S3 core: streaming bodies, xl.meta v2, objects, multipart, listing, checksums | `mint` core suites (awscli, aws-sdk-go, minio-go, mc, s3cmd) |
| 2 | Erasure coding, multi-drive, distributed (RPC, dsync, pools, heal, scanner, MRF), TLS | Drive and node loss with no data loss; reads MinIO-written drives |
| 3 | Operator and CRDs, K8s-aware server, kind e2e | `kubectl apply` gives a healthy 4×4 cluster; pod and PVC loss heals |
| 4 | IAM, STS, policy, LDAP, OIDC, plugins, admin API core | `mc admin user/policy/svcacct`; mint IAM |
| 5 | Versioning, object lock, tagging, CORS, quota, lifecycle, SSE-S3/KMS/C, compression | Full mint pass; ceph s3-tests at or above the MinIO baseline |
| 6 | Console (web + consoled) as its own Deployment | Playwright e2e on kind |
| 7 | Notifications (10 targets), audit, metrics v2/v3 | Zero metric-name diff against MinIO |
| 8 | Bucket and site replication, tiering, batch jobs, decommission, rebalance | Two-cluster and three-site e2e |
| 9 | S3 Select, object lambda, SFTP/FTP, Veeam SOS, remaining admin | `docs/parity.md` at 100% |
| 10 | Performance parity (warp), fuzz soak, Helm chart | warp within 10% of MinIO or better |
