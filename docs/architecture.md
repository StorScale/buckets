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

## Current state (0.2.0)

Single-node S3 is feature-complete for the core API. It is verified three ways:
- **Conformance:** minio-go's functional suite (the Go suite inside MinIO's `mint`) gives 78 pass, 0 fail. The other 24 tests need later-phase features.
- **On-disk compatibility:** a real MinIO build (`tests/integration/interop.sh`) reads what Buckets wrote, and Buckets reads what MinIO wrote. That covers single PUT, streaming PUT, multipart, checksums, folder objects, metadata and bucket creation times.
- **Byte-level fixtures:** `tests/data/minio-ref` holds files written by MinIO, and `xl.meta` and `.metadata.bin` round-trip byte for byte.

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

**Phase 2 so far (erasure, multi-drive):**
- Reed-Solomon codec, ellipsis drive syntax and set sizing identical to MinIO, SipHash set selection and `hashOrder` shard placement.
- `format.json` negotiation across drives, including healing a replaced drive into its slot.
- Erasure object layer with read/write quorum, bitrot detection and parity reconstruction. It covers puts, gets, listings and multipart across sets.
- `tests/integration/erasure.sh`: 4- and 16-drive sets, drive loss up to and beyond parity, and MinIO reading Buckets-written sets. minio-go conformance also passes on a 4-drive set (`DRIVES=4`).
- A drive I/O thread pool fans each operation out across the drives of a set.
- Request handlers run on worker threads, with MinIO-style namespace locks keeping concurrent writers consistent.
- Object healing, an MRF queue for heal-on-read and partial writes, and background healing of replaced drives.
- Still to come in Phase 2: multiple pools, distributed mode (internode RPC, remote drives, dsync locks), and TLS.

**Known interim choices, each replaced in a later phase:**
- One event-loop thread moves bytes for all connections. Handlers and stream pulls run on a worker pool, and each fans out per-drive work to the drive I/O pool. Request bodies are still spooled synchronously on the loop thread. Multiple reactors, then io_uring, follow.
- Crypto primitives (SHA-256, MD5, SHA-1, HighwayHash, CRCs) are portable C, and all are verified against MinIO's Go libraries. SIMD and OpenSSL come later, with TLS in Phase 2.
- Only the root credential is accepted. IAM comes in Phase 4.
- Buckets are unversioned. Versioning, object lock, tagging and SSE come in Phase 5.

## Build phases

| Phase | Deliverable | Exit gate |
|---|---|---|
| 0 ✅ | Repo, build, core runtime, HTTP server, CI script, Dockerfile | `ctest` green, fuzz corpora replay, ASan/UBSan clean |
| 1 ✅ | Single-node S3 core: streaming bodies, xl.meta v2, objects, multipart, listing, checksums, SigV2, POST policy | minio-go functional suite at 0 failures; MinIO interop both ways |
| 2 🚧 | Erasure coding, multi-drive, distributed (RPC, dsync, pools, heal, scanner, MRF), TLS | Drive and node loss with no data loss; reads MinIO-written drives |
| 3 | Operator and CRDs, K8s-aware server, kind e2e | `kubectl apply` gives a healthy 4×4 cluster; pod and PVC loss heals |
| 4 | IAM, STS, policy, LDAP, OIDC, plugins, admin API core | `mc admin user/policy/svcacct`; mint IAM |
| 5 | Versioning, object lock, tagging, CORS, quota, lifecycle, SSE-S3/KMS/C, compression | Full mint pass; ceph s3-tests at or above the MinIO baseline |
| 6 | Console (web + consoled) as its own Deployment | Playwright e2e on kind |
| 7 | Notifications (10 targets), audit, metrics v2/v3 | Zero metric-name diff against MinIO |
| 8 | Bucket and site replication, tiering, batch jobs, decommission, rebalance | Two-cluster and three-site e2e |
| 9 | S3 Select, object lambda, SFTP/FTP, Veeam SOS, remaining admin | `docs/parity.md` at 100% |
| 10 | Performance parity (warp), fuzz soak, Helm chart | warp within 10% of MinIO or better |
