# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Kubernetes (Phase 3):
  - CRDs: `BucketsCluster` (with status and printer columns), `BucketsUser`, `BucketsPolicy` and `Bucket`.
  - `buckets-operator` in C:
    - server-side-applies a headless Service (publishing unready pods), the S3 Service, a StatefulSet per pool and PodDisruptionBudgets
    - generates root credentials that outlive the cluster
    - restarts every server together on a topology change, and rolls other changes one server at a time
    - reports status, and elects a leader on a Lease
  - Manifests: `operator/deploy/operator.yaml` (namespace, least-privilege RBAC, a 2-replica Deployment), `docker/Dockerfile.operator`, and examples, including TLS with cert-manager.
  - bucketsd:
    - reads drives from `BUCKETS_VOLUMES`/`MINIO_VOLUMES`
    - reads root credentials from `*_FILE`
    - treats endpoints whose first DNS label is the pod's hostname as local
  - Tests:
    - operator manifest unit tests
    - `tests/e2e-k8s/envtest.sh`: 34 checks against a real kube-apiserver and etcd, as the operator's own ServiceAccount
    - `tests/e2e-k8s/kind.sh`: the full kind end to end (not yet run: needs docker)
- HTTP client: chunked responses, and CA bundles given as a file.
- IAM (Phase 4, in progress):
  - The IAM policy engine, ported from minio/pkg v3.1.3 and checked against golden vectors from the Go package.
  - madmin `EncryptData`/`DecryptData` (Argon2id, AES-256-GCM or ChaCha20-Poly1305 over sio).
  - The IAM store (`src/iam/iam.c`): users, groups, policies, policy mappings, service accounts and STS credentials. They are cached in memory and stored in MinIO's `.minio.sys/config/iam` layout, so MinIO deployments carry their IAM state over. It also:
    - reloads on a timer
    - loads keys on a cache miss
    - takes per-item peer reload notifications
  - HS256/384/512 JWTs for session tokens, and `.minio.sys` config object helpers.
  - The madmin-compatible admin API (`/minio/admin/v3`) for IAM, which works with `mc admin user|group|policy|user svcacct`. It covers:
    - add-user, remove-user, list-users, user-info, set-user-status
    - update-group-members, group, groups, set-group-status
    - list-, info-, add- and remove-canned-policy, set-user-or-group-policy, and `idp/builtin/policy/attach|detach`
    - add-, update-, info-, list- and delete-service-account
    - list-access-keys-bulk, info-access-key, temporary-account-info, and `idp/builtin/policy-entities`
    - madmin encryption where MinIO uses it, and JSON errors
  - Bucket policies (`policy.BucketPolicy`):
    - parsing and evaluation, checked against 5,323 golden vectors from the Go package (`policygen bpvectors`)
    - `?policy` PUT, GET and DELETE
    - anonymous requests authorized against the policy; works with `mc anonymous`, and in both directions with MinIO
  - `mc admin info` (ServerInfo). Every server reports its own drives (state, space, inodes, pool/set/drive index) over a new peer RPC, and the answer combines them with the backend's shape and per-set capacity. Unreachable servers show as offline.
  - Peer notifications (`src/dist/peer`): IAM and bucket-metadata changes are pushed asynchronously to every other server over internode RPC, so they take effect cluster-wide at once. `cluster.sh` checks this across nodes.
  - A bucket-metadata cache (`src/bucket/metasys`): refcounted snapshots, invalidated on local writes, with a TTL in distributed mode.
  - STS `AssumeRole`:
    - SigV4 for the `sts` service, over the body's hash
    - session policies, `DurationSeconds`, and `MINIO_STS_DURATION`
    - MinIO's XML responses and errors
  - The operator reconciles `BucketsUser`, `BucketsPolicy` and `Bucket` through the cluster's admin and S3 APIs, using a SigV4-signing client with madmin encryption:
    - users, with their policies and group memberships, and policies, are applied idempotently; unchanged objects are skipped by a hash kept in status
    - a finalizer removes users and policies from the cluster when their objects are deleted; deleting a `Bucket` leaves the bucket and its data
    - `buckets.io/endpoint` overrides the service address
    - envtest now checks all of this against a real bucketsd (45 checks)
  - OpenID Connect:
    - `AssumeRoleWithWebIdentity` and `AssumeRoleWithClientGrants`, taking form or query parameters
    - `identity_openid` providers from config or env: discovery document, JWKS (RSA, EC, Ed25519, and client-secret HMAC; refetched when a key is unknown), claim-based policies with a prefix, or role-policy providers selected by `RoleArn`
    - `aud`/`azp` checks, UserInfo claims, DurationSeconds, session policies, and MinIO's parent-user derivation
    - `tests/integration/openid.sh` runs against a mock identity provider
  - HTTP plugins:
    - `policy_plugin` (and the older `policy_opa`), to which every authorization decision is delegated
    - `identity_plugin`, for `AssumeRoleWithCustomToken`, with its `idmp-` role ARN
    - Both are probed when set through `mc admin config`; `tests/integration/plugins.sh` covers them.
  - LDAP / Active Directory:
    - `src/net/ldap.c`, a compact LDAPv3 client (BER, simple bind, search, StartTLS, LDAPS) with go-ldap's filter compiler, filter escaping and DN normalization, checked against vectors generated from go-ldap (`tools/ldapvec`)
    - `identity_ldap` (`src/iam/ldapidp.c`, from MinIO's `identity/ldap` and minio/pkg `ldap`): validated against the directory on startup and on `mc admin config set`, lookup bind, user and group search with several base DNs, user attributes, SRV records, and trust in `certs/CAs`
    - `AssumeRoleWithLDAPIdentity`, with the `ldapUser`/`ldapActualUser`/`ldapUsername`/`ldapAttrib_*` claims, DurationSeconds and session policies
    - IAM's LDAP mode: policies mapped on user and group DNs (`policydb/sts-users`, `policydb/groups`), and built-in user/group changes refused as in MinIO
    - admin `idp/ldap/policy/attach|detach`, `policy-entities`, `add-service-account`, `list-access-keys` and `list-access-keys-bulk`, and LDAP handling in `set-user-or-group-policy`
    - `tests/integration/ldap.sh` runs `mc idp ldap` against a mock directory (`ldapmock.py`), over plain LDAP, LDAPS and StartTLS
  - `mc admin accesskey sts-revoke` (`revoke-tokens`, by token type or all), `mc idp openid accesskey ls` (`idp/openid/list-access-keys-bulk`), and the provider details (`userProvider`, LDAP user, OpenID config and claims) in `info-access-key`
  - `mc admin cluster iam export|import` (`export-iam`, `import-iam`, `import-iam-v2`): the zip of policies, users, groups, service accounts and mappings, with MinIO's import semantics (LDAP DN normalization included); archives move between MinIO and bucketsd in both directions (`iam-interop.sh`). `src/core/zip.c` reads and writes the archives on libdeflate, now a dependency.
  - `mc admin service restart|stop|freeze|unfreeze` (`service`, v1 and v2 responses), applied across the cluster: freeze holds S3 calls until unfreeze, restart drains and re-executes the server in place, stop drains and exits. The admin API and health probes now run on their own small worker pool, so a frozen API never blocks them (`tests/integration/service.sh`, and three new `cluster.sh` checks).
  - admin `accountinfo`: the effective policy (consoleAdmin for root or with an authorization plugin, role or claim policies, else the mapped ones), the backend layout, and the buckets the account can read or write. Usage figures and bucket feature details stay zero until the scanner and bucket metadata land.
  - `mc idp openid|ldap add|update|info|ls|rm` (the `idp-config` admin API): configuration shown without defaults or secrets, with its environment overrides, role ARNs and live state, and LDAP validation errors in MinIO's format
  - The server configuration (`src/config`), a port of MinIO's `internal/config`:
    - all 34 sub-systems, with their keys, defaults and help, generated from MinIO's own registry (`tools/configgen`)
    - set/reset validation, `MINIO_*` (and `BUCKETS_*`) environment overrides and env-defined targets, and `config.json` and history in `.minio.sys` (MinIO-compatible in both directions)
    - admin `mc admin config get|set|reset|export|import|history|restore`, and changes pushed to peers
  - Tests:
    - `tests/integration/config.sh`: `mc admin config`, with MinIO interop
    - `tests/integration/iam.sh`: the `mc admin` suite, including a restart
    - `tests/integration/iam-interop.sh`: IAM state written by real MinIO is honoured by bucketsd, and the reverse
  - S3 requests authenticate against IAM, covering users, service accounts and STS with session-token checks. Each route is authorized with MinIO's policy action, using MinIO's condition values (`getConditionValues`), including copy sources, DeleteObjects keys and POST policy uploads. Keys that are disabled or unknown before IAM loads get MinIO's error codes.

### Fixed
- The HTTP server allows 16 prefix routes (was 4, too few once internode and control routes are both present).
- The inherited policy reported for a service account now includes its parent's group policies.
- RFC 3339 parsing no longer relies on `timegm()`, which fails on macOS for Go's zero time (year 1).
- ctest now registers tests outside `tests/unit` (`enable_testing()` moved before the subdirectories).

### Changed
- PUT and GET throughput. Single-stream PUT went from 2.6–3.3× MinIO's time to MinIO's speed or better, at the MD5 floor. GET is 30–50% faster than MinIO warm and 2–4× faster cold. Details and numbers are in `docs/performance.md`.
  - MD5 and SHA-256 use OpenSSL's optimized block functions, with value-type contexts and no allocation.
  - Payload hashes run one block behind in the background, overlapping reads, parity and writes.
  - Reed-Solomon parity is computed in parallel byte ranges.
  - Large request bodies (with Content-Length) stream to the handler through a bounded pipe with socket backpressure, instead of being spooled to disk first.
  - HighwayHash has NEON and SSSE3 update loops, bit-identical to the portable one.
  - Object readers keep part files open.
  - Response streams are double-buffered.
  - On Linux, shard data syncs with `fdatasync`.
  - Reed-Solomon uses split-nibble SIMD (NEON and SSSE3). A randomized test checks it against the scalar code.
  - Multi-block PUTs hash on a dedicated thread fed through a four-buffer ring. On macOS the thread prefers a performance core.
  - Local drive writers buffer 1 MiB, and shard writes are grouped per pool task.
  - GETs copy straight out of the verified shards and read the next block ahead.
- The default drive I/O pool is the set size + 2 threads (it now also runs the payload hashes).

### Fixed
- SigV4 canonicalization of an unsigned `content-length` header used the in-memory body length, which is 0 for spooled or streamed bodies.

### Added
- `tests/bench/putget.sh`: single-stream PUT/GET timings, side by side with MinIO when `MINIO_BIN` is set.

## [0.3.0] - 2026-09-28

Phase 2: erasure coding, pools, distributed mode.

### Added
- Reed-Solomon erasure codec (GF(2^8), klauspost-compatible matrix), verified against all 60 of MinIO's erasure self-test vectors.
- MinIO ellipsis drive syntax (`/data{1...16}`, zero-padded and hex ranges), set sizing identical to MinIO's `getSetIndexes`, SipHash set selection, and CRC32 `hashOrder` shard distribution.
- A StorageAPI on local drives (ReadAll, WriteAll, CreateFile, ReadAt, RenameData, Delete, ListDir) that mirrors MinIO's, ready for remote drives.
- `format.json` negotiation across drives: fresh deployments, quorum-voted reference layouts, foreign-deployment rejection, and healing of replaced drives into their slot.
- Multi-drive erasure object layer: per-block encoding with HighwayHash bitrot, read/write quorum, bitrot detection with parity reconstruction, quorum-consistent metadata, merged listings and multipart across erasure sets. Real MinIO reads erasure sets written by Buckets, and Buckets reads MinIO's.
- `bucketsd server` accepts multiple drives and ellipsis patterns and honors `ERASURE_SET_DRIVE_COUNT` and `STORAGE_CLASS_STANDARD=EC:N` (`BUCKETS_` or `MINIO_` prefixed).
- Drive I/O thread pool (`core/pool`): metadata loads, shard hashing and writes, fsyncs, commits, deletes and shard reads now run on all drives of a set at once. `BUCKETS_IO_THREADS` sets its size (default: set size - 1). GETs from a 16-drive set run about 2x faster. The code is clean under ThreadSanitizer.
- Request handlers and response-stream pulls run on a worker pool (`BUCKETS_API_THREADS`, default 2 x CPUs, minimum 8). The event-loop thread only moves bytes, so a slow drive or request no longer stalls other clients.
- Namespace locks (`object/nslock`): object writes lock only their commit, as in MinIO. Reads hold a shared lock until EOF, and multipart parts share their upload's lock while complete and abort take it exclusively. A lock not granted in 30 s fails with `RequestTimeout`.
- Object healing (`buckets_obj_heal`, after MinIO's erasure-healing.go):
  - finds drives missing a version, or holding missing, truncated or (deep scan) bitrotten shards
  - rebuilds only those shards from the intact drives and commits them to the outdated drives
  - purges dangling versions by MinIO's `isObjectDangling` rules: offline or unreadable drives block a verdict, and corrupt shards never count
- Background healer (`heal/healer`):
  - an MRF queue fed by reads that hit a missing or rotten shard (bitrot queues a deep scan) and by writes that missed a drive
  - replaced drives are filled in the background, with a resumable tracker in `.minio.sys/buckets-healing.json`
- `tests/integration/heal.sh` covers bitrot, missing and inline repairs, an unreadable object that must not be purged, a dangling object that must be, and a replaced drive.
- Server pools (`object/pools.c`, after MinIO's erasure-server-pool.go):
  - each ellipsis argument is a pool, and a new pool joins the deployment's format
  - buckets are created on every pool
  - reads resolve the pool with the newest copy, and overwrites stay in their pool
  - new objects go to a pool picked at random, weighted by free space
  - listings merge across pools, deletes reach every pool, and multipart uploads find their pool
  - real MinIO reads an expanded deployment written by Buckets (`tests/integration/pools.sh`)
- HTTPS (OpenSSL 3), after MinIO's certs directory:
  - `--certs-dir` holds `public.crt` and `private.key`; the default is `~/.buckets/certs`, then `~/.minio/certs`
  - certificates in subdirectories are chosen by SNI
  - certificates reload when their files change, without a restart
  - TLS 1.2 minimum with MinIO's AEAD cipher suites, and `BUCKETS_CERT_PASSWD` for encrypted keys
  - certificates with explicit EC parameters are refused at startup, as Go-based MinIO does
- CMake uses the system OpenSSL 3, or builds a pinned 3.5.4 once into `.deps/`.
- `tests/integration/tls.sh` covers the above. `TLS=1` runs minio-go conformance over HTTPS: 80 pass, 0 fail.
- Distributed mode:
  - drives given as `http(s)://host:port/path` URLs, and a node recognizes its own drives by port and interface address
  - remote drives work over internode RPC (our own protocol: HTTP/1.1 under `/buckets/internode/v1/`, HMAC-authenticated, pooled, TLS-capable, on a separate worker pool)
  - dsync locks with quorum, refresh and expiry, failing fast when quorum is unreachable
  - bootstrap waits for peers, only a pool's first node formats it, and S3 answers `XMinioServerNotInitialized` until ready
  - `tests/integration/cluster.sh` runs 4 nodes, including node loss, rejoin, and loss beyond quorum; with `MINIO_BIN`, a real MinIO cluster reads the drives
  - minio-go gives 78/0 with `CLUSTER=1` and 80/0 over HTTPS
- A background scanner walks the sets each node leads and heals what it finds. `BUCKETS_SCANNER_INTERVAL` sets the cycle.
- `/minio/health/cluster` and `/cluster/read` report per-set quorum.
- `tests/integration/concurrency.sh`: racing PUTs of one key (every drive must agree), 24 parallel round trips, overwrite during a slow read, CopyObject onto itself, and parallel multipart parts.
- `tests/integration/erasure.sh`: 4- and 16-drive sets, bitrot, drive loss up to and beyond parity, drive replacement, and MinIO interop. `DRIVES=4` runs the minio-go conformance suite on an erasure set.

### Changed
- The single-drive layer is now the erasure layer with one drive (EC 1+0); on-disk output is unchanged.
- Requests with server-side encryption are refused until SSE lands (Phase 5), instead of being stored unencrypted:
  - SSE-C over plain HTTP gets `InsecureSSECustomerRequest`
  - SSE-S3/KMS gets MinIO's no-KMS `NotImplemented`
  - SSE-C keys on GET or HEAD get `InvalidRequest`
- `Location` headers use `https` on TLS connections.
- The object namespace check (a key vs. an existing prefix) runs under the object lock. Racing writers of one key could briefly see each other's directory and fail with `XMinioObjectExistsAsDirectory`.
- GetObject loads the first block before sending headers, so an object without enough intact shards gets `503 SlowDownRead` instead of a truncated `200`.

## [0.2.0] - 2026-09-27

### Changed
- The error generator splits acronym boundaries (for example `ErrMalformedPOSTRequest` becomes `BUCKETS_ERR_MALFORMED_POST_REQUEST`).
- Signed aws-chunked trailers are hashed with exactly one trailing newline, as in MinIO. minio-go already sends one.
- The storage class is stored under MinIO's lowercase `x-amz-storage-class` key, and `STANDARD` is not stored.
- Object uploads now read the body to EOF after the declared length. Extra bytes are rejected as IncompleteBody, and trailers are always consumed.
- `ListObjects` now returns real objects instead of the 0.1.0 empty placeholder.

### Added
- HighwayHash-256 (MinIO bitrot), XXH64 and XXH3-64, ported to C and verified against the Go libraries MinIO links.
- A MessagePack encoder/decoder that reproduces tinylib/msgp's exact encodings, as groundwork for xl.meta and bucket metadata.
- xl.meta v2 (format 1.3) codec: parse, serialize, version ordering, inline data, and object version encode/decode with MinIO's exact signatures. It round-trips files written by real MinIO byte for byte (`tests/data/minio-ref`).
- Single-drive object layer in MinIO's exact on-disk layout: xl.meta, bitrot-framed `part.N` files, inline data under 128 KiB, and `__XLDIR__` folder objects. Real MinIO reads drives written by Buckets, and Buckets reads MinIO's.
- S3 object APIs: PutObject, GetObject (ranges, conditional requests, response-* overrides), HeadObject, DeleteObject, DeleteObjects, CopyObject (metadata directives and copy-source conditions), and ListObjects v1/v2 with real results (prefix, delimiter, marker, continuation token, url encoding).
- Multipart uploads: Create, UploadPart, UploadPartCopy (with ranges), ListParts, Complete (ETag = md5-of-md5s-N), Abort, and ListMultipartUploads, in MinIO's `.minio.sys/multipart` layout.
- S3 additional checksums (CRC32, CRC32C, CRC64NVME, SHA1, SHA256):
  - via headers or aws-chunked trailers
  - verified before commit and stored in MinIO's `x-minio-internal-crc` format
  - returned with `x-amz-checksum-mode: ENABLED`
  - multipart composite (`-N`) and full-object checksums, merged with CRC combination
  - real MinIO reports identical values for objects Buckets wrote
- AWS Signature V2 (header and presigned), verified against AWS's published examples.
- `partNumber` on GET/HEAD (206, `x-amz-mp-parts-count`, per-part checksums).
- GetObjectAttributes (ETag, Checksum, ObjectParts, StorageClass, ObjectSize).
- POST-policy browser uploads:
  - multipart/form-data parsed as a stream
  - V4 and V2 policy signatures
  - MinIO's condition rules and exact failure messages
  - `content-length-range`
  - checksum form fields
  - `success_action_redirect` and `success_action_status`
- Bucket and object ACL APIs: canned `private` only, as in MinIO.
- `ListObjectsV2` with `metadata=true` (MinIO's ListObjectsV2M extension).
- `tests/conformance/minio-go.sh` runs minio-go's functional suite (mint's Go suite). Current result: 78 pass, 0 fail, 24 not implemented (versioning, tagging, CORS, policies and notifications come in later phases).
- `tests/integration/interop.sh`: round trips through `mc` and a real MinIO build in both directions. `tools/build-oracles.sh` builds the oracles.
- aws-chunked uploads: signed chunks (chained chunk signatures), signed trailers, and unsigned trailers.
- HTTP request bodies over 1 MiB spool to disk (up to 5 TiB), and responses stream from the object reader.
- Bucket metadata (`.minio.sys/buckets/<b>/.metadata.bin`), byte-compatible with MinIO. It is written on CreateBucket, used for ListBuckets creation dates, and removed on DeleteBucket.
- `tools/golden`, a Go program that generates reference vectors (`tests/unit/golden_vectors.inc`) from those libraries.

## [0.1.0] - 2026-09-27

### Added
- Repository scaffolding:
  - CMake build with pinned dependencies (llhttp, yyjson, cmocka)
  - strict warnings, and sanitizer builds via `BUCKETS_SANITIZE`
  - `scripts/ci.sh` gate
  - distroless `docker/Dockerfile.bucketsd`
- Core runtime: buffers, string slices, S3 time formats, Go-compatible query parsing, JSON-lines logging, UUIDs, and an epoll/kqueue event loop.
- HTTP/1.1 server:
  - keep-alive and pipelining
  - `Expect: 100-continue`
  - idle timeouts
  - 413 and 400 handling
  - correct half-close behavior
  - graceful drain on SIGTERM
- Crypto: SHA-256, HMAC-SHA256, MD5, base64 and constant-time compare, tested against NIST and RFC vectors.
- AWS Signature V4 for signed headers and presigned URLs, with MinIO's exact parsing and error semantics:
  - region and service checks
  - 15-minute clock skew
  - presign expiry
  - `Content-MD5` and `x-amz-content-sha256` payload verification
- S3 error table generated from MinIO's `cmd/api-errors.go` (327 codes) by `scripts/gen-s3-errors.py`.
- Strict XML reader that rejects DOCTYPE, entities and CDATA and limits nesting depth, plus an escaping XML writer.
- Single-drive storage with a MinIO-compatible `.minio.sys/format.json` (`xl-single`), and bucket volumes.
- `bucketsd server [--address HOST:PORT] DIR`, with `BUCKETS_*` configuration and `MINIO_*` fallbacks.
- S3 handlers:
  - ListBuckets, CreateBucket (with LocationConstraint), HeadBucket, DeleteBucket
  - GetBucketLocation
  - GetBucketVersioning (always unversioned)
  - ListObjects v1 and v2 (validated parameters, empty results until the object layer exists)
- Health endpoints `/minio/health/*`, also served under `/buckets/health/*`.
- Unit tests, fuzz harnesses (SigV4, XML) with seed corpora, and an end-to-end smoke test driven by curl's SigV4 signer.
- `docs/architecture.md`, and `docs/parity.md` generated from MinIO's routers (222 handlers tracked).
