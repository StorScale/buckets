# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Bucket notifications (Phase 7, in progress):
  - `?notification` GET and PUT with MinIO's validation and error order (unknown ARNs, regions, event names, filter rules, overlapping queues, topics and lambdas), stored in the bucket metadata as MinIO stores it; queues whose target is gone are left out when read back.
  - Events from every handler MinIO sends them from: Put, Post, Copy, CompleteMultipartUpload, Get, Head, GetObjectAttributes, tagging put and delete, retention and legal hold put and get, Delete, DeleteMarkerCreated, NoOP deletes, DeleteObjects, BucketCreated and BucketRemoved. Records match MinIO's byte for byte (field order, Go's JSON escaping, the escaped key for targets, userMetadata as cleanMetadata leaves it, content-length only where MinIO's handler had written the response).
  - The webhook target (`notify_webhook`: endpoint, auth_token, queue_dir, queue_limit, client_cert/client_key), with a worker per target and MinIO's queue store: `<queue_dir>/minio-webhook-<id>/<uuid>.event` files kept until delivered, retried every 3s, replayed after restarts; stores are interchangeable with MinIO's in both directions (batched and S2-compressed entries are read too). Targets are rebuilt when a `notify_*` subsystem changes, and `config set` validates them.
  - ListenNotification and ListenBucketNotification (`GET /?events=` and `GET /bucket?events=`, with prefix, suffix and ping), streamed as chunked `text/event-stream`: the HTTP server now sends chunked responses for streams of unknown length. Single server for now; listening across a cluster's peers comes later.
  - `x-minio-origin-endpoint` from `MINIO_SERVER_URL` (or `BUCKETS_SERVER_URL`), else the listen address, else the local IPv4 address MinIO would pick.
  - `tests/integration/notify-interop.sh` diffs MinIO and bucketsd (S3 transcript, webhook deliveries, both kinds of listener); `tests/integration/notify-store.sh` hands queue stores between them.

### Fixed
- Requests with `.` or `..` path segments in a query value (other than `delimiter`), or an invalid or reserved bucket name, are now rejected before authentication and without `BucketName`/`Key` in the error, as MinIO's request validity filter does.

## [0.6.0] - 2026-09-28

Phase 6: the web console as its own Deployment. Verified here with the
Playwright suite (11 tests) against bucketsd and consoled, also under
ASan/UBSan, and `tests/integration/console.sh` (31 checks). The gate's kind
run (`tests/e2e-k8s/kind.sh`, which now deploys the console and runs the
same Playwright suite through it) needs Docker and kind and has not been run
in this environment yet, like the Phase 3 kind check.

### Added
- The web console (Phase 6), deployed apart from storage:
  - `consoled` (`src/console`, `src/cmd/consoled`): serves the SPA and logs users in by exchanging their keys for STS credentials at bucketsd (AssumeRole), kept in an AES-256-GCM cookie keyed by PBKDF2 of `CONSOLE_PBKDF_PASSPHRASE`/`SALT` (MinIO console's names; replicas share it). The SPA's S3 and admin calls go through a SigV4-signing proxy to bucketsd (`/api/v1/s3/*`, `/api/v1/admin/*`), streaming uploads (UNSIGNED-PAYLOAD) and downloads, with madmin encryption of admin bodies and replies done server side. Unsafe requests need `X-Console-Request`, cookies are HttpOnly and SameSite=Strict, pages carry a strict CSP.
  - `console/web`: React 18 + TypeScript + Vite SPA: dashboard (servers, drives, usage), buckets, an object browser (folders, uploads with progress, downloads, bulk and recursive deletes, versions, object metadata and tags), bucket settings (versioning, quota, tags, access policy with presets, default encryption, object lock retention, lifecycle), users, groups, policies, access keys (service accounts, secret shown once) and configuration by subsystem.
  - Playwright end-to-end suite (`console/web/e2e`, 11 tests) against a real bucketsd and consoled, in `scripts/ci.sh` under ASan/UBSan.
  - The operator deploys it from `spec.console` (`enabled`, `replicas`, `image`, `serviceType`, `resources`, `ingress` with host, class, TLS and annotations): a `<name>-console` Deployment (non-root, read-only root filesystem, trusting the cluster CA under TLS), Service and Ingress, and a generated cookie-key Secret; console pods never match the storage Service. Disabling it removes them. `docker/Dockerfile.console` builds the image; `tests/e2e-k8s/kind.sh` runs the Playwright suite against the console on kind.
  - OpenID sign-in: the authorization code flow against the provider of `BUCKETS_CONSOLE_OIDC_CONFIG_URL` (or `MINIO_IDENTITY_OPENID_*`), with state and nonce in a short-lived encrypted cookie, then AssumeRoleWithWebIdentity with the ID token; provider and storage errors come back to the sign-in page. Tested against `tests/integration/oidcmock.py` with curl and in the browser.
  - LDAP sign-in (AssumeRoleWithLDAPIdentity, offered when `CONSOLE_LDAP_ENABLED` is on), share links (presigned GETs at `BUCKETS_CONSOLE_S3_URL`, as long as the session lasts and at most 7 days), inline preview of images and small text objects, and object retention and legal hold in buckets with object locking.
  - `tests/integration/console.sh` (no browser needed): key, LDAP and OpenID sign-in against the mocks, the signed proxy (a 20 MiB streamed round trip, encrypted admin calls), share links, CSRF and sessions; in CI under ASan/UBSan.
  - libbuckets gains a streaming HTTP client and a SigV4 request signer and presigner (`src/s3/sign.c`).

## [0.5.0] - 2026-09-28

Phase 5: versioning, object lock, tagging, CORS, quotas, lifecycle expiry,
SSE-S3/SSE-KMS/SSE-C with the builtin KMS, and compression. Gate: mint over
HTTPS 149 PASS / 0 FAIL (with and without compression), and ceph s3-tests
(`tests/conformance/s3-tests.sh`, same harness for both) 324 passed against
MinIO RELEASE.2025-10-15's 315, with no test that MinIO passes failing.

### Added
- Bucket versioning (Phase 5):
  - `?versioning` GET/PUT with MinIO's excluded-prefix and exclude-folders extensions; object lock prevents suspending
  - versioned PUT, CopyObject and CompleteMultipartUpload create new versions; suspended buckets replace the "null" version
  - DeleteObject and DeleteObjects create delete markers (with a new version ID, or "null" when suspended), or remove a version for good by `versionId`, with MinIO's response headers and `DeleteMarker`/`DeleteMarkerVersionId` results
  - GET/HEAD/GetObjectAttributes of a delete marker: NoSuchKey (or MethodNotAllowed by version ID) with the marker's headers
  - `ListObjectVersions` (`?versions`), with key and version-id markers, delimiters and `metadata=true`
  - delete markers on disk are byte-compatible with MinIO's `xlMetaV2DeleteMarker`; `tests/integration/versioning-interop.sh` moves versioned buckets between MinIO and bucketsd both ways
- Object lock (Phase 5):
  - `X-Amz-Bucket-Object-Lock-Enabled` on CreateBucket (turns on versioning), and `?object-lock` GET/PUT with default GOVERNANCE/COMPLIANCE retention in days or years
  - `?retention` and `?legal-hold` GET/PUT on objects, updating the version's metadata in place, and the `x-amz-object-lock-*` headers on PUT, CopyObject and CreateMultipartUpload
  - locked versions refuse deletion unless governance is bypassed with `x-amz-bypass-governance-retention` and the matching permission; COMPLIANCE can only be extended
  - retention and legal hold are stored under MinIO's metadata keys, so locks carry over between the two servers
- Tagging (Phase 5):
  - object `?tagging` GET/PUT/DELETE, per version, stored in the version's `X-Amz-Tagging` metadata as MinIO does
  - bucket `?tagging` GET/PUT/DELETE, stored as the bucket metadata's `TaggingConfigXML`
  - `X-Amz-Tagging` validated on PutObject and CreateMultipartUpload (minio-go's rules: 10 object / 50 bucket tags, key and value charset and lengths, duplicates), the `tagging` field of POST policy uploads, and `x-amz-tagging-directive` COPY/REPLACE on CopyObject
  - `x-amz-tagging-count` on GET/HEAD (plus the tags themselves with MinIO's `X-Amz-Tagging-Directive: ACCESS`), and `UserTags` in `metadata=true` listings
- CORS: the global middleware MinIO runs (rs/cors with `api cors_allow_origin`): preflights answered with 204 and the requested method and headers, `Access-Control-Allow-Origin`/`-Expose-Headers`/`-Allow-Credentials` on allowed origins.
- MinIO's fixed sub-resources: bucket `?cors` (NoSuchCORSConfiguration / NotImplemented), `?website`, `?accelerate`, `?requestPayment`, `?logging` and `?policyStatus` (public when the bucket policy lets anyone list and write); the rejected GETs (`?inventory`, `?metrics`, `?publicAccessBlock`, `?ownershipControls`, `?intelligent-tiering`, `?analytics`) and object `?torrent` / DELETE `?acl` answer NotImplemented without naming the bucket, as MinIO does.
- Bucket quotas (Phase 5): `mc quota set|info|clear` (admin `set-bucket-quota` / `get-bucket-quota`, stored as the bucket metadata's `QuotaConfigJSON`), enforced as MinIO's hard quota on PutObject, CopyObject, UploadPart and UploadPartCopy, counting the bucket's size from the latest data usage (refreshed every 10s).
- Data scanner and data usage: the scanner moved out of the healer into `src/scanner/`. Each cycle the cluster leader walks every version, counts objects, versions, delete markers, sizes and MinIO's size and version histograms per bucket, and stores them as MinIO's `DataUsageInfo` in `.minio.sys/buckets/.usage.json` (with `.bkp` every tenth time and the `.bloomcycle.bin` cycle counter); every node still heals the objects of the sets it leads. The cycle follows `scanner speed` (`MINIO_SCANNER_SPEED`; `BUCKETS_SCANNER_INTERVAL` still overrides it). Admin `datausageinfo` serves the stored usage.
- Lifecycle expiry (Phase 5): bucket `?lifecycle` GET/PUT/DELETE with MinIO's parser, validation and error mapping (every rule element, including And/Tag/size filters, ExpiredObjectAllVersions, DelMarkerExpiration and NewerNoncurrentVersions), stored as MinIO's marshalled `LifecycleConfigXML` with `ExpiryUpdatedAt`; `withUpdatedAt`. The scanner applies Expiration, NoncurrentVersionExpiration, ExpiredObjectDeleteMarker, ExpiredObjectAllVersions and DelMarkerExpiration as MinIO's evaluator does (object lock respected). `x-amz-expiration` is predicted on GET, HEAD, PUT, CopyObject and CompleteMultipartUpload. Transition rules wait for tiering (Phase 8): their storage class is refused as unknown, as MinIO does without that tier.
- KMS APIs (Phase 5): `/minio/kms/v1` status, metrics (request counters and latency histogram), apis, version, key create/list/status, and the admin v3 `kms/status`, `kms/key/create`, `kms/key/status` that `mc admin kms` uses, over the builtin KMS, with MinIO's responses and errors.
- Bucket default encryption (Phase 5): `?encryption` GET/PUT/DELETE with MinIO's parser and errors (a KMS key is test-generated before it is accepted), stored as `EncryptionConfigXML`; writes that ask for no encryption (PutObject, CopyObject, CreateMultipartUpload, POST uploads) get the bucket's SSE-S3 or SSE-KMS default, or SSE-KMS with the default key under `MINIO_KMS_AUTO_ENCRYPTION`. POST policy uploads honor SSE form fields.
- SSE-C (Phase 5): customer-key encryption over TLS on every path above, with copy-source keys for encrypted sources; GetObjectAttributes and `x-amz-checksum-mode` unseal the stored checksums of encrypted objects and report plaintext sizes. mint over HTTPS: 149 PASS, 0 FAIL (the NA tests are CORS, S3 zip and notifications).
- Encrypted multipart uploads (Phase 5): CreateMultipartUpload with SSE-S3/SSE-KMS seals the object key into the upload; each part is DARE-encrypted with its part key and MinIO's derived nonce, recording the sealed plaintext MD5, plaintext size and checksum; ListParts, UploadPart responses and CompleteMultipartUpload use the client-visible part ETags (unsealed for SSE-S3), and the final checksum is sealed. UploadPartCopy into an encrypted upload encrypts the copied range. Reads decrypt across parts with per-part keys.
- Server-side encryption (Phase 5), single-part objects and copies: SSE-S3 and SSE-KMS (builtin KMS; key ID, ARN and encryption context) on PutObject, GET/HEAD with ranges across DARE packages, ListObjects/Versions with plaintext sizes and ETags (and the encryption entry in `metadata=true` listings), CopyObject between any mix of encrypted and plain objects (re-encrypting onto itself included) and UploadPartCopy from encrypted sources. Stored exactly as MinIO stores them (sealed keys in system metadata, sealed ETags, encrypted checksums); `tests/integration/sse-interop.sh` moves encrypted objects between MinIO and bucketsd both ways. Request validation and errors follow MinIO (InvalidArgument for bad SSE headers on writes, BadRequest for SSE-S3/KMS headers on reads, `kms:KeyNotFound`).
- Encryption groundwork (Phase 5): DARE 2.0 streams (`src/crypto/dare.c`, byte-for-byte with minio/sio), object keys with MinIO's key derivation, sealing, part keys and ETag sealing (`src/crypto/objkey.c`), and the builtin KMS of `MINIO_KMS_SECRET_KEY` / `_FILE` (`src/kms/`) with `kms.Context` marshalling; unit tests use vectors produced by MinIO's own `internal/crypto` and `internal/kms`.
- Object compression (Phase 5): the `compression` config subsystem (`enable`, `allow_encryption`, `extensions`, `mime_types`, with MinIO's environment variables and legacy names) and MinIO's rules for what qualifies (never the standard compressed extensions and content types; encrypted writes, bucket defaults included, only with `allow_encryption`; single writes over 4 KiB). Qualifying PutObject, CopyObject and multipart parts are stored as S2 streams (`klauspost/compress/s2` in `X-Minio-Internal-compression`, the plaintext size in `X-Minio-Internal-actual-size` and the part records), with an S2 index for each part over 8 MiB (`PartIdx` in xl.meta). Encrypted objects compress before they encrypt, with streams padded to 256 bytes and indexes sealed with the object key. Reads decompress, using the index to start ranges near their offset; sizes in HEAD, listings, ListParts, GetObjectAttributes and data usage are the plaintext sizes. `tests/integration/compress-interop.sh` moves compressed objects (with and without SSE, single and multipart, with indexes) between MinIO and bucketsd both ways, and `scenarios/compress.json` matches MinIO line for line. mint with compression on: 149 PASS, 0 FAIL.
- S2 codec (`src/compress/s2.c`): block encoder and decoder, the stream format with CRCs, padding, concatenated streams and snappy-framed input, and the stream index; the encoder is byte-for-byte klauspost's pure-Go `encodeBlock` (unit tests use vectors from klauspost/compress v1.20.1), with a `fuzz_s2` target for blocks, streams and indexes.
- xl.meta `PartIdx` and part records' `i` field, and puts of unknown size in the object layer (compressed streams).
- A ListMultipartUploads without a prefix answers from the node's cache of uploads it started (MinIO's `mpCache`), dropped on complete, abort or after a day.
- `tests/integration/s3diff.sh`: runs request scenarios against real MinIO and bucketsd and diffs the normalized responses (`scenarios/{versioning,objectlock,uploads,tagging,subresources,quota,usage,lifecycle,sse,kms,compress}.json` match line for line, a `NAME.env` file sets server environment and `repeat` builds large bodies; admin JSON errors are normalized too, and a `sleep` step waits for the scanner); `tests/integration/usage.sh` covers usage-based quotas.; it signs requests itself, since curl's `--aws-sigv4` misorders `x-amz-tagging` and `x-amz-tagging-directive`.

### Changed
- XML escaping follows Go's `xml.EscapeText` (`&#34;`, `&#39;`), and S3 timestamps in XML carry milliseconds, as MinIO's do.
- DeleteObjects requires Content-MD5 or an `x-amz-checksum-*` header and verifies it (`MissingContentMD5`, `BadDigest`), as MinIO does.
- HEAD error responses have no body.
- Emptiness checks for bucket deletion count every version and delete marker.
- Bucket configuration documents keep the `xmlns` of the document that was PUT, as MinIO does.
- ListMultipartUploads matches MinIO: uploads oldest first, paging by `upload-id-marker` with `NextUploadIdMarker` and `IsTruncated`, the 10000 default, `EncodingType` echoed, and empty Initiator/Owner/StorageClass.

### Fixed
- Found by ceph s3-tests against MinIO:
  - listings put a directory object (`a/`) before the keys under it, so paged version listings no longer skip it (bucket cleanup failed with BucketNotEmpty)
  - an empty `delimiter` is not echoed in ListObjects V1/V2
  - PutObject, CreateMultipartUpload and CompleteMultipartUpload honor `If-Match` / `If-None-Match` against the current version (PreconditionFailed; NoSuchKey for an If-Match on a missing key), as MinIO's checkPreconditionsPUT does
  - `response-content-type` and the other response overrides replace the header instead of adding a second value
  - a presigned URL with `X-Amz-Expires=0` has expired
  - requests wait for a namespace lock as long as MinIO's globalOperationTimeout allows (5 minutes, `BUCKETS_LOCK_TIMEOUT` to override) instead of 30 seconds, so a write outlasts a reader that stalls mid-download (dropped after 60 seconds) as it does on MinIO
  - `x-amz-copy-source` splits its query at the first literal `?` before decoding, so keys with an encoded `?` (or ` `) and version IDs copy correctly
- A client that stops reading a response no longer holds it (and the object's read lock, blocking every writer of that key) forever: a response that makes no progress for 60 seconds is closed (found by ceph s3-tests).
- An unsatisfiable range answers MinIO's InvalidRange (the range and `ActualObjectSize`/`RangeRequested` in the document, no `Content-Range`), and a malformed one fails before the object is looked up.
- An `x-amz-checksum-algorithm` header without a checksum value asks for nothing (getContentChecksum); bucketsd computed and stored one.
- GetObjectAttributes reports the stored size of each part of an encrypted object, as MinIO does (the object size stays the plaintext one).
- Encrypted (and compressed) writes of a known size read to the end of the body, so trailing checksums of aws-chunked uploads are seen; a longer body fails.
- test_dare read past a short stream's buffer (ASan).
- ListParts follows MinIO: 10000 parts by default and at most, NextPartNumberMarker only when truncated, the owner ID as display name, and ChecksumAlgorithm/ChecksumType always present.
- A completed multipart object records the sum of its parts' actual (plaintext) sizes, and internal (`x-minio-internal-*`) upload metadata is stored as system metadata and carried to the object, as in MinIO.
- s3diff passes request bodies through a file, so large parts fit.
- UploadPartCopy ranges follow MinIO: an unparsable range is InvalidCopyPartRange and one past the source's end InvalidCopyPartRangeSource (it was clamped), and errors name the source object.
- DELETE without a version ID on a key that never existed, in a versioned or suspended bucket, stores no delete marker (MinIO's DeleteObject); DeleteObjects still reports one, as MinIO does.
- Shutdown no longer frees the object layer under the IAM loader, its periodic refresh or the LDAP sync thread: they sleep on a condition variable and are joined first (an ASan use-after-free in the cluster test).
- PUT, DELETE and HEAD on a bucket with an unrecognized query go to CreateBucket, DeleteBucket and HeadBucket, like MinIO's catch-all routes, instead of NotImplemented; `?acl` and `?policy` only take the methods MinIO routes to them.
- `metadata=true` listings report each object's real erasure data and parity counts in `Internal`, not 1/0.
- Errors from CopyObject after the source is authorized name the source bucket and key, as MinIO's do.
- `encoding-type=url` listings encode keys as MinIO does (space as `+`, `*` kept, `~` escaped).

## [0.4.0] - 2026-09-28

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
  - `AssumeRoleWithCertificate` (identity_tls, enabled by `MINIO_IDENTITY_TLS_ENABLE`): the TLS server asks for (never requires) a client certificate; it must be the only leaf, verify for client authentication against the system roots and `certs/CAs` (or carry the clientAuth usage with `skip_verify`), and its CN names the policy of the `tls/<CN>` credentials, whose expiry never outlives the certificate (`tests/integration/certsts.sh`).
  - LDAP / Active Directory:
    - `src/net/ldap.c`, a compact LDAPv3 client (BER, simple bind, search, StartTLS, LDAPS) with go-ldap's filter compiler, filter escaping and DN normalization, checked against vectors generated from go-ldap (`tools/ldapvec`)
    - `identity_ldap` (`src/iam/ldapidp.c`, from MinIO's `identity/ldap` and minio/pkg `ldap`): validated against the directory on startup and on `mc admin config set`, lookup bind, user and group search with several base DNs, user attributes, SRV records, and trust in `certs/CAs`
    - `AssumeRoleWithLDAPIdentity`, with the `ldapUser`/`ldapActualUser`/`ldapUsername`/`ldapAttrib_*` claims, DurationSeconds and session policies
    - IAM's LDAP mode: policies mapped on user and group DNs (`policydb/sts-users`, `policydb/groups`), and built-in user/group changes refused as in MinIO
    - admin `idp/ldap/policy/attach|detach`, `policy-entities`, `add-service-account`, `list-access-keys` and `list-access-keys-bulk`, and LDAP handling in `set-user-or-group-policy`
    - an hourly sync (MinIO's purgeExpiredCredentialsForLDAP and updateGroupMembershipsForLDAP) removes the credentials of users gone from the directory and updates the groups of the rest
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
