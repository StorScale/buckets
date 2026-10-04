# Buckets

S3-compatible object storage written in C, built to run natively on Kubernetes. It is a rewrite of MinIO's last public release (`RELEASE.2025-10-15T17-29-55Z`; the upstream project was archived in April 2026).

**Status: 1.1.1. All build phases are done:** Buckets implements 220 of MinIO's 222 API handlers (the other two are dropped on purpose) in MinIO's exact on-disk format, on anything from one drive to multi-pool clusters of nodes:
- erasure coding, bitrot protection and healing; survives drive and node loss
- IAM, STS, and sign-in with LDAP or OpenID Connect (Microsoft Entra ID with app roles is in use)
- versioning, object lock, lifecycle, SSE with KMS, compression, replication, tiering, batch jobs, S3 Select, SFTP/FTP
- a Kubernetes operator and a web console deployed apart from storage
- `buckets-kes`, a KES-compatible key server keeping keys in HashiCorp Vault, AWS Secrets Manager, Azure Key Vault or Google Secret Manager

Real MinIO and Buckets can serve each other's drives, clusters included.

| Document | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Components, layers, the compatibility contract, build phases |
| [docs/parity.md](docs/parity.md) | Every MinIO API handler and its status |
| [docs/migration.md](docs/migration.md) | Moving a MinIO deployment to Buckets in place, KES included, and back |
| [docs/identity.md](docs/identity.md) | Sign-in with Microsoft Entra ID (or another OpenID provider) and role-based access |
| [docs/encryption.md](docs/encryption.md) | Setting up the KMS in the console: KES with Vault, AWS, Azure or Google |
| [docs/performance.md](docs/performance.md) | Benchmarks against MinIO and how to run them |
| [docs/roadmap.md](docs/roadmap.md) | What comes next, and why |
| [CHANGELOG.md](CHANGELOG.md) | Changes by release |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, and which releases get fixes |

## Build

You need a C17 compiler and CMake 3.20+ (Ninja is recommended). Dependencies (llhttp, yyjson, libssh and others) are fetched and pinned at configure time; cmocka too when tests are built.

OpenSSL must be 3.2 or later (madmin's encrypted admin payloads need its Argon2id). The system's is used when it is new enough; otherwise (for example Ubuntu 24.04, which has 3.0) a pinned release is built once from source into `.deps/`, which needs perl and make.

```bash
cmake -S . -B build -G Ninja
ninja -C build
ctest --test-dir build
```

To build with sanitizers, add `-DBUCKETS_SANITIZE=address,undefined` or `-DBUCKETS_SANITIZE=thread`.

## Run

```bash
BUCKETS_ROOT_USER=admin BUCKETS_ROOT_PASSWORD=change-me-now build/src/bucketsd server --address :9000 /srv/buckets
```

Or run the published image, without building anything. Every release's images are on `ghcr.io/storscale`: `bucketsd`, `buckets-operator`, `buckets-console` and `buckets-kes`, tagged with the version and `latest`, and signed (see [Test](#test) for verifying them):

```bash
docker run -p 9000:9000 -v buckets-data:/data \
  -e BUCKETS_ROOT_USER=admin -e BUCKETS_ROOT_PASSWORD=change-me-now \
  ghcr.io/storscale/bucketsd:1.1.1
```

Several drives form erasure sets, and each ellipsis argument is a server pool:

```bash
bucketsd server /mnt/disk{1...8}                            # one pool, one 8-drive set (EC 4+4)
bucketsd server /mnt/a{1...8} /mnt/b{1...8}                 # two pools
```

For a cluster, run the same command on every node, giving the drives as URLs. Nodes find their own drives by address and port:

```bash
bucketsd server http://node{1...4}.example.net:9000/mnt/disk{1...4}
```

For HTTPS, put `public.crt` and `private.key` in `~/.buckets/certs` or a `--certs-dir`. Certificates in its subdirectories are served by SNI, and nodes trust CAs in its `CAs/` directory.

### On Kubernetes

The operator runs `BucketsCluster` objects as StatefulSets (one per pool), with a Service, root credentials, and PodDisruptionBudgets. Install it, with its CRDs, from the published Helm chart (`watchNamespace` limits it, and its RBAC, to one namespace), then create a cluster:

```bash
helm install buckets-operator oci://ghcr.io/storscale/charts/buckets-operator \
  --version 1.1.1 -n buckets-system --create-namespace
kubectl apply -f operator/examples/cluster.yaml     # 4 servers x 4 drives
kubectl get bucketsclusters                          # SERVERS 4/4, PHASE Ready
```

The chart is signed like the images (`cosign verify ghcr.io/storscale/charts/buckets-operator:<version>` with the same identity). From a checkout, install the chart in `operator/helm/buckets-operator` instead, or apply the plain manifests:

```bash
kubectl apply -f operator/deploy/crds/
kubectl apply -f operator/deploy/operator.yaml
```

Root credentials land in the Secret `<name>-root` unless `spec.credsSecret` names your own. Pools can be appended to expand a cluster; the operator then restarts every server together. Image changes roll one server at a time. `operator/examples/cluster-tls.yaml` shows TLS with cert-manager.

`spec.console.enabled` adds the web console as a Deployment of its own (`<name>-console`, port 9090, optionally behind an Ingress). In `spec.console`:
- `tls.certSecret` names a `kubernetes.io/tls` Secret that the console serves itself, so it can sit behind a LoadBalancer on 443 without an Ingress;
- `env` adds environment variables, such as its OpenID sign-in settings, with `valueFrom` for secrets.

`operator/examples/cluster-entra.yaml` puts these together: TLS on the servers and the console, and sign-in with Microsoft Entra ID (see [docs/identity.md](docs/identity.md)).

Any S3 client works:

```bash
curl --aws-sigv4 "aws:amz:us-east-1:s3" --user admin:change-me-now -X PUT http://localhost:9000/photos
aws --endpoint-url http://localhost:9000 s3 ls
```

### The web console

The console is a separate process, `consoled`, serving the SPA and talking to `bucketsd` like any other client:

```bash
(cd console/web && npm ci && npm run build)
CONSOLE_MINIO_SERVER=http://127.0.0.1:9000 CONSOLE_PBKDF_PASSPHRASE=some-secret \
  build/src/consoled --address :9090 --web-dir console/web/dist
```

Building the console needs Node.js 22 or later (its image uses Node 24; Node 18 is too old for its build tools).

Sign in at http://localhost:9090 with any Buckets credentials: the console exchanges them for STS credentials and keeps those in an encrypted cookie. `CONSOLE_PBKDF_PASSPHRASE`/`CONSOLE_PBKDF_SALT` derive the cookie key; give every replica the same values. `--certs-dir` serves the console over HTTPS (`public.crt` and `private.key`).

| Setting | Effect |
|---|---|
| `CONSOLE_LDAP_ENABLED=on` | Adds LDAP sign-in |
| `BUCKETS_CONSOLE_OIDC_CONFIG_URL`, `_CLIENT_ID`, `_CLIENT_SECRET` | Adds OpenID sign-in; the redirect URI is `<console>/oauth_callback` unless `BUCKETS_CONSOLE_OIDC_REDIRECT_URI` sets it. `_SCOPES` and `_DISPLAY_NAME` are optional |
| `BUCKETS_CONSOLE_LOCAL_USERS=on` | Offers Create user on the Users page. Off by default while OpenID sign-in is on, so people come from the identity provider; existing local users are still listed |
| `BUCKETS_CONSOLE_S3_URL` | The S3 endpoint browsers can reach; enables share links |

With OpenID sign-in, the Users page also lists the provider's people that Buckets knows of (signed in now, or holding access keys), with their names and roles.

`MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` and `MINIO_REGION` are honored as fallbacks, so existing deployments can switch over. The health endpoints are `/minio/health/{live,ready,cluster}`, also served under `/buckets/health/...`.

## Test

| Command | What it runs |
|---|---|
| `ctest --test-dir build` | Unit tests (AWS SigV4 vectors, NIST/RFC hash vectors, XML, drive) and fuzz-corpus replay |
| `tests/integration/smoke.sh` | End-to-end against a live `bucketsd`, using curl's independent SigV4 signer |
| `tests/integration/interop.sh` | Round trips with `mc` and a real MinIO build in both directions (needs `MC_BIN` and `MINIO_BIN`; `tools/build-oracles.sh` builds them) |
| `tests/conformance/minio-go.sh` | minio-go's functional suite (MinIO mint's Go suite); needs Go |
| `tests/integration/{erasure,heal,concurrency,pools,tls,cluster}.sh` | Drive loss and bitrot; healing; racing writers; pool expansion; HTTPS; a 4-node cluster losing and regaining nodes (`MINIO_BIN` adds MinIO interop) |
| `tests/integration/console.sh` | `consoled` without a browser: key, LDAP and OpenID sign-in (with a session cookie over 1 KB, as Entra ID's are), the admin proxy, streams, share links |
| `tests/integration/openid.sh` | OpenID Connect: AssumeRoleWithWebIdentity and ClientGrants against a mock provider, claim-based and role-policy providers |
| `tests/integration/buckets-kes.sh` | bucketsd on `buckets-kes`: SSE-S3/KMS, keys, policies, restarts; the same keys read by MinIO's KES (`KES_BIN`); Vault (`VAULT_BIN`), AWS via moto (`MOTO_SERVER`), Azure via Lowkey Vault (`LOWKEY_JAR`), Google via `gcpmock.py` |
| `tests/e2e-k8s/envtest.sh` | The operator against a real kube-apiserver and etcd (envtest binaries, downloaded on first use), running as its own ServiceAccount |
| `tests/e2e-k8s/kind.sh` | Full end to end on kind: images, operator, a 4-server cluster, pod and PVC loss, pool expansion, image rollout, the console Deployment and its Playwright suite (needs docker and kind; see `tests/e2e-k8s/README.md`) |
| `tests/integration/select.sh` | S3 Select against MinIO, case by case (CSV, JSON, Parquet, every compression, errors) |
| `tests/integration/lambda.sh` | Object lambda: a local lambda function called by MinIO and Buckets alike |
| `tests/integration/zip.sh` | Files inside zip archives (x-minio-extract) against MinIO, then each server on the other's drives |
| `tests/integration/snowball.sh` | Snowball archives (plain and compressed) extracted by MinIO and Buckets alike |
| `tests/e2e-k8s/multisite.sh` | Two Buckets clusters and a MinIO site on kind: Buckets↔MinIO bucket replication, three-site site replication, a forwarded multi-server decommission |
| `console/web: npx playwright test` | The console end to end: starts bucketsd and consoled (or `CONSOLE_URL`) and drives the SPA in Chromium |
| `tests/bench/warp.sh` | warp-style concurrent PUT/GET throughput, Buckets then MinIO on the same drives (`S3BENCH`, `MINIO_BIN`; see `docs/performance.md`) |
| `tests/fuzz/soak.sh` | Every fuzz target under libFuzzer with ASan/UBSan in a Linux container, for `SECONDS` each (needs docker) |
| `scripts/ci.sh` | The full gate: release, ASan/UBSan and TSan builds, unit, smoke and interop tests |

`.github/workflows/images.yml` builds the `bucketsd`, `buckets-operator`, `buckets-console` and `buckets-kes` images on every push to `main` and on tags, and pushes them to `ghcr.io/storscale/<image>`: the short commit SHA (8 characters) and `main`, or the version (the tag without its `v`) and `latest`. Each image carries an SBOM and build provenance. Release images are signed with cosign, keyless, as this workflow, and the operator's Helm chart is pushed to `oci://ghcr.io/storscale/charts/buckets-operator`. To verify an image:

```bash
cosign verify ghcr.io/storscale/bucketsd:<version> \
  --certificate-identity-regexp '^https://github.com/StorScale/buckets/\.github/workflows/images\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`.gitlab-ci.yml` builds the same images into an internal registry for a development cluster, and runs the MinIO round trip there (`adopt-roundtrip`). It runs only on pushes to a GitLab copy of the repository; the variables it needs are listed at its top.

## Layout

```
src/core     runtime: buffers, strings, time, query, logging, event loop
src/net      HTTP/1.1 server and client, TLS
src/crypto   SHA-256/1, MD5, HMAC, HighwayHash, xxHash, CRC32/32C/64NVME, base64
src/s3       S3 front end: routing, SigV4/V2, aws-chunked, POST policy, checksums, errors (generated), XML
src/storage  drives (local and remote), format.json negotiation, xl.meta v2 codec
src/erasure  Reed-Solomon, drive layout (ellipses, set sizing, placement)
src/object   object layer: pools, erasure sets, quorum, multipart, healing, namespace locks
src/dist     internode RPC: remote drives, storage server, dsync locks, endpoints
src/heal     background healer: MRF queue, replaced drives, scanner
src/bucket   bucket metadata (.metadata.bin)
src/kes      buckets-kes: KES's API, keys and key stores (Vault, AWS, Azure, GCP, fs)
src/cmd      the bucketsd, consoled and buckets-kes entry points
tests/       unit (cmocka), fuzz (libFuzzer), integration
scripts/     generators (S3 error table, parity checklist), CI
docker/      container images
operator/    the Kubernetes operator (C): CRDs, RBAC, Helm chart, manifests, examples
console/     the web console: web/ (React + TypeScript SPA, Playwright e2e) served by
             src/console + src/cmd/consoled (the C backend-for-frontend)
docs/        architecture, parity, migration, identity, encryption, performance, roadmap; docs/brand holds the logo artwork
```

## License

GNU AGPL v3 or later. Buckets ports behavior and logic from MinIO, which is AGPL-3.0.
