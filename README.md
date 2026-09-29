# Buckets

S3-compatible object storage written in C, built to run natively on Kubernetes. It is a rewrite of MinIO's last public release (`RELEASE.2025-10-15T17-29-55Z`; the upstream project was archived in April 2026).

**Status: 0.3.0, erasure-coded and distributed.** The S3 core runs in MinIO's exact on-disk format, on anything from one drive to multi-pool clusters of nodes:
- erasure coding, bitrot protection and healing
- HTTPS
- cluster-wide locks
- survives drive and node loss

Real MinIO and Buckets can serve each other's drives, clusters included. minio-go's functional suite (mint's Go suite) passes with zero failures on one node and on a cluster; its remaining tests need features from later phases. Next up is the Kubernetes operator. See [docs/architecture.md](docs/architecture.md) for the roadmap and [docs/parity.md](docs/parity.md) for per-handler progress.

## Build

You need a C17 compiler and CMake 3.20+ (Ninja is recommended). Dependencies (llhttp, yyjson, cmocka) are fetched and pinned at configure time. OpenSSL 3 is used from the system when present, and otherwise built once from a pinned release into `.deps/` (this needs perl and make).

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

The operator runs `BucketsCluster` objects as StatefulSets (one per pool), with a Service, root credentials, and PodDisruptionBudgets:

```bash
kubectl apply -f operator/deploy/crds/
kubectl apply -f operator/deploy/operator.yaml
kubectl apply -f operator/examples/cluster.yaml     # 4 servers x 4 drives
kubectl get bucketsclusters                          # SERVERS 4/4, PHASE Ready
```

Root credentials land in the Secret `<name>-root` unless `spec.credsSecret` names your own. `spec.console.enabled` adds the web console as a Deployment of its own (`<name>-console`, port 9090, optionally behind an Ingress); sign in with any Buckets credentials. Pools can be appended to expand a cluster; the operator then restarts every server together. Image changes roll one server at a time. `operator/examples/cluster-tls.yaml` shows TLS with cert-manager.

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

Sign in at http://localhost:9090 with any Buckets credentials: the console exchanges them for STS credentials and keeps those in an encrypted cookie. `CONSOLE_PBKDF_PASSPHRASE`/`CONSOLE_PBKDF_SALT` derive the cookie key; give every replica the same values.

`MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` and `MINIO_REGION` are honored as fallbacks, so existing deployments can switch over. The health endpoints are `/minio/health/{live,ready,cluster}`, also served under `/buckets/health/...`.

## Test

| Command | What it runs |
|---|---|
| `ctest --test-dir build` | Unit tests (AWS SigV4 vectors, NIST/RFC hash vectors, XML, drive) and fuzz-corpus replay |
| `tests/integration/smoke.sh` | End-to-end against a live `bucketsd`, using curl's independent SigV4 signer |
| `tests/integration/interop.sh` | Round trips with `mc` and a real MinIO build in both directions (needs `MC_BIN` and `MINIO_BIN`; `tools/build-oracles.sh` builds them) |
| `tests/conformance/minio-go.sh` | minio-go's functional suite (MinIO mint's Go suite); needs Go |
| `tests/integration/{erasure,heal,concurrency,pools,tls,cluster}.sh` | Drive loss and bitrot; healing; racing writers; pool expansion; HTTPS; a 4-node cluster losing and regaining nodes (`MINIO_BIN` adds MinIO interop) |
| `tests/e2e-k8s/envtest.sh` | The operator against a real kube-apiserver and etcd (envtest binaries, downloaded on first use), running as its own ServiceAccount |
| `tests/e2e-k8s/kind.sh` | Full end to end on kind: images, operator, a 4-server cluster, pod and PVC loss, pool expansion, image rollout (needs docker and kind) |
| `console/web: npx playwright test` | The console end to end: starts bucketsd and consoled (or `CONSOLE_URL`) and drives the SPA in Chromium |
| `scripts/ci.sh` | The full gate: release, ASan/UBSan and TSan builds, unit, smoke and interop tests |

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
src/cmd      bucketsd entry point
tests/       unit (cmocka), fuzz (libFuzzer), integration
scripts/     generators (S3 error table, parity checklist), CI
docker/      container images
```

operator/    the Kubernetes operator (C): CRDs, RBAC, manifests, examples

console/     the web console: web/ (React + TypeScript SPA, Playwright e2e) served by
             src/console + src/cmd/consoled (the C backend-for-frontend)

## License

GNU AGPL v3 or later. Buckets ports behavior and logic from MinIO, which is AGPL-3.0.
