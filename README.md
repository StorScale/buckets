# Buckets

S3-compatible object storage written in C, built to run natively on Kubernetes. It is a rewrite of MinIO's last public release (`RELEASE.2025-10-15T17-29-55Z`; the upstream project was archived in April 2026).

**Status: 0.2.0, single-node S3 core complete.** Objects, multipart uploads, checksums, SigV2/SigV4/POST-policy auth and listing all work on a single drive, in MinIO's exact on-disk format. Real MinIO and Buckets can serve each other's drives. minio-go's functional suite (mint's Go suite) passes with zero failures; its remaining tests need features from later phases. Next up is erasure coding and distribution. See [docs/architecture.md](docs/architecture.md) for the roadmap and [docs/parity.md](docs/parity.md) for per-handler progress.

## Build

You need a C17 compiler and CMake 3.20+ (Ninja is recommended). Dependencies (llhttp, yyjson, cmocka) are fetched and pinned at configure time.

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

Any S3 client works:

```bash
curl --aws-sigv4 "aws:amz:us-east-1:s3" --user admin:change-me-now -X PUT http://localhost:9000/photos
aws --endpoint-url http://localhost:9000 s3 ls
```

`MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` and `MINIO_REGION` are honored as fallbacks, so existing deployments can switch over. The health endpoints are `/minio/health/{live,ready,cluster}`, also served under `/buckets/health/...`.

## Test

| Command | What it runs |
|---|---|
| `ctest --test-dir build` | Unit tests (AWS SigV4 vectors, NIST/RFC hash vectors, XML, drive) and fuzz-corpus replay |
| `tests/integration/smoke.sh` | End-to-end against a live `bucketsd`, using curl's independent SigV4 signer |
| `tests/integration/interop.sh` | Round trips with `mc` and a real MinIO build in both directions (needs `MC_BIN` and `MINIO_BIN`; `tools/build-oracles.sh` builds them) |
| `tests/conformance/minio-go.sh` | minio-go's functional suite (MinIO mint's Go suite); needs Go |
| `scripts/ci.sh` | The full gate: release, ASan/UBSan and TSan builds, unit, smoke and interop tests |

## Layout

```
src/core     runtime: buffers, strings, time, query, logging, event loop
src/net      HTTP/1.1 server
src/crypto   SHA-256/1, MD5, HMAC, HighwayHash, xxHash, CRC32/32C/64NVME, base64
src/s3       S3 front end: routing, SigV4/V2, aws-chunked, POST policy, checksums, errors (generated), XML
src/storage  local drive, xl.meta v2 codec (MinIO-compatible on-disk layout)
src/object   object layer: put/get/list/delete, multipart, bitrot framing
src/bucket   bucket metadata (.metadata.bin)
src/cmd      bucketsd entry point
tests/       unit (cmocka), fuzz (libFuzzer), integration
scripts/     generators (S3 error table, parity checklist), CI
docker/      container images
```

Coming in later phases: `operator/` (the BucketsCluster operator) and `console/` (the web UI, deployed separately from storage).

## License

GNU AGPL v3 or later. Buckets ports behavior and logic from MinIO, which is AGPL-3.0.
