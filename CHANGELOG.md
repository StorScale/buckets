# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- HighwayHash-256 (MinIO bitrot), XXH64 and XXH3-64, ported to C and verified against the Go libraries MinIO links.
- A MessagePack encoder/decoder that reproduces tinylib/msgp's exact encodings, as groundwork for xl.meta and bucket metadata.
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
