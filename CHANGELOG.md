# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
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
- Bucket and object ACL APIs: canned `private` only, as in MinIO.
- `ListObjectsV2` with `metadata=true` (MinIO's ListObjectsV2M extension).
- `tests/conformance/minio-go.sh` runs minio-go's functional suite (mint's Go suite). Current result: 76 pass, 2 fail (POST policy), 24 not implemented.
- `tests/integration/interop.sh`: round trips through `mc` and a real MinIO build in both directions. `tools/build-oracles.sh` builds the oracles.
- aws-chunked uploads: signed chunks (chained chunk signatures), signed trailers, and unsigned trailers.
- HTTP request bodies over 1 MiB spool to disk (up to 5 TiB), and responses stream from the object reader.
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
