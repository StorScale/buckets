# Performance

`tests/bench/putget.sh` times one PUT and two GETs of a single object on one
stream, and runs MinIO side by side when `MINIO_BIN` is set. The drives are
temp directories on one disk, so it measures the server's CPU path (payload
hashing, erasure coding, bitrot checks, HTTP) rather than the disks. GETs
come from the page cache.

## Results (0.3.x, Apple M-series laptop, 1 GiB object, release build)

| Drives | Buckets PUT | MinIO PUT | Buckets GET (warm) | MinIO GET (warm) |
|---|---|---|---|---|
| 1 | 1.06 s | 1.17 s | 0.22 s | 0.21 s |
| 4 (EC 2+2) | 1.14 s | 1.19 s | 0.19 s | 0.17 s |
| 16 (EC 12+4) | 1.25–1.6 s | 1.20 s | 0.15 s | 0.17 s |

- **Cold GET:** MinIO's first GET after startup is 2–4× slower (0.4–0.6 s); Buckets' is not.
- **16-drive PUT:** varies run to run on macOS. Both servers sync every shard file.

## What moved the numbers

The starting point was PUT at 0.80–1.03 s per 256 MiB (2.6–3.3× MinIO) and GET within 2×. In order of impact:

1. **MD5 on OpenSSL.** Every PUT computes the whole object's MD5 for the ETag, and profiling put it at ~65% of PUT CPU. OpenSSL's arm64 assembly hashes at ~1 GB/s versus ~390 MB/s for the portable C. SHA-256 also moved to OpenSSL, which uses the hardware SHA instructions.
2. **Payload hashes off the critical path.** MD5, SHA-256 and checksums are serial per object. They now run one block behind as a background task, over two alternating block buffers, so they overlap the next block's read, parity and writes.
3. **Parity in parallel.** Reed-Solomon encodes four byte ranges of each block on separate threads.
4. **Streamed request bodies.** Large uploads used to be spooled to disk in full before the handler started. Now the handler starts once the headers arrive and reads through a bounded in-memory pipe (8 MiB high, 2 MiB low watermark). The event loop stops reading the socket while the pipe is full. This removed a full extra disk write per upload and let receiving overlap encoding.
5. **HighwayHash in SIMD.** The bitrot hash dominated GET. NEON (arm64) and SSSE3 (x86-64, chosen at runtime) versions of its update loop are bit-identical to the portable one; the golden vectors and a randomized comparison test check this.
6. **Open files kept open.** Object readers hold each drive's part file open instead of opening it for every shard block (about 12,000 opens per GiB on 16 drives).
7. **Double-buffered responses.** A worker fills the next response chunk while the event loop sends the current one.

## Known headroom

- **Reed-Solomon:** the GF(2^8) multiply is table-driven scalar code. klauspost's split-nibble SIMD (NEON/AVX2) is several times faster.
- **Single stream:** a single-stream PUT is bound by MD5 at ~1 GB/s, as it is for MinIO. Concurrent streams scale across cores.
- **Event loop:** one event-loop thread moves all bytes for a node. Multiple reactors come with the rest of the I/O work.
