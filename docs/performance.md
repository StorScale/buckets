# Performance

`tests/bench/putget.sh` times one PUT and two GETs of a single object on one
stream, and runs MinIO side by side when `MINIO_BIN` is set. The drives are
temp directories on one disk, so it measures the server's CPU path (payload
hashing, erasure coding, bitrot checks, HTTP) rather than the disks. GETs
come from the page cache.

## Results (Apple M-series laptop, 1 GiB object, release build)

| Drives | Buckets PUT | MinIO PUT | Buckets GET (cold / warm) | MinIO GET (cold / warm) |
|---|---|---|---|---|
| 1 | 1.05 s | 1.18 s | 0.15 / 0.14 s | 0.21 / 0.21 s |
| 4 (EC 2+2) | 1.08–1.16 s | 1.20 s | 0.13 / 0.12 s | 0.41 / 0.17 s |
| 16 (EC 12+4) | 1.17–1.21 s | 1.20 s | 0.11 / 0.11 s | 0.46 / 0.17 s |

**PUT floor.** A single-stream PUT cannot finish before the whole object's MD5 is computed for the ETag. MD5's 64 dependent rounds per block leave no parallelism, and OpenSSL's assembly MD5 runs at about 1.03 GB/s here, which is roughly 1.04 s per GiB. Buckets sits at that floor on one drive and within a few percent of it on 16. MinIO is bound by the same floor. Concurrent PUTs scale across cores.

## What moved the numbers

The starting point was PUT at 0.80–1.03 s per 256 MiB (2.6–3.3× MinIO) and GET within 2×. In order of impact:

1. **MD5 on OpenSSL.** Every PUT computes the whole object's MD5 for the ETag, and profiling put it at ~65% of PUT CPU. OpenSSL's arm64 assembly hashes at ~1 GB/s versus ~390 MB/s for the portable C. SHA-256 also moved to OpenSSL, which uses the hardware SHA instructions.
2. **Payload hashes off the critical path.** MD5, SHA-256 and checksums are serial per object. They now run one block behind as a background task, over two alternating block buffers, so they overlap the next block's read, parity and writes.
3. **Parity in parallel.** Reed-Solomon encodes four byte ranges of each block on separate threads.
4. **Streamed request bodies.** Large uploads used to be spooled to disk in full before the handler started. Now the handler starts once the headers arrive and reads through a bounded in-memory pipe (8 MiB high, 2 MiB low watermark). The event loop stops reading the socket while the pipe is full. This removed a full extra disk write per upload and let receiving overlap encoding.
5. **HighwayHash in SIMD.** The bitrot hash dominated GET. NEON (arm64) and SSSE3 (x86-64, chosen at runtime) versions of its update loop are bit-identical to the portable one; the golden vectors and a randomized comparison test check this.
6. **Open files kept open.** Object readers hold each drive's part file open instead of opening it for every shard block (about 12,000 opens per GiB on 16 drives).
7. **Double-buffered responses.** A worker fills the next response chunk while the event loop sends the current one.
8. **SIMD Reed-Solomon.** GF(2^8) multiplication uses split-nibble table lookups, 16 bytes per instruction (`vqtbl1q_u8` on NEON, `pshufb` on SSSE3), as in klauspost/reedsolomon. Each input chunk is loaded once, and each output is written once. A randomized test checks it against the scalar code for encode and reconstruct.
9. **The MD5 thread.** Each multi-block PUT hashes on its own thread, instead of queueing behind shard writes on the I/O pool. Blocks circulate through a four-buffer ring, so the hasher and the encoder don't wait on each other block by block. On macOS that thread asks for a performance core.
10. **Buffered drive writers.** Writers buffer 1 MiB, so a block no longer costs two `write()` calls per drive (hash, then shard). Shard writes are grouped four drives per pool task.
11. **Direct GET copies.** GETs copy straight out of the verified shard buffers instead of assembling each block first.
12. **GET read-ahead.** The reader loads and verifies block N+1 in the background, into a second set of shard buffers, while block N is sent.

## Known headroom

- **Single-stream PUT:** bound by MD5, as it is for MinIO. The only ways around it would change the ETag's meaning, which S3 clients rely on.
- **Event loop:** one event-loop thread per node moves every byte for all connections. It is not the bottleneck for one stream (GET reaches ~9 GB/s), but it will matter under many concurrent clients. Multiple reactors are planned.
- **AVX2:** the x86 paths use SSSE3 (128-bit). AVX2 versions would roughly double RS and HighwayHash throughput on x86 servers.
