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

## Concurrent load (warp)

`tests/bench/warp.sh` runs bucketsd, then MinIO, on the same drive layout and
load-tests each with [warp](https://github.com/minio/warp) (v1.3.1, `WARP=`) or
with `tests/bench/s3bench` (minio-go, as warp uses; `S3BENCH=`). Each case
runs `warp put` for a fixed time, then `warp get` over a fixed set of 64
objects, so both servers read the same working set.

```bash
WARP=$T/bin/warp MINIO_BIN=$T/minio-bin DURATION=15s tests/bench/warp.sh build-rel/src/bucketsd
```

Apple M-series laptop (12 cores, shared with warp), 4 drives (EC 2+2) on one SSD, release build, 15 s per phase:

| Case | Buckets PUT | MinIO PUT | Buckets GET | MinIO GET |
|---|---|---|---|---|
| 10 MiB × 16 clients | 709 MiB/s | 494 MiB/s | 14684 MiB/s ¹ | 15155 MiB/s ¹ (Buckets −3.1%) |
| 1 MiB × 32 clients | 571 MiB/s ² | 362 MiB/s ² | 10527 MiB/s | 8574 MiB/s |
| 64 KiB × 32 clients | 2604 op/s | 1312 op/s | 24277 op/s | 19265 op/s |

¹ Mean of four alternating runs (Buckets 14444–14857, MinIO 14826–15447).
² Mean of four alternating runs; single runs swing widely with the disk.

- **PUTs** are bound by the one disk and vary by ±30% from run to run for both servers. Buckets' throughput leads, but its median latency on 10 MiB PUTs is higher than MinIO's (415 ms vs 143 ms), while its p99 is similar.
- **GETs** come from the page cache and measure the servers. With fewer clients Buckets leads on 10 MiB GETs too: +29% with 1 client, +10% with 4.
- At 16 clients the server and warp saturate the machine together, so throughput follows CPU per byte. Profiles (Instruments' Time Profiler, which charges kernel time to the calling syscall) show both servers splitting it alike: about 30% socket sends, 25% HighwayHash, 20–24% page-cache reads, 6–8% copies. The remaining difference is Buckets' thread hand-offs.

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
13. **One metadata read per GET.** GET resolved `xl.meta` on every drive twice (stat, then open). It now takes the lock and resolves once, and positions the reader from that result. 1 MiB GETs went from 5400 to 6700 MiB/s and small GETs from 14.9k to 21k op/s.
14. **Several event loops.** One loop thread moved every byte for every connection, and under 16 large GETs it was busy 99% of the time in `sendto`. Accepted connections are now dealt round-robin across `BUCKETS_NET_THREADS` loops (CPUs / 2 by default, at most 16). The first loop, which also accepts, is the caller's.
17. **Responses sent by the worker that reads them, from the reader's buffers.** A streamed response used to cross three threads per 256 KiB: an I/O thread read and verified the shards, a worker copied them into the response buffer, and an event loop sent it. The data was cold in each next core's cache, often a different cluster. The worker now runs the stream itself: it sends straight from the verified shard buffers (`stream_view`/`stream_consume`, no copy) until the socket is full, the response ends, or 4 MiB have gone, and only then hands the connection back to the loop. 10 MiB GETs at 16 clients went from 8.5% behind MinIO to 3% behind; 1 MiB GETs from +7% to +23%.
15. **No thundering herds in the worker pool.** A parallel batch woke every idle worker, and every finished batch woke every waiting caller. Now it wakes as many as it has tasks, and each caller has its own condition variable.
16. **Fewer drive syscalls per PUT.** Directories are created leaf first, as MinIO's osMkdirAll does, and xl.meta writes no longer fsync their directory. On 4 drives a 1 MiB PUT went from 80 mkdir calls and 4 directory syncs to 16 and none, and 1 MiB PUTs moved from behind MinIO to ahead.

## Known headroom

- **Single-stream PUT:** bound by MD5, as it is for MinIO. The only ways around it would change the ETag's meaning, which S3 clients rely on.
- **AVX2:** the x86 paths use SSSE3 (128-bit). AVX2 versions would roughly double RS and HighwayHash throughput on x86 servers.
