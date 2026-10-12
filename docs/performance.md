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

## On a Kubernetes cluster

`tests/bench/cluster.sh` compares the two servers where they will run: a MinIO tenant (4 servers × 2 drives, laid out as the MinIO Operator lays one out) is load-tested with `tests/bench/s3bench` from a client pod, adopted in place by Buckets (`scripts/adopt-minio.sh`) and tested again on the same volumes and nodes, then rolled back and tested a third time. The second MinIO round shows how far the storage itself drifted.

```bash
S3BENCH=/tmp/s3bench MINIO_IMAGE=<mirror>/minio:RELEASE.2024-10-13T13-34-11Z \
  REGISTRY=ghcr.io/storscale BUCKETS_TAG=<tag> tests/bench/cluster.sh
```

A development cluster on OpenStack (16-vCPU VMs, Cinder network volumes shared with other workloads), MinIO `RELEASE.2024-10-13`, Buckets after 1.19.0 (local shards first, below), 20 s per phase, one run of `cluster.sh`:

| Case | MinIO | Buckets | MinIO again |
|---|---|---|---|
| 10 MiB GET × 16 clients | 619 MiB/s | 834 MiB/s | 652 MiB/s |
| 1 MiB GET × 32 clients | 620 MiB/s | 859 MiB/s | 697 MiB/s |
| 64 KiB GET × 32 clients | 3213 op/s | 3680 op/s | 3182 op/s |
| 10 MiB PUT × 16 clients | 210 MiB/s | 197 MiB/s | 197 MiB/s |
| 1 MiB PUT × 32 clients | 210 MiB/s | 194 MiB/s | 196 MiB/s |
| 64 KiB PUT × 32 clients | 1154 op/s | 1164 op/s | 777 op/s |

- **GETs:** Buckets leads MinIO's better round by 28% on 10 MiB, 23% on 1 MiB and 15% on 64 KiB, with lower median latency (1 MiB: 29.5 ms against 33–51 ms; 10 MiB: 155 ms against 157–277 ms). Single runs here swing by about 15%.
- **PUTs** are bound by the shared network storage: MinIO's two rounds differed by up to a third (1,154 and 777 op/s on 64 KiB), and earlier runs by 40%. Treat PUT differences under that as noise.
- **Memory** per server pod peaked at 403 MiB for Buckets (the mean of four) against 732 and 676 for MinIO, and idled at 11 against 76–80 (see [Memory](#memory)).

The same cluster has itself grown faster since it was first measured, so compare runs by their margins over MinIO rather than by raw numbers:

| GET, Buckets' lead over MinIO | 1.1.1 | 1.19.0 ([Memory](#memory)) | Local shards first |
|---|---|---|---|
| 10 MiB × 16 clients | +13% (583 vs 514 MiB/s) | about even (546–612 vs 503–644) | +28% (834 vs 619–652) |
| 1 MiB × 32 clients | +11% (604 vs 544 MiB/s) | about even (529–618 vs 575–734) | +23% (859 vs 620–697) |
| 64 KiB × 32 clients | +37% (3853 vs 2816 op/s) | +10–18% (3746–3759 vs 3164–3397) | +15% (3680 vs 3182–3213) |

64 KiB objects are stored inline, so reading local shards first doesn't change them; MinIO's 64 KiB GETs rose from about 2,800 to 3,200 op/s on its unchanged image between the 1.1.1 run and later ones.

**Before 1.1.1** Buckets trailed MinIO on every GET here (64 KiB: about 2,000 op/s against 2,800), the reverse of the laptop results. In a distributed cluster most drives are on other servers, so every per-request round trip to them costs about 2 ms (pod network, conntrack, VM wake-ups). Profiling found two of them on every read:
1. **The bucket was checked on every drive, one after another** (7.6 internode round trips, 6.6 ms of a 12.7 ms GET, measured with uprobes on live requests). Reads now check the bucket only when the object is missing, and the check asks every drive at once.
2. **The read lock's release was waited for** (2.5 ms per GET). It is now released in the background, as MinIO does.

With both, 64 KiB GETs went from about 2,000 to 3,850 op/s and 1 MiB GETs from 384 to 604 MiB/s.

### Calls between servers

Each server counts the internode calls it makes and handles, by operation (`storage/read_at`, `lock/lock`, ...):
- `buckets_node_internode_calls_total` and `buckets_node_internode_call_seconds_total`: the calls it made, and the time it waited for their answers;
- `buckets_node_internode_served_total` and `buckets_node_internode_served_seconds_total`: the calls it handled, and the time it took;
- `buckets_node_internode_queued_seconds_total`: the time those calls waited for a thread first.

A call's wait less its peer's queueing and handling is the network's share. `s3bench -metrics host:port,...` reads them before and after each phase and reports the calls per request, and `cluster.sh` lists them for Buckets' rounds:

```
Buckets     1024 KiB x 32 GET     595.0 MiB/s    595.0 op/s  p50    44.5 ms  p99   118.4 ms
    storage/read_all         6.45 per request  wait    3.05 ms  queued    0.07 ms  handled in    0.03 ms
    lock/lock                3.12 per request  wait    3.13 ms  queued    0.07 ms  handled in    0.01 ms
    storage/read_at          3.00 per request  wait   11.87 ms  queued    0.07 ms  handled in    0.08 ms
```

On the cluster above (4 servers × 2 drives, EC 4+4), they showed:
- **The links between nodes are full.** Ping between server pods takes 0.5 ms, and a call is queued for 0.07 ms and handled in 0.01–0.1 ms, but under 32 clients the caller waits 2–3.5 ms for a lock or metadata read, and 10–12 ms for a 256 KiB shard. With 4 clients the same calls take 0.6–1 ms. Traffic between two nodes tops out at about 220 MiB/s on this cluster: with the client on its server's node, 1 MiB GETs to one server reached 984 MiB/s, and 220 MiB/s from another node. Small calls queue behind shard data on full links. (Turning off TCP slow start after idle in the servers' network namespaces changed nothing.)
- **So the bytes between servers set GET throughput.** A GET read the data shards wherever they were: with 2 of 8 drives on each server, 3 of its 4 shards came over the network. It now reads the shards on its own drives first, data or parity, and rebuilds the data shards it skipped, as MinIO does: 2 of 4 come over the network. On one cluster, its image switched back and forth:

| GET | Before (two runs) | Local shards first (two runs) |
|---|---|---|
| 10 MiB × 16 clients | 530, 530 MiB/s | 667, 652 MiB/s (+25%) |
| 1 MiB × 32 clients | 530, 518 MiB/s | 596, 625 MiB/s (+17%) |
| 64 KiB × 32 clients | 3557, 3581 op/s | 3602, 3586 op/s (inline: no shard reads) |

  On one machine, where the CPU rather than the network is the limit, rebuilding costs some throughput (10 MiB GETs on four local servers: about 1,300 MiB/s rather than 1,600).
- **The rest is round trips.** A PUT makes these calls to each other server's drives, one after another: `stat_vol` (the bucket), `create`, `append` (every 4 MiB), `fsync`, then under the lock `read_all` and `rename_data`, then `delete` (the staging directory). MinIO streams each shard in one call and renames it in another, which reads the old metadata and removes the staging directory on the drive's own server. A 10 MiB GET reads each remote shard block by block (10 calls per drive). See [Known headroom](#known-headroom).

## Memory

Both benchmarks measure memory as well as throughput:
- `tests/bench/warp.sh` reads the server's RSS idle before each case, its peak (`VmHWM`), and RSS again once the load has stopped and the server has been quiet for `MEM_SETTLE` seconds (10 by default).
- `tests/bench/cluster.sh` reads each server pod's memory from its node's kubelet (cAdvisor, through the API server's node proxy, so no metrics server is needed): idle after a minute of quiet, sampled every 2 s during the load, and idle again a minute after it. RSS is the memory the server itself holds; the working set adds page cache that can't be dropped at once, and is what Kubernetes compares with memory limits.

Neither server had a memory limit, so each sized itself from the node's memory.

**Four servers × 2 drives on Kubernetes** (`cluster.sh`): the cluster above (16-vCPU nodes), against MinIO `RELEASE.2024-10-13` (the release the lakehouse runs; the cluster can pull no newer MinIO image), 20 s per phase, the three cases one after another. Per server pod, MiB, the mean of the four, with the largest in brackets; each row is one run of `cluster.sh`, and MinIO's row is from the same run:

| Server | RSS idle | RSS peak | RSS after load | Working set peak | MinIO RSS peak |
|---|---|---|---|---|---|
| Buckets 1.18.1 | 9 (11) | 992 (1091) | 989 (1079) | 1354 (1434) | 652 (708) |
| Buckets 1.18.1, again | 11 (14) | 1107 (1306) | 1111 (1310) | 1513 (1711) | 731 (836) |
| Buckets, malloc fixed | 12 (15) | 387 (437) | 370 (378) | 774 (780) | 670 (984) |
| Buckets, malloc fixed, again | 11 (13) | 362 (423) | 368 (420) | 764 (818) | 698 (798) |

MinIO idled at 75–81 MiB of RSS in every run. Throughput didn't move with the fix (GET, MiB/s for 10 MiB and 1 MiB objects, op/s for 64 KiB; single runs here swing by about 15%):

| | 10 MiB × 16 | 1 MiB × 32 | 64 KiB × 32 |
|---|---|---|---|
| Buckets 1.18.1 (two runs) | 650, 595 | 638, 538 | 3751, 3743 |
| Buckets, malloc fixed (two runs) | 612, 546 | 529, 618 | 3746, 3759 |
| MinIO (four runs) | 531, 503, 614, 644 | 575, 680, 734, 588 | 3365, 3397, 3164, 3326 |

**One server, 4 drives** (`warp.sh`): a Linux VM with 8 vCPUs and 31 GiB, glibc 2.39, against MinIO `RELEASE.2025-10-15T17-29-55Z`, 15 s per phase, a fresh server for each case. RSS in MiB, idle / peak / after:

| Case | Buckets, malloc fixed | Buckets 1.18.1 | MinIO |
|---|---|---|---|
| 10 MiB × 16 clients | 11 / 353 / 181 | 11 / 534 / 459 | 117 / 813 / 733 |
| 1 MiB × 32 clients | 11 / 279 / 199 | 11 / 330 / 325 | 119 / 1078 / 984 |
| 64 KiB × 32 clients | 11 / 165 / 94 | 12 / 253 / 195 | 117 / 497 / 476 |

- **Idle,** Buckets uses about a seventh of MinIO's memory: 9–15 MiB of RSS against 75–120 MiB.
- **Under load,** Buckets now peaks at about half of MinIO's RSS in the cluster, and at a third or less on one server.
- **After the load,** Buckets keeps about what it peaked at in the cluster, and half to two thirds of it on one server; MinIO keeps nearly all of its peak in both.

Peaks move between runs: one MinIO pod's peak differed by 375 MiB between the two MinIO rounds of one cluster run (618 and 993 MiB), so treat peak differences under about a third as noise. Idle figures varied by a few MiB.

### Why the cluster cost more, and the fix

Before the fix, Buckets peaked *higher* than MinIO in the cluster (about 1,000–1,100 MiB per server against 650–730), though lower on one server. Four servers on one machine, with the load spread over them as the cluster's Service spreads it, reproduced it, and two tools showed where the memory was:
- glibc's `mallinfo2`, sampled every 200 ms: each server's peak **in use** was about 300 MiB, while malloc had taken 950–1,140 MiB from the system. After the load, 2.5–106 MiB was in use, and nearly all the rest stayed taken.
- A heap tracker (an `LD_PRELOAD` that records every live allocation of 64 KiB or more with its stack): the large buffers were request bodies (the streamed-body pipe, up to 16 MiB), the aws-chunked decoder (16 MiB per upload), remote drive writers (up to 4 MiB each), and connections' input buffers (2 MiB each, kept while the connection idled).

The cause was glibc's malloc. Each time a buffer larger than its mmap threshold is freed, glibc raises the threshold to that size (up to 32 MiB), and its trim threshold to twice that. The first 16 MiB upload buffer to be freed moved every later buffer up to 16 MiB from `mmap` into malloc's arenas, and the arenas (up to eight per CPU) keep what is freed rather than give it back. The distributed path allocates more large buffers than a single server does, so it fragmented more of them.

`bucketsd` now fixes glibc's thresholds when it starts: 4 MiB for `mmap`, 8 MiB for trimming. Naming any malloc setting in `GLIBC_TUNABLES` (for example `GLIBC_TUNABLES=glibc.malloc.mmap_threshold=…`) leaves glibc's own behaviour, and that setting, in place. Choosing the values, on four servers on one machine, four alternating runs each:

| glibc thresholds | Peak RSS | RSS after | 10 MiB PUT / GET | 1 MiB PUT / GET | 64 KiB PUT / GET |
|---|---|---|---|---|---|
| glibc's own (rising) | 781 | 708–714 | 272 / 1731 | 83 / 902 | 15 / 106 |
| mmap 4 MiB, trim 8 MiB | 341 | 210–244 | 274 / 1827 | 87 / 1071 | 16 / 112 |
| mmap 32 MiB, trim 8 MiB | 369 | 232–260 | 256 / 1780 | 84 / 980 | 16 / 118 |

(MiB per server; throughput in MiB/s across the four servers.) Fixing only the mmap threshold, and leaving trimming at glibc's default of 128 KiB, also brought memory down, but cost 30% of 10 MiB GETs: the arenas shrank and regrew between requests.

Two buffers no longer start or stay large:
- **The aws-chunked decoder** allocated MinIO's largest chunk (16 MiB) for every upload. It now grows to the largest chunk the client sends (64 KiB from minio-go).
- **A connection's input buffer,** grown to 2 MiB by a large request body, was kept for the connection's idle life. It is freed once everything in it is parsed, and connections between requests keep at most 128 KiB.

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
- **Round trips between servers** ([Calls between servers](#calls-between-servers)): a PUT makes about seven calls, one after another, to each remote drive, where MinIO's design needs two; large GETs read remote shards block by block rather than as one stream; listing a remote drive stats each entry with a call of its own.
