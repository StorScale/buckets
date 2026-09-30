#!/usr/bin/env bash
# Concurrent PUT then GET throughput (warp's put/get), Buckets and MinIO one
# after the other on the same drives layout, through tests/bench/s3bench.
#   S3BENCH=/path/to/s3bench [MINIO_BIN=/path/to/minio] tests/bench/warp.sh [bucketsd]
# Env: DRIVES (default "d{1...4}"), DURATION (default 15s), CASES ("size:clients ...").
set -u
BIN=${1:-build-rel/src/bucketsd}
: "${S3BENCH:?set S3BENCH (tests/bench/s3bench built)}"
PORT=${PORT:-19580}
DRIVES=${DRIVES:-"d{1...4}"}
DURATION=${DURATION:-15s}
CASES=${CASES:-"10485760:16 1048576:32 65536:32"}
AK=benchuser
SK=benchsecret1

run() { # kind binary size clients
  local W; W=$(mktemp -d "${TMPDIR:-/tmp}/buckets-warp-XXXXXX")
  if [[ $1 == buckets ]]; then
    BUCKETS_SCANNER_INTERVAL=0 BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$2" server \
      --address "127.0.0.1:$PORT" "$W/$DRIVES" 2>"$W.log" &
  else
    MINIO_CI_CD=on MINIO_BROWSER=off MINIO_ROOT_USER=$AK MINIO_ROOT_PASSWORD=$SK "$2" server --quiet \
      --address "127.0.0.1:$PORT" "$W/$DRIVES" >"$W.log" 2>&1 &
  fi
  local pid=$!
  for _ in $(seq 200); do curl -sf "http://127.0.0.1:$PORT/minio/health/ready" >/dev/null && break; sleep 0.1; done
  local out
  out=$("$S3BENCH" -endpoint "127.0.0.1:$PORT" -access $AK -secret $SK -size "$3" -concurrent "$4" -duration "$DURATION")
  kill "$pid"; wait "$pid" 2>/dev/null; rm -rf "$W" "$W.log"
  [[ -n "${RESULTS:-}" ]] && echo "$1 $3 $4 $out" >>"$RESULTS"
  python3 "$(dirname "$0")/warpfmt.py" "$1" "$3" "$4" "$out"
}

echo "drives $DRIVES, $DURATION per phase"
for c in $CASES; do
  size=${c%%:*} clients=${c##*:}
  run buckets "$BIN" "$size" "$clients"
  [[ -n "${MINIO_BIN:-}" ]] && run minio "$MINIO_BIN" "$size" "$clients"
done
