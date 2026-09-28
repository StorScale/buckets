#!/usr/bin/env bash
# Single-stream PUT and GET throughput against a local bucketsd, optionally
# side by side with MinIO (MINIO_BIN). Drives are temp dirs on one disk, so
# this measures the server's CPU path (hashing, erasure coding, HTTP), not
# the disks.
#   tests/bench/putget.sh [bucketsd] [size-MiB]          (default 1024 MiB)
#   MINIO_BIN=/path/to/minio tests/bench/putget.sh build-rel/src/bucketsd
set -u
BIN=${1:-build-rel/src/bucketsd}
MIB=${2:-1024}
PORT=${PORT:-19590}
AK=benchuser
SK=benchsecret1
DATA=$(mktemp "${TMPDIR:-/tmp}/buckets-bench-XXXXXX")
trap 'rm -f "$DATA"' EXIT
head -c $((MIB * 1024 * 1024)) /dev/urandom >"$DATA"
A=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD")
secs() { curl -s -o /dev/null -w '%{time_total}' "${A[@]}" "$@"; }

run() { # kind binary drives
  local W; W=$(mktemp -d "${TMPDIR:-/tmp}/buckets-bench-XXXXXX")
  if [[ $1 == buckets ]]; then
    BUCKETS_SCANNER_INTERVAL=0 BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$2" server \
      --address "127.0.0.1:$PORT" "$W/$3" 2>"$W.log" &
  else
    MINIO_CI_CD=on MINIO_ROOT_USER=$AK MINIO_ROOT_PASSWORD=$SK "$2" server --address "127.0.0.1:$PORT" \
      --console-address "127.0.0.1:$((PORT + 1))" "$W/$3" >"$W.log" 2>&1 &
  fi
  local pid=$!
  for _ in $(seq 100); do curl -sf "http://127.0.0.1:$PORT/minio/health/ready" >/dev/null && break; sleep 0.1; done
  curl -s -o /dev/null "${A[@]}" -X PUT "http://127.0.0.1:$PORT/bench"
  local put get1 get2
  put=$(secs -T "$DATA" "http://127.0.0.1:$PORT/bench/o")
  get1=$(secs "http://127.0.0.1:$PORT/bench/o")
  get2=$(secs "http://127.0.0.1:$PORT/bench/o")
  awk -v k="$1" -v d="$3" -v p="$put" -v g1="$get1" -v g2="$get2" -v m="$MIB" 'BEGIN {
    printf "%-8s %-10s PUT %6.2fs %6.0f MiB/s   GET %6.2fs %6.0f MiB/s (warm %6.2fs %6.0f MiB/s)\n",
      k, d, p, m / p, g1, m / g1, g2, m / g2 }'
  kill "$pid"; wait "$pid" 2>/dev/null; rm -rf "$W" "$W.log"
}

echo "$MIB MiB object, single stream"
for spec in d1 "d{1...4}" "d{1...16}"; do
  run buckets "$BIN" "$spec"
  [[ -n "${MINIO_BIN:-}" ]] && run minio "$MINIO_BIN" "$spec"
done
