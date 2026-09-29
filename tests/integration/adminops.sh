#!/usr/bin/env bash
# The remaining admin APIs against MinIO (heal, storage info, background heal
# status, top locks, bucket metadata export/import, inspect, speedtests,
# profiling, health info): both servers get the same requests and damage
# and must answer alike.
#   MINIO_BIN=/path/to/minio MC=/path/to/mc tests/integration/adminops.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "adminops: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19800}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-adminops-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$WORK/m/d{1...4}" \
  >"$WORK/m.log" 2>&1 &
PIDS+=($!)
"$BIN" server --address "127.0.0.1:$((PORT + 1))" "$WORK/b/d{1...4}" 2>>"$WORK/b.log" &
PIDS+=($!)
for p in $PORT $((PORT + 1)); do
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
done
python3 "$HERE/adminops_cases.py" "http://127.0.0.1:$PORT" "http://127.0.0.1:$((PORT + 1))" rootadmin rootsecret123 \
  "$WORK/m" "$WORK/b"
