#!/usr/bin/env bash
# Files inside zip archives (x-minio-extract) against MinIO: the same
# answers, then each server on the other's drives reading the archive
# indexes the other stored (zip_cases.py).
#   MINIO_BIN=/path/to/minio tests/integration/zip.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "zip: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19780}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-zip-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
PIDS=()
stop() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  PIDS=()
}
cleanup() {
  stop
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
start() { # minio-drives buckets-drives
  MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$WORK/$1/d{1...4}" \
    >>"$WORK/m.log" 2>&1 &
  PIDS+=($!)
  "$BIN" server --address "127.0.0.1:$((PORT + 1))" "$WORK/$2/d{1...4}" 2>>"$WORK/b.log" &
  PIDS+=($!)
  for p in $PORT $((PORT + 1)); do
    for _ in $(seq 300); do
      [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
      sleep 0.1
    done
  done
}
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
rc=0
start m b
python3 "$HERE/zip_cases.py" "http://127.0.0.1:$PORT" "http://127.0.0.1:$((PORT + 1))" rootadmin rootsecret123 fresh || rc=1
stop
start b m # MinIO on bucketsd's drives, bucketsd on MinIO's
python3 "$HERE/zip_cases.py" "http://127.0.0.1:$PORT" "http://127.0.0.1:$((PORT + 1))" rootadmin rootsecret123 swapped || rc=1
exit $rc
