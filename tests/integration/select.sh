#!/usr/bin/env bash
# S3 Select against MinIO: every case in select_cases.py runs on both
# servers and the answers must agree, except where Buckets differs on
# purpose (docs/parity.md).
#   MINIO_BIN=/path/to/minio tests/integration/select.sh [bucketsd] [case filter]
# SELGEN: tests/integration/selgen built (see its main.go), for zstd, lz4, s2
# and snappy input and generated Parquet files.
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "select: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19760}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-select-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
export MINIO_COMPRESSION_ENABLE=on MINIO_COMPRESSION_ALLOW_ENCRYPTION=on
export MINIO_API_SELECT_PARQUET=on
export TZ=UTC # MinIO formats Parquet timestamps in the local zone
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$WORK/m/d{1...4}" \
  >>"$WORK/m.log" 2>&1 &
PIDS+=($!)
"$BIN" server --address "127.0.0.1:$((PORT + 1))" "$WORK/b/d{1...4}" 2>>"$WORK/b.log" &
PIDS+=($!)
for p in $PORT $((PORT + 1)); do
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
done
python3 "$HERE/select_cases.py" "http://127.0.0.1:$PORT" "http://127.0.0.1:$((PORT + 1))" rootadmin rootsecret123 "${2:-}"
