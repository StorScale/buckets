#!/usr/bin/env bash
# Object lambda against MinIO: both servers call the same local lambda
# function (a webhook in lambda_cases.py) and must answer alike.
#   MINIO_BIN=/path/to/minio tests/integration/lambda.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "lambda: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19790}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-lambda-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_LAMBDA_WEBHOOK_ENABLE_fn=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_fn="http://127.0.0.1:$((PORT + 2))/"
export MINIO_LAMBDA_WEBHOOK_AUTH_TOKEN_fn=secret-token
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$WORK/m/d{1...4}" >/dev/null 2>&1 &
PIDS+=($!)
"$BIN" server --address "127.0.0.1:$((PORT + 1))" "$WORK/b/d{1...4}" 2>>"$WORK/b.log" &
PIDS+=($!)
for p in $PORT $((PORT + 1)); do
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
done
python3 "$HERE/lambda_cases.py" "http://127.0.0.1:$PORT" "http://127.0.0.1:$((PORT + 1))" rootadmin rootsecret123 $((PORT + 2))
