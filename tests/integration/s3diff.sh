#!/usr/bin/env bash
# Runs S3 scenarios (tests/integration/scenarios/*.json) against real MinIO
# and bucketsd, each on fresh drives, and diffs the normalized transcripts.
#   MINIO_BIN=/path/to/minio tests/integration/s3diff.sh [bucketsd] [scenario...]
# Skips (exit 0) when MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
shift || true
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "s3diff: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
SCEN=("$@")
[[ ${#SCEN[@]} -eq 0 ]] && SCEN=("$HERE"/scenarios/*.json)
PORT=${PORT:-19800}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-s3diff-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_SCANNER_SPEED=fastest # usage scenarios wait for a scanner cycle
export MINIO_KMS_SECRET_KEY=s3diff-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= # SSE-S3 / SSE-KMS
EXTRA=() # per-scenario environment: scenarios/NAME.env, one VAR=value per line
start() { # minio|buckets drives-dir
  mkdir -p "$2"/d{1..4}
  if [[ $1 == minio ]]; then
    env ${EXTRA[@]+"${EXTRA[@]}"} MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" \
      "$2/d{1...4}" >>"$WORK/log" 2>&1 &
  else
    env ${EXTRA[@]+"${EXTRA[@]}"} "$BIN" server --address "127.0.0.1:$PORT" "$2/d{1...4}" 2>>"$WORK/log" &
  fi
  PID=$!
  for _ in $(seq 150); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 \
      "$EP/") == 200 ]] && return
    sleep 0.1
  done
  echo "$1 did not start"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
fails=0
for s in "${SCEN[@]}"; do
  name=$(basename "$s" .json)
  EXTRA=()
  if [[ -f "${s%.json}.env" ]]; then
    while IFS= read -r l; do [[ -n "$l" && $l != \#* ]] && EXTRA+=("$l"); done <"${s%.json}.env"
  fi
  for kind in minio buckets; do
    start "$kind" "$WORK/$name-$kind"
    python3 "$HERE/s3diff.py" "$EP" rootadmin rootsecret123 "$s" >"$WORK/$name.$kind.txt"
    stop
  done
  if diff -u "$WORK/$name.minio.txt" "$WORK/$name.buckets.txt" >"$WORK/$name.diff"; then
    echo "  ok    $name ($(wc -l <"$WORK/$name.minio.txt" | tr -d ' ') lines identical)"
  else
    echo "  FAIL  $name"; cat "$WORK/$name.diff"; fails=$((fails + 1))
  fi
done
echo "s3diff: $(( ${#SCEN[@]} - fails )) passed, $fails failed"
[[ $fails -eq 0 ]]
