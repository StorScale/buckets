#!/usr/bin/env bash
# mc admin trace, differentially: a trace subscriber on MinIO and on
# bucketsd while the same requests run; diffs the records, normalized.
#   MINIO_BIN=/path/to/minio tests/integration/trace-interop.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "trace-interop: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19910}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-trace-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID= LISTEN=
cleanup() {
  for p in $LISTEN $PID; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
start() {
  mkdir -p "$2"/d{1..4}
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$2/d{1...4}" >>"$WORK/$1.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$2/d{1...4}" 2>>"$WORK/$1.log" &
  fi
  PID=$!
  for _ in $(seq 150); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "$EP/minio/health/ready") == 200 ]] && return
    sleep 0.1
  done
  echo "$1 did not start"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
Q="s3=true&internal=false&storage=false&os=false&err=false&threshold=0s"
for kind in minio buckets; do
  start "$kind" "$WORK/$kind"
  python3 "$HERE/listen.py" "$EP" rootadmin rootsecret123 /minio/admin/v3/trace "$Q" >"$WORK/$kind.raw" &
  LISTEN=$!
  sleep 1
  python3 "$HERE/s3diff.py" "$EP" rootadmin rootsecret123 "$HERE/audit/scenario.json" >"$WORK/$kind.txt"
  sleep 1
  kill "$LISTEN" 2>/dev/null || true; LISTEN=
  stop
  python3 "$HERE/trace/normalize.py" <"$WORK/$kind.raw" >"$WORK/$kind.trace"
done
fails=0
for part in txt trace; do
  if diff -u "$WORK/minio.$part" "$WORK/buckets.$part" >"$WORK/$part.diff"; then
    echo "  ok    $part ($(wc -l <"$WORK/minio.$part" | tr -d ' ') lines identical)"
  else
    echo "  FAIL  $part"; head -n "${DIFF_LINES:-60}" "$WORK/$part.diff"; fails=$((fails + 1))
  fi
done
echo "trace-interop: $((2 - fails)) passed, $fails failed"
[[ $fails -eq 0 ]]
