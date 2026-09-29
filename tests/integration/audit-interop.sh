#!/usr/bin/env bash
# Audit logging, differentially: the notification scenario against MinIO and
# bucketsd, each with an audit webhook (a local sink); diffs the entries,
# normalized (times, IDs, sizes that depend on the server's own headers).
#   MINIO_BIN=/path/to/minio tests/integration/audit-interop.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "audit-interop: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19880}
SINK_PORT=$((PORT + 1))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-audit-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID= SINK=
cleanup() {
  for p in $PID $SINK; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_AUDIT_WEBHOOK_ENABLE_sink=on MINIO_AUDIT_WEBHOOK_ENDPOINT_sink="http://127.0.0.1:$SINK_PORT/audit"
export MINIO_AUDIT_WEBHOOK_AUTH_TOKEN_sink="Token sinksecret"
export MINIO_PROMETHEUS_AUTH_TYPE=public
python3 "$HERE/webhooksink.py" "$SINK_PORT" "$WORK/sink.log" &
SINK=$!
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
for kind in minio buckets; do
  : >"$WORK/sink.log"
  start "$kind" "$WORK/$kind"
  sleep 1
  : >"$WORK/sink.log" # only the scenario's requests
  python3 "$HERE/s3diff.py" "$EP" rootadmin rootsecret123 "$HERE/audit/scenario.json" >"$WORK/$kind.txt"
  sleep 2
  # the targets' metrics: names, labels and the delivered count
  { curl -s "$EP/minio/v2/metrics/cluster"; curl -s "$EP/minio/metrics/v3/audit"; curl -s "$EP/minio/metrics/v3/logger/webhook"; } |
    grep -E '^minio_(audit|cluster_webhook|logger_webhook)_' | grep -v 'target_id="sys_console_0"\|name="console+http"' |
    sed -E 's/ [0-9.e+]+$/ (value)/; s/server="[^"]*"/server=/' | sort >"$WORK/$kind.metrics"
  stop
  python3 "$HERE/audit/normalize.py" <"$WORK/sink.log" >"$WORK/$kind.audit"
done
fails=0
for part in txt audit metrics; do
  if diff -u "$WORK/minio.$part" "$WORK/buckets.$part" >"$WORK/$part.diff"; then
    echo "  ok    $part ($(wc -l <"$WORK/minio.$part" | tr -d ' ') lines identical)"
  else
    echo "  FAIL  $part"; head -n "${DIFF_LINES:-80}" "$WORK/$part.diff"; fails=$((fails + 1))
  fi
done
echo "audit-interop: $((3 - fails)) passed, $fails failed"
[[ $fails -eq 0 ]]
