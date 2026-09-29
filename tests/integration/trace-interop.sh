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
PID= LISTEN= SINK=
cleanup() {
  for p in $LISTEN $PID $SINK; do kill "$p" 2>/dev/null || true; done
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
# background records: the scanner walking a bucket, healing on read, lifecycle expiry
LC='<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status><Filter><Prefix>old/</Prefix></Filter><Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>'
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
echo hello >"$WORK/f"
SINK_PORT=$((PORT + 1))
python3 "$HERE/webhooksink.py" "$SINK_PORT" "$WORK/sink.log" &
SINK=$!
for kind in minio buckets; do
  : >"$WORK/sink.log"
  MINIO_AUDIT_WEBHOOK_ENABLE_sink=on MINIO_AUDIT_WEBHOOK_ENDPOINT_sink="http://127.0.0.1:$SINK_PORT/audit" \
    MINIO_SCANNER_SPEED=fastest BUCKETS_SCANNER_INTERVAL=1 start "$kind" "$WORK/bg-$kind"
  curl -s "${S3[@]}" -X PUT "$EP/trb" >/dev/null
  for o in old/a old/b keep/c; do curl -s "${S3[@]}" -T "$WORK/f" "$EP/trb/$o" >/dev/null; done
  python3 "$HERE/listen.py" "$EP" rootadmin rootsecret123 /minio/admin/v3/trace "scanner=true&healing=true&ilm=true&err=false&threshold=0s" >"$WORK/bg-$kind.raw" &
  LISTEN=$!
  sleep 1
  rm -rf "$WORK/bg-$kind/d2/trb/keep"                      # healed when read
  curl -s "${S3[@]}" -X PUT "$EP/trb?lifecycle" -H "Content-MD5: $(printf '%s' "$LC" | openssl md5 -binary | base64)" -d "$LC" >/dev/null
  curl -s "${S3[@]}" "$EP/trb/keep/c" >/dev/null
  for _ in $(seq 60); do # until both expiries were traced
    [[ $(grep -c '"ilm:expiry"' "$WORK/bg-$kind.raw") -ge 2 ]] && break
    sleep 1
  done
  sleep 3 # a few more scanner cycles
  kill "$LISTEN" 2>/dev/null || true; LISTEN=
  stop
  python3 "$HERE/trace/bgnormalize.py" "$WORK" <"$WORK/bg-$kind.raw" >"$WORK/$kind.bg"
  # the server's own audit entries (auditLogInternal), times and IDs aside
  python3 -c '
import json, sys
for l in open(sys.argv[1]):
    if l.startswith("{"):
        e = json.loads(l)
        if e.get("trigger") != "incoming":
            e.pop("time"); e.pop("deploymentid", None)
            print(json.dumps(e, sort_keys=True))' "$WORK/sink.log" | sort -u >"$WORK/$kind.internal"
done
kill "$SINK" 2>/dev/null || true; wait "$SINK" 2>/dev/null || true; SINK=
fails=0
for part in txt trace bg internal; do
  if diff -u "$WORK/minio.$part" "$WORK/buckets.$part" >"$WORK/$part.diff"; then
    echo "  ok    $part ($(wc -l <"$WORK/minio.$part" | tr -d ' ') lines identical)"
  else
    echo "  FAIL  $part"; head -n "${DIFF_LINES:-60}" "$WORK/$part.diff"; fails=$((fails + 1))
  fi
done
echo "trace-interop: $((4 - fails)) passed, $fails failed"
[[ $fails -eq 0 ]]
