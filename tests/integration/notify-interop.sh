#!/usr/bin/env bash
# Bucket notifications, differentially: the same scenario against real
# MinIO and bucketsd, each with a webhook target (a local sink) and a
# ListenNotification stream; diffs the S3 transcripts, the webhook
# deliveries and the listened events, normalized.
#   MINIO_BIN=/path/to/minio tests/integration/notify-interop.sh [bucketsd]
# Skips (exit 0) when MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "notify-interop: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
SCEN="$HERE/notify/notification.json"
PORT=${PORT:-19820}
SINK_PORT=$((PORT + 1))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-notify-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID= SINK= LISTEN=
cleanup() {
  for p in $LISTEN $PID $SINK; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_NOTIFY_WEBHOOK_ENABLE_primary=on
export MINIO_NOTIFY_WEBHOOK_ENDPOINT_primary="http://127.0.0.1:$SINK_PORT/hook"
export MINIO_NOTIFY_WEBHOOK_AUTH_TOKEN_primary=sinktoken
python3 "$HERE/webhooksink.py" "$SINK_PORT" "$WORK/sink.jsonl" &
SINK=$!

start() { # minio|buckets drives-dir
  mkdir -p "$2"/d{1..4}
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$2/d{1...4}" \
      >>"$WORK/$1.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$2/d{1...4}" 2>>"$WORK/$1.log" &
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

# Volatile values out; the rest (key order, escaping, spacing) stays as sent.
normalize() {
  python3 -c '
import re, sys
ids = {}
def nid(m):
    ids.setdefault(m.group(0), "V%d" % (len(ids) + 1))
    return ids[m.group(0)]
for line in sys.stdin:
    line = re.sub(r"\"eventTime\":\"[^\"]*\"", "\"eventTime\":\"(t)\"", line)
    line = re.sub(r"\"sequencer\":\"[0-9A-F]+\"", "\"sequencer\":\"(seq)\"", line)
    line = re.sub(r"\"(x-amz-request-id|x-amz-id-2|x-minio-deployment-id)\":\"[^\"]*\"", r"\"\1\":\"(v)\"", line)
    line = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", nid, line)
    sys.stdout.write(line)
'
}

EVENTS="events=s3:ObjectCreated:*&events=s3:ObjectRemoved:*&events=s3:ObjectAccessed:*&events=s3:BucketCreated:*&events=s3:BucketRemoved:*"
for kind in minio buckets; do
  : >"$WORK/sink.jsonl"
  start "$kind" "$WORK/$kind"
  python3 "$HERE/listen.py" "$EP" rootadmin rootsecret123 / "$EVENTS" >"$WORK/$kind.listen" &
  LISTEN=$!
  sleep 0.5 # the bucket listener needs the bucket
  python3 "$HERE/s3diff.py" "$EP" rootadmin rootsecret123 <(echo '[{"method": "PUT", "path": "/nbkt"}]') >/dev/null
  python3 "$HERE/listen.py" "$EP" rootadmin rootsecret123 /nbkt \
    "events=s3:ObjectCreated:*&prefix=p/&suffix=.txt&ping=1" >"$WORK/$kind.listen-bucket" &
  LISTEN="$LISTEN $!"
  sleep 1
  python3 "$HERE/s3diff.py" "$EP" rootadmin rootsecret123 "$SCEN" >"$WORK/$kind.txt"
  # deliveries are asynchronous: wait for the sink to go quiet
  prev=-1
  for _ in $(seq 50); do
    n=$(wc -l <"$WORK/sink.jsonl")
    [[ $n -eq $prev && $n -gt 0 ]] && break
    prev=$n; sleep 0.3
  done
  sleep 1.5 # a ping on the bucket listener
  for p in $LISTEN; do kill "$p" 2>/dev/null || true; done
  LISTEN=
  stop
  normalize <"$WORK/sink.jsonl" >"$WORK/$kind.sink"
  # keep-alive spaces come between records
  sed -E 's/^ +//; /^$/d' "$WORK/$kind.listen" | normalize >"$WORK/$kind.listen.n"
  # pings: whether one arrived, not how many
  sed '/^{"Records":null}$/d' "$WORK/$kind.listen-bucket" | normalize >"$WORK/$kind.listen-bucket.n"
  grep -q '^{"Records":null}$' "$WORK/$kind.listen-bucket" && echo "(pinged)" >>"$WORK/$kind.listen-bucket.n"
done

fails=0
for part in txt sink listen.n listen-bucket.n; do
  if diff -u "$WORK/minio.$part" "$WORK/buckets.$part" >"$WORK/$part.diff"; then
    echo "  ok    $part ($(wc -l <"$WORK/minio.$part" | tr -d ' ') lines identical)"
  else
    echo "  FAIL  $part"; cat "$WORK/$part.diff"; fails=$((fails + 1))
  fi
done
echo "notify-interop: $((4 - fails)) passed, $fails failed"
[[ $fails -eq 0 ]]
