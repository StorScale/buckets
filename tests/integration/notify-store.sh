#!/usr/bin/env bash
# The notification queue store across servers: while the webhook sink
# fails, one server queues events in queue_dir; the other replays them once
# the sink is back (MinIO -> bucketsd, then bucketsd -> MinIO), and bucketsd
# replays its own store after a restart.
#   MINIO_BIN=/path/to/minio tests/integration/notify-store.sh [bucketsd]
# Skips (exit 0) when MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "notify-store: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19840}
SINK_PORT=$((PORT + 1))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-nstore-XXXXXX")
EP="http://127.0.0.1:$PORT"
Q="$WORK/queue"
STORE="$Q/minio-webhook-primary"
PID= SINK=
cleanup() {
  for p in $PID $SINK; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_NOTIFY_WEBHOOK_ENABLE_primary=on
export MINIO_NOTIFY_WEBHOOK_ENDPOINT_primary="http://127.0.0.1:$SINK_PORT/hook"
export MINIO_NOTIFY_WEBHOOK_QUEUE_DIR_primary="$Q"
touch "$WORK/fail"
python3 "$HERE/webhooksink.py" "$SINK_PORT" "$WORK/sink.log" "$WORK/fail" &
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
fails=0
check() { # description, command...
  local d=$1; shift
  if "$@"; then echo "  ok    $d"; else echo "  FAIL  $d"; fails=$((fails + 1)); fi
}
queued() { ls "$STORE" 2>/dev/null | grep -c '\.event$' || true; }
delivered() { grep -c '^/hook ' "$WORK/sink.log" 2>/dev/null || true; }
wait_delivered() { # n
  for _ in $(seq 100); do [[ $(delivered) -ge $1 && $(queued) -eq 0 ]] && return 0; sleep 0.2; done
  return 1
}
# three events into the bucket's webhook queue
produce() { # tag
  cat >"$WORK/produce.json" <<JSON
[{"method": "PUT", "path": "/qbkt"},
 {"method": "PUT", "path": "/qbkt", "query": "notification",
  "body": "<NotificationConfiguration><QueueConfiguration><Queue>arn:minio:sqs::primary:webhook</Queue><Event>s3:ObjectCreated:Put</Event></QueueConfiguration></NotificationConfiguration>"},
 {"method": "PUT", "path": "/qbkt/$1-1", "body": "a"},
 {"method": "PUT", "path": "/qbkt/$1-2", "body": "bb"},
 {"method": "PUT", "path": "/qbkt/$1%203", "body": "ccc"}]
JSON
  python3 "$HERE/s3diff.py" "$EP" rootadmin rootsecret123 "$WORK/produce.json" >"$WORK/produce.$1.txt"
  sleep 1
}

# MinIO queues, bucketsd delivers
start minio "$WORK/minio"
produce m
stop
check "minio queued 3 events" test "$(queued)" -eq 3
cp -R "$STORE" "$WORK/minio-store"
rm "$WORK/fail"
start buckets "$WORK/buckets"
check "bucketsd replayed minio's store" wait_delivered 3
check "  as minio wrote them" bash -c "grep -c '\"key\":\"m-1\"\\|\"key\":\"m-2\"\\|\"key\":\"m+3\"' '$WORK/sink.log' | grep -qx 3"
check "  with the unescaped Key" grep -q '"Key":"qbkt/m 3"' "$WORK/sink.log"
stop

# bucketsd queues (and keeps them across a restart), MinIO delivers
: >"$WORK/sink.log"
touch "$WORK/fail"
start buckets "$WORK/buckets"
produce b
stop
check "bucketsd queued 3 events" test "$(queued)" -eq 3
check "  in minio's format" bash -c "for f in '$STORE'/*.event; do python3 -c 'import json,sys; e=json.load(open(sys.argv[1])); assert e[\"eventName\"]==\"s3:ObjectCreated:Put\"' \"\$f\" || exit 1; done"
start buckets "$WORK/buckets"
sleep 4 # a retry while the sink still fails
check "  kept across a restart" test "$(queued)" -eq 3
stop
rm "$WORK/fail"
start minio "$WORK/minio"
check "minio replayed bucketsd's store" wait_delivered 3
check "  keys intact" bash -c "grep -c '\"Key\":\"qbkt/b-1\"\\|\"Key\":\"qbkt/b-2\"\\|\"Key\":\"qbkt/b 3\"' '$WORK/sink.log' | grep -qx 3"
stop
echo "notify-store: $fails failed"
[[ $fails -eq 0 ]]
