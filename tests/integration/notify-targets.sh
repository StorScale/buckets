#!/usr/bin/env bash
# The notification targets beyond webhooks, differentially: MinIO and
# bucketsd deliver the same events to protocol mocks that log every command
# they receive, and the logs are diffed (normalized). Also checks config set
# validation for each target type.
#   MINIO_BIN=/path/to/minio tests/integration/notify-targets.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "notify-targets: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19950}
MOCK_PORT=$((PORT + 1))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-targets-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID= MOCK=
cleanup() {
  for p in $PID $MOCK; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MC_CONFIG_DIR="$WORK/mc"
# mc admin config set, its message without mc's decoration
config_set() { "$MC_BIN" admin config set t "$@" 2>&1 | sed -E 's/^mc: <ERROR> //' | head -3 || true; }
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
start() { # kind dir
  mkdir -p "$2"/d{1..4}
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$2/d{1...4}" >>"$WORK/$1.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$2/d{1...4}" 2>>"$WORK/$1.log" &
  fi
  PID=$!
  for _ in $(seq 150); do
    if [[ $(curl -s -o /dev/null -w '%{http_code}' "$EP/minio/health/ready") == 200 ]]; then
      "$MC_BIN" alias set t "$EP" rootadmin rootsecret123 >/dev/null 2>&1
      return
    fi
    sleep 0.1
  done
  echo "$1 did not start"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
mock_start() { # script log args...
  local script=$1 log=$2; shift 2
  : >"$log"
  python3 "$HERE/targets/$script" "$MOCK_PORT" "$log" "$@" &
  MOCK=$!
  for _ in $(seq 50); do nc -z 127.0.0.1 "$MOCK_PORT" 2>/dev/null && return; sleep 0.1; done
}
mock_stop() { kill "$MOCK" 2>/dev/null || true; wait "$MOCK" 2>/dev/null || true; MOCK=; }
notification() { # arn...
  local body="<NotificationConfiguration>"
  for arn in "$@"; do
    body+="<QueueConfiguration><Queue>$arn</Queue><Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event></QueueConfiguration>"
  done
  body+="</NotificationConfiguration>"
  curl -s "${S3[@]}" -X PUT "$EP/tbucket?notification" -d "$body"
}
workload() {
  echo hello >"$WORK/f"
  curl -s -o /dev/null "${S3[@]}" -T "$WORK/f" "$EP/tbucket/a.txt"
  curl -s -o /dev/null "${S3[@]}" -T "$WORK/f" "$EP/tbucket/dir/b%20c.txt"
  curl -s -o /dev/null "${S3[@]}" -X PUT -H "x-amz-copy-source: /tbucket/a.txt" "$EP/tbucket/copy.txt"
  curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/tbucket/a.txt"
  curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/tbucket/dir/b%20c.txt"
}
pass=0 fails=0
compare() { # name
  if diff -u "$WORK/minio.$1" "$WORK/buckets.$1" >"$WORK/$1.diff"; then
    pass=$((pass + 1)); echo "  ok    $1 ($(grep -vc '^--$' "$WORK/minio.$1") lines identical)"
  else
    fails=$((fails + 1)); echo "  FAIL  $1"; head -n "${DIFF_LINES:-60}" "$WORK/$1.diff"
  fi
}

echo "== redis"
for kind in minio buckets; do
  mock_start redismock.py "$WORK/redis.raw" pw123
  MINIO_NOTIFY_REDIS_ENABLE_ns=on MINIO_NOTIFY_REDIS_ADDRESS_ns="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_REDIS_KEY_ns=nsevents \
    MINIO_NOTIFY_REDIS_PASSWORD_ns=pw123 \
    MINIO_NOTIFY_REDIS_ENABLE_acc=on MINIO_NOTIFY_REDIS_ADDRESS_acc="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_REDIS_KEY_acc=accevents \
    MINIO_NOTIFY_REDIS_FORMAT_acc=access MINIO_NOTIFY_REDIS_USER_acc=default MINIO_NOTIFY_REDIS_PASSWORD_acc=pw123 \
    MINIO_NOTIFY_REDIS_ENABLE_st=on MINIO_NOTIFY_REDIS_ADDRESS_st="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_REDIS_KEY_st=stevents \
    MINIO_NOTIFY_REDIS_PASSWORD_st=pw123 MINIO_NOTIFY_REDIS_QUEUE_DIR_st="$WORK/$kind-queue" \
    start "$kind" "$WORK/$kind-redis"
  curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
  notification arn:minio:sqs::ns:redis arn:minio:sqs::acc:redis arn:minio:sqs::st:redis
  workload
  sleep 3
  # config set: the target named must be reachable; bad settings are refused
  for kv in "notify_redis:cfg1 address=127.0.0.1:1 key=k" "notify_redis:cfg2 address=127.0.0.1:$MOCK_PORT key=" \
    "notify_redis:cfg3 address=127.0.0.1:$MOCK_PORT key=k format=weird" "notify_redis:cfg4 address=nohost:x key=k" \
    "notify_redis:cfg5 address=127.0.0.1:$MOCK_PORT key=k queue_dir=rel" "notify_webhook:w1 endpoint=http://127.0.0.1:1/x"; do
    # shellcheck disable=SC2086
    config_set $kv >>"$WORK/$kind.redis-config"
  done
  stop
  mock_stop
  python3 "$HERE/targets/normalize.py" <"$WORK/redis.raw" >"$WORK/$kind.redis"
done
compare redis
compare redis-config

echo "== nsq"
for kind in minio buckets; do
  HEARTBEAT_MS=1500 mock_start nsqmock.py "$WORK/nsq.raw"
  MINIO_NOTIFY_NSQ_ENABLE_q1=on MINIO_NOTIFY_NSQ_NSQD_ADDRESS_q1="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_NSQ_TOPIC_q1=events \
    MINIO_NOTIFY_NSQ_ENABLE_q2=on MINIO_NOTIFY_NSQ_NSQD_ADDRESS_q2="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_NSQ_TOPIC_q2=stored \
    MINIO_NOTIFY_NSQ_QUEUE_DIR_q2="$WORK/$kind-nsqq" \
    start "$kind" "$WORK/$kind-nsq"
  curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
  notification arn:minio:sqs::q1:nsq arn:minio:sqs::q2:nsq
  workload
  sleep 4 # heartbeats get answered in the meantime
  for kv in "notify_nsq:c1 nsqd_address=127.0.0.1:1 topic=t" "notify_nsq:c2 nsqd_address=127.0.0.1:$MOCK_PORT topic=" \
    "notify_nsq:c3 nsqd_address= topic=t" "notify_nsq:c4 nsqd_address=[::1 topic=t"; do
    # shellcheck disable=SC2086
    config_set $kv >>"$WORK/$kind.nsq-config"
  done
  stop
  mock_stop
  python3 "$HERE/targets/normalize.py" <"$WORK/nsq.raw" | grep -v '^\["NOP"\]$' >"$WORK/$kind.nsq"
  grep -c '^\["NOP"\]' "$WORK/nsq.raw" >/dev/null || true
done
compare nsq
compare nsq-config

echo "notify-targets: $pass passed, $fails failed"
[[ $fails -eq 0 ]]
