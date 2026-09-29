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

echo "== nats"
# an NKey user seed and a .creds file (JWT, then the seed)
SEED=$(python3 -c '
import base64, os
def crc16(b):
    c = 0
    for x in b:
        c ^= x << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021 if c & 0x8000 else c << 1) & 0xFFFF
    return c
raw = bytes([149, 0]) + bytes(range(32))
c = crc16(raw)
print(base64.b32encode(raw + bytes([c & 255, c >> 8])).decode().rstrip("="))')
echo "$SEED" >"$WORK/user.nk"
printf -- '-----BEGIN NATS USER JWT-----\neyJ0eXAiOiJKV1QifQ.e30.c2ln\n------END NATS USER JWT------\n\n************************* IMPORTANT *************************\n\n-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------\n' "$SEED" >"$WORK/user.creds"
for kind in minio buckets; do
  mock_start natsmock.py "$WORK/nats.raw"
  MINIO_NOTIFY_NATS_ENABLE_n1=on MINIO_NOTIFY_NATS_ADDRESS_n1="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_NATS_SUBJECT_n1=core \
    MINIO_NOTIFY_NATS_USERNAME_n1=natsuser MINIO_NOTIFY_NATS_PASSWORD_n1=natspass \
    MINIO_NOTIFY_NATS_ENABLE_n2=on MINIO_NOTIFY_NATS_ADDRESS_n2="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_NATS_SUBJECT_n2=js \
    MINIO_NOTIFY_NATS_JETSTREAM_n2=on MINIO_NOTIFY_NATS_NKEY_SEED_n2="$WORK/user.nk" \
    MINIO_NOTIFY_NATS_ENABLE_n3=on MINIO_NOTIFY_NATS_ADDRESS_n3="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_NATS_SUBJECT_n3=stored \
    MINIO_NOTIFY_NATS_TOKEN_n3=s3cret MINIO_NOTIFY_NATS_QUEUE_DIR_n3="$WORK/$kind-natsq" \
    MINIO_NOTIFY_NATS_ENABLE_n4=on MINIO_NOTIFY_NATS_ADDRESS_n4="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_NATS_SUBJECT_n4=creds \
    MINIO_NOTIFY_NATS_USER_CREDENTIALS_n4="$WORK/user.creds" \
    start "$kind" "$WORK/$kind-nats"
  curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
  notification arn:minio:sqs::n1:nats arn:minio:sqs::n2:nats arn:minio:sqs::n3:nats arn:minio:sqs::n4:nats
  workload
  sleep 3
  for kv in "notify_nats:c1 address=127.0.0.1:1 subject=s" "notify_nats:c2 address=127.0.0.1:$MOCK_PORT subject=" \
    "notify_nats:c3 address=127.0.0.1:$MOCK_PORT subject=s username=u" \
    "notify_nats:c4 address=127.0.0.1:$MOCK_PORT subject=s client_cert=/x" \
    "notify_nats:c5 address=127.0.0.1:$MOCK_PORT subject=s ping_interval=x" \
    "notify_nats:c6 address=127.0.0.1:$MOCK_PORT subject=s queue_dir=rel" \
    "notify_nats:c7 address=127.0.0.1:$MOCK_PORT subject=s streaming=on"; do
    # shellcheck disable=SC2086
    config_set $kv >>"$WORK/$kind.nats-config"
  done
  stop
  mock_stop
  python3 "$HERE/targets/normalize.py" <"$WORK/nats.raw" >"$WORK/$kind.nats"
done
compare nats
compare nats-config

echo "== mqtt"
for kind in minio buckets; do
  mock_start mqttmock.py "$WORK/mqtt.raw"
  MINIO_NOTIFY_MQTT_ENABLE_m1=on MINIO_NOTIFY_MQTT_BROKER_m1="tcp://127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_MQTT_TOPIC_m1=q0 \
    MINIO_NOTIFY_MQTT_USERNAME_m1=mqttuser MINIO_NOTIFY_MQTT_PASSWORD_m1=mqttpass MINIO_NOTIFY_MQTT_KEEP_ALIVE_INTERVAL_m1=2s \
    MINIO_NOTIFY_MQTT_ENABLE_m2=on MINIO_NOTIFY_MQTT_BROKER_m2="tcp://127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_MQTT_TOPIC_m2=q1 \
    MINIO_NOTIFY_MQTT_QOS_m2=1 MINIO_NOTIFY_MQTT_QUEUE_DIR_m2="$WORK/$kind-mqttq" \
    MINIO_NOTIFY_MQTT_ENABLE_m3=on MINIO_NOTIFY_MQTT_BROKER_m3="ws://127.0.0.1:$MOCK_PORT/mqtt" MINIO_NOTIFY_MQTT_TOPIC_m3=q2 \
    MINIO_NOTIFY_MQTT_QOS_m3=2 \
    start "$kind" "$WORK/$kind-mqtt"
  curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
  notification arn:minio:sqs::m1:mqtt arn:minio:sqs::m2:mqtt arn:minio:sqs::m3:mqtt
  workload
  sleep 5 # keep-alive pings in the meantime
  for kv in "notify_mqtt:c1 broker=tcp://127.0.0.1:1 topic=t" "notify_mqtt:c2 broker=tcp://127.0.0.1 topic=t" \
    "notify_mqtt:c3 broker=http://127.0.0.1:$MOCK_PORT topic=t" "notify_mqtt:c4 broker=tcp://127.0.0.1:$MOCK_PORT topic=t qos=x" \
    "notify_mqtt:c5 broker=tcp://127.0.0.1:$MOCK_PORT topic=t queue_dir=/tmp/q" \
    "notify_mqtt:c6 broker=tcp://127.0.0.1:$MOCK_PORT topic=t keep_alive_interval=10" \
    "notify_mqtt:c7 broker=tcp:/x topic=t"; do
    # shellcheck disable=SC2086
    config_set $kv >>"$WORK/$kind.mqtt-config"
  done
  stop
  mock_stop
  grep -c PINGREQ "$WORK/mqtt.raw" >"$WORK/$kind.mqtt-pings" || true
  grep -v PINGREQ "$WORK/mqtt.raw" | python3 "$HERE/targets/normalize.py" >"$WORK/$kind.mqtt"
done
compare mqtt
compare mqtt-config
[[ $(cat "$WORK/buckets.mqtt-pings") -gt 0 ]] && echo "  ok    mqtt keep-alive pings" || { echo "  FAIL  no keep-alive pings"; fails=$((fails + 1)); }

echo "notify-targets: $pass passed, $fails failed"
[[ $fails -eq 0 ]]
