#!/usr/bin/env bash
# The notification targets beyond webhooks, differentially: MinIO and
# bucketsd deliver the same events to protocol mocks that log every command
# they receive, and the logs are diffed (normalized). Also checks config set
# validation for each target type.
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc [PG_BIN=/path/to/postgres/bin] \
#     tests/integration/notify-targets.sh [bucketsd]
# PG_BIN (initdb, pg_ctl, postgres) adds the PostgreSQL target against a real server, MYSQL_DIR (a
# MySQL 8 installation: bin/mysqld, bin/mysql) the MySQL target, KFAKE_BIN (targets/kfake, built with Go)
# the Kafka target.
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

echo "== elasticsearch"
for kind in minio buckets; do
  mock_start esmock.py "$WORK/es.raw"
  MINIO_NOTIFY_ELASTICSEARCH_ENABLE_e1=on MINIO_NOTIFY_ELASTICSEARCH_URL_e1="http://127.0.0.1:$MOCK_PORT" \
    MINIO_NOTIFY_ELASTICSEARCH_INDEX_e1=nsindex MINIO_NOTIFY_ELASTICSEARCH_FORMAT_e1=namespace \
    MINIO_NOTIFY_ELASTICSEARCH_USERNAME_e1=esuser MINIO_NOTIFY_ELASTICSEARCH_PASSWORD_e1=espass \
    MINIO_NOTIFY_ELASTICSEARCH_ENABLE_e2=on MINIO_NOTIFY_ELASTICSEARCH_URL_e2="http://127.0.0.1:$MOCK_PORT" \
    MINIO_NOTIFY_ELASTICSEARCH_INDEX_e2=accindex MINIO_NOTIFY_ELASTICSEARCH_FORMAT_e2=access \
    MINIO_NOTIFY_ELASTICSEARCH_QUEUE_DIR_e2="$WORK/$kind-esq" \
    start "$kind" "$WORK/$kind-es"
  curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
  notification arn:minio:sqs::e1:elasticsearch arn:minio:sqs::e2:elasticsearch
  workload
  sleep 3
  for kv in "notify_elasticsearch:c1 url=http://127.0.0.1:1 index=i format=namespace" \
    "notify_elasticsearch:c2 url=ftp://127.0.0.1:$MOCK_PORT index=i format=namespace" \
    "notify_elasticsearch:c3 url=http://127.0.0.1:$MOCK_PORT index=i format=weird" \
    "notify_elasticsearch:c4 url=http://127.0.0.1:$MOCK_PORT index=i format=namespace username=u"; do
    # shellcheck disable=SC2086
    config_set $kv >>"$WORK/$kind.es-config"
  done
  stop
  mock_stop
  # requests go to one target or the other in any order: each index's requests, in order
  python3 - "$WORK/es.raw" >"$WORK/$kind.es.raw2" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1])]
def idx(r):
    p = r[2].split("/")
    return p[3] if p[1] == "_resolve" else p[1] if len(p) > 1 and p[1] else ""
for group in sorted({idx(r) for r in recs}):
    lines = []
    for r in recs:
        if idx(r) == group:
            r[0] = group or "(root)"
            lines.append(json.dumps(r))
    print("\n".join(sorted(lines) if not group else lines))  # both targets check the server at once
PY
  python3 "$HERE/targets/normalize.py" <"$WORK/$kind.es.raw2" | sed -E 's/"User-Agent[^"]*"//' >"$WORK/$kind.es"
done
compare es
compare es-config

echo "== amqp"
for kind in minio buckets; do
  mock_start amqpmock.py "$WORK/amqp.raw"
  MINIO_NOTIFY_AMQP_ENABLE_a1=on MINIO_NOTIFY_AMQP_URL_a1="amqp://amqpuser:amqppass@127.0.0.1:$MOCK_PORT/vh1" \
    MINIO_NOTIFY_AMQP_EXCHANGE_a1=events MINIO_NOTIFY_AMQP_EXCHANGE_TYPE_a1=fanout MINIO_NOTIFY_AMQP_ROUTING_KEY_a1=rk \
    MINIO_NOTIFY_AMQP_DURABLE_a1=on MINIO_NOTIFY_AMQP_DELIVERY_MODE_a1=2 \
    MINIO_NOTIFY_AMQP_ENABLE_a2=on MINIO_NOTIFY_AMQP_URL_a2="amqp://127.0.0.1:$MOCK_PORT" \
    MINIO_NOTIFY_AMQP_EXCHANGE_a2=stored MINIO_NOTIFY_AMQP_EXCHANGE_TYPE_a2=direct MINIO_NOTIFY_AMQP_PUBLISHING_CONFIRMS_a2=on \
    MINIO_NOTIFY_AMQP_MANDATORY_a2=on MINIO_NOTIFY_AMQP_QUEUE_DIR_a2="$WORK/$kind-amqpq" \
    start "$kind" "$WORK/$kind-amqp"
  curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
  notification arn:minio:sqs::a1:amqp arn:minio:sqs::a2:amqp
  workload
  sleep 3
  for kv in "notify_amqp:c1 url=amqp://127.0.0.1:1 exchange=e" "notify_amqp:c2 url=http://127.0.0.1:$MOCK_PORT exchange=e" \
    "notify_amqp:c3 url=amqp://127.0.0.1:$MOCK_PORT delivery_mode=x" "notify_amqp:c4 url=amqp://127.0.0.1:$MOCK_PORT queue_dir=rel"; do
    # shellcheck disable=SC2086
    config_set $kv >>"$WORK/$kind.amqp-config"
  done
  stop
  mock_stop
  python3 "$HERE/targets/normalize.py" <"$WORK/amqp.raw" >"$WORK/$kind.amqp"
done
compare amqp
compare amqp-config

if [[ -n "${KFAKE_BIN:-}" ]]; then
  echo "== kafka"
  for kind in minio buckets; do
    : >"$WORK/kafka.raw"
    "$KFAKE_BIN" -port "$MOCK_PORT" -out "$WORK/kafka.raw" -topics events,stored,audit,batched &
    MOCK=$!
    for _ in $(seq 50); do nc -z 127.0.0.1 "$MOCK_PORT" 2>/dev/null && break; sleep 0.1; done
    MINIO_NOTIFY_KAFKA_ENABLE_k1=on MINIO_NOTIFY_KAFKA_BROKERS_k1="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_KAFKA_TOPIC_k1=events \
      MINIO_NOTIFY_KAFKA_ENABLE_k2=on MINIO_NOTIFY_KAFKA_BROKERS_k2="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_KAFKA_TOPIC_k2=stored \
      MINIO_NOTIFY_KAFKA_QUEUE_DIR_k2="$WORK/$kind-kafkaq" \
      MINIO_AUDIT_KAFKA_ENABLE_ak=on MINIO_AUDIT_KAFKA_BROKERS_ak="127.0.0.1:$MOCK_PORT" MINIO_AUDIT_KAFKA_TOPIC_ak=audit \
      MINIO_NOTIFY_KAFKA_ENABLE_k3=on MINIO_NOTIFY_KAFKA_BROKERS_k3="127.0.0.1:$MOCK_PORT" MINIO_NOTIFY_KAFKA_TOPIC_k3=batched \
      MINIO_NOTIFY_KAFKA_QUEUE_DIR_k3="$WORK/$kind-kafkabq" MINIO_NOTIFY_KAFKA_BATCH_SIZE_k3=3 MINIO_NOTIFY_KAFKA_BATCH_COMMIT_TIMEOUT_k3=2s \
      start "$kind" "$WORK/$kind-kafka"
    curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
    notification arn:minio:sqs::k1:kafka arn:minio:sqs::k2:kafka arn:minio:sqs::k3:kafka
    workload
    sleep 5 # the batch's 2s commit and its delivery
    for kv in "notify_kafka:c1 brokers=127.0.0.1:1 topic=t" "notify_kafka:c2 brokers=127.0.0.1:x topic=t" \
      "notify_kafka:c3 brokers=127.0.0.1:$MOCK_PORT topic=t version=bogus" \
      "notify_kafka:c4 brokers=127.0.0.1:$MOCK_PORT topic=t batch_size=10" \
      "notify_kafka:c5 brokers=127.0.0.1:$MOCK_PORT topic=t queue_dir=/tmp/q batch_commit_timeout=1s"; do
      # shellcheck disable=SC2086
      config_set $kv >>"$WORK/$kind.kafka-config"
    done
    stop
    mock_stop
    # each topic's requests in order (the two targets run at once)
    python3 - "$WORK/kafka.raw" "$HERE/audit" >"$WORK/$kind.kafka" <<'PY'
import json, re, sys
sys.argv, audit_dir = sys.argv[:2], sys.argv[2]
sys.path.insert(0, audit_dir)
import importlib.util
spec = importlib.util.spec_from_file_location("auditnorm", audit_dir + "/normalize.py")
groups = {}
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r[0] == "Produce" and len(r) > 4 and r[4][0] == "audit":  # audit entries: normalized as audit-interop does
        for rec in r[4][10:]:
            e = json.loads(rec[2])
            for k in ("time", "requestID", "deploymentid"):
                e.pop(k, None)
            for k in ("timeToFirstByte", "timeToFirstByteInNS", "timeToResponse", "timeToResponseInNS", "txHeaders"):
                e.get("api", {}).pop(k, None)
            for k in ("Authorization", "X-Amz-Date", "X-Amz-Content-Sha256", "User-Agent"):
                e.get("requestHeader", {}).pop(k, None)
            for k in ("X-Amz-Request-Id", "X-Amz-Id-2", "Server", "Date", "X-Ratelimit-Limit", "X-Ratelimit-Remaining", "Last-Modified"):
                e.get("responseHeader", {}).pop(k, None)
            e.pop("tags", None)
            e.pop("remotehost", None)
            e.pop("userAgent", None)
            if "bucket" in e.get("api", {}) and e["api"]["bucket"].startswith("probe-bsign-"):
                e["api"]["bucket"] = "probe-bsign-(v)"
                e["requestPath"] = "/probe-bsign-(v)/"
            rec[2] = json.dumps(e, sort_keys=True)
    s = re.sub(r'\\"(eventTime|sequencer|x-amz-request-id|x-amz-id-2|x-minio-deployment-id)\\":\\"[^\\]*\\"', r'\\"\1\\":\\"(v)\\"', json.dumps(r))
    topic = r[4][0] if r[0] == "Produce" and len(r) > 4 and isinstance(r[4], list) else "(metadata)"
    if topic == "batched":  # how sarama splits a stored batch into requests is timing: the records, in order
        for rec in json.loads(s)[4][10:]:
            groups.setdefault(topic, []).append(json.dumps(rec[1:]))  # offset deltas follow the split
        continue
    groups.setdefault(topic, []).append(s)
for t in sorted(groups):
    lines = groups[t]
    if t == "(metadata)":  # how often each client refreshes is not behavior
        lines = sorted(set(lines))
    print("== " + t); print("\n".join(lines))
PY
  done
  compare kafka
  compare kafka-config
fi

if [[ -n "${PG_BIN:-}" ]]; then
  echo "== postgresql"
  # a real server (SCRAM auth, a database per kind), its statement log and the tables compared
  PG_PORT=$((PORT + 2))
  PGDATA="$WORK/pgdata"
  echo secretpw >"$WORK/pgpw"
  "$PG_BIN/initdb" -D "$PGDATA" -U pguser --pwfile="$WORK/pgpw" --auth=scram-sha-256 >/dev/null 2>&1
  for db in minio_db buckets_db; do echo "CREATE DATABASE $db;" | "$PG_BIN/postgres" --single -D "$PGDATA" postgres >/dev/null 2>&1; done
  "$PG_BIN/pg_ctl" -D "$PGDATA" -l "$WORK/pg.log" -o "-p $PG_PORT -c unix_socket_directories='' -c listen_addresses=127.0.0.1 -c log_statement=all -c log_line_prefix='%d|%c|'" start >/dev/null
  for kind in minio buckets; do
    CS="host=127.0.0.1 port=$PG_PORT user=pguser password=secretpw dbname=${kind}_db sslmode=disable"
    MINIO_NOTIFY_POSTGRES_ENABLE_p1=on MINIO_NOTIFY_POSTGRES_CONNECTION_STRING_p1="$CS" MINIO_NOTIFY_POSTGRES_TABLE_p1=nsevents \
      MINIO_NOTIFY_POSTGRES_FORMAT_p1=namespace \
      MINIO_NOTIFY_POSTGRES_ENABLE_p2=on MINIO_NOTIFY_POSTGRES_CONNECTION_STRING_p2="postgres://pguser:secretpw@127.0.0.1:$PG_PORT/${kind}_db?sslmode=disable" \
      MINIO_NOTIFY_POSTGRES_TABLE_p2=accevents MINIO_NOTIFY_POSTGRES_FORMAT_p2=access MINIO_NOTIFY_POSTGRES_QUEUE_DIR_p2="$WORK/$kind-pgq" \
      start "$kind" "$WORK/$kind-pg"
    curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
    notification arn:minio:sqs::p1:postgresql arn:minio:sqs::p2:postgresql
    workload
    sleep 5 # store deliveries included (slower under sanitizers)
    for kv in "notify_postgres:c1 connection_string=host=127.0.0.1\ port=1\ sslmode=disable table=t format=namespace" \
      "notify_postgres:c2 connection_string=x table=bad-name format=namespace" \
      "notify_postgres:c3 connection_string=x table=t format=weird" \
      "notify_postgres:c4 table=t format=namespace" \
      "notify_postgres:c5 connection_string=host=127.0.0.1\ port=$PG_PORT\ user=pguser\ password=wrong\ dbname=postgres\ sslmode=disable table=t format=namespace" \
      "notify_postgres:c6 connection_string=host=127.0.0.1\ port=$PG_PORT table=t format=namespace"; do
      # shellcheck disable=SC2086
      eval config_set $kv >>"$WORK/$kind.pg-config"
    done
    stop
  done
  "$PG_BIN/pg_ctl" -D "$PGDATA" stop >/dev/null
  for kind in minio buckets; do
    # each table's statements in order: which pooled session runs them is timing
    # (MinIO's concurrent sends open more connections), so sessions and pings are dropped
    python3 - "$WORK/pg.log" "${kind}_db" >"$WORK/$kind.pg" <<'PY'
import re, sys
groups, last = {}, {}
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r"([^|]*)\|([^|]*)\|(.*)", line.rstrip("\n"))
    if not m or m.group(1) != sys.argv[2]:
        continue
    text = re.sub(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?([Z+-][0-9:]*)?", "(t)", m.group(3))
    text = re.sub(r'"(eventTime|sequencer|x-amz-request-id|x-amz-id-2|x-minio-deployment-id)": ?"[^"]*"', r'"\1":"(v)"', text)
    if text == "LOG:  statement: ;":
        continue
    t = re.search(r"\b(nsevents|accevents)\b", text)
    table = t.group(1) if t else last.get(m.group(2), "")
    last[m.group(2)] = table
    groups.setdefault(table, []).append(text)
for table in sorted(groups):
    print("== " + table); print("\n".join(groups[table]))
PY
    for tbl in nsevents accevents; do
      echo "SELECT * FROM $tbl ORDER BY 1;" | "$PG_BIN/postgres" --single -D "$PGDATA" "${kind}_db" 2>/dev/null |
        sed -E 's/"(eventTime|sequencer|x-amz-request-id|x-amz-id-2|x-minio-deployment-id)": "[^"]*"/"\1": "(v)"/g; s/event_time = "[^"]*"/event_time = (t)/'
    done >"$WORK/$kind.pg-rows"
  done
  compare pg
  compare pg-rows
  compare pg-config
fi

if [[ -n "${MYSQL_DIR:-}" ]]; then
  echo "== mysql"
  # a real MySQL (caching_sha2_password), its general log and the tables compared
  MY_PORT=$((PORT + 3))
  MYDATA="$WORK/mydata"
  "$MYSQL_DIR/bin/mysqld" --no-defaults --initialize-insecure --datadir="$MYDATA" --basedir="$MYSQL_DIR" >/dev/null 2>&1
  "$MYSQL_DIR/bin/mysqld" --no-defaults --datadir="$MYDATA" --basedir="$MYSQL_DIR" --port="$MY_PORT" --bind-address=127.0.0.1 \
    --socket="$WORK/my.sock" --mysqlx=OFF --general-log=1 --general-log-file="$WORK/mygeneral.log" >"$WORK/mysqld.log" 2>&1 &
  MYSQLD=$!
  for _ in $(seq 100); do "$MYSQL_DIR/bin/mysql" --no-defaults -h127.0.0.1 -P"$MY_PORT" -uroot -e "SELECT 1" >/dev/null 2>&1 && break; sleep 0.2; done
  "$MYSQL_DIR/bin/mysql" --no-defaults -h127.0.0.1 -P"$MY_PORT" -uroot \
    -e "CREATE USER 'myuser'@'%' IDENTIFIED BY 'mypass'; GRANT ALL ON *.* TO 'myuser'@'%'; CREATE DATABASE minio_db; CREATE DATABASE buckets_db;"
  for kind in minio buckets; do
    # an empty caching_sha2_password cache: each client goes through full (RSA) authentication
    "$MYSQL_DIR/bin/mysql" --no-defaults -h127.0.0.1 -P"$MY_PORT" -uroot -e "FLUSH PRIVILEGES"
    MINIO_NOTIFY_MYSQL_ENABLE_y1=on MINIO_NOTIFY_MYSQL_DSN_STRING_y1="myuser:mypass@tcp(127.0.0.1:$MY_PORT)/${kind}_db" \
      MINIO_NOTIFY_MYSQL_TABLE_y1=nsevents MINIO_NOTIFY_MYSQL_FORMAT_y1=namespace \
      MINIO_NOTIFY_MYSQL_ENABLE_y2=on MINIO_NOTIFY_MYSQL_DSN_STRING_y2="myuser:mypass@tcp(127.0.0.1:$MY_PORT)/${kind}_db" \
      MINIO_NOTIFY_MYSQL_TABLE_y2=accevents MINIO_NOTIFY_MYSQL_FORMAT_y2=access MINIO_NOTIFY_MYSQL_QUEUE_DIR_y2="$WORK/$kind-myq" \
      start "$kind" "$WORK/$kind-my"
    curl -s -o /dev/null "${S3[@]}" -X PUT "$EP/tbucket"
    notification arn:minio:sqs::y1:mysql arn:minio:sqs::y2:mysql
    workload
    sleep 5 # store deliveries included (slower under sanitizers)
    for kv in "notify_mysql:c1 dsn_string=u:p@tcp(127.0.0.1:1)/d table=t format=namespace" \
      "notify_mysql:c2 dsn_string=u:p@tcp(127.0.0.1:1 table=t format=namespace" \
      "notify_mysql:c3 dsn_string=nodb table=t format=namespace" \
      "notify_mysql:c4 dsn_string=myuser:wrong@tcp(127.0.0.1:$MY_PORT)/minio_db table=t format=namespace" \
      "notify_mysql:c5 dsn_string=myuser:mypass@tcp(127.0.0.1:$MY_PORT)/minio_db table=t format=weird" \
      "notify_mysql:c6 dsn_string=myuser:mypass@tcp(127.0.0.1:$MY_PORT)/minio_db?tls=bogus table=t format=namespace"; do
      # shellcheck disable=SC2086
      config_set $kv >>"$WORK/$kind.my-config"
    done
    stop
  done
  for kind in minio buckets; do
    python3 - "$WORK/mygeneral.log" "${kind}_db" >"$WORK/$kind.my" <<'PY'
import re, sys
db_of, groups, last = {}, {}, {}
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r"\S+\s+(\d+)\s+(\w+)\t?(.*)", line.rstrip("\n"))
    if not m:
        continue
    tid, cmd, arg = m.groups()
    if cmd == "Connect":
        db_of[tid] = arg.split(" on ")[1].split(" ")[0] if " on " in arg else ""
        continue
    if db_of.get(tid) != sys.argv[2] or cmd in ("Quit", "Ping"):
        continue
    arg = re.sub(r"'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?'", "'(t)'", arg)
    arg = re.sub(r'\\"(eventTime|sequencer|x-amz-request-id|x-amz-id-2|x-minio-deployment-id)\\":\\"[^\\]*\\"', r'\\"\1\\":\\"(v)\\"', arg)
    t = re.search(r"\b(nsevents|accevents)\b", arg)
    table = t.group(1) if t else last.get(tid, "")
    last[tid] = table
    groups.setdefault(table, []).append(cmd + " " + arg)
for table in sorted(groups):
    print("== " + table); print("\n".join(groups[table]))
PY
    for q in "SELECT key_name, key_hash, value FROM nsevents ORDER BY key_name" "SELECT event_data FROM accevents ORDER BY event_data"; do
      "$MYSQL_DIR/bin/mysql" --no-defaults -h127.0.0.1 -P"$MY_PORT" -uroot -D "${kind}_db" -N -e "$q" 2>&1
    done | sed -E 's/"(eventTime|sequencer|x-amz-request-id|x-amz-id-2|x-minio-deployment-id)": "[^"]*"/"\1": "(v)"/g' | sort >"$WORK/$kind.my-rows"
  done
  kill "$MYSQLD" 2>/dev/null || true; wait "$MYSQLD" 2>/dev/null || true
  compare my
  compare my-rows
  compare my-config
fi

echo "notify-targets: $pass passed, $fails failed"
[[ $fails -eq 0 ]]
