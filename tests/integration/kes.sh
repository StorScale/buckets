#!/usr/bin/env bash
# SSE-S3 / SSE-KMS through KES (MINIO_KMS_KES_*): MinIO and bucketsd use one
# KES server, must answer alike, and must read each other's encrypted
# objects once their drives are swapped. The KES server is buckets-kms
# (BUCKETS_KES: buckets-kes), a real KES (KES_BIN), or tests/integration/fakekes (FAKEKES).
#   MINIO_BIN=/path/to/minio BUCKETS_KES=build/src/buckets-kes tests/integration/kes.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${BUCKETS_KES:-}${KES_BIN:-}${FAKEKES:-}" ]]; then
  echo "kes: skipped (set MINIO_BIN and BUCKETS_KES, KES_BIN or FAKEKES)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19650}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-kes-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
PIDS=()
stop() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  for p in ${PIDS[@]+"${PIDS[@]}"}; do wait "$p" 2>/dev/null || true; done
  PIDS=()
}
cleanup() {
  stop
  kill "$KESPID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" -keyout "$WORK/kes.key" -out "$WORK/kes.crt" >/dev/null 2>&1
export MINIO_KMS_KES_API_KEY="kes:v1:$(python3 -c 'import os,base64;print(base64.b64encode(b"\0"+os.urandom(32)).decode())')"
KESADDR="127.0.0.1:$((PORT + 5))"
if [[ -n "${BUCKETS_KES:-}${KES_BIN:-}" ]]; then
  # a real KES server's config: the servers' API key may manage and use keys
  KMS=${BUCKETS_KES:-$KES_BIN}
  ID=$("${KES_BIN:-$KMS}" identity of "$MINIO_KMS_KES_API_KEY" | tail -1 | awk '{print $NF}')
  cat >"$WORK/kes.yaml" <<EOF
version: v1
address: $KESADDR
admin:
  identity: disabled
tls:
  key: $WORK/kes.key
  cert: $WORK/kes.crt
policy:
  servers:
    allow: [/v1/key/*, /v1/status, /v1/api, /v1/metrics, /v1/identity/self/describe]
    identities: [$ID]
keys: [{name: my-key}, {name: other-key}]
keystore:
  fs:
    path: $WORK/keys
EOF
  "$KMS" server --config "$WORK/kes.yaml" >"$WORK/kes.log" 2>&1 &
  KESPID=$!
  for _ in $(seq 100); do curl -sk -o /dev/null "https://$KESADDR/version" && break; sleep 0.1; done
else
  "$FAKEKES" -addr "$KESADDR" -cert "$WORK/kes.crt" -key "$WORK/kes.key" -keys my-key,other-key 2>"$WORK/kes.log" &
  KESPID=$!
fi
export MINIO_KMS_KES_ENDPOINT="https://$KESADDR" MINIO_KMS_KES_KEY_NAME=my-key
export MINIO_KMS_KES_CAPATH="$WORK/kes.crt"
start() { # minio-drives buckets-drives
  MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$1/d{1...4}" \
    >>"$WORK/m.log" 2>&1 &
  PIDS+=($!)
  "$BIN" server --address "127.0.0.1:$((PORT + 1))" "$2/d{1...4}" 2>>"$WORK/b.log" &
  PIDS+=($!)
  for p in $PORT $((PORT + 1)); do
    for _ in $(seq 300); do
      [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
      sleep 0.1
    done
  done
}
start "$WORK/m" "$WORK/b"
python3 "$HERE/kes_cases.py" "$PORT" rootadmin rootsecret123 fresh || RC=1
stop
start "$WORK/b" "$WORK/m" # each reads what the other wrote
python3 "$HERE/kes_cases.py" "$PORT" rootadmin rootsecret123 swapped || RC=1
exit ${RC:-0}
