#!/usr/bin/env bash
# buckets-kes against a real KES server, request for request
# (kes_diff_cases.py): the same config, certificates and requests to both;
# then each serves the other's keystore (KES's fs format) and decrypts the
# other's ciphertexts.
#   KES_BIN=/path/to/kes KMSREQ=/path/to/kmsreq tests/integration/kes-diff.sh [buckets-kes]
# (KES_BIN: a KES server built from github.com/minio/kes; KMSREQ:
# tests/integration/kmsreq, which sends the requests with Go's TLS.)
set -uo pipefail
KMS=${1:-build/src/buckets-kes}
if [[ -z "${KES_BIN:-}" || -z "${KMSREQ:-}" ]]; then
  echo "kes-diff: skipped (set KES_BIN and KMSREQ)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
KMS=$(cd "$(dirname "$KMS")" && pwd)/$(basename "$KMS")
PORT=${PORT:-19670}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-kes-diff-XXXXXX")
PIDS=()
stop() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  for p in ${PIDS[@]+"${PIDS[@]}"}; do wait "$p" 2>/dev/null || true; done
  PIDS=()
}
cleanup() {
  stop
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
# the servers' certificate, and clients: admin, app, ops (allow and deny rules), stranger (no policy)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
  -keyout server.key -out server.crt >/dev/null 2>&1
for c in admin app ops stranger; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$c" \
    -keyout "$c.key" -out "$c.crt" >/dev/null 2>&1
  eval "ID_$c=\$(\"$KMS\" identity of $c.crt)"
done
APIKEY="kes:v1:$(python3 -c 'import os,base64;print(base64.b64encode(b"\0"+os.urandom(32)).decode())')"
ID_apikey=$("$KES_BIN" identity of "$APIKEY" | tail -1)
config() { # address keystore-dir [seal]
  cat <<EOF
version: v1
address: $1
admin:
  identity: \${KMS_ADMIN}
tls:
  key: $WORK/server.key
  cert: $WORK/server.crt
policy:
  app:
    allow:
    - /v1/key/create/app-*
    - /v1/key/generate/app-*
    - /v1/key/decrypt/app-*
    - /v1/key/encrypt/app-*
    - /v1/key/describe/*
    - /v1/key/list/*
    - /v1/status
    identities: [$ID_app, $ID_apikey]
  ops:
    allow: [/v1/key/*, /v1/policy/*, /v1/identity/*]
    deny: [/v1/key/delete/*, /v1/key/decrypt/app-secret*]
    identities: [$ID_ops]
keys: [{name: preset-key}]
log:
  error: on
  audit: on
keystore:
  fs:
    path: $2
EOF
  [[ -n "${3:-}" ]] && echo "    seal: $3"
}
export KMS_ADMIN=$ID_admin
config "127.0.0.1:$PORT" "$WORK/kes-keys" >kes.yaml
config "127.0.0.1:$((PORT + 1))" "$WORK/kms-keys" >kms.yaml
start() { # kes-config kms-config
  "$KES_BIN" server --config "$1" >>kes.log 2>&1 &
  PIDS+=($!)
  "$KMS" server --config "$2" >>kms.log 2>&1 &
  PIDS+=($!)
  for p in $PORT $((PORT + 1)); do
    for _ in $(seq 100); do curl -sk -o /dev/null "https://127.0.0.1:$p/version" && break; sleep 0.1; done
  done
}
export KES_CLIENT=$KES_BIN APIKEY WORK
start kes.yaml kms.yaml
python3 "$HERE/kes_diff_cases.py" "$PORT" fresh || RC=1
stop
# each serves the other's keystore
mv kes-keys swap && mv kms-keys kes-keys && mv swap kms-keys
start kes.yaml kms.yaml
python3 "$HERE/kes_diff_cases.py" "$PORT" swapped || RC=1
stop
exit ${RC:-0}
