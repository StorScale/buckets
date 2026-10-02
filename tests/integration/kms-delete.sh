#!/usr/bin/env bash
# Deleting KMS keys (POST /minio/kms/v1/key/delete?key-id=, a Buckets
# extension): a KES key nothing depends on goes; the KMS's default key and a
# key a bucket encrypts with by default are refused (409 KMSKeyInUse, naming
# the buckets); the static builtin key cannot be deleted.
#   FAKEKES=/path/to/fakekes tests/integration/kms-delete.sh [bucketsd]
# (fakekes: cd tests/integration/fakekes && go build -o /tmp/fakekes main.go)
set -euo pipefail
BIN=${1:-build/src/bucketsd}
[[ -n ${FAKEKES:-} ]] || { echo "kms-delete: skipped (set FAKEKES)"; exit 0; }
PORT=${PORT:-19670}
U="http://127.0.0.1:$PORT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-kmsdel-XXXXXX")
PIDS=()
cleanup() { for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
export BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123
R=(--aws-sigv4 aws:amz:us-east-1:s3 --user rootadmin:rootsecret123)
call() { curl -s "${R[@]}" -o "$WORK/out" -w '%{http_code}' "$@"; }
start() { # drives
  "$BIN" server --address "127.0.0.1:$PORT" "$1/d{1...4}" 2>>"$WORK/b.log" &
  PIDS+=($!)
  for _ in $(seq 300); do [[ $(curl -s "${R[@]}" -o /dev/null -w '%{http_code}' "$U/") == 200 ]] && return; sleep 0.1; done
  echo "bucketsd did not start"; tail -5 "$WORK/b.log"; exit 1
}
stop() { kill "${PIDS[-1]}"; wait "${PIDS[-1]}" 2>/dev/null || true; unset 'PIDS[-1]'; }
keys() { call "$U/minio/kms/v1/key/list?pattern=*" >/dev/null; python3 -c 'import json,sys; print(" ".join(sorted(k["name"] for k in json.load(open(sys.argv[1])))))' "$WORK/out"; }

echo "== KES"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" -keyout "$WORK/kes.key" -out "$WORK/kes.crt" >/dev/null 2>&1
"$FAKEKES" -addr "127.0.0.1:$((PORT + 5))" -cert "$WORK/kes.crt" -key "$WORK/kes.key" -keys my-key,spare,team-key \
  2>"$WORK/kes.log" &
PIDS+=($!)
mkdir -p "$WORK"/kes/d{1..4} "$WORK"/static/d{1..4}
MINIO_KMS_KES_ENDPOINT="https://127.0.0.1:$((PORT + 5))" MINIO_KMS_KES_KEY_NAME=my-key MINIO_KMS_KES_CAPATH="$WORK/kes.crt" \
  MINIO_KMS_KES_API_KEY="kes:v1:$(python3 -c 'import os,base64;print(base64.b64encode(b"\0"+os.urandom(32)).decode())')" \
  start "$WORK/kes"
expect "the keys" "$(keys)" "my-key spare team-key"
expect "an unused key is deleted" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=spare")" 200
expect "it is gone" "$(keys)" "my-key team-key"
expect "the default key is refused" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=my-key")" 409
expect "  with KMSKeyInUse" "$(grep -o KMSKeyInUse "$WORK/out")" KMSKeyInUse
call -X PUT "$U/payroll" >/dev/null
call -X PUT "$U/payroll?encryption" -d '<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>team-key</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>' >/dev/null
expect "a bucket's default key is refused" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=team-key")" 409
expect "  naming the bucket" "$(grep -o 'by default: payroll' "$WORK/out")" "by default: payroll"
expect "the key still works" "$(call -X PUT "$U/payroll/doc" --data-binary secret)" 200
call -X DELETE "$U/payroll?encryption" >/dev/null
expect "once the bucket no longer uses it, it can go" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=team-key")" 200
expect "a missing key" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=nosuch")" 500
expect "  says so" "$(grep -o 'key with given key ID does not exist' "$WORK/out")" "key with given key ID does not exist"
expect "the route needs key-id" "$(call -X POST "$U/minio/kms/v1/key/delete")" 501
stop

echo "== the static builtin key"
MINIO_KMS_SECRET_KEY="static-key:$(openssl rand -base64 32)" start "$WORK/static"
expect "it cannot be deleted" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=static-key")" 409
expect "another name is not supported" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=other")" 500
expect "  as not supported" "$(grep -o 'not supported' "$WORK/out")" "not supported"
stop

echo "kms-delete: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
