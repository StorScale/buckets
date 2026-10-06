#!/usr/bin/env bash
# buckets-kes, Buckets' own KES-compatible key server, behind bucketsd:
# SSE-S3 and SSE-KMS through it, its key API through bucketsd's KMS API, its
# policies (bucketsd may not import keys), its errors, a restart, and keys
# kept as MinIO KES keeps them.
#   tests/integration/buckets-kes.sh [bucketsd] [buckets-kes]
# Google Secret Manager runs against tests/integration/gcpmock.py. Optional:
# KES_BIN (MinIO's kes) reads the keys buckets-kes made and the other way
# round; VAULT_BIN runs the same against a Vault dev server; MOTO_SERVER
# (moto's moto_server) for AWS Secrets Manager; LOWKEY_JAR (Lowkey Vault's
# jar, and java) for Azure Key Vault.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(realpath "${1:-build/src/bucketsd}")
KES=$(realpath "${2:-$(dirname "$BIN")/buckets-kes}")
PORT=${PORT:-19720}
KPORT=$((PORT + 3))
U="http://127.0.0.1:$PORT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-kes-XXXXXX")
PIDS=()
cleanup() { [[ -n ${KEEP:-} ]] && { echo "kept $WORK"; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; return; }; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
cd "$WORK"
# an API key and its identity (kms-go's: SHA-256 of the Ed25519 public key's SPKI)
apikey() { echo "kes:v1:$( (printf '\0'; head -c 32 /dev/urandom) | base64 -w0)"; }
ident() {
  local seed
  seed=$(echo "${1#kes:v1:}" | base64 -d | tail -c 32 | xxd -p -c 64)
  echo "302e020100300506032b657004220420$seed" | xxd -r -p | openssl pkey -inform DER -pubout -outform DER | sha256sum | cut -d' ' -f1
}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=kes \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout srv.key -out srv.crt >/dev/null 2>&1
# the admin: an ECDSA client certificate curl can present (not a CA: KES ignores those)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=admin \
  -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=clientAuth -keyout admin.key -out admin.crt >/dev/null 2>&1
ADMIN=$("$KES" identity of admin.crt)
CLIENT=$(apikey)
config() { # port keystore-json
  cat <<EOF
{"version": "v1", "address": "127.0.0.1:$1", "admin": {"identity": "$ADMIN"},
 "tls": {"key": "$WORK/srv.key", "cert": "$WORK/srv.crt"},
 "policy": {"buckets": {"allow": ["/v1/key/create/*", "/v1/key/generate/*", "/v1/key/decrypt/*", "/v1/key/list/*",
            "/v1/key/delete/*", "/v1/status", "/v1/metrics", "/v1/api"], "deny": ["/v1/key/delete/protected"],
            "identities": ["$(ident "$CLIENT")"]}},
 "api": {"/v1/ready": {"skip_auth": true}},
 "keys": [{"name": "buckets-default"}],
 "keystore": $2}
EOF
}
start_kes() { # binary config
  ! curl -sk -o /dev/null "https://127.0.0.1:$KPORT/version" || { echo "a key server is still running on $KPORT"; exit 1; }
  "$1" server --config "$2" >>kes.log 2>&1 &
  PIDS+=($!)
  for _ in $(seq 100); do [[ $(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$KPORT/version") == 200 ]] && return; sleep 0.1; done
  echo "the key server did not start"; tail -5 kes.log; exit 1
}
stop_last() { kill "${PIDS[-1]}" 2>/dev/null || true; wait "${PIDS[-1]}" 2>/dev/null || true; unset 'PIDS[-1]'; }
export BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123
R=(--aws-sigv4 aws:amz:us-east-1:s3 --user rootadmin:rootsecret123)
start_bucketsd() {
  mkdir -p d/{1..4}
  MINIO_KMS_KES_ENDPOINT="https://localhost:$KPORT" MINIO_KMS_KES_KEY_NAME=buckets-default MINIO_KMS_KES_API_KEY="$CLIENT" \
    MINIO_KMS_KES_CAPATH="$WORK/srv.crt" "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d/{1...4}" >>b.log 2>&1 &
  PIDS+=($!)
  for _ in $(seq 300); do [[ $(curl -s "${R[@]}" -o /dev/null -w '%{http_code}' "$U/") == 200 ]] && return; sleep 0.1; done
  echo "bucketsd did not start"; tail -5 b.log; exit 1
}
call() { curl -s "${R[@]}" -o out -w '%{http_code}' "$@"; }
A=(-sk --cert admin.crt --key admin.key)
K="https://127.0.0.1:$KPORT"

echo "== buckets-kes (fs) behind bucketsd"
config "$KPORT" "{\"fs\": {\"path\": \"$WORK/keys\"}}" >kes.json
start_kes "$KES" kes.json
expect "the configured key exists at startup" "$(ls keys)" buckets-default
expect "ready without an identity (skip_auth)" "$(curl -sk -o /dev/null -w '%{http_code}' "$K/v1/ready")" 200
expect "anything else needs one" "$(curl -sk "$K/v1/status" | grep -o 'client certificate is required')" "client certificate is required"
start_bucketsd
expect "bucketsd's KMS is KES" "$(call "$U/minio/kms/v1/status"; grep -o '"default-key-id":"buckets-default"' out)" '200"default-key-id":"buckets-default"'
call -X PUT "$U/enc" >/dev/null
expect "SSE-KMS write" "$(call -X PUT "$U/enc/a" -H 'x-amz-server-side-encryption: aws:kms' --data-binary kms-data)" 200
expect "SSE-S3 write" "$(call -X PUT "$U/enc/b" -H 'x-amz-server-side-encryption: AES256' --data-binary s3-data)" 200
expect "SSE-KMS read" "$(curl -s "${R[@]}" "$U/enc/a")" kms-data
expect "SSE-S3 read" "$(curl -s "${R[@]}" "$U/enc/b")" s3-data
expect "a key through bucketsd" "$(call -X POST "$U/minio/kms/v1/key/create?key-id=team-key")" 200
call -X PUT "$U/team" >/dev/null
sse() { echo "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>$1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"; }
call -X PUT "$U/team?encryption" -d "$(sse team-key)" >/dev/null
expect "SSE-KMS with it (the bucket's default)" "$(call -X PUT "$U/team/c" --data-binary team)" 200
expect "  with that key" "$(curl -s "${R[@]}" -I "$U/team/c" | tr -d '\r' | grep -i 'kms-key-id' | sed 's/.*: //')" "arn:aws:kms:team-key"
expect "  reads back" "$(curl -s "${R[@]}" "$U/team/c")" team
call -X PUT "$U/nokey" >/dev/null
expect "an unknown key is refused as the bucket's default" "$(call -X PUT "$U/nokey?encryption" -d "$(sse nosuch)"; grep -o 'KeyNotFound\|does not exist' out | head -1)" "404KeyNotFound"
expect "keys listed" "$(call "$U/minio/kms/v1/key/list?pattern=*" >/dev/null; python3 -c 'import json; print(" ".join(sorted(k["name"] for k in json.load(open("out")))))')" "buckets-default team-key"
expect "the key status check" "$(call "$U/minio/kms/v1/key/status?key-id=team-key"; grep -c 'error' out)" 2000
# the policy: bucketsd may not import keys, nor delete what is denied
curl "${A[@]}" -X PUT "$K/v1/key/create/protected" -o /dev/null
expect "a denied path" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=protected"; grep -o 'insufficient permissions\|NotAuthorized' out | head -1)" "500insufficient permissions"
expect "the admin may" "$(curl "${A[@]}" -X DELETE -o /dev/null -w '%{http_code}' "$K/v1/key/delete/protected")" 200
expect "a deleted key" "$(curl "${A[@]}" -o /dev/null -w '%{http_code}' "$K/v1/key/describe/protected")" 404
expect "decrypting with the wrong context" "$(curl "${A[@]}" -X PUT "$K/v1/key/decrypt/team-key" -d '{"ciphertext":"'"$(head -c 60 /dev/urandom | base64 -w0)"'"}' | grep -o 'not authentic')" "not authentic"
echo "== minio_cluster_kms_online follows KES"
# a metrics token for root, as mc admin prometheus generate makes it (HS512, issuer prometheus)
TOKEN=$(python3 -c '
import base64, hashlib, hmac, json, time
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
m = b(json.dumps({"alg": "HS512", "typ": "JWT"}).encode()) + "." + b(json.dumps({"exp": int(time.time()) + 3600, "sub": "rootadmin", "iss": "prometheus"}).encode())
print(m + "." + b(hmac.new(b"rootsecret123", m.encode(), hashlib.sha512).digest()))')
kms_online() { curl -s -H "Authorization: Bearer $TOKEN" "$U/minio/v2/metrics/cluster" | sed -n 's/^minio_cluster_kms_online{[^}]*} //p'; }
expect "online while KES answers" "$(kms_online)" 1
KESPID=${PIDS[-2]}
kill "$KESPID"; wait "$KESPID" 2>/dev/null || true
for _ in $(seq 45); do [[ $(kms_online) == 0 ]] && break; sleep 1; done
expect "offline once it stops (within the 30s it is cached)" "$(kms_online)" 0
start_kes "$KES" kes.json
for _ in $(seq 45); do [[ $(kms_online) == 1 ]] && break; sleep 1; done
expect "online again" "$(kms_online)" 1
echo "== a restart: keys stay, objects read"
stop_last; stop_last
start_kes "$KES" kes.json
start_bucketsd
expect "SSE-KMS after restarts" "$(curl -s "${R[@]}" "$U/team/c")" team
expect "SSE-S3 after restarts" "$(curl -s "${R[@]}" "$U/enc/b")" s3-data
stop_last

if [[ -n ${KES_BIN:-} ]]; then
  echo "== MinIO KES on the same keys"
  stop_last
  start_kes "$KES_BIN" kes.json
  start_bucketsd
  expect "MinIO KES decrypts what buckets-kes wrapped" "$(curl -s "${R[@]}" "$U/team/c")" team
  expect "  and SSE-S3" "$(curl -s "${R[@]}" "$U/enc/b")" s3-data
  expect "MinIO KES makes a key" "$(call -X POST "$U/minio/kms/v1/key/create?key-id=minio-made")" 200
  call -X PUT "$U/mbkt" >/dev/null
  call -X PUT "$U/mbkt?encryption" -d "$(sse minio-made)" >/dev/null
  call -X PUT "$U/mbkt/m" --data-binary minio >/dev/null
  stop_last; stop_last
  start_kes "$KES" kes.json
  start_bucketsd
  expect "buckets-kes reads MinIO KES's key" "$(curl -s "${R[@]}" "$U/mbkt/m")" minio
  stop_last
fi
stop_last

if [[ -n ${VAULT_BIN:-} ]]; then
  echo "== Vault (KV v2, AppRole, Transit)"
  VPORT=$((PORT + 7))
  "$VAULT_BIN" server -dev -dev-root-token-id=root -dev-listen-address="127.0.0.1:$VPORT" >vault.log 2>&1 &
  PIDS+=($!)
  export VAULT_ADDR="http://127.0.0.1:$VPORT" VAULT_TOKEN=root
  for _ in $(seq 50); do "$VAULT_BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
  V() { "$VAULT_BIN" "$@"; }
  V secrets enable -version=2 kv >/dev/null; V secrets enable transit >/dev/null; V write -f transit/keys/wrap >/dev/null
  V auth enable approle >/dev/null
  printf 'path "kv/data/b/*" {capabilities = ["create","read","delete"]}\npath "kv/metadata/b/*" {capabilities = ["list","delete"]}\npath "kv/metadata/b" {capabilities = ["list"]}\npath "transit/encrypt/wrap" {capabilities = ["update"]}\npath "transit/decrypt/wrap" {capabilities = ["update"]}\n' |
    V policy write kes - >/dev/null
  V write auth/approle/role/kes token_policies=kes token_ttl=5s token_max_ttl=1h >/dev/null
  RID=$(V read -field=role_id auth/approle/role/kes/role-id)
  SID=$(V write -f -field=secret_id auth/approle/role/kes/secret-id)
  vks() { echo "{\"vault\": {\"endpoint\": \"$VAULT_ADDR\", \"engine\": \"kv\", \"version\": \"v2\", \"prefix\": \"b\", \"approle\": {\"id\": \"$RID\", \"secret\": \"$1\"}, \"transit\": {\"key\": \"wrap\"}}}"; }
  config "$KPORT" "$(vks bad-secret)" >bad.json
  expect "a wrong secret ID stops it, saying so" "$("$KES" server --config bad.json 2>&1 | grep -o 'invalid role or secret ID')" "invalid role or secret ID"
  config "$KPORT" "$(vks "$SID")" >vault.json
  start_kes "$KES" vault.json
  rm -rf d
  start_bucketsd
  call -X PUT "$U/vbkt" >/dev/null
  expect "SSE-KMS on Vault" "$(call -X PUT "$U/vbkt/o" -H 'x-amz-server-side-encryption: aws:kms' --data-binary in-vault)" 200
  expect "  reads back" "$(curl -s "${R[@]}" "$U/vbkt/o")" in-vault
  expect "the key is in Vault, wrapped by Transit" "$(V kv get -field=buckets-default kv/b/buckets-default | cut -c1-9)" "vault:v1:"
  sleep 12 # the 5 s token renewed (or signed in again) twice
  expect "a new key after the token expired" "$(call -X POST "$U/minio/kms/v1/key/create?key-id=later")" 200
  stop_last; stop_last
  start_kes "$KES" vault.json
  start_bucketsd
  expect "SSE-KMS after restarts" "$(curl -s "${R[@]}" "$U/vbkt/o")" in-vault
  if [[ -n ${KES_BIN:-} ]]; then
    stop_last; stop_last
    start_kes "$KES_BIN" vault.json
    start_bucketsd
    expect "MinIO KES reads buckets-kes's Vault keys" "$(curl -s "${R[@]}" "$U/vbkt/o")" in-vault
  fi
  stop_last; stop_last
fi

# A cloud key store behind bucketsd: SSE-KMS, a new key, a restart, the key
# listed and deleted.
cloud() { # label keystore-json
  config "$KPORT" "$2" >cloud.json
  start_kes "$KES" cloud.json
  rm -rf d
  start_bucketsd
  call -X PUT "$U/cloud" >/dev/null
  expect "$1: SSE-KMS write" "$(call -X PUT "$U/cloud/o" -H 'x-amz-server-side-encryption: aws:kms' --data-binary "in $1")" 200
  expect "$1: a key through bucketsd" "$(call -X POST "$U/minio/kms/v1/key/create?key-id=cloud-key")" 200
  stop_last; stop_last
  start_kes "$KES" cloud.json
  start_bucketsd
  expect "$1: reads back after restarts" "$(curl -s "${R[@]}" "$U/cloud/o")" "in $1"
  expect "$1: keys listed" "$(call "$U/minio/kms/v1/key/list?pattern=*" >/dev/null; python3 -c 'import json; print(" ".join(sorted(k["name"] for k in json.load(open("out")))))')" "buckets-default cloud-key"
  expect "$1: a key deleted" "$(call -X POST "$U/minio/kms/v1/key/delete?key-id=cloud-key")" 200
  expect "$1: and gone" "$(curl "${A[@]}" -o /dev/null -w '%{http_code}' "$K/v1/key/describe/cloud-key")" 404
  stop_last; stop_last
}

echo "== Google Secret Manager (mock)"
GPORT=$((PORT + 12)) # clear of Vault, whose dev server also takes its port + 1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out sa.pem 2>/dev/null
openssl pkey -in sa.pem -pubout -out sa.pub
python3 "$HERE/gcpmock.py" "$GPORT" "$WORK/sa.pub" kes@p1.iam.gserviceaccount.com p1 2>gcp.log &
PIDS+=($!)
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$GPORT/v1" && break; sleep 0.2; done
export GOOGLE_OAUTH_TOKEN_URI="http://127.0.0.1:$GPORT/token"
GKS=$(python3 -c 'import json,sys; print(json.dumps({"gcp": {"secretmanager": {"project_id": "p1", "endpoint": sys.argv[1],
  "credentials": {"client_email": "kes@p1.iam.gserviceaccount.com", "private_key_id": "k", "private_key": open("sa.pem").read()}}}}))' \
  "http://127.0.0.1:$GPORT")
cloud gcp "$GKS"

if [[ -n ${MOTO_SERVER:-} ]]; then
  echo "== AWS Secrets Manager (moto)"
  MPORT=$((PORT + 13))
  "$MOTO_SERVER" -p "$MPORT" >moto.log 2>&1 &
  PIDS+=($!)
  for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$MPORT/" && break; sleep 0.2; done
  cloud aws "{\"aws\": {\"secretsmanager\": {\"endpoint\": \"http://127.0.0.1:$MPORT\", \"region\": \"us-east-1\",
    \"credentials\": {\"accesskey\": \"AKIDTEST\", \"secretkey\": \"secret\"}}}}"
fi

if [[ -n ${LOWKEY_JAR:-} ]]; then
  echo "== Azure Key Vault (Lowkey Vault, managed identity)"
  LPORT=$((PORT + 14))
  java -jar "$LOWKEY_JAR" --server.port="$LPORT" --app.token.port=$((LPORT + 1)) >lowkey.log 2>&1 &
  PIDS+=($!)
  for _ in $(seq 120); do curl -sk -o /dev/null "https://127.0.0.1:$LPORT/ping" && break; sleep 0.5; done
  echo | openssl s_client -connect "127.0.0.1:$LPORT" 2>/dev/null | openssl x509 >lowkey-ca.pem
  # a vault whose deleted secrets may be purged, as KES's deletes need
  curl -sk -X DELETE "https://127.0.0.1:$LPORT/management/vault?baseUri=https://127.0.0.1:$LPORT" >/dev/null
  curl -sk -X DELETE "https://127.0.0.1:$LPORT/management/vault/purge?baseUri=https://127.0.0.1:$LPORT" >/dev/null
  curl -sk -X POST "https://127.0.0.1:$LPORT/management/vault" -H 'Content-Type: application/json' \
    -d "{\"baseUri\":\"https://127.0.0.1:$LPORT\",\"recoveryLevel\":\"Recoverable+Purgeable\",\"recoverableDays\":90}" >/dev/null
  SSL_CERT_FILE="$WORK/lowkey-ca.pem" AZURE_IMDS_ENDPOINT="http://127.0.0.1:$((LPORT + 1))" \
    cloud azure "{\"azure\": {\"keyvault\": {\"endpoint\": \"https://127.0.0.1:$LPORT\", \"managed_identity\": {\"client_id\": \"mi\"}}}}"
fi

echo "buckets-kes: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
