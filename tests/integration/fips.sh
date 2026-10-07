#!/usr/bin/env bash
# FIPS 140-3 mode (docs/fips.md): a server with BUCKETS_FIPS=on installs and
# loads the OpenSSL FIPS provider, says so (log, admin info, metric), serves
# S3, SSE-S3, SSE-C and STS through it, and accepts an admin payload from a
# standard mc (Argon2id, outside the module). It refuses what the module
# lacks: TLS with ChaCha20 or X25519, data sealed with ChaCha20 (written
# beforehand outside FIPS mode, and counted by the encryption report), an
# Ed25519 SFTP host key, and, in strict mode, Argon2id admin payloads.
#   tests/integration/fips.sh [bucketsd]
# Needs a FIPS provider: .deps/fips-<version> (cmake -DBUCKETS_FIPS_PROVIDER=ON),
# or BUCKETS_FIPS_MODULE and BUCKETS_FIPS_OPENSSL. Skips (exit 0) without one.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FIPS_DIR=$(ls -d "$ROOT"/.deps/fips-* 2>/dev/null | tail -1 || true)
export BUCKETS_FIPS_MODULE=${BUCKETS_FIPS_MODULE:-$FIPS_DIR/lib/ossl-modules/fips.so}
export BUCKETS_FIPS_OPENSSL=${BUCKETS_FIPS_OPENSSL:-$FIPS_DIR/bin/openssl}
if [[ ! -r $BUCKETS_FIPS_MODULE ]]; then
  echo "fips: skipped (no FIPS provider; cmake -DBUCKETS_FIPS_PROVIDER=ON builds one)"
  exit 0
fi
PORT=${PORT:-19970}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-fips-XXXXXX")
EP="https://localhost:$PORT"
P=0
cleanup() {
  [[ $P != 0 ]] && kill "$P" 2>/dev/null || true
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
until_true() { for _ in $(seq "${2:-150}"); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

# an ECDSA P-256 certificate: a key FIPS mode can use
mkdir -p "$WORK/certs" "$WORK"/d{1..4}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$WORK/certs/private.key" -out "$WORK/certs/public.crt" 2>/dev/null
KMS="test-key:$(openssl rand -base64 32)"
start() { # [env...]
  env MINIO_KMS_SECRET_KEY="$KMS" MINIO_PROMETHEUS_AUTH_TYPE=public BUCKETS_SCANNER_INTERVAL=1 \
    BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 "$@" \
    "$BIN" server --address "localhost:$PORT" --certs-dir "$WORK/certs" "$WORK/d{1...4}" 2>>"$WORK/log" &
  P=$!
  until_true "curl -sf --cacert $WORK/certs/public.crt $EP/minio/health/ready" || true
}
stop() { kill "$P"; wait "$P" 2>/dev/null || true; P=0; }
export MC_CONFIG_DIR="$WORK/mc" SSL_CERT_FILE="$WORK/certs/public.crt"
export MC_HOST_f="https://rootadmin:rootsecret123@localhost:$PORT"
api() { curl -s --cacert "$WORK/certs/public.crt" --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 "$@"; }

# ---- outside FIPS mode: an object sealed with ChaCha20, as MinIO writes on CPUs without AES ----
start BUCKETS_DARE_TEST_CIPHER=chacha20
mc mb f/data >/dev/null
echo "old secret" | mc pipe --enc-s3 f/data f/data/chacha >/dev/null
until_true "[[ \$(api $EP/minio/admin/v3/buckets/compliance | python3 -c 'import json,sys; print([b[\"counts\"][\"chacha20\"][\"versions\"] for b in json.load(sys.stdin)[\"buckets\"] if b[\"counts\"]])') == '[1]' ]]" 300 || true
expect "the encryption report counts the ChaCha20 version" \
  "$(api $EP/minio/admin/v3/buckets/compliance | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["fips"], d["buckets"][0]["counts"]["chacha20"]["versions"])')" "False 1"
stop

# ---- FIPS mode ----------------------------------------------------------------------------------------
start BUCKETS_FIPS=on
expect "the log names the module" "$(grep -o 'FIPS 140-3 mode, with OpenSSL FIPS Provider [0-9.]*' "$WORK/log" | head -1)" \
  "FIPS 140-3 mode, with OpenSSL FIPS Provider $(basename "$FIPS_DIR" | sed 's/fips-//')"
expect "admin info says so" "$(api $EP/minio/admin/v3/info | python3 -c 'import json,sys; s=json.load(sys.stdin)["servers"][0]["fips"]; print(s["enabled"], s["module"].startswith("OpenSSL FIPS Provider"))')" "True True"
expect "and the metric" "$(curl -s --cacert "$WORK/certs/public.crt" $EP/minio/v2/metrics/node | grep '^buckets_node_fips_mode' | awk '{print $2}')" 1
echo "hello" | mc pipe f/data/plain >/dev/null
expect "S3: put and get" "$(mc cat f/data/plain)" hello
echo "new secret" | mc pipe --enc-s3 f/data f/data/aes >/dev/null
expect "SSE-S3 through the module" "$(mc cat f/data/aes)" "new secret"
SSEC="f/data/ssec=$(openssl rand -hex 32)"
echo "customer" | mc pipe --enc-c "$SSEC" f/data/ssec >/dev/null
expect "SSE-C through the module" "$(mc cat --enc-c "$SSEC" f/data/ssec)" customer
expect "data sealed with ChaCha20 is refused, saying why" \
  "$(curl -s --cacert "$WORK/certs/public.crt" --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 $EP/data/chacha | sed -n 's:.*<Message>\(.*\)</Message>.*:\1:p' | cut -c1-71)" \
  "FIPS mode: this object is encrypted with ChaCha20-Poly1305, which the F"
expect "and the log names it" "$(grep -c 'fips: data/chacha is encrypted with ChaCha20-Poly1305' "$WORK/log")" 1
expect "the encryption report: FIPS mode, ChaCha20 data counted" \
  "$(api $EP/minio/admin/v3/buckets/compliance | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["fips"], d["buckets"][0]["counts"]["chacha20"]["versions"] >= 1)')" "True True"
mc admin user add f alice alicesecret123 >/dev/null 2>&1 || true
expect "an admin payload from a standard mc (Argon2id) is accepted" "$(mc admin user info f alice --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["userStatus"])')" enabled
mc admin policy attach f readwrite --user alice >/dev/null
sts=$(curl -s --cacert "$WORK/certs/public.crt" --aws-sigv4 "aws:amz:us-east-1:sts" --user alice:alicesecret123 -X POST \
  -d "Action=AssumeRole&Version=2011-06-15&DurationSeconds=900" "$EP/")
expect "STS: temporary credentials" "$(grep -c '<SessionToken>' <<<"$sts")" 1
# TLS: what the module provides, and nothing else
tls() { curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/certs/public.crt" "$@" "$EP/minio/health/live"; }
expect "TLS 1.3 with AES-GCM" "$(tls --tlsv1.3 --tls13-ciphers TLS_AES_256_GCM_SHA384)" 200
expect "TLS 1.3 with ChaCha20 is refused" "$(tls --tlsv1.3 --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256)" 000
expect "TLS 1.2 with ChaCha20 is refused" "$(tls --tlsv1.2 --tls-max 1.2 --ciphers ECDHE-ECDSA-CHACHA20-POLY1305)" 000
expect "X25519 key exchange is refused" "$(tls --curves X25519)" 000
expect "P-256 key exchange" "$(tls --curves P-256)" 200
stop

# ---- strict mode: Argon2id admin payloads refused too -----------------------------------------------
start BUCKETS_FIPS=on BUCKETS_FIPS_STRICT=on
expect "strict: a standard mc's admin payload is refused, saying why" \
  "$(mc admin user add f bob bobsecret12345 2>&1 | grep -o 'FIPS strict mode: the request is sealed with Argon2id')" \
  "FIPS strict mode: the request is sealed with Argon2id"
stop

# ---- SFTP: an Ed25519 host key can't sign in FIPS mode ----------------------------------------------
ssh-keygen -q -t ed25519 -N '' -f "$WORK/ed25519" 2>/dev/null
out=$(env BUCKETS_FIPS=on BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 timeout 20 "$BIN" server \
  --address "localhost:$PORT" --sftp "address=:$((PORT + 1))" --sftp "ssh-private-key=$WORK/ed25519" "$WORK/d{1...4}" 2>&1 || true)
expect "SFTP: an Ed25519 host key is refused" "$(grep -c 'FIPS mode needs an ECDSA (NIST curve) or RSA host key' <<<"$out")" 1

expect "no sanitizer reports" "$(grep -c 'Sanitizer\|runtime error' "$WORK/log" || true)" 0
echo "fips: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
