#!/usr/bin/env bash
# AssumeRoleWithCertificate (identity_tls): client certificates issued by a
# CA in certs/CAs map to the policy named by their CN; untrusted
# certificates, certificates without the clientAuth usage, no certificate,
# and unknown policies are refused; expiry never outlives the certificate.
#   MC_BIN=/path/to/mc tests/integration/certsts.sh [bucketsd]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" ]]; then
  echo "certsts: skipped (set MC_BIN)"
  exit 0
fi
PORT=${PORT:-19780}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-certsts-XXXXXX")
EP="https://127.0.0.1:$PORT"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; exit 1; }
mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color --insecure "$@"; }

# ---- a CA, the server's certificate, and client certificates ----------------
C="$WORK/pki"
mkdir -p "$C" "$WORK/certs/CAs"
key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null; }
key "$C/ca.key"
openssl req -x509 -sha256 -new -key "$C/ca.key" -days 2 -subj "/CN=Test CA" -out "$C/ca.crt" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
sign() { # name subject days extensions
  key "$C/$1.key"
  openssl req -new -key "$C/$1.key" -subj "$2" -out "$C/$1.csr" 2>/dev/null
  printf '%s\n' "$4" >"$C/$1.ext"
  openssl x509 -req -sha256 -in "$C/$1.csr" -CA "$C/ca.crt" -CAkey "$C/ca.key" -CAcreateserial -days "$3" \
    -extfile "$C/$1.ext" -out "$C/$1.crt" 2>/dev/null
}
sign server "/CN=localhost" 2 "subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth"
sign reader "/CN=readers/O=Buckets QA" 1 "extendedKeyUsage=clientAuth"
sign nopolicy "/CN=nosuchpolicy" 1 "extendedKeyUsage=clientAuth"
sign serveronly "/CN=readers" 1 "extendedKeyUsage=serverAuth"
key "$C/rogue.key"
# self-signed, and explicitly no CA: req -x509's defaults make it one, and CAs in the chain count as intermediates
openssl req -x509 -sha256 -new -key "$C/rogue.key" -days 1 -subj "/CN=readers" -out "$C/rogue.crt" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=clientAuth" 2>/dev/null
cp "$C/server.crt" "$WORK/certs/public.crt"
cp "$C/server.key" "$WORK/certs/private.key"
cp "$C/ca.crt" "$WORK/certs/CAs/ca.crt"

mkdir -p "$WORK"/d{1..4}
BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 MINIO_IDENTITY_TLS_ENABLE=on \
  "$BIN" server --address "127.0.0.1:$PORT" --certs-dir "$WORK/certs" "$WORK/d{1...4}" 2>>"$WORK/log" &
PID=$!
for _ in $(seq 100); do
  mc alias set root "$EP" rootadmin rootsecret123 >/dev/null 2>&1 && mc admin info root >/dev/null 2>&1 && break
  sleep 0.1
done
mc mb root/docs >/dev/null || fail "make bucket"
echo hello | mc pipe root/docs/a.txt >/dev/null || fail "put object"
mc admin policy create root readers <(echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::docs/*"]}]}') >/dev/null ||
  fail "policy"

sts() { # client-cert-name [extra query]
  local certargs=()
  [[ -n "$1" ]] && certargs=(--cert "$C/$1.crt" --key "$C/$1.key")
  curl -s --cacert "$C/ca.crt" ${certargs[@]+"${certargs[@]}"} -X POST \
    "$EP/?Action=AssumeRoleWithCertificate&Version=2011-06-15${2:-}"
}
xml() { sed -n "s:.*<$1>\\(.*\\)</$1>.*:\\1:p"; }
has() { grep -e "$2" >/dev/null <<<"$1" || fail "$3: $(head -c 500 <<<"$1")"; }

echo "== a trusted client certificate"
r=$(sts reader)
has "$r" "<AssumeRoleWithCertificateResult><Credentials>" "result shape"
AK=$(xml AccessKeyId <<<"$r"); SK=$(xml SecretAccessKey <<<"$r"); TK=$(xml SessionToken <<<"$r")
code() { curl -s -o /dev/null -w '%{http_code}' --cacert "$C/ca.crt" --aws-sigv4 "aws:amz:us-east-1:s3" \
  --user "$AK:$SK" -H "X-Amz-Security-Token: $TK" "$@"; }
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "the CN's policy allows reads"
[[ $(code -X PUT --data x "$EP/docs/b.txt") == 403 ]] || fail "and nothing else"
out=$(mc admin user info root "tls/readers" 2>&1 || true)
echo "$out" >>"$WORK/log"

echo "== expiry capped by the certificate"
r=$(sts reader "&DurationSeconds=172800")
exp=$(xml Expiration <<<"$r")
python3 -c "import datetime,sys; e=datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); d=(e-datetime.datetime.now(datetime.timezone.utc)).total_seconds(); sys.exit(0 if 80000<d<86500 else 1)" "$exp" ||
  fail "expiry should be the certificate's (one day): $exp"
has "$(sts reader "&DurationSeconds=60")" "<Code>MissingParameter</Code>" "too short a duration"

echo "== refused"
has "$(sts "")" "No client certificate provided" "no certificate"
has "$(sts rogue)" "<Code>InvalidClientCertificate</Code>" "untrusted certificate"
has "$(sts serveronly)" "<Code>InvalidClientCertificate</Code>" "no clientAuth usage"
has "$(sts nopolicy)" "<Code>InternalError</Code>" "no policy named by the CN"
echo "PASS"
