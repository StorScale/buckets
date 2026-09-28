#!/usr/bin/env bash
# HTTPS: S3 over TLS with a throwaway certificate, large transfers, plain
# HTTP refused, SNI certificate selection, hot certificate reload, and the
# TLS 1.2 minimum. Certificates are generated for this run only.
#   tests/integration/tls.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19740}
AK=tlsuser
SK=tlssecret1234
OPENSSL=${OPENSSL:-openssl}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-tls-XXXXXX")
EP="https://127.0.0.1:$PORT"
CERTS="$WORK/certs"
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" --cacert "$CERTS/public.crt")
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }
mkcert() { # dir cn san
  mkdir -p "$1"
  "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 1 \
    -keyout "$1/private.key" -out "$1/public.crt" -subj "/CN=$2" -addext "subjectAltName=$3" 2>/dev/null
}
fingerprint() { "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
served() { # [servername] -> fingerprint of the certificate the server presents
  local sni=()
  [[ -n "${1:-}" ]] && sni=(-servername "$1")
  echo | "$OPENSSL" s_client -connect "127.0.0.1:$PORT" ${sni[@]+"${sni[@]}"} 2>/dev/null |
    "$OPENSSL" x509 -noout -fingerprint -sha256 | cut -d= -f2
}
pass=0
fail=0
expect() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$@"; }

mkcert "$CERTS" localhost "DNS:localhost,IP:127.0.0.1"
mkcert "$CERTS/other" other.test "DNS:other.test"
BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$PORT" --certs-dir "$CERTS" \
  "$WORK/d{1...4}" 2>>"$WORK/log" &
PID=$!
for _ in $(seq 50); do curl -sf --cacert "$CERTS/public.crt" "$EP/minio/health/live" >/dev/null && break; sleep 0.1; done

echo "== S3 over HTTPS"
expect "health over TLS" "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERTS/public.crt" "$EP/minio/health/live")" 200
expect "create bucket" "$(status -X PUT "$EP/tlsbucket")" 200
head -c 20000000 /dev/urandom >"$WORK/big"
expect "20 MB upload" "$(status -T "$WORK/big" "$EP/tlsbucket/big.bin")" 200
expect "20 MB download" "$(curl -s "${S3[@]}" "$EP/tlsbucket/big.bin" | md5of)" "$(md5of <"$WORK/big")"
keep=$(curl -s "${S3[@]}" -o /dev/null -o /dev/null -o /dev/null -w '%{num_connects} ' \
  "$EP/minio/health/live" "$EP/minio/health/live" "$EP/minio/health/live" | tr -d ' \n')
expect "keep-alive reuses the TLS connection" "$keep" 100
for i in $(seq 1 12); do head -c 400000 /dev/urandom >"$WORK/p$i"; done
pids=()
for i in $(seq 1 12); do curl -s -o /dev/null "${S3[@]}" -T "$WORK/p$i" "$EP/tlsbucket/p$i" & pids+=($!); done
wait "${pids[@]}"
ok=0; for i in $(seq 1 12); do [[ "$(curl -s "${S3[@]}" "$EP/tlsbucket/p$i" | md5of)" == "$(md5of <"$WORK/p$i")" ]] && ok=$((ok + 1)); done
expect "12 parallel round trips" "$ok" 12
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/minio/health/live" || true)
expect "plain HTTP is refused" "$([[ "$code" != 200 ]] && echo refused)" refused

echo "== certificates"
expect "default certificate" "$(served)" "$(fingerprint "$CERTS/public.crt")"
expect "SNI picks other.test's certificate" "$(served other.test)" "$(fingerprint "$CERTS/other/public.crt")"
expect "unknown names get the default" "$(served nobody.test)" "$(fingerprint "$CERTS/public.crt")"
old=$(fingerprint "$CERTS/public.crt")
mkcert "$WORK/next" localhost "DNS:localhost,IP:127.0.0.1"
cp "$WORK/next/private.key" "$CERTS/private.key.tmp" && cp "$WORK/next/public.crt" "$CERTS/public.crt.tmp"
mv "$CERTS/private.key.tmp" "$CERTS/private.key" && mv "$CERTS/public.crt.tmp" "$CERTS/public.crt"
for _ in $(seq 80); do [[ "$(served)" != "$old" ]] && break; sleep 0.1; done
expect "reloaded without a restart" "$(served)" "$(fingerprint "$CERTS/public.crt")"
expect "requests work with the new certificate" \
  "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERTS/public.crt" "$EP/minio/health/live")" 200
if "$OPENSSL" s_client -help 2>&1 | grep -q -- '-tls1_1'; then
  echo | "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -tls1_1 >/dev/null 2>&1 && v=accepted || v=refused
  expect "TLS 1.1 is refused" "$v" refused
fi

kill "$PID"; wait "$PID" 2>/dev/null || true; PID=
if grep -q 'Sanitizer\|runtime error' "$WORK/log"; then
  fail=$((fail + 1)); echo "  FAIL  sanitizer report:"; grep -A20 'Sanitizer\|runtime error' "$WORK/log" | head -40
fi
echo "== explicit EC parameters are refused at startup"
mkdir -p "$WORK/explicit"
"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:explicit -nodes -days 1 \
  -keyout "$WORK/explicit/private.key" -out "$WORK/explicit/public.crt" -subj /CN=localhost 2>/dev/null
rc=0
"$BIN" server --address "127.0.0.1:$((PORT + 1))" --certs-dir "$WORK/explicit" "$WORK/e{1...4}" 2>"$WORK/explicit.log" &
e=$!
for _ in $(seq 30); do kill -0 $e 2>/dev/null || break; sleep 0.1; done
if kill -0 $e 2>/dev/null; then kill $e; wait $e 2>/dev/null || true; else wait $e || rc=$?; fi
expect "startup fails" "$([[ $rc != 0 ]] && echo failed)" failed
expect "explains why" "$(grep -c 'explicit EC parameters' "$WORK/explicit.log")" 1

echo "tls: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
