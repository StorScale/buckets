#!/usr/bin/env bash
# Metrics authentication, MinIO vs bucketsd: bearer JWTs (issuer
# "prometheus", signed with the key owner's secret, owner allowed
# admin:Prometheus), and MINIO_PROMETHEUS_AUTH_TYPE=public.
#   MINIO_BIN=... MC_BIN=... tests/integration/metrics-auth.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "metrics-auth: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
PORT=${PORT:-19870}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-mauth-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID=
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123 MC_CONFIG_DIR="$WORK/mc"
MC() { "$MC_BIN" --quiet --no-color "$@"; }
token() { # access-key secret [issuer]
  python3 - "$@" <<'PY'
import base64, hashlib, hmac, json, sys
ak, sk = sys.argv[1], sys.argv[2]
iss = sys.argv[3] if len(sys.argv) > 3 else "prometheus"
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=")
h = b(json.dumps({"alg": "HS512", "typ": "JWT"}).encode())
p = b(json.dumps({"iss": iss, "sub": ak, "exp": 4102444800}).encode())
s = b(hmac.new(sk.encode(), h + b"." + p, hashlib.sha512).digest())
print((h + b"." + p + b"." + s).decode())
PY
}
start() { # kind dir [public]
  mkdir -p "$2"
  local env=()
  [[ -n "${3:-}" ]] && env=(MINIO_PROMETHEUS_AUTH_TYPE=public)
  if [[ $1 == minio ]]; then
    env ${env[@]+"${env[@]}"} MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$2" >/dev/null 2>&1 &
  else
    env ${env[@]+"${env[@]}"} "$BIN" server --address "127.0.0.1:$PORT" "$2" 2>/dev/null &
  fi
  PID=$!
  for _ in $(seq 150); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "$EP/minio/health/ready") == 200 ]] && return
    sleep 0.1
  done
  echo "$1 did not start"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
probe() { # label [token]
  local h=()
  [[ -n "${2:-}" ]] && h=(-H "Authorization: Bearer $2")
  for p in v2/metrics/cluster v2/metrics/node metrics/v3/api/requests metrics/v3/nothing; do
    local out
    out=$(curl -s -o "$WORK/body" -w '%{http_code}' ${h[@]+"${h[@]}"} "$EP/minio/$p")
    printf '%-18s %-26s %s %s\n' "$1" "$p" "$out" "$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["Code"])
except Exception: print(open(sys.argv[1]).read(40).strip().splitlines()[0] if open(sys.argv[1]).read(40).strip() else "")' "$WORK/body")"
  done
}
run() { # kind
  start "$1" "$WORK/$1"
  MC alias set m "$EP" rootadmin rootsecret123 >/dev/null
  MC admin user add m plain plainsecret123 >/dev/null
  MC admin user add m prom promsecret1234 >/dev/null
  printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:Prometheus"]}]}' >"$WORK/p.json"
  MC admin policy create m promonly "$WORK/p.json" >/dev/null
  MC admin policy attach m promonly --user prom >/dev/null
  probe none
  probe garbage abc.def.ghi
  probe root "$(token rootadmin rootsecret123)"
  probe wrong-secret "$(token rootadmin nottherightone)"
  probe wrong-issuer "$(token rootadmin rootsecret123 someone)"
  probe plain-user "$(token plain plainsecret123)"
  probe prom-user "$(token prom promsecret1234)"
  stop
  start "$1" "$WORK/$1" public
  probe public
  stop
}
run minio >"$WORK/minio.txt"
run buckets >"$WORK/buckets.txt"
if diff -u "$WORK/minio.txt" "$WORK/buckets.txt"; then
  [[ -n "${VERBOSE:-}" ]] && cat "$WORK/buckets.txt"
  echo "metrics-auth: ok ($(wc -l <"$WORK/minio.txt" | tr -d ' ') probes identical)"
else
  echo "metrics-auth: FAIL"; exit 1
fi
