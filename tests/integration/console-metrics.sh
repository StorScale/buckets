#!/usr/bin/env bash
# consoled's /metrics (src/console/console.c): failed sign-ins by method, for
# exactly the bearer tokens bucketsd accepts for its own metrics (one made by
# `mc admin prometheus generate`), or anyone when bucketsd's metrics are
# public (MINIO_PROMETHEUS_AUTH_TYPE=public).
#   MC_BIN=/path/to/mc tests/integration/console-metrics.sh [bucketsd] [consoled]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
if [[ -z "${MC_BIN:-}" ]]; then
  echo "console-metrics: skipped (set MC_BIN)"
  exit 0
fi
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
PORT=${PORT:-19800}
CPORT=$((PORT + 1))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-cmetrics-XXXXXX")
EP="http://127.0.0.1:$PORT"
C="http://127.0.0.1:$CPORT"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
pass=0
fail=0
check() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); else
    fail=$((fail + 1))
    echo "FAIL: $1: got '$2', want '$3'"
  fi
}
start() { # [env...]: bucketsd and consoled, fresh
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  PIDS=()
  env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 "$@" \
    "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
  PIDS+=($!)
  for _ in $(seq 150); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.1; done
  env CONSOLE_MINIO_SERVER="$EP" CONSOLE_PBKDF_PASSPHRASE=it CONSOLE_PBKDF_SALT=it \
    "$CBIN" --address "127.0.0.1:$CPORT" 2>>"$WORK/clog" &
  PIDS+=($!)
  for _ in $(seq 100); do curl -s -o /dev/null "$C/healthz" && break; sleep 0.1; done
}
mkdir -p "$WORK"/d{1..4}
start
mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
mc alias set it "$EP" rootadmin rootsecret123 >/dev/null
TOKEN=$(mc admin prometheus generate it | sed -n 's/^ *bearer_token: *//p')
[[ -n $TOKEN ]] || echo "FAIL: no token from mc admin prometheus generate"
metrics() { curl -s ${1:+-H "Authorization: Bearer $1"} "$C/metrics"; }
code() { curl -s -o /dev/null -w '%{http_code}' ${1:+-H "Authorization: Bearer $1"} "$C/metrics"; }
failed() { metrics "$TOKEN" | sed -n "s/^buckets_console_logins_failed_total{method=\"$1\"} //p"; }
H="X-Console-Request: 1"

echo "== who may read it"
check "without a token" "$(code "")" 403
check "with a token bucketsd does not accept" "$(code "${TOKEN%?}x")" 403
check "with the token mc made" "$(code "$TOKEN")" 200
check "Prometheus' text format" "$(curl -s -o /dev/null -w '%{content_type}' -H "Authorization: Bearer $TOKEN" "$C/metrics")" \
  "text/plain; version=0.0.4; charset=utf-8"
check "the same as bucketsd's rule" "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$EP/minio/v2/metrics/cluster")" 200

echo "== failed sign-ins, counted"
check "none yet" "$(failed password) $(failed ldap) $(failed openid)" "0 0 0"
for _ in 1 2 3; do
  curl -s -o /dev/null -H "$H" -d '{"accessKey":"rootadmin","secretKey":"wrong-password"}' "$C/api/v1/login"
done
check "three wrong passwords" "$(failed password)" 3
curl -s -o /dev/null -H "$H" -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login"
check "a good one is not counted" "$(failed password)" 3
curl -s -o /dev/null "$C/oauth_callback?code=x&state=y"
check "a forged OpenID callback" "$(failed openid)" 1
check "help and type lines" "$(metrics "$TOKEN" | grep -c '^# \(HELP\|TYPE\) buckets_console_logins_failed_total')" 2

echo "== public metrics"
start MINIO_PROMETHEUS_AUTH_TYPE=public
check "anyone may read them" "$(code "")" 200

echo "console-metrics: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
