#!/usr/bin/env bash
# mc admin service: freeze holds S3 calls (not the admin API or health
# probes) until unfreeze; restart re-executes the server in place; stop
# drains and exits.
#   MC_BIN=/path/to/mc tests/integration/service.sh [bucketsd]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" ]]; then
  echo "service: skipped (set MC_BIN)"
  exit 0
fi
PORT=${PORT:-19770}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-svc-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; exit 1; }
mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

mkdir -p "$WORK"/d{1..4}
BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 "$BIN" server --address "127.0.0.1:$PORT" \
  "$WORK/d{1...4}" 2>>"$WORK/log" &
PID=$!
for _ in $(seq 100); do
  mc alias set r "$EP" rootadmin rootsecret123 >/dev/null 2>&1 && mc admin info r >/dev/null 2>&1 && break
  sleep 0.1
done
[[ $(code "${S3[@]}" -X PUT "$EP/svcbucket") == 200 ]] || fail "make bucket"

echo "== freeze and unfreeze"
mc admin service freeze r >/dev/null || fail "freeze"
[[ $(code --max-time 2 "${S3[@]}" "$EP/svcbucket") == 000 ]] || fail "S3 call not held while frozen"
[[ $(code "$EP/minio/health/ready") == 200 ]] || fail "health probe while frozen"
mc admin user ls r >/dev/null || fail "admin API while frozen"
(code "${S3[@]}" "$EP/svcbucket" >"$WORK/held") &
HELD=$!
sleep 1
mc admin service unfreeze r >/dev/null || fail "unfreeze"
wait "$HELD"
[[ $(cat "$WORK/held") == 200 ]] || fail "held S3 call completes after unfreeze"

echo "== restart"
out=$(mc --json admin service restart r 2>&1) || fail "restart: $out"
grep '"action":"restart"' >/dev/null <<<"$out" || fail "restart result: $out"
for _ in $(seq 100); do [[ $(code "${S3[@]}" "$EP/svcbucket") == 200 ]] && break; sleep 0.1; done
grep "bucketsd restarting" "$WORK/log" >/dev/null || fail "did not restart"
kill -0 "$PID" || fail "restart must keep the process (exec in place)"
[[ $(code "${S3[@]}" "$EP/svcbucket") == 200 ]] || fail "serving after restart"

echo "== stop"
mc admin service stop r >/dev/null || fail "stop"
for _ in $(seq 100); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$PID" 2>/dev/null; then fail "still running after stop"; fi
wait "$PID" 2>/dev/null || true
PID=
echo "PASS"
