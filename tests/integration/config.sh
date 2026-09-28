#!/usr/bin/env bash
# mc admin config: get/set/reset, validation, env overrides, history and
# restore, export/import, persistence. With MINIO_BIN, also that config.json
# moves between MinIO and bucketsd on the same drives, both ways.
#   MC_BIN=/path/to/mc [MINIO_BIN=/path/to/minio] tests/integration/config.sh [bucketsd]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" ]]; then
  echo "config: skipped (set MC_BIN)"
  exit 0
fi
PORT=${PORT:-19740}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-config-XXXXXX")
EP="http://127.0.0.1:$PORT"
D="$WORK/drives"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; exit 1; }
ok() { "$@" >/dev/null 2>&1 || fail "expected success: ${*:2}"; }
has() { # text pattern what
  grep -e "$2" >/dev/null <<<"$1" || fail "$3: $(head -c 400 <<<"$1")"
}

export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
start() { # minio | buckets, extra env...
  local kind=$1
  shift
  echo "-- starting $kind" >>"$WORK/log"
  if [[ $kind == minio ]]; then
    env "$@" MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$D/d{1...4}" \
      >>"$WORK/log" 2>&1 &
  else
    env "$@" "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" 2>>"$WORK/log" &
  fi
  PID=$!
  for _ in $(seq 150); do
    mc alias set root "$EP" rootadmin rootsecret123 >/dev/null 2>&1 && mc admin config get root api >/dev/null 2>&1 && return
    sleep 0.1
  done
  fail "$kind did not start"
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }

mkdir -p "$D"/d{1..4}
start buckets MINIO_SCANNER_SPEED=fastest

echo "== get and set"
out=$(mc admin config get root api)
has "$out" "^api requests_max=0 " "api defaults"
out=$(mc admin config get root scanner)
has "$out" "^# MINIO_SCANNER_SPEED=fastest" "env override shown"
ok mc admin config set root scanner alert_excess_versions=42
has "$(mc admin config get root scanner)" "alert_excess_versions=42" "set scanner"
ok mc admin config set root notify_webhook:hook1 endpoint=http://127.0.0.1:9999/ queue_limit=10 comment="first hook"
out=$(mc admin config get root notify_webhook)
has "$out" '^notify_webhook:hook1 endpoint=http://127.0.0.1:9999/ .*queue_limit=10' "webhook target"
has "$out" 'comment="first hook"' "quoted comment"

echo "== validation"
out=$(mc admin config set root identity_ldap enable=on 2>&1 || true)
has "$out" "'server_addr' is not optional" "required keys"
out=$(mc admin config set root api nosuchkey=1 2>&1 || true)
has "$out" "cannot have empty keys" "unknown keys"
out=$(mc admin config set root scanner:x speed=slow 2>&1 || true)
has "$out" "only supports single target" "single-target sub-systems"

echo "== reset"
ok mc admin config reset root scanner alert_excess_versions
has "$(mc admin config get root scanner)" "alert_excess_versions=100" "reset to default"
ok mc admin config reset root notify_webhook:hook1
out=$(mc admin config get root notify_webhook)
if grep hook1 >/dev/null <<<"$out"; then fail "target removed"; fi

echo "== history and restore"
out=$(mc admin config history root)
has "$out" "notify_webhook:hook1 endpoint" "history entry"
id=$(sed -n 's/^RestoreId: //p' <<<"$out" | tail -1)
ok mc admin config restore root "$id"
has "$(mc admin config get root notify_webhook)" "hook1" "restored"

echo "== export and import"
mc admin config export root >"$WORK/exported"
has "$(cat "$WORK/exported")" "^notify_webhook:hook1 " "export"
sed -i.bak 's/queue_limit=10/queue_limit=20/' "$WORK/exported"
ok mc admin config import root <"$WORK/exported"
has "$(mc admin config get root notify_webhook)" "queue_limit=20" "import"

echo "== persistence"
stop
start buckets
has "$(mc admin config get root notify_webhook)" "hook1 endpoint=http://127.0.0.1:9999/ .*queue_limit=20" "survives a restart"
has "$(mc admin config get root scanner)" "speed=default" "env override gone"

if [[ -n "${MINIO_BIN:-}" ]]; then
  echo "== bucketsd's config.json in MinIO"
  ok mc admin config set root scanner speed=slow
  ok mc admin config set root api requests_max=500
  stop
  start minio
  has "$(mc admin config get root scanner)" "speed=slow" "MinIO reads scanner"
  has "$(mc admin config get root api)" "requests_max=500" "MinIO reads api"
  has "$(mc admin config get root notify_webhook)" "hook1" "MinIO reads the webhook target"
  echo "== MinIO's config.json in bucketsd"
  ok mc admin config set root scanner speed=fast
  # (MinIO connects to new webhook endpoints before saving, so change something offline.)
  ok mc admin config set root compression enable=on extensions=.foo,.bar
  stop
  start buckets
  has "$(mc admin config get root scanner)" "speed=fast" "bucketsd reads scanner"
  has "$(mc admin config get root compression)" "extensions=.foo,.bar" "bucketsd reads compression"
fi
echo "PASS"
