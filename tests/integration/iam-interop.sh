#!/usr/bin/env bash
# IAM on-disk compatibility with real MinIO, both ways, through mc:
#  1. MinIO creates users, a canned policy, a group and service accounts.
#  2. bucketsd, started on the same drives, must honour all of them.
#  3. bucketsd adds a user and a policy; MinIO, restarted on the drives,
#     must honour those too.
#   MC_BIN=/path/to/mc MINIO_BIN=/path/to/minio tests/integration/iam-interop.sh [bucketsd]
# Skips (exit 0) when MC_BIN or MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" || -z "${MINIO_BIN:-}" ]]; then
  echo "iam-interop: skipped (set MC_BIN and MINIO_BIN)"
  exit 0
fi
PORT=${PORT:-19730}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-iamx-XXXXXX")
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
denied() { if "$@" >/dev/null 2>&1; then fail "expected denial: ${*:2}"; fi; }

export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
start() { # $1: minio | buckets
  echo "-- starting $1" >>"$WORK/log"
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$D/d{1...4}" >>"$WORK/log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" 2>>"$WORK/log" &
  fi
  PID=$!
  for _ in $(seq 150); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.1; done
  curl -sf "$EP/minio/health/ready" >/dev/null || fail "$1 did not start"
  # IAM loads after the object layer is up: retry until the admin API answers.
  for _ in $(seq 150); do
    mc alias set root "$EP" rootadmin rootsecret123 >/dev/null 2>&1 && mc admin user ls root >/dev/null 2>&1 && return
    sleep 0.1
  done
  fail "$1: admin API not ready"
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }

mkdir -p "$D"/d{1..4}
echo hello >"$WORK/f.txt"

echo "== MinIO writes IAM state"
start minio
ok mc mb root/photos
ok mc mb root/logs
ok mc cp "$WORK/f.txt" root/photos/a.txt
ok mc cp "$WORK/f.txt" root/logs/f.txt
cat >"$WORK/photos-rw.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}
JSON
ok mc admin policy create root photos-rw "$WORK/photos-rw.json"
ok mc admin user add root alice alicesecret123
ok mc admin policy attach root photos-rw --user alice
ok mc admin user add root bob bobsecret123
ok mc admin group add root devs bob
ok mc admin policy attach root readonly --group devs
ok mc admin user add root carl carlsecret123
ok mc admin user disable root carl
ok mc admin user svcacct add root alice --access-key alicesvc01 --secret-key alicesvcsecret1
cat >"$WORK/ro.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::photos/*"]}]}
JSON
ok mc admin user svcacct add root alice --access-key alicesvc02 --secret-key alicesvcsecret2 --policy "$WORK/ro.json"
stop

echo "== bucketsd honours it"
start buckets
ok mc alias set alice "$EP" alice alicesecret123
ok mc alias set bob "$EP" bob bobsecret123
# mc alias set refuses a disabled user's credentials; MC_HOST_ does not check.
export MC_HOST_carl="http://carl:carlsecret123@127.0.0.1:$PORT"
ok mc alias set asvc "$EP" alicesvc01 alicesvcsecret1
ok mc alias set asvc2 "$EP" alicesvc02 alicesvcsecret2
ok mc cat alice/photos/a.txt
ok mc cp "$WORK/f.txt" alice/photos/b.txt
denied mc cat alice/logs/f.txt
ok mc cat bob/logs/f.txt
denied mc cp "$WORK/f.txt" bob/logs/x.txt
denied mc cat carl/logs/f.txt
ok mc cat asvc/photos/a.txt
ok mc cp "$WORK/f.txt" asvc/photos/c.txt
ok mc cat asvc2/photos/a.txt
denied mc cp "$WORK/f.txt" asvc2/photos/d.txt
mc admin user ls root | grep "disabled.*carl" >/dev/null || fail "carl should be listed disabled"
mc admin group info root devs | grep "Policy: readonly" >/dev/null || fail "group policy"
mc admin policy info root photos-rw | grep "arn:aws:s3:::photos/\*" >/dev/null || fail "policy info"

echo "== bucketsd writes, MinIO reads"
cat >"$WORK/logs-ro.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::logs/*"]}]}
JSON
ok mc admin policy create root logs-ro "$WORK/logs-ro.json"
ok mc admin user add root dana danasecret123
ok mc admin policy attach root logs-ro --user dana
ok mc admin user svcacct add root dana --access-key danasvc001 --secret-key danasvcsecret1
ok mc admin group add root devs dana
ok mc admin user enable root carl
stop
start minio
ok mc alias set dana "$EP" dana danasecret123
ok mc alias set dsvc "$EP" danasvc001 danasvcsecret1
ok mc cat dana/logs/f.txt
denied mc cp "$WORK/f.txt" dana/logs/y.txt
ok mc cat dsvc/logs/f.txt
# carl has no policy, so is denied, but must no longer be disabled.
out=$(mc cat carl/logs/f.txt 2>&1 || true)
if echo "$out" | grep -i "disabled" >/dev/null; then fail "carl should be enabled in MinIO: $out"; fi
mc admin group info root devs | grep "dana" >/dev/null || fail "MinIO sees dana in devs"
ok mc cat alice/photos/b.txt
stop
echo "PASS"
