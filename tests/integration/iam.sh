#!/usr/bin/env bash
# IAM through the real mc client: users, canned policies, attach/detach,
# groups (and disabling them), service accounts (inherited and embedded
# policies), disabled users, and state surviving a restart.
#   MC_BIN=/path/to/mc tests/integration/iam.sh [bucketsd]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" ]]; then
  echo "iam: skipped (set MC_BIN)"
  exit 0
fi
MCBIN=$MC_BIN
PORT=${PORT:-19720}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-iam-XXXXXX")
EP="http://127.0.0.1:$PORT"
D="$WORK/drives"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

mc() { "$MCBIN" --config-dir "$WORK/mc" --no-color "$@"; }
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; exit 1; }
ok() { "$@" >/dev/null 2>&1 || fail "expected success: ${*:2}"; }
denied() { if "$@" >/dev/null 2>&1; then fail "expected denial: ${*:2}"; fi; }

start() {
  BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 "$BIN" server --address "127.0.0.1:$PORT" \
    "$D/d{1...4}" 2>>"$WORK/log" &
  PID=$!
  for _ in $(seq 50); do curl -sf "$EP/minio/health/ready" >/dev/null && return; sleep 0.1; done
  fail "server did not start"
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }

mkdir -p "$D"/d{1..4}
start
ok mc alias set root "$EP" rootadmin rootsecret123
ok mc mb root/photos
ok mc mb root/logs
echo hello >"$WORK/f.txt"
ok mc cp "$WORK/f.txt" root/logs/f.txt

echo "== users and canned policies"
ok mc admin user add root alice alicesecret123
mc admin user ls root | grep "enabled.*alice" >/dev/null || fail "alice not listed"
cat >"$WORK/photos-rw.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}
JSON
ok mc admin policy create root photos-rw "$WORK/photos-rw.json"
mc admin policy info root photos-rw | grep '"arn:aws:s3:::photos/\*"' >/dev/null || fail "policy info"
ok mc alias set alice "$EP" alice alicesecret123
denied mc cp "$WORK/f.txt" alice/photos/a.txt
ok mc admin policy attach root photos-rw --user alice
mc admin user info root alice | grep "PolicyName: photos-rw" >/dev/null || fail "user info policy"
ok mc cp "$WORK/f.txt" alice/photos/a.txt
ok mc cat alice/photos/a.txt
denied mc cat alice/logs/f.txt
denied mc cp "$WORK/f.txt" alice/logs/b.txt
mc ls alice | grep photos >/dev/null || fail "alice should see photos"
if mc ls alice | grep logs >/dev/null; then fail "alice should not see logs"; fi
# Re-attaching answers XMinioAdminPolicyChangeAlreadyApplied, which mc treats as done.
ok mc admin policy attach root photos-rw --user alice
out=$(mc admin policy rm root photos-rw 2>&1 || true)
echo "$out" | grep -i "in use" >/dev/null || fail "removing an attached policy should fail: $out"

echo "== groups"
ok mc admin user add root bob bobsecret123
ok mc admin group add root devs bob
ok mc admin policy attach root readonly --group devs
mc admin group info root devs | grep "bob" >/dev/null || fail "group info members"
ok mc alias set bob "$EP" bob bobsecret123
ok mc cat bob/logs/f.txt
denied mc cp "$WORK/f.txt" bob/logs/c.txt
ok mc admin group disable root devs
denied mc cat bob/logs/f.txt
ok mc admin group enable root devs
ok mc cat bob/logs/f.txt
out=$(mc admin group rm root devs 2>&1 || true)
echo "$out" | grep -i "not empty" >/dev/null || fail "removing a non-empty group should fail: $out"

echo "== service accounts"
out=$(mc admin user svcacct add root alice --access-key alicesvc01 --secret-key alicesvcsecret1)
echo "$out" | grep alicesvc01 >/dev/null || fail "svcacct add: $out"
ok mc alias set asvc "$EP" alicesvc01 alicesvcsecret1
ok mc cat asvc/photos/a.txt
denied mc cat asvc/logs/f.txt
cat >"$WORK/ro.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::photos/*"]}]}
JSON
ok mc admin user svcacct add root alice --access-key alicesvc02 --secret-key alicesvcsecret2 --policy "$WORK/ro.json"
ok mc alias set asvc2 "$EP" alicesvc02 alicesvcsecret2
ok mc cat asvc2/photos/a.txt
denied mc cp "$WORK/f.txt" asvc2/photos/z.txt
mc admin user svcacct ls root alice | grep alicesvc02 >/dev/null || fail "svcacct ls"
mc admin user svcacct info root alicesvc02 | grep "Policy: embedded" >/dev/null || fail "svcacct info policy"
mc admin user svcacct info root alicesvc01 | grep "Policy: implied" >/dev/null || fail "svcacct info implied"
mc admin user svcacct info root alicesvc02 --json | grep "s3:GetObject" >/dev/null || fail "svcacct info policy json"
ok mc admin user svcacct disable root alicesvc02
denied mc cat asvc2/photos/a.txt
ok mc admin user svcacct rm root alicesvc02
# A user creates a service account for itself.
ok mc admin user svcacct add alice alice --access-key alicesvc03 --secret-key alicesvcsecret3

echo "== STS AssumeRole"
sts() { # user secret [extra --data-urlencode args...]
  local u=$1 p=$2; shift 2
  curl -s --aws-sigv4 "aws:amz:us-east-1:sts" --user "$u:$p" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode Action=AssumeRole \
    --data-urlencode Version=2011-06-15 "$@" "$EP/"
}
xml() { sed -n "s:.*<$1>\(.*\)</$1>.*:\1:p"; }
r=$(sts alice alicesecret123 --data-urlencode DurationSeconds=900)
tak=$(xml AccessKeyId <<<"$r"); tsk=$(xml SecretAccessKey <<<"$r"); ttok=$(xml SessionToken <<<"$r")
[[ -n "$tak" && -n "$ttok" ]] || fail "AssumeRole: $r"
s3tmp() { curl -sf --aws-sigv4 "aws:amz:us-east-1:s3" --user "$tak:$tsk" "$@"; }
[[ "$(s3tmp -H "X-Amz-Security-Token: $ttok" "$EP/photos/a.txt")" == hello ]] || fail "STS read"
denied s3tmp -H "X-Amz-Security-Token: $ttok" "$EP/logs/f.txt"
denied s3tmp "$EP/photos/a.txt" # the token is required
r=$(sts alice alicesecret123 --data-urlencode \
  'Policy={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::photos/a.txt"]}]}')
tak=$(xml AccessKeyId <<<"$r"); tsk=$(xml SecretAccessKey <<<"$r"); ttok=$(xml SessionToken <<<"$r")
ok s3tmp -H "X-Amz-Security-Token: $ttok" "$EP/photos/a.txt"
denied s3tmp -H "X-Amz-Security-Token: $ttok" -X PUT --data x "$EP/photos/q.txt"
# Service accounts cannot assume roles.
sts alicesvc01 alicesvcsecret1 | grep AccessDenied >/dev/null || fail "svcacct AssumeRole should be denied"

echo "== disabled users"
ok mc admin user disable root alice
out=$(mc cat alice/photos/a.txt 2>&1 || true)
echo "$out" | grep -i "disabled\|denied" >/dev/null || fail "disabled user: $out"
ok mc admin user enable root alice
ok mc cat alice/photos/a.txt

echo "== restart"
stop
start
ok mc cat alice/photos/a.txt
ok mc cat asvc/photos/a.txt
ok mc cat bob/logs/f.txt
denied mc cp "$WORK/f.txt" bob/logs/d.txt
mc admin group info root devs | grep "Policy: readonly" >/dev/null || fail "group policy after restart"

echo "== cleanup"
ok mc admin policy detach root photos-rw --user alice
ok mc admin policy rm root photos-rw
ok mc admin user rm root alice
denied mc ls asvc/photos # the user's service accounts went with it
ok mc admin group rm root devs bob
ok mc admin group rm root devs
ok mc admin user rm root bob
[[ -z "$(mc admin user ls root)" ]] || fail "users left over"
echo "PASS"
