#!/usr/bin/env bash
# Ransomware alerts (docs/design/ransomware-alerts.md), in a cluster of four
# with a webhook target. A credential deleting objects through two servers at
# once opens one MassDelete incident that names it, its event reaches the
# webhook, and with BUCKETS_RANSOMWARE_RESPONSE=disable its access key is
# turned off (and back on, undone). Overwrites open MassOverwrite; deletes
# under the floor open nothing; suspending versioning and a policy letting
# anyone write open ProtectionRemoved at once. Then a false alarm, the metrics,
# and the console's API answering through another server.
#   tests/integration/ransomware.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
BASE=${PORT:-19840}
WPORT=$((BASE + 9))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-ransomware-XXXXXX")
AK=rootadmin
SK=rootsecret123
PIDS=(0 0 0 0 0)
WPID=0
cleanup() {
  for n in 1 2 3 4; do [[ ${PIDS[$n]} != 0 ]] && kill "${PIDS[$n]}" 2>/dev/null || true; done
  [[ $WPID != 0 ]] && kill "$WPID" 2>/dev/null || true
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

# a webhook that keeps every event it is sent, one JSON document per line
cat >"$WORK/hook.py" <<'PY'
import http.server, sys
out = open(sys.argv[2], "ab", buffering=0)
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        out.write(self.rfile.read(n).replace(b"\n", b" ") + b"\n")
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/hook.py" "$WPORT" "$WORK/events" &
WPID=$!

ep() { echo "http://127.0.0.1:$((BASE + $1))"; }
ENDPOINTS=()
for n in 1 2 3 4; do ENDPOINTS+=("$(ep "$n")$WORK/n$n/d1"); done
for n in 1 2 3 4; do
  env BUCKETS_RANSOMWARE_FLOOR=200 BUCKETS_RANSOMWARE_INTERVAL=1 BUCKETS_RANSOMWARE_RESPONSE=disable \
    MINIO_NOTIFY_WEBHOOK_ENABLE_1=on MINIO_NOTIFY_WEBHOOK_ENDPOINT_1="http://127.0.0.1:$WPORT/" \
    MINIO_PROMETHEUS_AUTH_TYPE=public BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK \
    "$BIN" server --address "127.0.0.1:$((BASE + n))" "${ENDPOINTS[@]}" 2>>"$WORK/log$n" &
  PIDS[$n]=$!
done
ready() { [[ $(curl -s -o /dev/null -w "%{http_code}" "$(ep "$1")/minio/health/cluster") == 200 ]]; }
admin() { # node method path [curl args]
  local n=$1 m=$2 p=$3
  shift 3
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -X "$m" "$@" "$(ep "$n")/minio/admin/v3/$p"
}
locks() { # every node takes write locks: health can answer before a peer's lock server does
  local n
  for n in 1 2 3 4; do
    [[ $(admin "$n" PUT buckets/usage-rates -o /dev/null -w '%{http_code}' -d '{"currency":"X"}') == 200 ]] || return 1
    [[ $(admin "$n" DELETE buckets/usage-rates -o /dev/null -w '%{http_code}') == 200 ]] || return 1
  done
}
until_true "ready 1 && ready 2 && ready 3 && ready 4 && locks" 300
export MC_CONFIG_DIR="$WORK/mc"
export MC_HOST_r="http://$AK:$SK@127.0.0.1:$((BASE + 1))"
incidents() { admin "${1:-1}" GET "buckets/incidents?state=all"; }
q() { python3 -c "import json,sys; d=json.load(sys.stdin); I=d.get('incidents',[]); print($1)"; }
# the incidents of a kind (and bucket), as python expressions over x
of() { echo "[x for x in I if x['kind']=='$1' and (x['bucket']=='$2' or '$2'=='')]"; }

# people with access keys, buckets, and their notification rules
for u in alice bob; do
  mc admin user add r "$u" "${u}secret123" >/dev/null
  mc admin policy attach r readwrite --user "$u" >/dev/null
  mc admin user svcacct add r "$u" --access-key "${u}key01" --secret-key "${u}keysecret1" >/dev/null
done
NOTIFY='<NotificationConfiguration><QueueConfiguration><Queue>arn:minio:sqs::1:webhook</Queue><Event>s3:Buckets:*</Event></QueueConfiguration></NotificationConfiguration>'
for b in data photos small; do
  mc mb -q "r/$b" >/dev/null
  expect "events of $b go to the webhook" \
    "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -X PUT --data "$NOTIFY" "$(ep 1)/$b?notification")" 200
done
mc version enable r/data >/dev/null
mkdir -p "$WORK/files/x" "$WORK/files/y"
for i in $(seq 150); do echo "x$i" >"$WORK/files/x/$i"; echo "y$i" >"$WORK/files/y/$i"; done
mc mirror -q "$WORK/files" r/data >/dev/null
mc mirror -q "$WORK/files/x" r/small >/dev/null
mc mirror -q "$WORK/files" r/photos >/dev/null
expect "uploads by root open nothing" "$(incidents | q "len(I)")" 0

# ---- a mass delete through two servers -----------------------------------------------------------------------
export MC_HOST_a1="http://alicekey01:alicekeysecret1@127.0.0.1:$((BASE + 1))"
export MC_HOST_a2="http://alicekey01:alicekeysecret1@127.0.0.1:$((BASE + 2))"
# the response may turn the key off before the deletes are done: what is left is refused
mc rm -q -r --force a1/data/x/ >/dev/null 2>&1 & mc rm -q -r --force a2/data/y/ >/dev/null 2>&1 || true; wait $! 2>/dev/null || true
until_true "[[ \$(incidents | q \"len($(of mass-delete data))\") == 1 ]]" 150 || true
expect "one MassDelete for data" "$(incidents | q "len($(of mass-delete data))")" 1
expect "naming the access key and its owner, with what it deleted (from the floor: the response stops it)" \
  "$(incidents | q "[(x['credentials'][0]['accessKey'], x['credentials'][0]['user'], x['credentials'][0]['type'], 200 <= x['counts']['deleted'] <= 300) for x in $(of mass-delete data)]")" \
  "[('alicekey01', 'alice', 'access-key', True)]"
expect "the response turned the key off" "$(incidents | q "[x['action'] for x in $(of mass-delete data)]")" "['disabled']"
expect "and it is off" "$(mc admin user svcacct info r alicekey01 --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["accountStatus"])')" off
until_true "grep -q 'Buckets:MassDelete' '$WORK/events'" 50 || true
expect "the webhook got s3:Buckets:MassDelete with the credential" \
  "$(python3 -c '
import json,sys
for l in open(sys.argv[1]):
    r = json.loads(l)["Records"][0]
    if r["eventName"] == "s3:Buckets:MassDelete":
        m = r["s3"]["object"]["userMetadata"]
        print(r["s3"]["bucket"]["name"], m["x-buckets-credential"], 200 <= int(m["x-buckets-objects"]) <= 300, m["x-buckets-action"]); break
' "$WORK/events")" "data alicekey01 True disabled"
expect "the log says so" "$(cat "$WORK"/log* | grep -c 'ransomware: mass delete in bucket data: [0-9]* objects')" 1

# ---- under the floor: nothing ---------------------------------------------------------------------------------
export MC_HOST_b3="http://bobkey01:bobkeysecret1@127.0.0.1:$((BASE + 3))"
mc rm -q -r --force b3/small >/dev/null
sleep 3
expect "150 deletes, under the floor: no incident" "$(incidents | q "len($(of mass-delete small))")" 0

# ---- overwrites -------------------------------------------------------------------------------------------------
for i in $(seq 150); do echo "encrypted x$i" >"$WORK/files/x/$i"; echo "encrypted y$i" >"$WORK/files/y/$i"; done
mc mirror -q --overwrite "$WORK/files" b3/photos >/dev/null 2>&1 || true # cut short once bob's key is off
until_true "[[ \$(incidents | q \"len($(of mass-overwrite photos))\") == 1 ]]" 150 || true
expect "a MassOverwrite for photos, by bob" \
  "$(incidents | q "[(x['credentials'][0]['user'], 200 <= x['counts']['overwritten'] <= 300) for x in $(of mass-overwrite photos)]")" "[('bob', True)]"
expect "a first write is not an overwrite" "$(incidents | q "len($(of mass-overwrite data))")" 0

# ---- protection removed: at once, whatever the numbers ---------------------------------------------------------
mc version suspend r/data >/dev/null
mc anonymous set upload r/photos >/dev/null
until_true "[[ \$(incidents | q \"len($(of protection-removed ''))\") == 2 ]]" 150 || true
expect "versioning suspended, and anyone may write" \
  "$(incidents | q "sorted((x['bucket'], x['change'], x['credentials'][0]['type']) for x in $(of protection-removed ''))")" \
  "[('data', 'versioning-suspended', 'root'), ('photos', 'public-write', 'root')]"
expect "root is never turned off" "$(incidents | q "[x['action'] for x in $(of protection-removed '')]")" "[None, None]"
until_true "grep -q 'Buckets:ProtectionRemoved' '$WORK/events'" 50 || true
expect "the webhook got s3:Buckets:ProtectionRemoved" "$(grep -c 'Buckets:ProtectionRemoved' "$WORK/events")" 2

# ---- what an admin does about it ------------------------------------------------------------------------------
ID=$(incidents | q "$(of mass-delete data)[0]['id']")
expect "undo turns the key back on" "$(admin 2 POST "buckets/incidents?id=$ID&action=undo" | python3 -c 'import json,sys; print(json.load(sys.stdin)["undone"])')" True
expect "and it is on" "$(mc admin user svcacct info r alicekey01 --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["accountStatus"])')" on
OW=$(incidents | q "$(of mass-overwrite photos)[0]['id']")
expect "a false alarm" "$(admin 3 POST "buckets/incidents?id=$OW&action=false-alarm" | python3 -c 'import json,sys; print(json.load(sys.stdin)["falseAlarm"])')" True
expect "an unknown action is refused" "$(admin 1 POST "buckets/incidents?id=$OW&action=delete" -o /dev/null -w '%{http_code}')" 400
expect "open incidents only" "$(admin 4 GET 'buckets/incidents?state=open' | q "len(I) == len([x for x in I if not x['closed']])")" True

# ---- metrics ----------------------------------------------------------------------------------------------------
m=$(for n in 1 2 3 4; do curl -s "$(ep "$n")/minio/v2/metrics/bucket"; done)
sum() { awk -v pat="$1" 'index($0, pat) == 1 {s += $2} END {print s + 0}' <<<"$m"; }
expect "deletes counted per bucket, over the servers" "$(( $(sum 'buckets_bucket_objects_deleted_total{bucket="data"') >= 200 ))" 1
expect "overwrites" "$(( $(sum 'buckets_bucket_objects_overwritten_total{bucket="photos"') >= 200 ))" 1
expect "protection changes" "$(sum 'buckets_bucket_protection_changes_total{bucket="data",change="versioning-suspended"')" 1
expect "incidents opened, by kind" \
  "$(for n in 1 2 3 4; do curl -s "$(ep "$n")/minio/v2/metrics/node"; done | awk '/^buckets_ransomware_incidents_total/ {s += $2} END {print s}')" 4

expect "no sanitizer reports" "$(cat "$WORK"/log* | grep -c 'Sanitizer\|runtime error' || true)" 0
echo "ransomware: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
