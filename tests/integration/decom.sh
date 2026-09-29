#!/usr/bin/env bash
# Pool decommission and rebalance against MinIO:
#  - decommission of a pool by bucketsd and by MinIO: every version stays
#    (IDs, ETags, times, delete markers), the data reads back, the pool is
#    left empty and new objects stay off it; the other server then serves
#    the remaining pool alone, and reports the decommission from pool.bin;
#  - mc admin decommission status/start/cancel and their errors, as MinIO
#    answers them; a canceled decommission started again; one resumed
#    after a restart;
#  - rebalance between pools on separate disk images (macOS hdiutil; skipped
#    elsewhere): status, stop, and each server reading the other's
#    rebalance.bin.
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc tests/integration/decom.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "decom: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19900}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-decom-XXXXXX")
export MC_CONFIG_DIR="$WORK/mc" MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
export _BUCKETS_DECOM_RESUME_DELAY=1s
PID=
MOUNTS=()
pass=0 fail=0
CASE=decom
cleanup() {
  [[ -n $PID ]] && kill "$PID" 2>/dev/null
  wait 2>/dev/null
  for m in ${MOUNTS[@]+"${MOUNTS[@]}"}; do hdiutil detach "$m" >/dev/null 2>&1; done
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
MC() { "$MC_BIN" "$@"; }
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL [$CASE] $*"; }
check() { if [[ "$2" == "$3" ]]; then ok; else bad "$1: got '$2' want '$3'"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then ok; else bad "$1: '$2' lacks '$3'"; fi; }
same() { if diff "$2" "$3" >/dev/null; then ok; else bad "$1 differs:"; diff "$2" "$3" | head -10; fi; }
start() { # kind log pools...
  local k=$1 log=$2
  shift 2
  if [[ $k == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$@" >>"$log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$@" 2>>"$log" &
  fi
  PID=$!
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
  MC alias set m "http://127.0.0.1:$PORT" rootadmin rootsecret123 >/dev/null
}
stop() { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=; }
admin() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 -X "$1" "http://127.0.0.1:$PORT/minio/admin/v3/$2"; }
versions() { MC ls -r --versions --json m | python3 -c 'import json,sys
for l in sys.stdin:
    d = json.loads(l)
    if d["key"].endswith("/") and d.get("versionId") is None and d.get("size") == 0: continue
    print(d["key"], d.get("versionId"), d.get("etag"), d.get("size"), d.get("lastModified"), d.get("isDeleteMarker", False))' | sort; }
decom_state() { MC admin decommission status m "$1" --json 2>/dev/null | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)["decommissionInfo"]
    print("complete" if d["complete"] else "failed" if d["failed"] else "canceled" if d["canceled"] else "running")
except Exception:
    print("unknown")'; }
wait_decom() { # pool
  for _ in $(seq 600); do
    local s
    s=$(decom_state "$1")
    [[ $s == complete || $s == failed || $s == canceled ]] && { echo "$s"; return; }
    sleep 0.2
  done
  echo timeout
}
fill() { # dir of the data
  MC mb m/vbkt m/pbkt >/dev/null
  MC version enable m/vbkt >/dev/null
  for v in 1 2 3; do echo "v$v" | MC pipe --attr "Color=red" m/vbkt/obj >/dev/null; done
  echo gone | MC pipe m/vbkt/gone >/dev/null
  MC rm m/vbkt/gone >/dev/null
  echo lone | MC pipe m/vbkt/lone >/dev/null
  head -c 12000000 /dev/urandom >"$1/mp"
  MC cp "$1/mp" m/pbkt/mp >/dev/null
  echo enc | MC pipe --enc-s3 m/pbkt m/pbkt/enc >/dev/null
  head -c 3000000 /dev/urandom | MC cp --enc-s3 m/pbkt - m/pbkt/encbig >/dev/null 2>&1 ||
    { head -c 3000000 /dev/urandom >"$1/eb"; MC cp --enc-s3 m/pbkt "$1/eb" m/pbkt/encbig >/dev/null; }
  for i in $(seq 1 30); do echo "s$i" | MC pipe "m/pbkt/small/$i" >/dev/null; done
  MC admin config set m compression enable=on extensions=.txt >/dev/null 2>&1
  yes buckets | head -c 2000000 >"$1/comp.txt"
  MC cp "$1/comp.txt" m/pbkt/comp.txt >/dev/null
}
objs_in() { find "$1" -name xl.meta -not -path '*/.minio.sys/*' 2>/dev/null | wc -l | tr -d ' '; }

# ---- decommission, by each server, and the other one serving what is left ----
decom_case() { # kind other
  CASE="decommission by $1"
  local dir="$WORK/d_$1" log="$WORK/d_$1.log" p1 p2
  mkdir -p "$dir"/p1/d{1..4} "$dir"/p2/d{1..4}
  p1="$dir/p1/d{1...4}" p2="$dir/p2/d{1...4}"
  start "$1" "$log" "$p1"
  fill "$dir"
  versions >"$dir/before"
  stop
  start "$1" "$log" "$p1" "$p2"
  admin GET "pools/list" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' >"$dir/npools"
  check "pools listed" "$(cat "$dir/npools")" 2
  check "start" "$(MC admin decommission start m "$p1" 2>&1)" "Decommission started successfully for \`$p1\`."
  check "outcome" "$(wait_decom "$p1")" complete
  admin GET "pools/status?pool=$p1" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    i = d["decommissionInfo"]
    print(d["id"], i["objectsDecommissioned"], i["objectsDecommissionedFailed"], i["complete"], i["failed"], i["canceled"])
except Exception as e:
    print("no status:", e)' >"$dir/status"
  versions >"$dir/after"
  if [[ $1 == minio ]]; then # MinIO's own moves give SSE multipart objects new ETags
    sed -i.bak -E 's#^(pbkt/enc [^ ]+) [^ ]+#\1 -#' "$dir/before" "$dir/after"
  fi
  same "versions after decommission" "$dir/before" "$dir/after"
  check "pool left empty" "$(objs_in "$dir/p1/d1")" 0
  check "mp data" "$(MC cat m/pbkt/mp | md5)" "$(md5 <"$dir/mp")"
  check "encrypted data" "$(MC cat m/pbkt/enc)" enc
  check "compressed data" "$(MC cat m/pbkt/comp.txt | md5)" "$(md5 <"$dir/comp.txt")"
  echo later | MC pipe m/pbkt/later >/dev/null
  check "new objects stay off the pool" "$(objs_in "$dir/p1/d1")" 0
  stop
  CASE="decommission by $1, then $2"
  start "$2" "$log" "$p1" "$p2"
  check "$2 reads pool.bin" "$(decom_state "$p1")" complete
  stop
  start "$2" "$log" "$p2"
  versions | grep -v '^pbkt/later ' >"$dir/alone"
  [[ $1 == minio ]] && sed -i.bak -E 's#^(pbkt/enc [^ ]+) [^ ]+#\1 -#' "$dir/alone"
  same "$2 alone on the other pool" "$dir/before" "$dir/alone"
  check "mp by $2" "$(MC cat m/pbkt/mp | md5)" "$(md5 <"$dir/mp")"
  check "encrypted by $2" "$(MC cat m/pbkt/enc)" enc
  check "versions by $2" "$(MC cat m/vbkt/obj)" v3
  stop
}
decom_case buckets minio
decom_case minio buckets
CASE="decommission counts"
same "status counts as MinIO's" "$WORK/d_minio/status" "$WORK/d_buckets/status"

# ---- errors, cancel, restart ----
CASE="decommission errors"
errs() { # kind -> the admin API's answers
  local dir="$WORK/e_$1"
  mkdir -p "$dir"/p1/d{1..4} "$dir"/p2/d{1..4}
  start "$1" "$dir.log" "$dir/p1/d{1...4}"
  {
    admin POST "pools/decommission?pool=$dir/p1/d%7B1...4%7D" | sed -E 's/"RequestId":"[^"]*","HostId":"[^"]*"//'
    echo
    admin GET "rebalance/status" | sed -E 's/"RequestId":"[^"]*","HostId":"[^"]*"//'
    echo
  } >"$WORK/errs1.$1"
  stop
  start "$1" "$dir.log" "$dir/p1/d{1...4}" "$dir/p2/d{1...4}"
  {
    admin POST "pools/decommission?pool=nosuch" | sed -E 's/"RequestId":"[^"]*","HostId":"[^"]*"//'
    echo
    admin GET "pools/status?pool=nosuch" | sed -E 's/"RequestId":"[^"]*","HostId":"[^"]*"//'
    echo
    admin GET "rebalance/status" | sed -E 's/"RequestId":"[^"]*","HostId":"[^"]*"//'
    echo
  } >"$WORK/errs2.$1"
  stop
}
errs minio
errs buckets
same "single pool" "$WORK/errs1.minio" "$WORK/errs1.buckets"
same "two pools" "$WORK/errs2.minio" "$WORK/errs2.buckets"

CASE="cancel and restart"
dir="$WORK/c"
mkdir -p "$dir"/p1/d{1..4} "$dir"/p2/d{1..4}
p1="$dir/p1/d{1...4}" p2="$dir/p2/d{1...4}"
start buckets "$dir.log" "$p1"
MC mb m/many >/dev/null
mkdir -p "$dir/src"
for i in $(seq 1 3000); do echo "o$i" >"$dir/src/o$i"; done
MC cp -r "$dir/src/" m/many/ >/dev/null
versions >"$dir/before"
stop
export _MINIO_DECOMMISSION_WORKERS=1
start buckets "$dir.log" "$p1" "$p2"
MC admin decommission start m "$p1" >/dev/null
MC admin decommission cancel m "$p1" >/dev/null 2>&1
check "canceled" "$(wait_decom "$p1")" canceled
MC admin decommission start m "$p1" >/dev/null
sleep 0.5
stop # mid-way
left=$(objs_in "$dir/p1/d1")
[[ $left -gt 0 ]] && ok || bad "the decommission finished before the restart"
start buckets "$dir.log" "$p1" "$p2"
check "resumed after the restart" "$(wait_decom "$p1")" complete
check "pool left empty" "$(objs_in "$dir/p1/d1")" 0
versions >"$dir/after"
same "versions" "$dir/before" "$dir/after"
stop
unset _MINIO_DECOMMISSION_WORKERS

# ---- rebalance (pools on disk images of different fill) ----
if command -v hdiutil >/dev/null 2>&1; then
  rebal_case() { # kind other
    CASE="rebalance by $1"
    local dir="$WORK/r_$1"
    mkdir -p "$dir"
    hdiutil create -size 300m -fs HFS+ -volname "rb1$1" "$dir/p1.dmg" >/dev/null 2>&1
    hdiutil create -size 1g -fs HFS+ -volname "rb2$1" "$dir/p2.dmg" >/dev/null 2>&1
    mkdir -p "$dir/m1" "$dir/m2"
    hdiutil attach "$dir/p1.dmg" -mountpoint "$dir/m1" -nobrowse >/dev/null 2>&1 && MOUNTS+=("$dir/m1")
    hdiutil attach "$dir/p2.dmg" -mountpoint "$dir/m2" -nobrowse >/dev/null 2>&1 && MOUNTS+=("$dir/m2")
    mkdir -p "$dir"/m1/d{1..4} "$dir"/m2/d{1..4}
    local p1="$dir/m1/d{1...4}" p2="$dir/m2/d{1...4}"
    start "$1" "$dir.log" "$p1"
    MC mb m/rbkt >/dev/null
    MC version enable m/rbkt >/dev/null
    head -c 1048576 /dev/urandom >"$dir/blob"
    for i in $(seq 1 50); do MC cp "$dir/blob" "m/rbkt/o$i" >/dev/null; done
    echo v2 | MC pipe m/rbkt/o1 >/dev/null
    MC rm m/rbkt/o2 >/dev/null
    versions >"$dir/before"
    stop
    start "$1" "$dir.log" "$p1" "$p2"
    sleep 1 # MinIO makes the buckets on the new pool in the background
    contains "start" "$(MC admin rebalance start m 2>&1)" "Rebalance started for m"
    local st=
    for _ in $(seq 300); do
      st=$(admin GET rebalance/status | python3 -c 'import json,sys; print(",".join(p["status"] for p in json.load(sys.stdin)["pools"]))' 2>/dev/null)
      [[ -n $st && $st != *Started* ]] && break
      sleep 0.2
    done
    check "outcome" "$st" "Completed,None"
    check "pool 1 moved objects" "$(admin GET rebalance/status | python3 -c 'import json,sys; p=json.load(sys.stdin)["pools"][0]["progress"]; print(p["objects"] > 0 and p["bytes"] > 0)')" True
    versions >"$dir/after"
    same "versions after rebalance" "$dir/before" "$dir/after"
    [[ $(objs_in "$dir/m2/d1") -gt 0 ]] && ok || bad "nothing reached pool 2"
    check "data" "$(MC cat m/rbkt/o3 | md5)" "$(md5 <"$dir/blob")"
    stop
    CASE="rebalance by $1, then $2"
    start "$2" "$dir.log" "$p1" "$p2"
    check "$2 reads rebalance.bin" "$(admin GET rebalance/status | python3 -c 'import json,sys; print(",".join(p["status"] for p in json.load(sys.stdin)["pools"]))')" "Completed,None"
    versions >"$dir/other"
    same "$2 sees the same versions" "$dir/before" "$dir/other"
    # a second rebalance stopped right away
    contains "restart" "$(MC admin rebalance start m 2>&1)" "Rebalance started"
    MC admin rebalance stop m >/dev/null 2>&1
    check "stopped" "$(admin GET rebalance/status | python3 -c 'import json,sys; print(not json.load(sys.stdin)["stoppedAt"].startswith("0001"))')" True
    stop
  }
  rebal_case buckets minio
  rebal_case minio buckets
else
  echo "decom: rebalance skipped (no hdiutil)"
fi

for log in "$WORK"/*.log; do
  [[ -f $log ]] && grep -l "AddressSanitizer\|runtime error:\|LeakSanitizer" "$log" && bad "sanitizer report in $log"
done
echo "decom: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
