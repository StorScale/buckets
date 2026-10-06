#!/usr/bin/env bash
# Local drive health (src/storage/health.c) on a real cluster: four nodes with
# two drives each. A drive that cannot be written, or whose format.json is
# gone, goes offline within a check: its own node's and the other nodes'
# metrics say so (what BucketsDriveOffline watches), so does `mc admin info`,
# S3 keeps working on the rest, the log says why; and it comes back. A drive
# wiped while its server runs (a replaced disk) is formatted back into its
# slot and healed; one that still holds data but lost its format.json is
# left alone.
#   tests/integration/drive-health.sh [bucketsd]
# MC_BIN (optional) adds the `mc admin info` checks.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
BASE=${PORT:-19840}
AK=healthuser
SK=healthsecret1
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-health-XXXXXX")
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
PIDS=(0 0 0 0 0)
cleanup() {
  chmod -R u+rwx "$WORK" 2>/dev/null || true
  for n in 1 2 3 4; do [[ ${PIDS[$n]} != 0 ]] && kill "${PIDS[$n]}" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
pass=0
fail=0
expect() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"; else
    fail=$((fail + 1))
    printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"
  fi
}
until_true() { for _ in $(seq 100); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
if [[ $(id -u) == 0 ]]; then
  echo "drive-health: skipped (root reads and writes through permissions)"
  exit 0
fi

ep() { echo "http://127.0.0.1:$((BASE + $1))"; }
ENDPOINTS=()
for n in 1 2 3 4; do for d in 1 2; do ENDPOINTS+=("$(ep "$n")$WORK/n$n/d$d"); done; done
for n in 1 2 3 4; do
  mkdir -p "$WORK/n$n/d1" "$WORK/n$n/d2"
  BUCKETS_DRIVE_CHECK_INTERVAL=1 MINIO_PROMETHEUS_AUTH_TYPE=public BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK \
    "$BIN" server --address "127.0.0.1:$((BASE + n))" "${ENDPOINTS[@]}" 2>>"$WORK/log$n" &
  PIDS[$n]=$!
done
for n in 1 2 3 4; do until_true "[[ \$(curl -s -o /dev/null -w '%{http_code}' $(ep $n)/minio/health/ready) == 200 ]]"; done
curl -s -o /dev/null "${S3[@]}" -X PUT "$(ep 1)/photos"

offline() { # node scope -> drives offline, as that node's metrics say
  curl -s "$(ep "$1")/minio/v2/metrics/$2" | sed -n "s/^minio_$2_drive_offline_total{[^}]*} //p"
}
put() { echo "$2" | curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" -X PUT --data-binary @- "$(ep "$1")/photos/$3"; }
get() { curl -s "${S3[@]}" "$(ep "$1")/photos/$2"; }

echo "== healthy"
expect "no drive offline (node 1's cluster view)" "$(offline 1 cluster)" 0
expect "none on node 2" "$(offline 2 node)" 0

echo "== a drive that cannot be written"
chmod 000 "$WORK/n2/d1"
until_true '[[ $(offline 2 node) == 1 ]]' || true
expect "its node counts it offline" "$(offline 2 node)" 1
until_true '[[ $(offline 1 cluster) == 1 ]]' || true
expect "another node's cluster view too" "$(offline 1 cluster)" 1
expect "and the cluster view on its own node" "$(offline 2 cluster)" 1
expect "the log says why" "$(grep -c "drive $WORK/n2/d1 is offline: faulty: Permission denied" "$WORK/log2")" 1
expect "writes go on" "$(put 1 hello a.txt)" 200
expect "and reads" "$(get 3 a.txt)" hello
if [[ -n ${MC_BIN:-} ]]; then
  mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
  mc alias set h "$(ep 1)" "$AK" "$SK" >/dev/null
  expect "mc admin info: offline" "$(mc admin info h --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(sum(1 for s in d["info"]["servers"] for x in s["drives"] if x["state"] != "ok"))')" 1
fi
chmod 755 "$WORK/n2/d1"
until_true '[[ $(offline 1 cluster) == 0 && $(offline 2 node) == 0 ]]' || true
expect "back online everywhere" "$(offline 1 cluster) $(offline 2 node)" "0 0"
expect "the log says so" "$(grep -c "drive $WORK/n2/d1 is back online" "$WORK/log2")" 1

echo "== a drive emptied under its mount point (format.json gone)"
mv "$WORK/n3/d2/.minio.sys/format.json" "$WORK/format.keep"
until_true '[[ $(offline 3 node) == 1 ]]' || true
expect "its node counts it offline" "$(offline 3 node)" 1
until_true '[[ $(offline 4 cluster) == 1 ]]' || true
expect "another node too" "$(offline 4 cluster)" 1
expect "said why" "$(grep -c "is offline: changed: format.json is gone" "$WORK/log3")" 1
expect "writes go on" "$(put 2 world b.txt)" 200
mv "$WORK/format.keep" "$WORK/n3/d2/.minio.sys/format.json"
until_true '[[ $(offline 4 cluster) == 0 && $(offline 3 node) == 0 ]]' || true
expect "back" "$(offline 4 cluster) $(offline 3 node)" "0 0"

echo "== two drives of one erasure set: reads go on, writes need quorum"
chmod 000 "$WORK/n1/d1" "$WORK/n2/d1"
until_true '[[ $(offline 3 cluster) == 2 ]]' || true
expect "two offline" "$(offline 3 cluster)" 2
expect "reads of what was written" "$(get 4 a.txt)" hello
chmod 755 "$WORK/n1/d1" "$WORK/n2/d1"
until_true '[[ $(offline 3 cluster) == 0 ]]' || true
expect "both back" "$(offline 3 cluster)" 0

echo "== a drive replaced while its server runs"
for i in $(seq 1 12); do put 1 "obj$i" "r$i.txt" >/dev/null; done
slot=$(python3 -c "import json; print(json.load(open('$WORK/n4/d1/.minio.sys/format.json'))['xl']['this'])")
had=$(find "$WORK/n4/d1/photos" -name xl.meta | wc -l)
rm -rf "$WORK/n4/d1/photos" "$WORK/n4/d1/.minio.sys"
until_true "[[ -f $WORK/n4/d1/.minio.sys/format.json ]]" || true
expect "formatted back" "$([[ -f $WORK/n4/d1/.minio.sys/format.json ]] && echo yes)" yes
expect "into its own slot" "$(python3 -c "import json; print(json.load(open('$WORK/n4/d1/.minio.sys/format.json'))['xl']['this'])")" "$slot"
until_true "[[ \$(find $WORK/n4/d1/photos -name xl.meta 2>/dev/null | wc -l) == $had ]]" || true
expect "every object healed back onto it ($had)" "$(find "$WORK/n4/d1/photos" -name xl.meta 2>/dev/null | wc -l | tr -d ' ')" "$had"
until_true "[[ ! -f $WORK/n4/d1/.minio.sys/buckets-healing.json ]]" || true
expect "healing finished" "$([[ -f $WORK/n4/d1/.minio.sys/buckets-healing.json ]] && echo pending || echo done)" done
expect "online everywhere" "$(offline 1 cluster) $(offline 4 node)" "0 0"
expect "the log says so" "$(grep -c "drive $WORK/n4/d1 was replaced: formatted into its slot as $slot" "$WORK/log4")" 1
expect "reads" "$(get 2 r7.txt)" obj7

echo "== a drive emptied while writes go on (they must not land on it)"
had=$(find "$WORK/n2/d2/photos" -name xl.meta | wc -l)
( for i in $(seq 1 60); do put $((i % 4 + 1)) "busy$i" "busy$i.txt" >/dev/null; sleep 0.05; done ) &
writer=$!
sleep 0.5
rm -rf "$WORK/n2/d2/photos" "$WORK/n2/d2/.minio.sys"
wait "$writer"
until_true "[[ -f $WORK/n2/d2/.minio.sys/format.json && ! -f $WORK/n2/d2/.minio.sys/buckets-healing.json ]]" || true
expect "still formatted back" "$([[ -f $WORK/n2/d2/.minio.sys/format.json ]] && echo yes)" yes
until_true "[[ \$(find $WORK/n2/d2/photos -name xl.meta 2>/dev/null | wc -l) -ge \$(( had + 60 )) ]]" || true
expect "and healed: what it had and all the writes" "$(( $(find "$WORK/n2/d2/photos" -name xl.meta 2>/dev/null | wc -l) >= had + 60 ))" 1
expect "the writes read back" "$(get 3 busy37.txt)" busy37
expect "online everywhere" "$(offline 1 cluster) $(offline 2 node)" "0 0"

echo "== a drive that lost only its format.json is left alone"
mv "$WORK/n3/d1/.minio.sys/format.json" "$WORK/format3.keep"
until_true "grep -q 'drive $WORK/n3/d1 has no format.json and was not formatted: it holds data' $WORK/log3" || true
sleep 3
expect "not formatted, told once" "$([[ -f $WORK/n3/d1/.minio.sys/format.json ]] && echo formatted || echo left) $(grep -c "drive $WORK/n3/d1 has no format.json" "$WORK/log3")" "left 1"
mv "$WORK/format3.keep" "$WORK/n3/d1/.minio.sys/format.json"
until_true '[[ $(offline 1 cluster) == 0 ]]' || true
expect "back once it is restored" "$(offline 1 cluster)" 0

echo "drive-health: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
