#!/usr/bin/env bash
# The data scanner: data usage after a cycle (admin datausageinfo), and hard
# quotas counting the bucket's stored size once usage is known.
#   tests/integration/usage.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19840}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-usage-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID=
pass=0 fail=0
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
ok() { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1"; }
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
mkdir -p "$WORK"/d{1..4}
BUCKETS_SCANNER_INTERVAL=1 BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>"$WORK/log" &
PID=$!
for _ in $(seq 100); do curl -s -o /dev/null "$EP/minio/health/live" && break; sleep 0.1; done
usage() { curl -s "${S3[@]}" "$EP/minio/admin/v3/datausageinfo"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

[[ $(usage | field 'd["bucketsUsageInfo"]') == None ]] && ok "no usage before a cycle" || bad "no usage before a cycle"
curl -sf "${S3[@]}" -X PUT "$EP/qbkt" >/dev/null
head -c 600 /dev/zero | curl -sf "${S3[@]}" -X PUT --data-binary @- "$EP/qbkt/a" >/dev/null
head -c 2000 /dev/zero | curl -sf "${S3[@]}" -X PUT --data-binary @- "$EP/qbkt/b" >/dev/null
for _ in $(seq 100); do
  [[ $(usage | field 'd["bucketsUsageInfo"] and d["bucketsUsageInfo"].get("qbkt",{}).get("objectsCount")') == 2 ]] && break
  sleep 0.1
done
u=$(usage)
[[ $(echo "$u" | field 'd["bucketsUsageInfo"]["qbkt"]["size"]') == 2600 ]] && ok "bucket size" || bad "bucket size: $u"
[[ $(echo "$u" | field 'd["bucketsSizes"]["qbkt"]') == 2600 ]] && ok "bucketsSizes" || bad "bucketsSizes"
[[ $(echo "$u" | field 'd["bucketsUsageInfo"]["qbkt"]["objectsSizesHistogram"]["BETWEEN_1024B_AND_1_MB"]') == 1 ]] &&
  ok "size histogram" || bad "size histogram"
[[ $(echo "$u" | field 'd["objectsTotalSize"]') == 2600 ]] && ok "total size" || bad "total size"

curl -sf "${S3[@]}" -X PUT --data-binary '{"size":3000,"quotatype":"hard"}' "$EP/minio/admin/v3/set-bucket-quota?bucket=qbkt" >/dev/null
code=$(head -c 300 /dev/zero | curl -s -o "$WORK/out" -w '%{http_code}' "${S3[@]}" -X PUT --data-binary @- "$EP/qbkt/c")
[[ $code == 200 ]] && ok "under quota with usage" || bad "under quota with usage: $code"
code=$(head -c 500 /dev/zero | curl -s -o "$WORK/out" -w '%{http_code}' "${S3[@]}" -X PUT --data-binary @- "$EP/qbkt/d")
[[ $code == 400 ]] && grep -q XMinioAdminBucketQuotaExceeded "$WORK/out" && ok "stored usage counts toward the quota" ||
  bad "stored usage counts toward the quota: $code $(cat "$WORK/out")"
grep -q 'Sanitizer\|runtime error' "$WORK/log" && bad "sanitizer report" && grep -A20 'Sanitizer\|runtime error' "$WORK/log" | head -30
echo "usage: $pass passed, $fail failed"
[[ $fail == 0 ]]
