#!/usr/bin/env bash
# Server pools: expanding a 4-drive deployment with a second pool. The new
# pool joins the deployment, buckets appear on it, old objects stay readable
# and stay put when overwritten, new objects spread across both pools, and
# listings, deletes and multipart uploads work across pools.
#   tests/integration/pools.sh [bucketsd]
# With MINIO_BIN set, real MinIO must read the expanded deployment too.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19730}
AK=poolsuser
SK=poolssecret1234
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-pools-XXXXXX")
EP="http://127.0.0.1:$PORT"
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
B=poolbucket
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }
start() {
  BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$PORT" "$@" 2>>"$WORK/log" &
  PID=$!
  for _ in $(seq 50); do curl -sf "$EP/minio/health/live" >/dev/null && return; sleep 0.1; done
  echo "server did not start"; cat "$WORK/log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
pass=0
fail=0
expect() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$@"; }
get_md5() { curl -s "${S3[@]}" "$EP/$B/$1" | md5of; }
in_pool() { [[ -f "$WORK/p$1/d1/$B/$2/xl.meta" ]] && echo yes || echo no; }
depid() { sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$1/.minio.sys/format.json"; }

head -c 3000000 /dev/urandom >"$WORK/big"
BIG=$(md5of <"$WORK/big")

echo "== one pool"
start "$WORK/p1/d{1...4}"
status -X PUT "$EP/$B" >/dev/null
status -T "$WORK/big" "$EP/$B/old.bin" >/dev/null
for i in $(seq 1 5); do echo "old $i" | curl -s -o /dev/null "${S3[@]}" -T - "$EP/$B/pre/o$i"; done
stop

echo "== expanded with a second pool"
start "$WORK/p1/d{1...4}" "$WORK/p2/d{1...4}"
expect "pool 2 joins the deployment" "$(depid "$WORK/p2/d3")" "$(depid "$WORK/p1/d1")"
expect "bucket created on pool 2" "$([[ -d "$WORK/p2/d2/$B" ]] && echo yes)" yes
expect "old object readable" "$(get_md5 old.bin)" "$BIG"
head -c 2000000 /dev/urandom >"$WORK/big2"
expect "overwrite old object" "$(status -T "$WORK/big2" "$EP/$B/old.bin")" 200
expect "overwrite stays in pool 1" "$(in_pool 1 old.bin)/$(in_pool 2 old.bin)" yes/no
expect "overwritten content" "$(get_md5 old.bin)" "$(md5of <"$WORK/big2")"
for i in $(seq 1 40); do echo "new $i" | curl -s -o /dev/null "${S3[@]}" -T - "$EP/$B/new/o$i"; done
n1=0; n2=0
for i in $(seq 1 40); do
  [[ $(in_pool 1 "new/o$i") == yes ]] && n1=$((n1 + 1))
  [[ $(in_pool 2 "new/o$i") == yes ]] && n2=$((n2 + 1))
done
expect "each new object in exactly one pool" "$((n1 + n2))" 40
expect "new objects spread over both pools" "$([[ $n1 -gt 0 && $n2 -gt 0 ]] && echo yes || echo "$n1/$n2")" yes
ok=0; for i in $(seq 1 40); do [[ "$(curl -s "${S3[@]}" "$EP/$B/new/o$i")" == "new $i" ]] && ok=$((ok + 1)); done
expect "40 new objects readable" "$ok" 40
keys=$(curl -s "${S3[@]}" "$EP/$B?list-type=2&max-keys=1000" | grep -o '<Key>[^<]*</Key>' | wc -l | tr -d ' ')
expect "listing merges both pools" "$keys" 46
paged=0; token=
while :; do
  q="list-type=2&max-keys=7"; [[ -n $token ]] && q="$q&continuation-token=$(printf %s "$token" | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g')"
  page=$(curl -s "${S3[@]}" "$EP/$B?$q")
  paged=$((paged + $(printf %s "$page" | grep -o '<Key>' | wc -l)))
  token=$(printf %s "$page" | sed -n 's/.*<NextContinuationToken>\([^<]*\)<.*/\1/p')
  [[ -z $token ]] && break
done
expect "paged listing across pools" "$paged" 46
expect "delimiter listing" "$(curl -s "${S3[@]}" "$EP/$B?list-type=2&delimiter=/" | grep -o '<Prefix>[^<]*/</Prefix>' | tr '\n' ' ')" "<Prefix>new/</Prefix> <Prefix>pre/</Prefix> "
expect "delete in whichever pool" "$(status -X DELETE "$EP/$B/new/o7")" 204
expect "deleted" "$(status "$EP/$B/new/o7")" 404

uid=$(curl -s "${S3[@]}" -X POST "$EP/$B/mp.bin?uploads" | sed -n 's/.*<UploadId>\(.*\)<\/UploadId>.*/\1/p')
head -c 5300000 /dev/urandom >"$WORK/part1"; head -c 1000 /dev/urandom >"$WORK/part2"
e1=$(curl -s "${S3[@]}" -T "$WORK/part1" -D - -o /dev/null "$EP/$B/mp.bin?partNumber=1&uploadId=$uid" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
e2=$(curl -s "${S3[@]}" -T "$WORK/part2" -D - -o /dev/null "$EP/$B/mp.bin?partNumber=2&uploadId=$uid" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
body="<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>$e1</ETag></Part><Part><PartNumber>2</PartNumber><ETag>$e2</ETag></Part></CompleteMultipartUpload>"
expect "multipart complete" "$(status -X POST --data-binary "$body" "$EP/$B/mp.bin?uploadId=$uid")" 200
expect "multipart content" "$(get_md5 mp.bin)" "$(cat "$WORK/part1" "$WORK/part2" | md5of)"
stop

echo "== a pool from another deployment is refused"
start "$WORK/x/d{1...4}"
stop
BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$PORT" \
  "$WORK/p1/d{1...4}" "$WORK/x/d{1...4}" 2>"$WORK/foreign.log" && rc=0 || rc=$?
expect "startup fails" "$([[ $rc != 0 ]] && echo failed)" failed
expect "names the foreign deployment" "$(grep -c 'belong to deployment' "$WORK/foreign.log")" 1

if [[ -n "${MINIO_BIN:-}" ]]; then
  echo "== real MinIO reads the expanded deployment"
  MINIO_CI_CD=on MINIO_ROOT_USER=$AK MINIO_ROOT_PASSWORD=$SK "$MINIO_BIN" server --address "127.0.0.1:$PORT" \
    --console-address "127.0.0.1:$((PORT + 1))" "$WORK/p1/d{1...4}" "$WORK/p2/d{1...4}" >"$WORK/minio.log" 2>&1 &
  PID=$!
  for _ in $(seq 100); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.2; done
  sleep 1
  ok=0; for i in $(seq 1 40); do [[ $i == 7 || "$(curl -s "${S3[@]}" "$EP/$B/new/o$i")" == "new $i" ]] && ok=$((ok + 1)); done
  expect "minio reads objects from both pools" "$ok" 40
  expect "minio reads the multipart object" "$(get_md5 mp.bin)" "$(cat "$WORK/part1" "$WORK/part2" | md5of)"
  stop
fi

if grep -q 'Sanitizer\|runtime error' "$WORK/log"; then
  fail=$((fail + 1)); echo "  FAIL  sanitizer report:"; grep -A20 'Sanitizer\|runtime error' "$WORK/log" | head -40
fi
echo "pools: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
