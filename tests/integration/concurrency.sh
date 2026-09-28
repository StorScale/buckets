#!/usr/bin/env bash
# Concurrent requests against a 4-drive erasure set: racing PUTs of one key
# must leave every drive agreeing on the same version, readers must see a
# whole object while it is overwritten, CopyObject onto itself must not
# deadlock, and parallel part uploads must assemble correctly.
#   tests/integration/concurrency.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19710}
AK=concurrencyuser
SK=concurrencysecret1
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-conc-XXXXXX")
EP="http://127.0.0.1:$PORT"
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
D="$WORK/drives"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }
start() {
  BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" \
    2>>"$WORK/log" &
  PID=$!
  for _ in $(seq 50); do curl -sf "$EP/minio/health/live" >/dev/null && return; sleep 0.1; done
  echo "server did not start"; cat "$WORK/log"; exit 1
}
pass=0
fail=0
expect() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$@"; }
jobs_=()
bg() { "$@" & jobs_+=($!); }
join() { wait "${jobs_[@]}"; jobs_=(); } # a bare `wait` would also wait for the server

start
status -X PUT "$EP/concbucket" >/dev/null

echo "== racing PUTs of one key"
for i in $(seq 1 16); do
  if ((i % 2)); then head -c 2500000 /dev/urandom >"$WORK/v$i"; else head -c 700 /dev/urandom >"$WORK/v$i"; fi
  md5of <"$WORK/v$i" >>"$WORK/versions"
done
put_to() { curl -s -o "$3.body" -w '%{http_code}' "${S3[@]}" -T "$1" "$2" >"$3"; }
for i in $(seq 1 16); do bg put_to "$WORK/v$i" "$EP/concbucket/hot" "$WORK/put$i"; done
join
ok=0; for i in $(seq 1 16); do [[ $(cat "$WORK/put$i") == 200 ]] && ok=$((ok + 1)); done
expect "all racing PUTs succeed" "$ok" 16
[[ $ok == 16 ]] || { echo "    statuses: $(cat "$WORK"/put? "$WORK"/put?? | tr '\n' ' ')"; cat "$WORK"/put*.body; grep -h 'WARN\|ERROR' "$WORK/log" | tail -5; }
# Read from each half of the set on its own: both halves must hold the same version.
read_half() { # hide drives $1 $2
  mv "$D/d$1/concbucket/hot" "$WORK/hide$1"; mv "$D/d$2/concbucket/hot" "$WORK/hide$2"
  curl -s "${S3[@]}" "$EP/concbucket/hot" | md5of
  mv "$WORK/hide$1" "$D/d$1/concbucket/hot"; mv "$WORK/hide$2" "$D/d$2/concbucket/hot"
}
a=$(read_half 1 2)
b=$(read_half 3 4)
expect "drives 3+4 agree with drives 1+2" "$a" "$b"
expect "the survivor is one of the uploads" "$(grep -c "^$a\$" "$WORK/versions")" 1

echo "== many keys in parallel"
for i in $(seq 1 24); do head -c $((300000 + i * 1000)) /dev/urandom >"$WORK/k$i"; done
for i in $(seq 1 24); do bg curl -s -o /dev/null "${S3[@]}" -T "$WORK/k$i" "$EP/concbucket/many/k$i"; done
join
for i in $(seq 1 24); do bg curl -s "${S3[@]}" "$EP/concbucket/many/k$i" -o "$WORK/g$i"; done
join
bad=0; for i in $(seq 1 24); do cmp -s "$WORK/k$i" "$WORK/g$i" || bad=$((bad + 1)); done
expect "24 parallel PUT+GET round trips" "$bad" 0

echo "== reading while the key is overwritten"
head -c 6000000 /dev/urandom >"$WORK/old"
head -c 6000000 /dev/urandom >"$WORK/new"
status -T "$WORK/old" "$EP/concbucket/swap" >/dev/null
curl -s "${S3[@]}" --limit-rate 3M "$EP/concbucket/swap" -o "$WORK/slow" &
g=$!
sleep 0.3
expect "overwrite during a read" "$(status -T "$WORK/new" "$EP/concbucket/swap")" 200
wait $g
expect "the slow reader got the whole old object" "$(md5of <"$WORK/slow")" "$(md5of <"$WORK/old")"
expect "later reads see the new object" "$(curl -s "${S3[@]}" "$EP/concbucket/swap" | md5of)" "$(md5of <"$WORK/new")"

echo "== CopyObject onto itself"
t0=$(date +%s)
code=$(status -X PUT -H "x-amz-copy-source: /concbucket/swap" -H "x-amz-metadata-directive: REPLACE" \
  -H "x-amz-meta-note: again" "$EP/concbucket/swap")
expect "self-copy succeeds" "$code" 200
expect "self-copy does not wait on its own lock" "$(( $(date +%s) - t0 < 10 ))" 1
expect "self-copy keeps the data" "$(curl -s "${S3[@]}" "$EP/concbucket/swap" | md5of)" "$(md5of <"$WORK/new")"

echo "== parallel multipart upload"
uid=$(curl -s "${S3[@]}" -X POST "$EP/concbucket/mp?uploads" | sed -n 's/.*<UploadId>\(.*\)<\/UploadId>.*/\1/p')
for p in 1 2 3 4 5; do head -c 5300000 /dev/urandom >"$WORK/p$p"; done
for p in 1 2 3 4 5; do
  bg curl -s "${S3[@]}" -T "$WORK/p$p" -D "$WORK/h$p" -o /dev/null "$EP/concbucket/mp?partNumber=$p&uploadId=$uid"
done
join
{
  echo "<CompleteMultipartUpload>"
  for p in 1 2 3 4 5; do
    et=$(tr -d '\r' <"$WORK/h$p" | sed -n 's/^[Ee][Tt]ag: //p')
    echo "<Part><PartNumber>$p</PartNumber><ETag>$et</ETag></Part>"
  done
  echo "</CompleteMultipartUpload>"
} >"$WORK/complete.xml"
expect "complete" "$(status -X POST --data-binary @"$WORK/complete.xml" "$EP/concbucket/mp?uploadId=$uid")" 200
cat "$WORK"/p1 "$WORK"/p2 "$WORK"/p3 "$WORK"/p4 "$WORK"/p5 >"$WORK/pall"
expect "assembled object" "$(curl -s "${S3[@]}" "$EP/concbucket/mp" | md5of)" "$(md5of <"$WORK/pall")"

kill "$PID"; wait "$PID" 2>/dev/null || true; PID=
if grep -q 'Sanitizer\|runtime error' "$WORK/log"; then
  fail=$((fail + 1)); echo "  FAIL  sanitizer report:"; grep -A20 'Sanitizer\|runtime error' "$WORK/log" | head -40
fi
echo "concurrency: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
