#!/usr/bin/env bash
# DeleteObjects on a heavily-versioned key: Buckets removes all the versions
# named in one request in a single metadata rewrite per drive, rather than one
# rewrite per version. This checks the result is correct (the named versions
# gone, other keys untouched) and that the batched path is dramatically faster
# than deleting the same versions one at a time (the quadratic old behaviour).
#   tests/integration/batch-delete.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19830}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-bdel-XXXXXX")
EP="http://127.0.0.1:$PORT"
D="$WORK/drives"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- log"; tail -20 "$WORK/log"; exit 1; }
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)

start() {
  "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" 2>>"$WORK/log" &
  PID=$!
  for _ in $(seq 150); do [[ $(curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$EP/") == 200 ]] && return; sleep 0.1; done
  fail "bucketsd did not start"
}
versioning() {
  curl -sf "${S3[@]}" -X PUT --data-binary "<VersioningConfiguration><Status>$1</Status></VersioningConfiguration>" \
    "$EP/photos?versioning" >/dev/null || fail "versioning $1"
}
put() { printf '%s' "$2" | curl -s -o /dev/null "${S3[@]}" -X PUT --data-binary @- "$EP/photos/$1"; }
# Version IDs of a key, newest first.
vids() { curl -s "${S3[@]}" "$EP/photos?versions&prefix=$1" | grep -oP '(?<=<VersionId>)[^<]+' || true; }
now_ms() { echo $(($(date +%s%N) / 1000000)); }

mkdir -p "$D"/d{1..4}
start
curl -sf "${S3[@]}" -X PUT "$EP/photos" >/dev/null || fail "make bucket"
versioning Enabled

N=${N:-400} # versions of "img"; half removed in one request, half one at a time
echo "== writing $N versions of img and 5 of keep"
for _ in $(seq "$N"); do put img "x"; done
for i in $(seq 5); do put keep "keep-$i"; done

mapfile -t IDS < <(vids img)
[[ ${#IDS[@]} -eq $N ]] || fail "expected $N versions, listed ${#IDS[@]}"
half=$((N / 2))

# --- batched: one DeleteObjects for the first half --------------------------
BODY="$WORK/del.xml"
{
  echo '<Delete>'
  for ((i = 0; i < half; i++)); do echo "<Object><Key>img</Key><VersionId>${IDS[$i]}</VersionId></Object>"; done
  echo '</Delete>'
} >"$BODY"
MD5=$(openssl dgst -md5 -binary "$BODY" | openssl base64)
t0=$(now_ms)
RESP=$(curl -s -H "Content-MD5: $MD5" "${S3[@]}" -X POST --data-binary @"$BODY" "$EP/photos?delete")
t1=$(now_ms)
batch_ms=$((t1 - t0))
got=$(grep -o '<Deleted>' <<<"$RESP" | wc -l)
[[ $got -eq $half ]] || fail "batched delete reported $got of $half (resp: $(head -c 300 <<<"$RESP"))"
grep -q '<Error>' <<<"$RESP" && fail "batched delete returned errors: $(head -c 300 <<<"$RESP")"
echo "   batched: removed $half versions in one request in ${batch_ms} ms"

# --- per-version: the remaining half, one DeleteObject each -----------------
t0=$(now_ms)
for ((i = half; i < N; i++)); do
  curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/photos/img?versionId=${IDS[$i]}"
done
t1=$(now_ms)
perver_ms=$((t1 - t0))
echo "   per-version: removed $half versions one at a time in ${perver_ms} ms"

# --- correctness ------------------------------------------------------------
left=$(vids img | wc -l)
[[ $left -eq 0 ]] || fail "img still has $left versions after deleting all"
keep=$(vids keep | wc -l)
[[ $keep -eq 5 ]] || fail "keep lost versions (have $keep, want 5); batch touched the wrong key"
# a kept version still reads back its bytes
body=$(curl -s "${S3[@]}" "$EP/photos/keep")
[[ $body == keep-* ]] || fail "keep unreadable after batch delete (got '$body')"
echo "   correctness: img emptied, keep intact (5 versions, readable)"

# --- the batched path must be faster than one-at-a-time ---------------------
# Same number of versions each way; per-version rewrites the whole record once
# per version (quadratic), batched rewrites it once.
if [[ $perver_ms -le $batch_ms ]]; then
  fail "batched ($batch_ms ms) not faster than per-version ($perver_ms ms)"
fi
echo "PASS: batched delete correct and ${batch_ms}ms vs ${perver_ms}ms per-version for $half versions"
