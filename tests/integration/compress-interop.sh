#!/usr/bin/env bash
# Compressed objects on disk, both ways between MinIO and bucketsd: with
# compression on (and allowed with encryption), objects one writes are read
# back byte for byte, with the same ETags, sizes and ranges, by the other.
# Covers single-part objects with and without an index (over 8 MiB),
# multipart objects, and SSE-S3 compressed objects (padded streams, sealed
# indexes).
#   MINIO_BIN=/path/to/minio tests/integration/compress-interop.sh [bucketsd]
# Skips (exit 0) when MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "compress-interop: skipped (set MINIO_BIN)"
  exit 0
fi
PORT=${PORT:-19860}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-comp-XXXXXX")
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
export MINIO_KMS_SECRET_KEY=interop-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
export MINIO_COMPRESSION_ENABLE=on MINIO_COMPRESSION_ALLOW_ENCRYPTION=on
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
start() {
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$D/d{1...4}" >>"$WORK/log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" 2>>"$WORK/log" &
  fi
  PID=$!
  for _ in $(seq 150); do [[ $(curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$EP/") == 200 ]] && return; sleep 0.1; done
  fail "$1 did not start"
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
put() { # name file headers...
  local name=$1 file=$2
  shift 2
  curl -sf "${S3[@]}" -X PUT -H "Content-Type: text/plain" --data-binary @"$file" "$@" "$EP/compx/$name" >/dev/null ||
    fail "put $name"
}
# name, then part files; extra headers for the create in CREATE_H
put_multipart() {
  local name=$1 up body="" n=0 e
  shift
  up=$(curl -sf "${S3[@]}" -X POST -H "Content-Type: text/plain" ${CREATE_H:+-H "$CREATE_H"} "$EP/compx/$name?uploads" |
    sed -n 's:.*<UploadId>\(.*\)</UploadId>.*:\1:p')
  [[ -n "$up" ]] || fail "create upload $name"
  for f in "$@"; do
    n=$((n + 1))
    e=$(curl -sf -D - -o /dev/null "${S3[@]}" -X PUT --data-binary @"$f" "$EP/compx/$name?partNumber=$n&uploadId=$up" |
      tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
    [[ -n "$e" ]] || fail "part $n of $name"
    body+="<Part><PartNumber>$n</PartNumber><ETag>$e</ETag></Part>"
  done
  curl -sf "${S3[@]}" -X POST --data-binary "<CompleteMultipartUpload>$body</CompleteMultipartUpload>" \
    "$EP/compx/$name?uploadId=$up" >/dev/null || fail "complete $name"
}
OBJECTS="small.txt big.txt tiny.txt mp.txt enc-big.txt enc-mp.txt plain.jpg"
RANGES="0-99 500-900 1048570-1048600 5242870-5243000 9000000-9000100 12000000-12582911 -777"
fetch() { # status, and a digest of 2xx bodies
  local code
  code=$(curl -s -o "$WORK/body" -w '%{http_code}' "${S3[@]}" "$@")
  if [[ $code == 2* ]]; then echo "$code:$(shasum -a 256 <"$WORK/body" | cut -c1-12)"; else echo "$code"; fi
}
snapshot() {
  for o in $OBJECTS; do
    h=$(curl -s -I "${S3[@]}" "$EP/compx/$o" | tr -d '\r' | grep -iE '^(etag|content-length|x-amz-server-side-encryption):' |
      sort | tr '\n' ' ')
    sum=$(curl -s "${S3[@]}" "$EP/compx/$o" | shasum -a 256 | cut -c1-16)
    line="$o $h $sum"
    # (error documents carry request IDs: only their status is compared)
    for r in $RANGES; do
      line+=" $(fetch -H "Range: bytes=$r" "$EP/compx/$o")"
    done
    line+=" p2:$(fetch "$EP/compx/$o?partNumber=2")"
    echo "$line"
  done
  curl -s "${S3[@]}" "$EP/compx?list-type=2" | grep -o '<Size>[0-9]*</Size>' | tr '\n' ' '
  echo
}
mkdir -p "$D"/d{1..4}
# compressible text
awk 'BEGIN { srand(7); for (i = 0; i < 320000; i++) printf "%08d the quick brown fox %d jumps over %x\n", i, int(rand() * 1000), i * 7 }' >"$WORK/text"
head -c 12582912 "$WORK/text" >"$WORK/big"
head -c 20000 "$WORK/big" >"$WORK/small"
head -c 3000 "$WORK/big" >"$WORK/tiny" # below minCompressibleSize
head -c 9437184 "$WORK/big" >"$WORK/part1" # 9 MiB: its part gets an index
tail -c 3000000 "$WORK/big" >"$WORK/part2"

for writer in buckets minio; do
  reader=$([[ $writer == buckets ]] && echo minio || echo buckets)
  echo "== $writer writes, $reader reads"
  rm -rf "$D" && mkdir -p "$D"/d{1..4}
  start "$writer"
  curl -sf "${S3[@]}" -X PUT "$EP/compx" >/dev/null || fail "make bucket"
  put small.txt "$WORK/small"
  put big.txt "$WORK/big"
  put tiny.txt "$WORK/tiny"
  put plain.jpg "$WORK/small" # an excluded extension
  put enc-big.txt "$WORK/big" -H "X-Amz-Server-Side-Encryption: AES256"
  put_multipart mp.txt "$WORK/part1" "$WORK/part2"
  CREATE_H="X-Amz-Server-Side-Encryption: AES256" put_multipart enc-mp.txt "$WORK/part1" "$WORK/part2"
  snapshot >"$WORK/$writer.w"
  stop
  if [[ $writer == buckets ]]; then
    # stored compressed: well under the 12 MiB objects' plaintext
    kb=$(du -sk "$D/d1/compx" | cut -f1)
    ((kb < 20000)) || fail "objects do not look compressed on disk (${kb} KiB on one drive)"
  fi
  start "$reader"
  snapshot >"$WORK/$writer.r"
  stop
  diff "$WORK/$writer.w" "$WORK/$writer.r" || fail "$reader reads $writer's compressed objects differently"
  grep -q "big.txt .* $(shasum -a 256 "$WORK/big" | cut -c1-16)" "$WORK/$writer.r" || fail "content"
done
cp "$WORK/buckets.w" "$WORK/cmp.buckets"
cp "$WORK/minio.w" "$WORK/cmp.minio"
# The same requests answered alike by both (ETags aside: MinIO's are over the plaintext too).
diff "$WORK/cmp.buckets" "$WORK/cmp.minio" || fail "bucketsd and MinIO answer differently"
echo "PASS"
