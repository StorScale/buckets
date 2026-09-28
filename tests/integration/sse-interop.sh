#!/usr/bin/env bash
# Encrypted objects on disk, both ways between MinIO and bucketsd: SSE-S3 and
# SSE-KMS objects (with the same builtin KMS key) written by one are read back
# byte for byte, with the same ETags and sizes, by the other.
#   MINIO_BIN=/path/to/minio tests/integration/sse-interop.sh [bucketsd]
# Skips (exit 0) when MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "sse-interop: skipped (set MINIO_BIN)"
  exit 0
fi
PORT=${PORT:-19850}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-sse-XXXXXX")
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
put() { # name file sse-headers...
  local name=$1 file=$2
  shift 2
  curl -sf "${S3[@]}" -X PUT --data-binary @"$file" "$@" "$EP/ssex/$name" >/dev/null || fail "put $name"
}
# every object: name, etag, size, sha256 of the content, and a range
# an SSE-S3 multipart object: two parts, each sealed with its part key
put_multipart() {
  local up e1 e2
  up=$(curl -sf "${S3[@]}" -X POST -H "X-Amz-Server-Side-Encryption: AES256" "$EP/ssex/s3-mp?uploads" |
    sed -n 's:.*<UploadId>\(.*\)</UploadId>.*:\1:p')
  [[ -n "$up" ]] || fail "create upload"
  e1=$(curl -sf -D - -o /dev/null "${S3[@]}" -X PUT --data-binary @"$WORK/part1" "$EP/ssex/s3-mp?partNumber=1&uploadId=$up" |
    tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
  e2=$(curl -sf -D - -o /dev/null "${S3[@]}" -X PUT --data-binary @"$WORK/small" "$EP/ssex/s3-mp?partNumber=2&uploadId=$up" |
    tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
  curl -sf "${S3[@]}" -X POST --data-binary \
    "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>$e1</ETag></Part><Part><PartNumber>2</PartNumber><ETag>$e2</ETag></Part></CompleteMultipartUpload>" \
    "$EP/ssex/s3-mp?uploadId=$up" >/dev/null || fail "complete upload"
}
snapshot() {
  for o in s3-small s3-big kms-small kms-ctx s3-mp; do
    h=$(curl -s -I "${S3[@]}" "$EP/ssex/$o" | tr -d '\r' | grep -iE '^(etag|content-length|x-amz-server-side-encryption[a-z-]*):' | sort | tr '\n' ' ')
    sum=$(curl -s "${S3[@]}" "$EP/ssex/$o" | shasum -a 256 | cut -c1-16)
    rng=$(curl -s "${S3[@]}" -H 'Range: bytes=500-900' "$EP/ssex/$o" | shasum -a 256 | cut -c1-16)
    echo "$o $h $sum $rng"
  done
}
mkdir -p "$D"/d{1..4}
head -c 1000 /dev/urandom >"$WORK/small"
head -c 200000 /dev/urandom >"$WORK/big"
head -c 5242880 /dev/urandom >"$WORK/part1"

for writer in buckets minio; do
  reader=$([[ $writer == buckets ]] && echo minio || echo buckets)
  echo "== $writer writes, $reader reads"
  rm -rf "$D" && mkdir -p "$D"/d{1..4}
  start "$writer"
  curl -sf "${S3[@]}" -X PUT "$EP/ssex" >/dev/null || fail "make bucket"
  put s3-small "$WORK/small" -H "X-Amz-Server-Side-Encryption: AES256"
  put s3-big "$WORK/big" -H "X-Amz-Server-Side-Encryption: AES256"
  put kms-small "$WORK/small" -H "X-Amz-Server-Side-Encryption: aws:kms"
  # (curl's --aws-sigv4 misorders headers whose names prefix each other, so
  # the key-ID and context headers are exercised by s3diff instead)
  put kms-ctx "$WORK/big" -H "X-Amz-Server-Side-Encryption: aws:kms"
  put_multipart
  snapshot >"$WORK/$writer.w"
  stop
  start "$reader"
  snapshot >"$WORK/$writer.r"
  stop
  diff "$WORK/$writer.w" "$WORK/$writer.r" || fail "$reader reads $writer's encrypted objects differently"
  grep -q "$(shasum -a 256 "$WORK/big" | cut -c1-16)" "$WORK/$writer.r" || fail "content"
done
echo "PASS"
