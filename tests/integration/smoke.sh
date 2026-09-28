#!/usr/bin/env bash
# End-to-end smoke test: starts bucketsd on a temp drive and drives it with
# curl's independent SigV4 signer (--aws-sigv4, curl >= 7.75).
#   usage: tests/integration/smoke.sh [path/to/bucketsd]
set -euo pipefail

BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19000}
AK=smoketestuser
SK=smoketestsecret123
DIR=$(mktemp -d "${TMPDIR:-/tmp}/buckets-smoke-XXXXXX")
LOG="$DIR.log"
EP="http://127.0.0.1:$PORT"

cleanup() {
  [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  rm -rf "$DIR" "$LOG"
}
trap cleanup EXIT

BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$PORT" "$DIR" 2>"$LOG" &
PID=$!
for _ in $(seq 50); do
  curl -sf "$EP/minio/health/live" >/dev/null && break
  sleep 0.1
done

pass=0
fail=0
# check NAME EXPECTED_STATUS EXPECTED_BODY_SUBSTRING -- curl args...
check() {
  local name=$1 want=$2 grepfor=$3
  shift 4
  local out status
  out=$(curl -s -w '\n%{http_code}' "$@" || true)
  status=${out##*$'\n'}
  body=${out%$'\n'*}
  if [[ "$status" == "$want" && ( -z "$grepfor" || "$body" == *"$grepfor"* ) ]]; then
    pass=$((pass + 1))
    printf '  ok    %-40s %s\n' "$name" "$status"
  else
    fail=$((fail + 1))
    printf '  FAIL  %-40s got %s, want %s %s\n%s\n' "$name" "$status" "$want" "$grepfor" "$body"
  fi
}

S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
BAD=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:wrong-secret-key")

check "health live"                200 ""                          -- "$EP/minio/health/live"
check "health ready (alias)"       200 ""                          -- "$EP/buckets/health/ready"
check "anonymous list denied"      403 "<Code>AccessDenied</Code>" -- "$EP/"
check "bad secret rejected"        403 "SignatureDoesNotMatch"     -- "${BAD[@]}" "$EP/"
check "list buckets (empty)"       200 "<Buckets></Buckets>"       -- "${S3[@]}" "$EP/"
check "create bucket"              200 ""                          -- "${S3[@]}" -X PUT "$EP/photos"
check "create bucket again"        409 "BucketAlreadyOwnedByYou"   -- "${S3[@]}" -X PUT "$EP/photos"
check "create invalid name"        400 "InvalidBucketName"         -- "${S3[@]}" -X PUT "$EP/Bad_Name"
check "create reserved name"       403 "AllAccessDisabled"         -- "${S3[@]}" -X PUT "$EP/minio"
check "create with location xml"   200 ""                          -- "${S3[@]}" -X PUT "$EP/logs" \
  --data '<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>'
check "create with malformed xml"  400 "MalformedXML"              -- "${S3[@]}" -X PUT "$EP/broken" --data '<Create'
check "list buckets"               200 "<Name>photos</Name>"       -- "${S3[@]}" "$EP/"
check "head bucket"                200 ""                          -- "${S3[@]}" -I "$EP/photos"
check "head missing bucket"        404 ""                          -- "${S3[@]}" -I "$EP/nothing-here"
check "get bucket location"        200 "<LocationConstraint"       -- "${S3[@]}" "$EP/photos?location"
check "get bucket versioning"      200 "<VersioningConfiguration"  -- "${S3[@]}" "$EP/photos?versioning"
check "list objects v2 (empty)"    200 "<KeyCount>0</KeyCount>"    -- "${S3[@]}" "$EP/photos?list-type=2&prefix=a%2Fb"
check "list objects bad max-keys"  400 "InvalidArgument"           -- "${S3[@]}" "$EP/photos?max-keys=-1"
check "object op not implemented"  501 "NotImplemented"            -- "${S3[@]}" "$EP/photos/cat.jpg"
check "path traversal refused"     400 "XMinioInvalidResourceName" -- "${S3[@]}" --path-as-is "$EP/photos/../../etc"
check "delete bucket"              204 ""                          -- "${S3[@]}" -X DELETE "$EP/photos"
check "delete missing bucket"      404 "NoSuchBucket"              -- "${S3[@]}" -X DELETE "$EP/photos"

echo "smoke: $pass passed, $fail failed"
if ((fail)); then
  echo "--- server log ---"
  cat "$LOG"
  exit 1
fi
