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
  rm -rf "$DIR" "$LOG" "$DIR.small" "$DIR.big"
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
check "get missing object"         404 "<Code>NoSuchKey</Code>"    -- "${S3[@]}" "$EP/photos/cat.jpg"
check "path traversal refused"     400 "XMinioInvalidResourceName" -- "${S3[@]}" --path-as-is "$EP/photos/../../etc"

# objects: small (inline) and multi-block (part file)
printf 'meow\n' > "$DIR.small"
head -c 3000000 /dev/urandom > "$DIR.big"
BIG_MD5=$( (md5sum "$DIR.big" 2>/dev/null || md5 -r "$DIR.big") | cut -d' ' -f1)
check "put small object"           200 ""                          -- "${S3[@]}" -T "$DIR.small" -H 'X-Amz-Meta-Pet: cat' "$EP/photos/cat.txt"
check "put object with bad md5"    400 "BadDigest"                 -- "${S3[@]}" -T "$DIR.small" -H 'Content-MD5: 1B2M2Y8AsgTpgAmY7PhCfg==' "$EP/photos/x.txt"
check "put large object"           200 ""                          -- "${S3[@]}" -T "$DIR.big" "$EP/photos/2026/big.bin"
check "get small object"           200 "meow"                      -- "${S3[@]}" "$EP/photos/cat.txt"
check "head object meta"           200 ""                          -- "${S3[@]}" -I "$EP/photos/cat.txt"
got=$(curl -s "${S3[@]}" "$EP/photos/2026/big.bin" | (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1)
if [[ "$got" == "$BIG_MD5" ]]; then pass=$((pass + 1)); echo "  ok    large object round trip"; else fail=$((fail + 1)); echo "  FAIL  large object round trip"; fi
check "range read"                 206 ""                          -- "${S3[@]}" -H 'Range: bytes=1048570-1048580' "$EP/photos/2026/big.bin"
check "unsatisfiable range"        416 "InvalidRange"              -- "${S3[@]}" -H 'Range: bytes=9999999-' "$EP/photos/cat.txt"
check "if-none-match"              304 ""                          -- "${S3[@]}" -H 'If-None-Match: *' "$EP/photos/cat.txt"
check "if-match mismatch"          412 "PreconditionFailed"        -- "${S3[@]}" -H 'If-Match: "nope"' "$EP/photos/cat.txt"
check "copy object"                200 "<CopyObjectResult"         -- "${S3[@]}" -X PUT -H 'X-Amz-Copy-Source: /photos/cat.txt' "$EP/photos/cat-copy.txt"
check "copy onto itself refused"   400 "InvalidRequest"            -- "${S3[@]}" -X PUT -H 'X-Amz-Copy-Source: /photos/cat.txt' "$EP/photos/cat.txt"
check "list with delimiter"        200 "<Prefix>2026/</Prefix>"    -- "${S3[@]}" "$EP/photos?delimiter=/"
check "list v2 paged"              200 "<NextContinuationToken>"   -- "${S3[@]}" "$EP/photos?list-type=2&max-keys=1"
check "parent is an object"        400 "XMinioObjectExistsAsDirectory" -- "${S3[@]}" -T "$DIR.small" "$EP/photos/cat.txt/inner"
check "delete non-empty bucket"    409 "BucketNotEmpty"            -- "${S3[@]}" -X DELETE "$EP/photos"
check "delete objects (batch)"     200 "<Deleted><Key>cat-copy.txt</Key>" -- "${S3[@]}" -X POST "$EP/photos?delete" \
  --data '<Delete><Object><Key>cat-copy.txt</Key></Object><Object><Key>2026/big.bin</Key></Object></Delete>'
check "delete object"              204 ""                          -- "${S3[@]}" -X DELETE "$EP/photos/cat.txt"
check "delete missing object"      204 ""                          -- "${S3[@]}" -X DELETE "$EP/photos/cat.txt"
check "list after deletes"         200 "<KeyCount>0</KeyCount>"    -- "${S3[@]}" "$EP/photos?list-type=2"
check "delete bucket"              204 ""                          -- "${S3[@]}" -X DELETE "$EP/photos"
check "delete missing bucket"      404 "NoSuchBucket"              -- "${S3[@]}" -X DELETE "$EP/photos"

echo "smoke: $pass passed, $fail failed"
if ((fail)); then
  echo "--- server log ---"
  cat "$LOG"
  exit 1
fi
