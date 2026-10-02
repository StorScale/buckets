#!/usr/bin/env bash
# Encrypting existing objects in place (KeyRotate with encryption.includeUnencrypted,
# a Buckets extension): every unencrypted version is rewritten encrypted with
# its version ID, modification time, metadata, tags and
# checksum kept (the ETag too for SSE-S3 and a single-part object: an
# SSE-KMS object's ETag is not its MD5, as in S3), compressed ones stay
# compressed, and nothing readable is left
# on the drives. Objects already encrypted are rotated as before.
#   tests/integration/encrypt-existing.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19690}
U="http://127.0.0.1:$PORT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-encex-XXXXXX")
P=
cleanup() { [[ -n $P ]] && kill "$P" 2>/dev/null; wait 2>/dev/null || true; [[ -n ${KEEP:-} ]] || rm -rf "$WORK"; }
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
export BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123
export MINIO_KMS_SECRET_KEY="static-key:$(openssl rand -base64 32)"
export MINIO_COMPRESSION_ENABLE=on MINIO_COMPRESSION_EXTENSIONS=.log MINIO_COMPRESSION_MIME_TYPES=none \
  MINIO_COMPRESSION_ALLOW_ENCRYPTION=on
R=(--aws-sigv4 aws:amz:us-east-1:s3 --user rootadmin:rootsecret123)
D="$WORK/d"
mkdir -p "$D"/{1..4}
start() {
  "$BIN" server --address "127.0.0.1:$PORT" "$D/{1...4}" 2>>"$WORK/b.log" &
  P=$!
  for _ in $(seq 300); do [[ $(curl -s "${R[@]}" -o /dev/null -w '%{http_code}' "$U/") == 200 ]] && return; sleep 0.1; done
  echo "bucketsd did not start"; tail -5 "$WORK/b.log"; exit 1
}
stop() { kill "$P"; wait "$P" 2>/dev/null || true; P=; }
code() { curl -s "${R[@]}" -o /dev/null -w '%{http_code}' "$@"; }
body() { curl -s "${R[@]}" "$@"; }
hdr() { # url header: its value
  curl -s "${R[@]}" -I "$1" ${3:+-H "$3"} | tr -d '\r' | awk -v h="$(echo "$2" | tr A-Z a-z)" -F': ' 'tolower($1)==h {print $2}'
}
admin() { curl -s "${R[@]}" "$U/minio/admin/v3/$1" "${@:2}"; }
run_job() { # yaml: start it, wait for it, print complete/failed and the objects counts
  local id
  id=$(admin start-job -X POST --data-binary "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  echo "$id" > "$WORK/last-job"
  for _ in $(seq 150); do
    local m
    m=$(admin "status-job?jobId=$id" | python3 -c 'import json,sys
m = json.load(sys.stdin)["LastMetric"]
if m["complete"] or m["failed"]:
    r = m.get("rotation") or {}
    print("complete" if m["complete"] else "failed", r.get("objects", 0), r.get("objectsFailed", 0))' 2>/dev/null || true)
    [[ -n $m ]] && { echo "$m"; return; }
    sleep 0.2
  done
  echo timeout
}
# what a version looks like to a client: everything that must survive
look() { # bucket key [versionId] [etag: "no" leaves it out]
  local q=${3:+?versionId=$3}
  curl -s "${R[@]}" -I -H 'x-amz-checksum-mode: ENABLED' "$U/$1/$2$q" | tr -d '\r' |
    grep -iE '^(etag|last-modified|content-type|content-length|x-amz-meta-[a-z]+|x-amz-version-id|x-amz-checksum-[a-z0-9]+|x-amz-tagging-count):' | { [[ ${4:-} == no ]] && grep -vi '^etag:' || cat; } | sort
  body "$U/$1/$2$q" | sha256sum
}

start
echo "== objects written before there was any encryption"
code -X PUT "$U/plain" >/dev/null
code -X PUT "$U/plain/small" -H 'Content-Type: text/x-small' -H 'x-amz-meta-owner: payroll' --data-binary 'PLAINTEXT-SMALL-MARKER' >/dev/null
head -c 400000 /dev/urandom > "$WORK/big"
printf 'PLAINTEXT-BIG-MARKER' >> "$WORK/big"
code -X PUT "$U/plain/big" --data-binary @"$WORK/big" >/dev/null # not inline
python3 -c 'print("PLAINTEXT-LOG-MARKER compressible line\n" * 8000, end="")' > "$WORK/app.log"
code -X PUT "$U/plain/app.log" --data-binary @"$WORK/app.log" >/dev/null
code -X PUT "$U/plain/summed" -H "x-amz-checksum-sha256: $(printf 'PLAINTEXT-SUMMED' | openssl dgst -sha256 -binary | base64)" \
  --data-binary 'PLAINTEXT-SUMMED' >/dev/null
code -X PUT "$U/plain/small?tagging" -d '<Tagging><TagSet><Tag><Key>team</Key><Value>fin</Value></Tag></TagSet></Tagging>' >/dev/null
code -X PUT "$U/plain/already" -H 'x-amz-server-side-encryption: AES256' --data-binary 'was-encrypted' >/dev/null
code -X PUT "$U/vers" >/dev/null
code -X PUT "$U/vers?versioning" -d '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>' >/dev/null
code -X PUT "$U/vers/doc" --data-binary 'PLAINTEXT-V1-MARKER' >/dev/null
v1=$(body "$U/vers?versions" | grep -oE '<VersionId>[^<]+' | sed 's/<VersionId>//')
sleep 1.1 # distinct modification times
code -X PUT "$U/vers/doc" --data-binary 'PLAINTEXT-V2-MARKER' >/dev/null
code -X PUT "$U/vers/gone" --data-binary 'PLAINTEXT-GONE-MARKER' >/dev/null
code -X DELETE "$U/vers/gone" >/dev/null # a delete marker over it
v2=$(hdr "$U/vers/doc" x-amz-version-id)
for k in small big app.log summed; do look plain "$k" > "$WORK/before.$k"; done
look vers doc "$v1" no > "$WORK/before.v1"
look vers doc "$v2" no > "$WORK/before.v2"
expect "app.log is stored compressed" "$(grep -rlc 'PLAINTEXT-LOG-MARKER compressible line' "$D" | wc -l | tr -d ' ')" 0
expect "the markers are on the drives in the clear" "$(grep -rl 'PLAINTEXT-[A-Z0-9]*-MARKER' "$D" | wc -l | tr -d ' ' | sed 's/^0$/none/;s/^[1-9][0-9]*$/some/')" some
expect "small is not encrypted" "$(hdr "$U/plain/small" x-amz-server-side-encryption)" ""

echo "== keyrotate without includeUnencrypted skips them (as MinIO's)"
expect "the job" "$(run_job $'keyrotate:\n  apiVersion: v1\n  bucket: plain\n  encryption:\n    type: sse-s3\n')" "complete 1 0"
expect "small is still not encrypted" "$(hdr "$U/plain/small" x-amz-server-side-encryption)" ""

echo "== includeUnencrypted, SSE-S3"
expect "the job" "$(run_job $'keyrotate:\n  apiVersion: v1\n  bucket: plain\n  encryption:\n    type: sse-s3\n    includeUnencrypted: true\n')" "complete 5 0"
for k in small big app.log summed; do
  expect "$k is SSE-S3" "$(hdr "$U/plain/$k" x-amz-server-side-encryption)" AES256
  expect "$k looks the same" "$(look plain "$k")" "$(cat "$WORK/before.$k")"
done
expect "the tag" "$(body "$U/plain/small?tagging" | grep -o '<Value>fin</Value>')" "<Value>fin</Value>"
expect "already-encrypted one still reads" "$(body "$U/plain/already")" was-encrypted

echo "== onlyUnencrypted leaves encrypted objects alone"
code -X PUT "$U/plain/later" --data-binary 'PLAINTEXT-LATER-MARKER' >/dev/null
code -X PUT "$U/plain/kms-one" -H 'x-amz-server-side-encryption: aws:kms' --data-binary 'kms-data' >/dev/null
already=$(hdr "$U/plain/already" etag)
# sse-s3 over an SSE-KMS object would fail as not applicable: here it is not visited
expect "the job: only later" "$(run_job $'keyrotate:\n  apiVersion: v1\n  bucket: plain\n  encryption:\n    type: sse-s3\n    onlyUnencrypted: true\n')" "complete 1 0"
expect "  described with the option" "$(admin "describe-job?jobId=$(cat "$WORK/last-job")" | grep -c 'onlyUnencrypted: true')" 1
expect "later is SSE-S3" "$(hdr "$U/plain/later" x-amz-server-side-encryption)" AES256
expect "kms-one is still SSE-KMS" "$(hdr "$U/plain/kms-one" x-amz-server-side-encryption)" aws:kms
expect "  and reads" "$(body "$U/plain/kms-one")" kms-data
expect "already is untouched" "$(hdr "$U/plain/already" etag)" "$already"

echo "== includeUnencrypted, SSE-KMS, every version"
expect "the job" "$(run_job $'keyrotate:\n  apiVersion: v1\n  bucket: vers\n  encryption:\n    type: sse-kms\n    key: static-key\n    includeUnencrypted: true\n')" "complete 3 0"
expect "v1 is SSE-KMS" "$(hdr "$U/vers/doc?versionId=$v1" x-amz-server-side-encryption)" aws:kms
expect "v2 is SSE-KMS" "$(hdr "$U/vers/doc?versionId=$v2" x-amz-server-side-encryption)" aws:kms
expect "v1 looks the same, but its ETag" "$(look vers doc "$v1" no)" "$(cat "$WORK/before.v1")"
expect "v2 looks the same, but its ETag" "$(look vers doc "$v2" no)" "$(cat "$WORK/before.v2")"
expect "no new versions" "$(body "$U/vers?versions" | grep -oE '<(Version|DeleteMarker)>' | sort | uniq -c | tr -s ' \n' ' ')" " 1 <DeleteMarker> 3 <Version> "
expect "  the same ones" "$(body "$U/vers?versions" | grep -oE "<VersionId>($v1|$v2)<" | wc -l | tr -d ' ')" 2

echo "== a version under object lock"
code -X PUT "$U/locked" -H 'x-amz-bucket-object-lock-enabled: true' >/dev/null
until=$(date -u -d '+2 days' +%Y-%m-%dT%H:%M:%SZ)
code -X PUT "$U/locked/held" -H 'x-amz-object-lock-mode: COMPLIANCE' -H "x-amz-object-lock-retain-until-date: $until" \
  -H 'x-amz-object-lock-legal-hold: ON' -H "Content-MD5: $(printf 'PLAINTEXT-HELD-MARKER' | openssl dgst -md5 -binary | base64)" \
  --data-binary 'PLAINTEXT-HELD-MARKER' >/dev/null
lockhdrs() { curl -s "${R[@]}" -I "$U/locked/held" | tr -d '\r' | grep -i '^x-amz-object-lock' | sort; }
before_lock=$(lockhdrs)
expect "it is locked" "$(echo "$before_lock" | grep -c 'COMPLIANCE\|ON')" 2
expect "the job" "$(run_job $'keyrotate:\n  apiVersion: v1\n  bucket: locked\n  encryption:\n    type: sse-s3\n    onlyUnencrypted: true\n')" "complete 1 0"
expect "it is SSE-S3" "$(hdr "$U/locked/held" x-amz-server-side-encryption)" AES256
expect "  still locked as it was" "$(lockhdrs)" "$before_lock"
expect "  and still cannot be deleted (WORM protected, as MinIO says)" \
  "$(code -X DELETE "$U/locked/held?versionId=$(hdr "$U/locked/held" x-amz-version-id)")" 400

echo "== on the drives and after a restart"
expect "no marker is left in the clear" "$(grep -rl 'PLAINTEXT-[A-Z0-9]*-MARKER' "$D" | wc -l | tr -d ' ')" 0
stop
start
for k in small big app.log summed; do expect "$k after a restart" "$(look plain "$k")" "$(cat "$WORK/before.$k")"; done
expect "big's bytes" "$(body "$U/plain/big" | cmp -s - "$WORK/big" && echo same)" same
expect "v1 after a restart" "$(body "$U/vers/doc?versionId=$v1")" PLAINTEXT-V1-MARKER
expect "a second run finds nothing unencrypted" "$(run_job $'keyrotate:\n  apiVersion: v1\n  bucket: vers\n  encryption:\n    type: sse-kms\n    key: static-key\n    includeUnencrypted: true\n')" "complete 3 0"
expect "  and everything still reads" "$(body "$U/vers/doc")" PLAINTEXT-V2-MARKER
expect "  described with the option" "$(admin "describe-job?jobId=$(cat "$WORK/last-job")" | grep -c 'includeUnencrypted: true')" 1
stop

echo "encrypt-existing: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
