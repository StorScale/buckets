#!/usr/bin/env bash
# Handing drives back to a MinIO older than RELEASE.2024-10-29: that MinIO
# refuses xl.meta metaVersion 3, which Buckets writes by default, so with
# BUCKETS_XL_META_VERSION=2 everything Buckets writes or rewrites on its drives
# must stay readable to it. Default (3): what Buckets wrote is unreadable to it.
#   MINIO_OLD_BIN=/path/to/minio-RELEASE.2024-10-13 tests/integration/minio-rollback.sh [bucketsd]
# (build one: git clone --branch RELEASE.2024-10-13T13-34-11Z https://github.com/minio/minio
#  and CGO_ENABLED=0 go build). Skipped without MINIO_OLD_BIN.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
[[ -n ${MINIO_OLD_BIN:-} ]] || { echo "minio-rollback: skipped (set MINIO_OLD_BIN)"; exit 0; }
PORT=${PORT:-19781}
U="http://127.0.0.1:$PORT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-rollback-XXXXXX")
P=
cleanup() { [[ -n $P ]] && kill "$P" 2>/dev/null; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
R=(--aws-sigv4 aws:amz:us-east-1:s3 --user rootadmin:rootsecret123)
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123 BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123
export MINIO_CI_CD=on # several drives on one filesystem
start() { # drives, then the server command
  local drives=$1
  shift
  "$@" server --address "127.0.0.1:$PORT" "$drives" > "$WORK/log" 2>&1 &
  P=$!
  # MinIO answers health checks before it is initialized: wait for a real call
  for _ in $(seq 200); do [[ $(curl -s "${R[@]}" -o /dev/null -w '%{http_code}' "$U/") == 200 ]] && return; sleep 0.2; done
  echo "server did not start"; tail -5 "$WORK/log"; exit 1
}
stop() { kill "$P"; wait "$P" 2>/dev/null || true; P=; }
code() { curl -s "${R[@]}" -o /dev/null -w '%{http_code}' "$@"; }
body() { curl -s "${R[@]}" "$@"; }
keys() { body "$U/$1?list-type=2" | grep -oE '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g' | tr '\n' ' '; }
versions() { body "$U/$1?versions" | grep -o '<Version>' | wc -l | tr -d ' '; }

run() { # metaVersion Buckets writes ("" for the default), then the checks MinIO is held to
  local mv=$1 d="$WORK/drives-${1:-default}"
  mkdir -p "$d"/{1..4}
  start "$d/{1...4}" "$MINIO_OLD_BIN"
  code -X PUT "$U/plain" >/dev/null
  code -X PUT "$U/vers" >/dev/null
  code -X PUT "$U/vers?versioning" -d '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>' >/dev/null
  code -X PUT "$U/plain/by-minio" --data-binary minio-data >/dev/null
  code -X PUT "$U/vers/doc" --data-binary v1-minio >/dev/null
  stop
  BUCKETS_XL_META_VERSION=$mv start "$d/{1...4}" "$BIN"
  code -X PUT "$U/plain/by-buckets" --data-binary buckets-data >/dev/null
  head -c 300000 /dev/urandom > "$WORK/big"
  code -X PUT "$U/plain/big-by-buckets" --data-binary @"$WORK/big" >/dev/null # not inline: a data dir
  code -X PUT "$U/vers/doc" --data-binary v2-buckets >/dev/null              # a version on MinIO's object
  code -X PUT "$U/plain/by-minio?tagging" -d '<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>' >/dev/null
  code -X DELETE "$U/vers/gone" >/dev/null                                  # a delete marker
  stop
  start "$d/{1...4}" "$MINIO_OLD_BIN"
}

echo "== Buckets with BUCKETS_XL_META_VERSION=2, then MinIO before 2024-10-29 again"
run 2
expect "MinIO lists Buckets' objects" "$(keys plain)" "big-by-buckets by-buckets by-minio "
expect "MinIO reads Buckets' object" "$(body "$U/plain/by-buckets")" buckets-data
expect "MinIO reads Buckets' large object" "$(body "$U/plain/big-by-buckets" | cmp -s - "$WORK/big" && echo same)" same
expect "MinIO's own object, re-tagged by Buckets" "$(body "$U/plain/by-minio")" minio-data
expect "the tag Buckets set" "$(body "$U/plain/by-minio?tagging" | grep -o '<Value>v</Value>')" "<Value>v</Value>"
expect "the version Buckets added" "$(body "$U/vers/doc")" v2-buckets
expect "versions" "$(versions vers)" 2
expect "MinIO writes again" "$(code -X PUT "$U/plain/after" --data-binary x)" 200
stop

echo "== Buckets with the default (metaVersion 3): MinIO before 2024-10-29 cannot read it"
run ""
# by-minio too: tagging it made Buckets rewrite its xl.meta as metaVersion 3
expect "MinIO lists none of them, its own re-tagged one included" "$(keys plain)" ""
expect "MinIO cannot read Buckets' object" "$(code "$U/plain/by-buckets")" 503
expect "nor its own object Buckets rewrote" "$(code "$U/plain/by-minio")" 503
stop

echo "minio-rollback: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
