#!/usr/bin/env bash
# Interoperability test against real MinIO, using the mc client.
#
#   MC_BIN=/path/to/mc MINIO_BIN=/path/to/minio tests/integration/interop.sh [bucketsd]
#
# 1. bucketsd serves a fresh drive; mc drives it (single PUT, aws-chunked
#    streaming PUT, multipart, listing, stat, delete).
# 2. The same drive is then served by real MinIO, which must return identical
#    bytes, ETags and metadata for everything bucketsd wrote.
# 3. MinIO writes new objects; bucketsd must read them back.
# Skips (exit 0) when MC_BIN or MINIO_BIN is not set.
set -euo pipefail

BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" || -z "${MINIO_BIN:-}" ]]; then
  echo "interop: skipped (set MC_BIN and MINIO_BIN)"
  exit 0
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-interop-XXXXXX")
DRIVE=$WORK/drive
export MC_CONFIG_DIR=$WORK/mc
AK=interopuser
SK=interopsecret123
BK_PORT=${BK_PORT:-19400}
MN_PORT=${MN_PORT:-19401}
pids=()

cleanup() {
  for p in "${pids[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }
wait_ready() {
  for _ in $(seq 100); do
    curl -sf "http://127.0.0.1:$1/minio/health/ready" >/dev/null && return 0
    sleep 0.1
  done
  echo "server on :$1 did not become ready" >&2
  return 1
}

pass=0
fail=0
expect_eq() {
  if [[ "$2" == "$3" ]]; then
    pass=$((pass + 1))
    printf '  ok    %s\n' "$1"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"
  fi
}

printf 'hello interop\n' >"$WORK/small.txt"
head -c 5000000 /dev/urandom >"$WORK/mid.bin"   # single streaming PUT
head -c 40000000 /dev/urandom >"$WORK/large.bin" # multipart
SMALL=$(md5of <"$WORK/small.txt")
MID=$(md5of <"$WORK/mid.bin")
LARGE=$(md5of <"$WORK/large.bin")

echo "== bucketsd writes"
BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$BK_PORT" "$DRIVE" 2>"$WORK/bk.log" &
pids+=($!)
wait_ready "$BK_PORT"
"$MC_BIN" alias set bk "http://127.0.0.1:$BK_PORT" "$AK" "$SK" >/dev/null
"$MC_BIN" mb -q bk/interop >/dev/null
"$MC_BIN" cp -q --attr 'X-Amz-Meta-Origin=buckets' "$WORK/small.txt" bk/interop/docs/small.txt >/dev/null
"$MC_BIN" cp -q "$WORK/mid.bin" bk/interop/mid.bin >/dev/null
"$MC_BIN" cp -q "$WORK/large.bin" bk/interop/deep/path/large.bin >/dev/null
"$MC_BIN" cp -q --checksum CRC64NVME "$WORK/large.bin" bk/interop/cks/large-crc64.bin >/dev/null
"$MC_BIN" cp -q --checksum SHA256 "$WORK/large.bin" bk/interop/cks/large-sha256.bin >/dev/null
"$MC_BIN" cp -q "$WORK/small.txt" bk/interop/delete-me.txt >/dev/null
"$MC_BIN" rm -q bk/interop/delete-me.txt >/dev/null
expect_eq "bucketsd small" "$("$MC_BIN" cat bk/interop/docs/small.txt | md5of)" "$SMALL"
expect_eq "bucketsd streaming put" "$("$MC_BIN" cat bk/interop/mid.bin | md5of)" "$MID"
expect_eq "bucketsd multipart" "$("$MC_BIN" cat bk/interop/deep/path/large.bin | md5of)" "$LARGE"
expect_eq "bucketsd listing" "$("$MC_BIN" ls -r --json bk/interop | grep -c '"key"')" "5"
cks_of() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -I -H 'x-amz-checksum-mode: ENABLED' "$1" | grep -i '^x-amz-checksum' | tr -d '\r' | sort | tr '\n' ' '; }
BK_CK1=$(cks_of "http://127.0.0.1:$BK_PORT/interop/cks/large-crc64.bin")
BK_CK2=$(cks_of "http://127.0.0.1:$BK_PORT/interop/cks/large-sha256.bin")
BK_ETAG=$("$MC_BIN" stat --json bk/interop/deep/path/large.bin | sed -n 's/.*"etag":"\([^"]*\)".*/\1/p')
kill "${pids[0]}"
wait "${pids[0]}" 2>/dev/null || true
pids=()

echo "== real MinIO reads the bucketsd drive"
MINIO_ROOT_USER=$AK MINIO_ROOT_PASSWORD=$SK "$MINIO_BIN" server --address "127.0.0.1:$MN_PORT" \
  --console-address "127.0.0.1:$((MN_PORT + 1))" "$DRIVE" >"$WORK/minio.log" 2>&1 &
pids+=($!)
wait_ready "$MN_PORT"
"$MC_BIN" alias set mn "http://127.0.0.1:$MN_PORT" "$AK" "$SK" >/dev/null
expect_eq "minio reads small" "$("$MC_BIN" cat mn/interop/docs/small.txt | md5of)" "$SMALL"
expect_eq "minio reads streaming put" "$("$MC_BIN" cat mn/interop/mid.bin | md5of)" "$MID"
expect_eq "minio reads multipart" "$("$MC_BIN" cat mn/interop/deep/path/large.bin | md5of)" "$LARGE"
MN_ETAG=$("$MC_BIN" stat --json mn/interop/deep/path/large.bin | sed -n 's/.*"etag":"\([^"]*\)".*/\1/p')
expect_eq "same multipart etag" "$MN_ETAG" "$BK_ETAG"
expect_eq "minio sees user metadata" \
  "$("$MC_BIN" stat --json mn/interop/docs/small.txt | grep -o '"X-Amz-Meta-Origin":"buckets"' | head -1)" \
  '"X-Amz-Meta-Origin":"buckets"'
expect_eq "minio listing" "$("$MC_BIN" ls -r --json mn/interop | grep -c '"key"')" "5"
expect_eq "same full-object crc64nvme" "$(cks_of "http://127.0.0.1:$MN_PORT/interop/cks/large-crc64.bin")" "$BK_CK1"
expect_eq "same composite sha256" "$(cks_of "http://127.0.0.1:$MN_PORT/interop/cks/large-sha256.bin")" "$BK_CK2"
"$MC_BIN" cp -q "$WORK/large.bin" mn/interop/from-minio/large.bin >/dev/null
"$MC_BIN" cp -q "$WORK/small.txt" mn/interop/from-minio/small.txt >/dev/null
kill "${pids[0]}"
wait "${pids[0]}" 2>/dev/null || true
pids=()

echo "== bucketsd reads what MinIO wrote"
BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$BK_PORT" "$DRIVE" 2>>"$WORK/bk.log" &
pids+=($!)
wait_ready "$BK_PORT"
expect_eq "bucketsd reads minio multipart" "$("$MC_BIN" cat bk/interop/from-minio/large.bin | md5of)" "$LARGE"
expect_eq "bucketsd reads minio small" "$("$MC_BIN" cat bk/interop/from-minio/small.txt | md5of)" "$SMALL"
expect_eq "bucketsd lists all" "$("$MC_BIN" ls -r --json bk/interop | grep -c '"key"')" "7"

echo "interop: $pass passed, $fail failed"
if ((fail)); then
  echo "--- bucketsd log ---"
  cat "$WORK/bk.log"
  exit 1
fi
