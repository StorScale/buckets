#!/usr/bin/env bash
# Erasure-coding resilience on one node: 4- and 16-drive sets, bitrot,
# drive loss up to parity, loss beyond parity, and a replaced (empty) drive.
# Background healing is covered by heal.sh.
#   tests/integration/erasure.sh [bucketsd]
# With MINIO_BIN set, real MinIO must also read the Buckets-written set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19700}
AK=erasureuser
SK=erasuresecret123
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-erasure-XXXXXX")
EP="http://127.0.0.1:$PORT"
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  rm -rf "$WORK"
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

head -c 3500000 /dev/urandom >"$WORK/big"
head -c 900 /dev/urandom >"$WORK/small"
BIG=$(md5of <"$WORK/big")
SMALL=$(md5of <"$WORK/small")

for n in 4 16; do
  D="$WORK/n$n"
  echo "== $n drives"
  start "$D/d{1...$n}"
  expect "create bucket" "$(status -X PUT "$EP/ecbucket")" 200
  expect "put large" "$(status -T "$WORK/big" "$EP/ecbucket/big.bin")" 200
  expect "put small (inline)" "$(status -T "$WORK/small" "$EP/ecbucket/small.bin")" 200
  expect "read large" "$(curl -s "${S3[@]}" "$EP/ecbucket/big.bin" | md5of)" "$BIG"
  expect "read range" "$(curl -s "${S3[@]}" -H 'Range: bytes=1048570-2097160' "$EP/ecbucket/big.bin" | wc -c | tr -d ' ')" 1048591
  parity=$((n == 4 ? 2 : 4))

  # bitrot on one drive: detected and reconstructed
  part=$(ls "$D"/d1/ecbucket/big.bin/*/part.1)
  printf 'XXXXXXXXXXXXXXXX' | dd of="$part" bs=1 seek=100 conv=notrunc 2>/dev/null
  expect "read through bitrot" "$(curl -s "${S3[@]}" "$EP/ecbucket/big.bin" | md5of)" "$BIG"

  # lose `parity` drives: everything still readable
  for i in $(seq 1 "$parity"); do rm -rf "$D/d$i/ecbucket"; done
  expect "read large after losing $parity drives" "$(curl -s "${S3[@]}" "$EP/ecbucket/big.bin" | md5of)" "$BIG"
  expect "read small after losing $parity drives" "$(curl -s "${S3[@]}" "$EP/ecbucket/small.bin" | md5of)" "$SMALL"

  # lose one more than parity at once: reads fail with an error, never wrong
  # data. (The reads above queued heals that restore the drives, so let them
  # settle first.)
  sleep 1
  for i in $(seq 1 $((parity + 1))); do rm -rf "$D/d$i/ecbucket/big.bin"; done
  code=$(status "$EP/ecbucket/big.bin")
  expect "read fails beyond parity" "$([[ "$code" != 200 ]] && echo refused || echo "served $code")" refused
  stop
done

echo "== replaced drive is formatted into the existing deployment"
D="$WORK/rep"
start "$D/d{1...4}"
status -X PUT "$EP/rep" >/dev/null
status -T "$WORK/big" "$EP/rep/big.bin" >/dev/null
stop
id=$(sed -n 's/.*"this":"\([^"]*\)".*/\1/p' "$D/d2/.minio.sys/format.json")
rm -rf "$D/d2" && mkdir -p "$D/d2"
start "$D/d{1...4}"
expect "replacement keeps its slot UUID" "$(sed -n 's/.*"this":"\([^"]*\)".*/\1/p' "$D/d2/.minio.sys/format.json")" "$id"
expect "read with replaced drive" "$(curl -s "${S3[@]}" "$EP/rep/big.bin" | md5of)" "$BIG"
stop

if [[ -n "${MINIO_BIN:-}" ]]; then
  echo "== real MinIO reads a Buckets-written 4-drive set"
  D="$WORK/interop"
  start "$D/d{1...4}"
  status -X PUT "$EP/iobucket" >/dev/null
  status -T "$WORK/big" "$EP/iobucket/big.bin" >/dev/null
  status -T "$WORK/small" "$EP/iobucket/small.bin" >/dev/null
  stop
  MINIO_CI_CD=on MINIO_ROOT_USER=$AK MINIO_ROOT_PASSWORD=$SK "$MINIO_BIN" server --address "127.0.0.1:$PORT" \
    --console-address "127.0.0.1:$((PORT + 1))" "$D/d{1...4}" >"$WORK/minio.log" 2>&1 &
  PID=$!
  for _ in $(seq 100); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.2; done
  sleep 1
  expect "minio reads large" "$(curl -s "${S3[@]}" "$EP/iobucket/big.bin" | md5of)" "$BIG"
  expect "minio reads small" "$(curl -s "${S3[@]}" "$EP/iobucket/small.bin" | md5of)" "$SMALL"
  stop
fi

if grep -q 'Sanitizer\|runtime error' "$WORK/log"; then
  fail=$((fail + 1)); echo "  FAIL  sanitizer report:"; grep -A20 'Sanitizer\|runtime error' "$WORK/log" | head -40
fi
echo "erasure: $pass passed, $fail failed"
((fail == 0)) || { cat "$WORK/log"; exit 1; }
