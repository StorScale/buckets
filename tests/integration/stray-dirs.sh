#!/usr/bin/env bash
# Directories on the drives that no bucket could be named (an ext4 drive's
# lost+found, or anything put there by hand) are not buckets, as with MinIO:
# not listed, not scanned, not counted, and left alone.
#   tests/integration/stray-dirs.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19810}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-stray-XXXXXX")
EP="http://127.0.0.1:$PORT"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
until_true() { for _ in $(seq "${2:-150}"); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

# every drive with what mkfs.ext4 leaves, and names no bucket can have
for i in 1 2 3 4; do
  mkdir -p "$WORK/d$i/lost+found" "$WORK/d$i/Has Space" "$WORK/d$i/ab"
  echo keep >"$WORK/d$i/lost+found/#1234"
done
BUCKETS_SCANNER_INTERVAL=1 BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
PIDS+=($!)
until_true "curl -sf $EP/minio/health/ready"
export MC_CONFIG_DIR="$WORK/mc" MC_HOST_b="http://rootadmin:rootsecret123@127.0.0.1:$PORT"
api() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 "$EP/minio/admin/v3/$1"; }
mc mb b/real >/dev/null
echo hello | mc pipe b/real/a.txt >/dev/null

expect "ListBuckets: only the real bucket" "$(mc ls b | awk '{print $NF}' | tr '\n' ' ')" "real/ "
until_true "[[ \$(api datausageinfo | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"bucketsCount\"])') == 1 ]]" 300 || true
expect "data usage: one bucket" "$(api datausageinfo | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["bucketsCount"], sorted((d["bucketsUsageInfo"] or {}).keys()))')" "1 ['real']"
expect "the compliance report: one bucket" "$(api buckets/compliance | python3 -c 'import json,sys; print([b["name"] for b in json.load(sys.stdin)["buckets"]])')" "['real']"
expect "lost+found cannot be made a bucket" "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 -X PUT "$EP/lost+found")" 400
expect "and is left alone on every drive" "$(cat "$WORK"/d{1..4}/lost+found/'#1234' | sort -u)" keep
expect "no sanitizer reports" "$(grep -c 'Sanitizer\|runtime error' "$WORK/log" || true)" 0
echo "stray-dirs: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
