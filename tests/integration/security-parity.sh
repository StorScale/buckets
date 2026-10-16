#!/usr/bin/env bash
# The 2026-10 security-parity fixes (docs/roadmap.md), end to end on a real
# server: a reserved bucket (.minio.sys) is refused as a CopyObject and
# UploadPartCopy source, even for a caller whose policy allows s3:GetObject on
# everything, so internal data can't be read through a copy the way it could in
# MinIO before its July 2026 release (and the way a direct GET is already
# blocked). An ordinary copy still works, so the guard doesn't break copies.
#   MC_BIN=/path/to/mc tests/integration/security-parity.sh [bucketsd]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
if [[ -z "${MC_BIN:-}" ]]; then
  echo "security-parity: skipped (set MC_BIN)"
  exit 0
fi
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19805}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-secparity-XXXXXX")
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
check() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); else
    fail=$((fail + 1))
    echo "FAIL: $1: got '$2', want '$3'"
  fi
}

mkdir -p "$WORK"/d{1..4}
env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>"$WORK/log" &
PIDS+=($!)
for _ in $(seq 150); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.1; done

mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
mc alias set it "$EP" rootadmin rootsecret123 >/dev/null
mc mb it/data >/dev/null
echo "hello" | mc pipe it/data/obj.txt >/dev/null
# alice gets the stock readwrite policy, whose resource is arn:aws:s3:::* — it
# would allow s3:GetObject on .minio.sys/* if nothing else refused the source.
mc admin user add it alice alicesecret123 >/dev/null
mc admin policy attach it readwrite --user alice >/dev/null

AK=alice SK=alicesecret123
# copy <src-header> <dest-path>: status code of a CopyObject as alice
copy() { curl -s -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
  -H "X-Amz-Copy-Source: $1" "$EP/$2"; }
# code <path>: error <Code> in a CopyObject response body
code() { curl -s -X PUT --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
  -H "X-Amz-Copy-Source: $1" "$EP/$2" | sed -n 's:.*<Code>\([^<]*\)</Code>.*:\1:p'; }

echo "== CopyObject with a source in .minio.sys is refused"
check "status" "$(copy "/.minio.sys/format.json" data/stolen.txt)" 403
check "error code" "$(code "/.minio.sys/format.json" data/stolen.txt)" AllAccessDisabled
check "config path too" "$(copy "/.minio.sys/config/iam/format.json" data/stolen.txt)" 403
check "not left on disk" "$(mc stat it/data/stolen.txt >/dev/null 2>&1 && echo yes || echo no)" no

echo "== UploadPartCopy with a source in .minio.sys is refused"
up=$(curl -s -X POST --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$EP/data/mp.txt?uploads" |
  sed -n 's:.*<UploadId>\([^<]*\)</UploadId>.*:\1:p')
check "got an upload id" "$([[ -n $up ]] && echo yes || echo no)" yes
upc=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
  -H "X-Amz-Copy-Source: /.minio.sys/format.json" "$EP/data/mp.txt?partNumber=1&uploadId=$up")
check "status" "$upc" 403
curl -s -o /dev/null -X DELETE --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
  "$EP/data/mp.txt?uploadId=$up" || true

echo "== an ordinary copy still works"
check "status" "$(copy "/data/obj.txt" data/copy.txt)" 200
check "content copied" "$(mc cat it/data/copy.txt)" "hello"

echo "security-parity: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
