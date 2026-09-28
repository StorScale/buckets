#!/usr/bin/env bash
# Runs minio-go's functional test suite (the Go suite inside MinIO's "mint")
# against a fresh bucketsd and summarizes PASS / FAIL / NA.
#   tests/conformance/minio-go.sh [bucketsd]      (needs Go and git)
# NA = the server answered NotImplemented: a feature not built yet.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
MINIO_GO_TAG=v7.0.91 # the minio-go MinIO RELEASE.2025-10-15 was built with
WORK=${WORK:-.conformance}
PORT=${PORT:-19500}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
[[ -d "$WORK/minio-go" ]] || git clone -q --depth 1 --branch "$MINIO_GO_TAG" https://github.com/minio/minio-go.git "$WORK/minio-go"
[[ -x "$WORK/functional-tests" ]] || (cd "$WORK/minio-go" && CGO_ENABLED=0 go build -o "$WORK/functional-tests" functional_tests.go)

DRIVE=$(mktemp -d "${TMPDIR:-/tmp}/buckets-conf-XXXXXX")
# DRIVES=4 runs against a 4-drive erasure set instead of a single drive.
TARGET="$DRIVE"
[[ -n "${DRIVES:-}" ]] && TARGET="$DRIVE/d{1...$DRIVES}"
BUCKETS_ROOT_USER=conformance BUCKETS_ROOT_PASSWORD=conformance123 "$BIN" server --address "127.0.0.1:$PORT" "$TARGET" 2>"$WORK/bucketsd.log" &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$DRIVE"' EXIT
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/minio/health/live" >/dev/null && break; sleep 0.1; done

SERVER_ENDPOINT=127.0.0.1:$PORT ACCESS_KEY=conformance SECRET_KEY=conformance123 ENABLE_HTTPS=0 ENABLE_KMS=0 \
  (cd "$WORK" && MINT_MODE=full RUN_ON_FAIL=1 "$WORK/functional-tests") >"$WORK/results.log" 2>&1 || true

python3 - "$WORK/results.log" <<'PY'
import collections, json, sys
counts, fails = collections.Counter(), []
for line in open(sys.argv[1]):
    if not line.startswith("{"):
        continue
    d = json.loads(line)
    counts[d.get("status")] += 1
    if d.get("status") == "FAIL":
        fails.append(f"  FAIL {d['name']}: {d.get('message')} {(d.get('error') or '')[:120]}")
print("\n".join(fails))
print(f"minio-go functional: {counts['PASS']} pass, {counts['FAIL']} fail, {counts['NA']} not implemented")
sys.exit(1 if counts["FAIL"] else 0)
PY
