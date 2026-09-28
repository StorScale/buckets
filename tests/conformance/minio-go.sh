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
# TLS=1 serves HTTPS with a throwaway certificate.
TLSARGS=()
SCHEME=http
HTTPS=0
if [[ -n "${TLS:-}" ]]; then
  mkdir -p "$DRIVE.certs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 1 \
    -keyout "$DRIVE.certs/private.key" -out "$DRIVE.certs/public.crt" -subj /CN=localhost \
    -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
  mkdir -p "$DRIVE.certs/CAs" && cp "$DRIVE.certs/public.crt" "$DRIVE.certs/CAs/"
  TLSARGS=(--certs-dir "$DRIVE.certs")
  SCHEME=https
  HTTPS=1
fi
# CLUSTER=1 runs a 4-node cluster (2 drives each) and tests through node 1.
PIDS=()
if [[ -n "${CLUSTER:-}" ]]; then
  EPS=()
  for n in 1 2 3 4; do for d in 1 2; do EPS+=("$SCHEME://127.0.0.1:$((PORT + n - 1))$DRIVE/n$n/d$d"); done; done
  for n in 1 2 3 4; do
    BUCKETS_ROOT_USER=conformance BUCKETS_ROOT_PASSWORD=conformance123 "$BIN" server --address "127.0.0.1:$((PORT + n - 1))" \
      ${TLSARGS[@]+"${TLSARGS[@]}"} "${EPS[@]}" 2>>"$WORK/bucketsd.log" &
    PIDS+=($!)
  done
  for _ in $(seq 100); do curl -sfk "$SCHEME://127.0.0.1:$PORT/minio/health/cluster" >/dev/null && break; sleep 0.1; done
else
  BUCKETS_ROOT_USER=conformance BUCKETS_ROOT_PASSWORD=conformance123 "$BIN" server --address "127.0.0.1:$PORT" \
    ${TLSARGS[@]+"${TLSARGS[@]}"} "$TARGET" 2>"$WORK/bucketsd.log" &
  PIDS+=($!)
fi
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$DRIVE" "$DRIVE.certs"' EXIT
for _ in $(seq 50); do curl -sfk "$SCHEME://127.0.0.1:$PORT/minio/health/ready" >/dev/null && break; sleep 0.1; done

# The suite drops scratch files in its working directory.
(cd "$WORK" && SERVER_ENDPOINT=127.0.0.1:$PORT ACCESS_KEY=conformance SECRET_KEY=conformance123 \
  ENABLE_KMS=0 ENABLE_HTTPS=$HTTPS SKIP_CERT_VALIDATION=$HTTPS MINT_MODE=full RUN_ON_FAIL=1 "$WORK/functional-tests") >"$WORK/results.log" 2>&1 || true

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
