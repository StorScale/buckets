#!/usr/bin/env bash
# Optional servers for tests/integration/notify-targets.sh: PG_BIN (PostgreSQL's bin), MYSQL_DIR (a MySQL 8
# installation) and KFAKE_BIN (tests/integration/targets/kfake built with Go); each adds its target.
# AZURITE_BIN (azurite-blob) and FAKE_GCS_BIN add Azure and GCS warm tiers to tests/integration/tier.sh.
# The full CI gate, runnable locally and from any CI host:
#   1. release build + unit tests + fuzz corpus replay
#   2. ASan/UBSan build + unit tests + end-to-end smoke test
#   3. TSan build + unit tests (Linux only; the server is single-threaded today)
set -euo pipefail
cd "$(dirname "$0")/.."

run() { echo "+ $*"; "$@"; }

build() {
  local dir=$1
  shift
  run cmake -S . -B "$dir" -G Ninja "$@" >/dev/null
  run ninja -C "$dir"
  run ctest --test-dir "$dir" --output-on-failure
}

build build-ci -DCMAKE_BUILD_TYPE=RelWithDebInfo
run tests/integration/smoke.sh build-ci/src/bucketsd
run tests/integration/erasure.sh build-ci/src/bucketsd
run tests/integration/concurrency.sh build-ci/src/bucketsd
run tests/integration/heal.sh build-ci/src/bucketsd
run tests/integration/pools.sh build-ci/src/bucketsd
run tests/integration/tls.sh build-ci/src/bucketsd
run tests/integration/cluster.sh build-ci/src/bucketsd
# IAM, identity providers, configuration and service control (these skip
# without MC_BIN; iam-interop also needs MINIO_BIN).
for t in iam iam-interop config openid plugins ldap certsts service usage; do
  run tests/integration/$t.sh build-ci/src/bucketsd
done
run tests/e2e-k8s/envtest.sh build-ci/operator/buckets-operator

build build-ci-asan -DCMAKE_BUILD_TYPE=Debug -DBUCKETS_SANITIZE=address,undefined
run tests/integration/smoke.sh build-ci-asan/src/bucketsd
run tests/integration/erasure.sh build-ci-asan/src/bucketsd
run tests/integration/concurrency.sh build-ci-asan/src/bucketsd
run tests/integration/heal.sh build-ci-asan/src/bucketsd
run tests/integration/pools.sh build-ci-asan/src/bucketsd
run tests/integration/tls.sh build-ci-asan/src/bucketsd
run tests/integration/cluster.sh build-ci-asan/src/bucketsd
for t in iam config openid plugins ldap certsts service usage; do
  run tests/integration/$t.sh build-ci-asan/src/bucketsd
done
run tests/integration/s3diff.sh build-ci-asan/src/bucketsd
run tests/integration/notify-interop.sh build-ci-asan/src/bucketsd
run tests/integration/notify-store.sh build-ci-asan/src/bucketsd
run tests/integration/metrics-names.sh build-ci-asan/src/bucketsd
run tests/integration/metrics-auth.sh build-ci-asan/src/bucketsd
run tests/integration/audit-interop.sh build-ci-asan/src/bucketsd
run tests/integration/trace-interop.sh build-ci-asan/src/bucketsd
run tests/integration/notify-targets.sh build-ci-asan/src/bucketsd
run tests/integration/replication.sh build-ci-asan/src/bucketsd
run tests/integration/siterepl.sh build-ci-asan/src/bucketsd
run tests/integration/tier.sh build-ci-asan/src/bucketsd
run tests/integration/console.sh build-ci-asan/src/bucketsd build-ci-asan/src/consoled
# The console: SPA build, typecheck and Playwright e2e against the sanitized
# bucketsd and consoled (skipped without npm).
if command -v npm >/dev/null; then
  (cd console/web && run npm ci --no-audit --no-fund && run npm run build && run npx playwright install chromium &&
    BUCKETSD_BIN=../../build-ci-asan/src/bucketsd CONSOLED_BIN=../../build-ci-asan/src/consoled run npx playwright test)
else
  echo "console e2e: skipped (no npm)"
fi

# MinIO interoperability (skipped unless MC_BIN and MINIO_BIN are set;
# tools/build-oracles.sh builds both).
run tests/integration/interop.sh build-ci/src/bucketsd
run tests/integration/s3diff.sh build-ci/src/bucketsd
run tests/integration/versioning-interop.sh build-ci/src/bucketsd
run tests/integration/sse-interop.sh build-ci/src/bucketsd
run tests/integration/compress-interop.sh build-ci/src/bucketsd
run tests/integration/notify-interop.sh build-ci/src/bucketsd
run tests/integration/notify-store.sh build-ci/src/bucketsd
run tests/integration/metrics-names.sh build-ci/src/bucketsd
run env NODES=4 tests/integration/metrics-names.sh build-ci/src/bucketsd
run env PLUGIN=1 tests/integration/metrics-names.sh build-ci/src/bucketsd
run tests/integration/audit-interop.sh build-ci/src/bucketsd
run tests/integration/trace-interop.sh build-ci/src/bucketsd
run tests/integration/notify-targets.sh build-ci/src/bucketsd
run tests/integration/replication.sh build-ci/src/bucketsd
run tests/integration/siterepl.sh build-ci/src/bucketsd
run tests/integration/tier.sh build-ci/src/bucketsd

if [[ "$(uname -s)" == Linux ]]; then
  build build-ci-tsan -DCMAKE_BUILD_TYPE=Debug -DBUCKETS_SANITIZE=thread
fi

echo "ci: all gates passed"
