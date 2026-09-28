#!/usr/bin/env bash
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
for t in iam iam-interop config openid plugins ldap certsts service; do
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
for t in iam config openid plugins ldap certsts service; do
  run tests/integration/$t.sh build-ci-asan/src/bucketsd
done

# MinIO interoperability (skipped unless MC_BIN and MINIO_BIN are set;
# tools/build-oracles.sh builds both).
run tests/integration/interop.sh build-ci/src/bucketsd

if [[ "$(uname -s)" == Linux ]]; then
  build build-ci-tsan -DCMAKE_BUILD_TYPE=Debug -DBUCKETS_SANITIZE=thread
fi

echo "ci: all gates passed"
