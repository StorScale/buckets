#!/usr/bin/env bash
# End to end on a kind cluster: build both images, install the operator,
# create a 4-server BucketsCluster, and check S3 through its Service while
# a pod is killed, a drive (PVC) is replaced, a pool is added, and the image
# is rolled. Needs docker, kind and kubectl.
#   tests/e2e-k8s/kind.sh            (KEEP_CLUSTER=1 leaves the cluster up)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NAME=${KIND_CLUSTER:-buckets-e2e}
NS=e2e
LPORT=${LPORT:-19990}
for t in docker kind kubectl curl; do command -v $t >/dev/null || { echo "needs $t"; exit 2; }; done
PF=
cleanup() {
  [[ -n "$PF" ]] && kill "$PF" 2>/dev/null || true
  [[ -n "${KEEP_CLUSTER:-}" ]] || kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
wait_ready() { kubectl -n $NS wait --for=jsonpath='{.status.phase}'=Ready bc/store --timeout="${1:-600}s" >/dev/null; }
md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }

echo "== images and cluster"
docker build -q -f "$ROOT/docker/Dockerfile.bucketsd" -t buckets/bucketsd:e2e "$ROOT" >/dev/null
docker build -q -f "$ROOT/docker/Dockerfile.operator" -t buckets/buckets-operator:e2e "$ROOT" >/dev/null
docker build -q -f "$ROOT/docker/Dockerfile.console" -t buckets/buckets-console:e2e "$ROOT" >/dev/null
docker tag buckets/bucketsd:e2e buckets/bucketsd:e2e2 # "a new release" for the rollout step
kind get clusters | grep -qx "$NAME" || kind create cluster --name "$NAME" --wait 120s
for img in buckets/bucketsd:e2e buckets/bucketsd:e2e2 buckets/buckets-operator:e2e buckets/buckets-console:e2e; do
  kind load docker-image --name "$NAME" "$img" >/dev/null
done
kubectl apply -f "$ROOT/operator/deploy/crds/" >/dev/null
kubectl apply -f "$ROOT/operator/deploy/operator.yaml" >/dev/null
kubectl -n buckets-system set image deploy/buckets-operator operator=buckets/buckets-operator:e2e >/dev/null
kubectl -n buckets-system rollout status deploy/buckets-operator --timeout=180s >/dev/null
kubectl create ns $NS >/dev/null 2>&1 || true

echo "== a 4-server cluster comes up"
kubectl -n $NS apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: store}
spec:
  image: buckets/bucketsd:e2e
  pools:
    - servers: 4
      volumesPerServer: 2
      volumeClaimTemplate: {resources: {requests: {storage: 1Gi}}}
YAML
wait_ready
expect "phase" "$(kubectl -n $NS get bc store -o jsonpath='{.status.phase}')" Ready
AK=$(kubectl -n $NS get secret store-root -o jsonpath='{.data.rootUser}' | base64 -d)
SK=$(kubectl -n $NS get secret store-root -o jsonpath='{.data.rootPassword}' | base64 -d)
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
kubectl -n $NS port-forward svc/store $LPORT:9000 >/dev/null 2>&1 &
PF=$!
sleep 3
EP=http://127.0.0.1:$LPORT
status() { curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$@"; }
head -c 20000000 /dev/urandom >/tmp/buckets-e2e-big
BIG=$(md5of </tmp/buckets-e2e-big)
expect "create bucket" "$(status -X PUT "$EP/e2ebucket")" 200
expect "put 20 MB" "$(status -T /tmp/buckets-e2e-big "$EP/e2ebucket/big.bin")" 200
expect "get it back" "$(curl -s "${S3[@]}" "$EP/e2ebucket/big.bin" | md5of)" "$BIG"

echo "== a pod dies"
kubectl -n $NS delete pod store-pool-0-1 --wait=false >/dev/null
sleep 2
expect "reads carry on" "$(curl -s "${S3[@]}" "$EP/e2ebucket/big.bin" | md5of)" "$BIG"
wait_ready
expect "back to Ready" "$(kubectl -n $NS get bc store -o jsonpath='{.status.phase}')" Ready

echo "== a drive is replaced (PVC deleted)"
kubectl -n $NS delete pvc data0-store-pool-0-2 --wait=false >/dev/null
kubectl -n $NS delete pod store-pool-0-2 >/dev/null
wait_ready
for _ in $(seq 60); do kubectl -n $NS logs store-pool-0-2 | grep -q 'healed' && break; sleep 5; done
expect "the new drive was healed" "$(kubectl -n $NS logs store-pool-0-2 | grep -c 'drive .* healed' || true)" 1
expect "data intact" "$(curl -s "${S3[@]}" "$EP/e2ebucket/big.bin" | md5of)" "$BIG"

echo "== a pool is added"
kubectl -n $NS patch bc store --type=json \
  -p '[{"op":"add","path":"/spec/pools/-","value":{"name":"more","servers":2,"volumesPerServer":2,"volumeClaimTemplate":{"resources":{"requests":{"storage":"1Gi"}}}}}]' >/dev/null
sleep 10
wait_ready
expect "six servers" "$(kubectl -n $NS get bc store -o jsonpath='{.status.readyServersText}')" 6/6
kill $PF; kubectl -n $NS port-forward svc/store $LPORT:9000 >/dev/null 2>&1 & PF=$!; sleep 3
expect "old data readable" "$(curl -s "${S3[@]}" "$EP/e2ebucket/big.bin" | md5of)" "$BIG"
expect "new writes work" "$(status -T /tmp/buckets-e2e-big "$EP/e2ebucket/after.bin")" 200

echo "== the image rolls one server at a time"
kubectl -n $NS patch bc store --type=merge -p '{"spec":{"image":"buckets/bucketsd:e2e2"}}' >/dev/null
for _ in $(seq 120); do
  imgs=$(kubectl -n $NS get pods -l buckets.io/cluster=store -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' | sort -u)
  [[ "$imgs" == "buckets/bucketsd:e2e2" ]] && break
  sleep 5
done
wait_ready
expect "all servers on the new image" "$imgs" buckets/bucketsd:e2e2
kill $PF; kubectl -n $NS port-forward svc/store $LPORT:9000 >/dev/null 2>&1 & PF=$!; sleep 3
expect "data intact after the rollout" "$(curl -s "${S3[@]}" "$EP/e2ebucket/big.bin" | md5of)" "$BIG"

echo "== the console runs as its own Deployment (Phase 6)"
kubectl -n $NS patch bc store --type=merge -p '{"spec":{"console":{"enabled":true,"replicas":2,"image":"buckets/buckets-console:e2e"}}}' >/dev/null
kubectl -n $NS rollout status deploy/store-console --timeout=180s >/dev/null && ok=yes || ok=no
expect "console deployment ready" "$ok" yes
expect "console pods are not storage pods" \
  "$(kubectl -n $NS get pods -l buckets.io/cluster=store,buckets.io/console=store -o name | wc -l | tr -d ' ')" 0
CPORT=$((LPORT + 1))
kubectl -n $NS port-forward svc/store-console $CPORT:9090 >/dev/null 2>&1 &
CPF=$!
sleep 3
if command -v npm >/dev/null; then
  (cd "$ROOT/console/web" && npm ci --no-audit --no-fund >/dev/null && npx playwright install chromium >/dev/null &&
    CONSOLE_URL="http://127.0.0.1:$CPORT" E2E_USER="$AK" E2E_PASSWORD="$SK" npx playwright test) && ok=yes || ok=no
  expect "console Playwright suite against the cluster" "$ok" yes
fi
kubectl -n $NS patch bc store --type=merge -p '{"spec":{"console":{"enabled":false}}}' >/dev/null
for _ in $(seq 30); do kubectl -n $NS get deploy/store-console >/dev/null 2>&1 || break; sleep 2; done
expect "disabling the console removes it" "$(kubectl -n $NS get deploy/store-console -o name 2>/dev/null)" ""
kill $CPF 2>/dev/null || true

echo "kind: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
