#!/usr/bin/env bash
# End to end on a kind cluster: build the images, install the operator,
# create a 4-server BucketsCluster, and check S3 through its Service while
# a pod is killed, a drive (PVC) is replaced, a pool is added, and the image
# is rolled. Needs docker, kind and kubectl.
#   tests/e2e-k8s/kind.sh            (KEEP_CLUSTER=1 leaves the cluster up)
set -euo pipefail
source "$(dirname "$0")/lib.sh"
NS=e2e
LPORT=${LPORT:-19990}
CPF=
SPF=
cleanup() {
  kill $CPF $SPF 2>/dev/null || true
  [[ -n "${KEEP_CLUSTER:-}" ]] || kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
wait_ready() { wait_bc $NS store "${1:-600}"; }

setup_cluster
# "a new release" for the rollout step: the same image under another tag
docker tag buckets/bucketsd:e2e buckets/bucketsd:e2e2
kind load docker-image --name "$NAME" buckets/bucketsd:e2e2 >/dev/null
start_cli $NS

echo "== a 4-server cluster comes up"
kubectl -n $NS apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: store}
spec:
  image: buckets/bucketsd:e2e
  env:
    - {name: MINIO_KMS_SECRET_KEY, value: "e2e-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
  pools:
    - servers: 4
      volumesPerServer: 2
      volumeClaimTemplate: {resources: {requests: {storage: 1Gi}}}
YAML
wait_ready
expect "phase" "$(kubectl -n $NS get bc store -o jsonpath='{.status.phase}')" Ready
read -r AK SK <<<"$(creds $NS store)"
EP=http://store:9000
# S3 through the Service from the client pod; retries ride out a pod that
# is going away while its endpoint is still being withdrawn.
s3() { kubectl -n $NS exec cli -- curl -s --retry 5 --retry-all-errors --retry-delay 1 --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }
status() { s3 -o /dev/null -w '%{http_code}' "$@"; }
getmd5() { s3 "$EP/e2ebucket/$1" -o /tmp/got && kubectl -n $NS exec cli -- md5sum /tmp/got | cut -d' ' -f1; }
kubectl -n $NS exec cli -- sh -c 'head -c 20000000 /dev/urandom >/tmp/big'
BIG=$(kubectl -n $NS exec cli -- md5sum /tmp/big | cut -d' ' -f1)
expect "create bucket" "$(status -X PUT "$EP/e2ebucket")" 200
expect "put 20 MB" "$(status -T /tmp/big "$EP/e2ebucket/big.bin")" 200
expect "get it back" "$(getmd5 big.bin)" "$BIG"

echo "== a pod dies"
kubectl -n $NS delete pod store-pool-0-1 --wait=false >/dev/null
sleep 2
expect "reads carry on" "$(getmd5 big.bin)" "$BIG"
wait_ready
expect "back to Ready" "$(kubectl -n $NS get bc store -o jsonpath='{.status.phase}')" Ready

echo "== a drive is replaced (PVC deleted)"
kubectl -n $NS delete pvc data0-store-pool-0-2 --wait=false >/dev/null
kubectl -n $NS delete pod store-pool-0-2 >/dev/null
wait_ready
for _ in $(seq 60); do kubectl -n $NS logs store-pool-0-2 | grep -q 'healed' && break; sleep 5; done
expect "the new drive was healed" "$(kubectl -n $NS logs store-pool-0-2 | grep -c 'drive .* healed' || true)" 1
expect "data intact" "$(getmd5 big.bin)" "$BIG"

echo "== a pool is added"
kubectl -n $NS patch bc store --type=json \
  -p '[{"op":"add","path":"/spec/pools/-","value":{"name":"more","servers":2,"volumesPerServer":2,"volumeClaimTemplate":{"resources":{"requests":{"storage":"1Gi"}}}}}]' >/dev/null
sleep 10
wait_ready
expect "six servers" "$(kubectl -n $NS get bc store -o jsonpath='{.status.readyServersText}')" 6/6
expect "old data readable" "$(getmd5 big.bin)" "$BIG"
expect "new writes work" "$(status -T /tmp/big "$EP/e2ebucket/after.bin")" 200

echo "== the image rolls one server at a time"
kubectl -n $NS patch bc store --type=merge -p '{"spec":{"image":"buckets/bucketsd:e2e2"}}' >/dev/null
for _ in $(seq 120); do
  imgs=$(kubectl -n $NS get pods -l buckets.io/cluster=store -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' | sort -u)
  [[ "$imgs" == "buckets/bucketsd:e2e2" ]] && break
  sleep 5
done
wait_ready
expect "all servers on the new image" "$imgs" buckets/bucketsd:e2e2
expect "data intact after the rollout" "$(getmd5 big.bin)" "$BIG"

echo "== the console runs as its own Deployment (Phase 6)"
# share links are signed for S3 as the browser (here, this host) reaches it
SPORT=$((LPORT + 1))
kubectl -n $NS port-forward svc/store $SPORT:9000 >/dev/null 2>&1 &
SPF=$!
kubectl -n $NS patch bc store --type=merge -p '{"spec":{"console":{"enabled":true,"replicas":2,"image":"buckets/buckets-console:e2e","s3URL":"http://127.0.0.1:'$SPORT'"}}}' >/dev/null
for _ in $(seq 60); do kubectl -n $NS get deploy/store-console >/dev/null 2>&1 && break; sleep 2; done
kubectl -n $NS rollout status deploy/store-console --timeout=180s >/dev/null && ok=yes || ok=no
expect "console deployment ready" "$ok" yes
expect "console pods are not storage pods" \
  "$(kubectl -n $NS get pods -l buckets.io/cluster=store,buckets.io/console=store -o name | wc -l | tr -d ' ')" 0
CPORT=$LPORT
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
kill $CPF $SPF 2>/dev/null || true

finish
