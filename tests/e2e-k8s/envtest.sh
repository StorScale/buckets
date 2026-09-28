#!/usr/bin/env bash
# The operator against a real kube-apiserver + etcd (the envtest binaries
# controller-runtime uses). There are no nodes or controllers, so the test
# plays their part: it marks StatefulSets ready and creates the pods a
# StatefulSet would, then checks what the operator does about them.
#   tests/e2e-k8s/envtest.sh [buckets-operator]
# ENVTEST_BIN: directory with kube-apiserver, etcd and kubectl (downloaded
# into .deps/envtest when unset).
set -euo pipefail
OP=${1:-build/operator/buckets-operator}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENVTEST_VERSION=v1.33.0
BIN=${ENVTEST_BIN:-$ROOT/.deps/envtest/$ENVTEST_VERSION}
if [[ ! -x "$BIN/kube-apiserver" ]]; then
  os=$(uname -s | tr A-Z a-z); arch=$(uname -m); [[ $arch == x86_64 ]] && arch=amd64; [[ $arch == aarch64 ]] && arch=arm64
  mkdir -p "$BIN"
  curl -sfL "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-$ENVTEST_VERSION/envtest-$ENVTEST_VERSION-$os-$arch.tar.gz" |
    tar xz -C "$BIN" --strip-components 2
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-envtest-XXXXXX")
APORT=${APORT:-17443}
EPORT=${EPORT:-17379}
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
k() { "$BIN/kubectl" --server "https://127.0.0.1:$APORT" --token envtest-token --insecure-skip-tls-verify "$@"; }
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
until_true() { for _ in $(seq 100); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

echo "== control plane"
openssl genrsa -out "$WORK/sa.key" 2048 2>/dev/null
echo "envtest-token,admin,1,system:masters" >"$WORK/tokens.csv"
# The operator runs as its own ServiceAccount, so a missing RBAC rule fails the test.
echo "operator-token,system:serviceaccount:buckets-system:buckets-operator,2,system:serviceaccounts" >>"$WORK/tokens.csv"
"$BIN/etcd" --data-dir "$WORK/etcd" --listen-client-urls "http://127.0.0.1:$EPORT" \
  --advertise-client-urls "http://127.0.0.1:$EPORT" --listen-peer-urls "http://127.0.0.1:$((EPORT + 1))" \
  >"$WORK/etcd.log" 2>&1 &
PIDS+=($!)
"$BIN/kube-apiserver" --etcd-servers "http://127.0.0.1:$EPORT" --cert-dir "$WORK/certs" --secure-port "$APORT" \
  --bind-address 127.0.0.1 --token-auth-file "$WORK/tokens.csv" --authorization-mode RBAC \
  --service-cluster-ip-range 10.0.0.0/24 --service-account-issuer https://kubernetes.default.svc \
  --service-account-key-file "$WORK/sa.key" --service-account-signing-key-file "$WORK/sa.key" \
  --disable-admission-plugins ServiceAccount >"$WORK/apiserver.log" 2>&1 &
PIDS+=($!)
until_true 'k get ns default' || { echo "apiserver did not start"; tail -20 "$WORK/apiserver.log"; exit 1; }
k apply -f "$ROOT/operator/deploy/crds/" >/dev/null
until_true 'k get bucketsclusters -A'
k apply -f "$ROOT/operator/deploy/operator.yaml" >/dev/null # RBAC (the Deployment never runs here)
k create ns tenant >/dev/null

start_operator() { # name
  POD_NAME=$1 POD_NAMESPACE=buckets-system BUCKETS_OPERATOR_RESYNC_MS=500 BUCKETS_KUBE_API="https://127.0.0.1:$APORT" \
    BUCKETS_KUBE_TOKEN=operator-token BUCKETS_KUBE_CA="$WORK/certs/apiserver.crt" "$OP" 2>>"$WORK/$1.log" &
  PIDS+=($!)
  eval "OP_$1=$!"
}
jp() { k -n tenant get "$1" -o "jsonpath=$2"; }

echo "== a BucketsCluster is reconciled"
start_operator opa
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: store, namespace: tenant}
spec:
  image: bucketsd:test
  parity: 2
  pools:
    - servers: 4
      volumesPerServer: 2
      volumeClaimTemplate: {resources: {requests: {storage: 2Gi}}}
YAML
until_true '[[ $(jp bc/store "{.status.phase}") == Provisioning ]]'
expect "phase" "$(jp bc/store '{.status.phase}')" Provisioning
expect "statefulset replicas" "$(jp sts/store-pool-0 '{.spec.replicas}')" 4
expect "volume claims per server" "$(jp sts/store-pool-0 '{.spec.volumeClaimTemplates[*].metadata.name}')" "data0 data1"
expect "BUCKETS_VOLUMES" "$(jp sts/store-pool-0 '{.spec.template.spec.containers[0].env[?(@.name=="BUCKETS_VOLUMES")].value}')" \
  "http://store-pool-0-{0...3}.store-hl.tenant.svc.cluster.local:9000/data{0...1}"
expect "parity" "$(jp sts/store-pool-0 '{.spec.template.spec.containers[0].env[?(@.name=="BUCKETS_STORAGE_CLASS_STANDARD")].value}')" EC:2
expect "headless service publishes unready pods" "$(jp svc/store-hl '{.spec.publishNotReadyAddresses}')" true
expect "owner reference" "$(jp sts/store-pool-0 '{.metadata.ownerReferences[0].kind}')" BucketsCluster
expect "PDB" "$(jp pdb/store-pool-0 '{.spec.maxUnavailable}')" 1
user1=$(jp secret/store-root '{.data.rootUser}' | base64 -d)
expect "generated root user is 20 characters" "${#user1}" 20
sleep 1.5
expect "credentials stable across resyncs" "$(jp secret/store-root '{.data.rootUser}' | base64 -d)" "$user1"

echo "== servers become ready"
TOPO=$(jp bc/store '{.status.topology}')
mkpod() { # name pool topology revision
  k -n tenant apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $1
  labels: {buckets.io/cluster: store, buckets.io/pool: $2, controller-revision-hash: $4}
  annotations: {buckets.io/topology: "$3"}
spec: {containers: [{name: bucketsd, image: bucketsd:test}]}
YAML
  k -n tenant patch pod "$1" --subresource=status --type=merge \
    -p '{"status":{"conditions":[{"type":"Ready","status":"True"}]}}' >/dev/null
}
for i in 0 1 2 3; do mkpod "store-pool-0-$i" pool-0 "$TOPO" rev1; done
k -n tenant patch sts store-pool-0 --subresource=status --type=merge \
  -p '{"status":{"replicas":4,"readyReplicas":4,"updateRevision":"rev1","currentRevision":"rev1"}}' >/dev/null
until_true '[[ $(jp bc/store "{.status.phase}") == Ready ]]'
expect "phase" "$(jp bc/store '{.status.phase}')" Ready
expect "ready condition" "$(jp bc/store '{.status.conditions[?(@.type=="Ready")].status}')" True
expect "servers column" "$(jp bc/store '{.status.readyServersText}')" 4/4
expect "no restarts while up to date" "$(k -n tenant get pods -o name | wc -l | tr -d ' ')" 4

echo "== an image change rolls one pod at a time"
k -n tenant patch sts store-pool-0 --subresource=status --type=merge -p '{"status":{"updateRevision":"rev2"}}' >/dev/null
until_true '[[ $(k -n tenant get pods -o name | wc -l | tr -d " ") == 3 ]]'
sleep 1.5
expect "exactly one pod restarted" "$(k -n tenant get pods -o name | wc -l | tr -d ' ')" 3
expect "phase while rolling" "$(jp bc/store '{.status.phase}')" Updating
mkpod store-pool-0-3 pool-0 "$TOPO" rev2
until_true '[[ $(k -n tenant get pods -o name | wc -l | tr -d " ") == 3 ]]'
expect "then the next one" "$(k -n tenant get pods -o name | wc -l | tr -d ' ')" 3
for i in 0 1 2 3; do mkpod "store-pool-0-$i" pool-0 "$TOPO" rev2; done
sleep 1.5
expect "rollout done" "$(k -n tenant get pods -o name | wc -l | tr -d ' ')" 4
until_true '[[ $(jp bc/store "{.status.phase}") == Ready ]]'
expect "ready again" "$(jp bc/store '{.status.phase}')" Ready

echo "== expanding with a pool restarts every server together"
k -n tenant patch bc store --type=json -p '[{"op":"add","path":"/spec/pools/-","value":{"name":"more","servers":2,"volumesPerServer":2}}]' >/dev/null
until_true 'k -n tenant get sts store-more'
expect "new pool's statefulset" "$(jp sts/store-more '{.spec.replicas}')" 2
v0=$(jp sts/store-pool-0 '{.spec.template.spec.containers[0].env[?(@.name=="BUCKETS_VOLUMES")].value}')
v1=$(jp sts/store-more '{.spec.template.spec.containers[0].env[?(@.name=="BUCKETS_VOLUMES")].value}')
expect "both pools get the same endpoints" "$v0" "$v1"
expect "endpoints name both pools" "$(tr ' ' '\n' <<<"$v0" | wc -l | tr -d ' ')" 2
until_true '[[ $(k -n tenant get pods -o name | wc -l | tr -d " ") == 0 ]]'
expect "all old-topology pods deleted at once" "$(k -n tenant get pods -o name | wc -l | tr -d ' ')" 0
expect "topology updated" "$([[ $(jp bc/store '{.status.topology}') != "$TOPO" ]] && echo changed)" changed

echo "== invalid specs are reported"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: tiny, namespace: tenant}
spec: {pools: [{servers: 1, volumesPerServer: 1}]}
YAML
until_true '[[ $(jp bc/tiny "{.status.phase}") == Invalid ]]'
expect "phase" "$(jp bc/tiny '{.status.phase}')" Invalid
expect "reason" "$(jp bc/tiny '{.status.conditions[0].reason}')" InvalidSpec
expect "nothing created for it" "$(k -n tenant get sts tiny-pool-0 -o name 2>/dev/null || echo none)" none

echo "== IAM kinds wait for the admin API"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsUser
metadata: {name: alice, namespace: tenant}
spec: {cluster: store, credsSecret: {name: alice-creds}}
YAML
until_true '[[ $(k -n tenant get bucketsuser alice -o jsonpath={.status.phase}) == Pending ]]'
expect "BucketsUser status" "$(k -n tenant get bucketsuser alice -o jsonpath='{.status.phase}')" Pending

echo "== leader election"
start_operator opb
sleep 3
expect "a second operator stays a follower" "$(grep -c 'became the leader' "$WORK/opb.log")" 0
expect "lease holder" "$(k -n buckets-system get lease buckets-operator -o jsonpath='{.spec.holderIdentity}')" opa
kill "$OP_opa"
until_true 'grep -q "became the leader" "$WORK/opb.log"'
expect "the follower takes over when the leader stops" "$(grep -c 'became the leader' "$WORK/opb.log")" 1
expect "lease holder" "$(k -n buckets-system get lease buckets-operator -o jsonpath='{.spec.holderIdentity}')" opb

errs=$(cat "$WORK"/op*.log | grep -c '"level":"ERROR"' || true)
expect "no operator errors" "$errs" 0
denied=$(cat "$WORK"/op*.log | grep -c ' 403 ' || true)
expect "no RBAC denials" "$denied" 0
echo "envtest: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
