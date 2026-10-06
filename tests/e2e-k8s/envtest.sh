#!/usr/bin/env bash
# The operator against a real kube-apiserver + etcd (the envtest binaries
# controller-runtime uses). There are no nodes or controllers, so the test
# plays their part: it marks StatefulSets ready and creates the pods a
# StatefulSet would, then checks what the operator does about them.
#   tests/e2e-k8s/envtest.sh [buckets-operator] [bucketsd]
# ENVTEST_BIN: directory with kube-apiserver, etcd and kubectl (downloaded
# into .deps/envtest when unset).
set -euo pipefail
OP=${1:-build/operator/buckets-operator}
BUCKETSD=${2:-build/src/bucketsd}
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
# ... and so does a console, as the Role the operator gives it allows
echo "console-token,system:serviceaccount:tenant:kmsc-console,3,system:serviceaccounts" >>"$WORK/tokens.csv"
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
  POD_NAME=$1 POD_NAMESPACE=buckets-system BUCKETS_OPERATOR_RESYNC_MS=500 BUCKETS_OPERATOR_DRIFT_MS=2000 BUCKETS_KUBE_API="https://127.0.0.1:$APORT" \
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
# Plays the StatefulSet controller: (re)creates a pod and marks it ready. The
# operator may delete the pod between apply's read and its patch (it is rolling
# the next one), so a failed attempt is retried, as the controller would.
mkpod() { # name pool topology revision
  for _ in 1 2 3 4; do mkpod_once "$@" 2>/dev/null && return 0; sleep 0.2; done
  mkpod_once "$@"
}
mkpod_once() {
  k -n tenant apply -f - >/dev/null <<YAML || return 1
apiVersion: v1
kind: Pod
metadata:
  name: $1
  labels: {buckets.io/cluster: store, buckets.io/pool: $2, controller-revision-hash: $4}
  annotations: {buckets.io/topology: "$3"}
spec: {containers: [{name: bucketsd, image: bucketsd:test}]}
YAML
  k -n tenant patch pod "$1" --subresource=status --type=merge \
    -p '{"status":{"conditions":[{"type":"Ready","status":"True"}]}}' >/dev/null || return 1
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

echo "== IAM kinds are applied through the admin API"
# A local bucketsd stands in for the cluster's pods, with its root credentials;
# the endpoint annotation points the operator at it.
BPORT=${BPORT:-17900}
rootu=$(k -n tenant get secret store-root -o jsonpath='{.data.rootUser}' | base64 -d)
rootp=$(k -n tenant get secret store-root -o jsonpath='{.data.rootPassword}' | base64 -d)
mkdir -p "$WORK/bk/d1" "$WORK/bk/d2" "$WORK/bk/d3" "$WORK/bk/d4"
MINIO_KMS_SECRET_KEY="envtest-key:$(openssl rand -base64 32)" \
  BUCKETS_ROOT_USER=$rootu BUCKETS_ROOT_PASSWORD=$rootp "$BUCKETSD" server --address "127.0.0.1:$BPORT" \
  "$WORK/bk/d{1...4}" 2>>"$WORK/bucketsd.log" &
PIDS+=($!)
until_true 'curl -sf http://127.0.0.1:$BPORT/minio/health/ready'
k -n tenant annotate bc store buckets.io/endpoint="http://127.0.0.1:$BPORT" >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Secret
metadata: {name: alice-creds, namespace: tenant}
stringData: {accessKey: alice, secretKey: alicesecret123}
---
apiVersion: buckets.io/v1alpha1
kind: BucketsPolicy
metadata: {name: photos-rw, namespace: tenant}
spec:
  cluster: store
  policy:
    Version: "2012-10-17"
    Statement:
      - {Effect: Allow, Action: ["s3:*"], Resource: ["arn:aws:s3:::photos", "arn:aws:s3:::photos/*"]}
---
apiVersion: buckets.io/v1alpha1
kind: Bucket
metadata: {name: photos, namespace: tenant}
spec: {cluster: store}
---
apiVersion: buckets.io/v1alpha1
kind: BucketsUser
metadata: {name: alice, namespace: tenant}
spec: {cluster: store, credsSecret: {name: alice-creds}, policies: [photos-rw], groups: [devs]}
YAML
until_true '[[ $(jp bucketsuser/alice {.status.phase}) == Ready ]]' || true
expect "BucketsPolicy ready" "$(jp bucketspolicy/photos-rw '{.status.phase}')" Ready
expect "Bucket ready" "$(jp bucket/photos '{.status.phase}')" Ready
expect "BucketsUser ready" "$(jp bucketsuser/alice '{.status.phase}')" Ready
expect "BucketsUser groups" "$(jp bucketsuser/alice '{.status.groups[0]}')" devs
expect "finalizer held" "$(jp bucketsuser/alice '{.metadata.finalizers[0]}')" buckets.io/cleanup
alice() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user alice:alicesecret123 "$@"; }
expect "alice writes to photos" "$(alice -X PUT --data hi "http://127.0.0.1:$BPORT/photos/a.txt")" 200
expect "alice cannot create buckets" "$(alice -X PUT "http://127.0.0.1:$BPORT/other")" 403
k -n tenant patch bucketsuser alice --type merge -p '{"spec":{"policies":[]}}' >/dev/null
until_true '[[ $(alice "http://127.0.0.1:$BPORT/photos/a.txt") == 403 ]]' || true
expect "policy removed from alice" "$(alice "http://127.0.0.1:$BPORT/photos/a.txt")" 403
k -n tenant delete bucketsuser alice --wait=false >/dev/null
until_true '! k -n tenant get bucketsuser alice' || true
expect "BucketsUser deleted" "$(k -n tenant get bucketsuser alice -o name 2>/dev/null || echo gone)" gone
code=$(curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user alice:alicesecret123 "http://127.0.0.1:$BPORT/photos/a.txt" |
  sed -n 's:.*<Code>\(.*\)</Code>.*:\1:p')
expect "alice removed from the cluster" "$code" InvalidAccessKeyId
k -n tenant delete bucketspolicy photos-rw --wait=false >/dev/null
until_true '! k -n tenant get bucketspolicy photos-rw' || true
expect "BucketsPolicy deleted" "$(k -n tenant get bucketspolicy photos-rw -o name 2>/dev/null || echo gone)" gone
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsUser
metadata: {name: bob, namespace: tenant}
spec: {cluster: store, credsSecret: {name: bob-creds}}
YAML
until_true '[[ $(jp bucketsuser/bob {.status.phase}) == Pending ]]' || true
expect "missing Secret is reported" "$(jp bucketsuser/bob '{.status.phase}')" Pending

echo "== a Bucket's settings are applied, changed and kept"
root() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$rootu:$rootp" "$@"; }
xml() { sed -n "s:.*<$2>\([^<]*\)</$2>.*:\1:p" <<<"$1" | head -1; }
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: Bucket
metadata: {name: reports, namespace: tenant}
spec:
  cluster: store
  versioning: true
  objectLock: {mode: GOVERNANCE, days: 30}
  quota: 1Gi
  encryption: {kmsKey: envtest-key}
  lifecycle:
    - {id: tmp, prefix: tmp/, expireDays: 7, abortIncompleteUploadDays: 2}
    - {id: markers, noncurrentExpireDays: 30, expireDeleteMarkers: true}
YAML
until_true '[[ $(jp bucket/reports {.status.phase}) == Ready ]]' || true
expect "Bucket with settings ready" "$(jp bucket/reports '{.status.phase}')" Ready
expect "message" "$(jp bucket/reports '{.status.message}')" "bucket reports matches its spec"
B="http://127.0.0.1:$BPORT/reports"
expect "versioning on" "$(xml "$(root "$B?versioning")" Status)" Enabled
lock=$(root "$B?object-lock")
expect "made with object lock" "$(xml "$lock" ObjectLockEnabled)" Enabled
expect "default retention" "$(xml "$lock" Mode)/$(xml "$lock" Days)" GOVERNANCE/30
expect "quota" "$(root "http://127.0.0.1:$BPORT/minio/admin/v3/get-bucket-quota?bucket=reports" | jq -r .quota)" 1073741824
expect "default encryption" "$(xml "$(root "$B?encryption")" KMSMasterKeyID)" envtest-key
lc=$(root "$B?lifecycle")
expect "lifecycle rules" "$(grep -o '<ID>[^<]*</ID>' <<<"$lc" | tr -d '\n')" "<ID>tmp</ID><ID>markers</ID>"
expect "expiry" "$(xml "$lc" Days)" 7
expect "checked at" "$([[ -n $(jp bucket/reports '{.status.checkedAt}') ]] && echo set)" set

k -n tenant patch bucket reports --type merge -p \
  '{"spec":{"objectLock":{"mode":"GOVERNANCE","days":60},"quota":"","encryption":{"kmsKey":null,"sse":"S3"},"lifecycle":[]}}' >/dev/null
until_true '[[ $(xml "$(root "$B?object-lock")" Days) == 60 ]]' || true
until_true '[[ $(jp bucket/reports {.status.phase}) == Ready && $(jp bucket/reports {.status.appliedHash}) != "" ]]' || true
sleep 1
expect "retention changed" "$(xml "$(root "$B?object-lock")" Days)" 60
expect "quota removed" "$(root "http://127.0.0.1:$BPORT/minio/admin/v3/get-bucket-quota?bucket=reports" | jq -r '.quota // 0')" 0
expect "encryption now SSE-S3" "$(xml "$(root "$B?encryption")" SSEAlgorithm)" AES256
expect "lifecycle: [] removes the rules" "$(xml "$(root "$B?lifecycle")" Code)" NoSuchLifecycleConfiguration
expect "no drift from spec changes" "$(jp bucket/reports '{.status.drift}')" ""

# changed by hand: put back by the next check
Q="http://127.0.0.1:$BPORT/minio/admin/v3/get-bucket-quota?bucket=reports"
expect "a quota set by hand" "$(root -X PUT --data '{"quota":5000,"quotatype":"hard"}' -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$BPORT/minio/admin/v3/set-bucket-quota?bucket=reports")/$(root "$Q" | jq -r .quota)" 200/5000
root -X DELETE "$B?encryption" >/dev/null
until_true '[[ $(jp bucket/reports "{.status.drift[1].field}") != "" ]]' || true
expect "quota put back" "$(root "$Q" | jq -r '.quota // 0')" 0
expect "encryption put back" "$(xml "$(root "$B?encryption")" SSEAlgorithm)" AES256
expect "drift reported" "$(jp bucket/reports '{.status.drift[*].field}' | tr ' ' '\n' | sort | tr '\n' ' ')" "encryption quota "

# a bucket that already exists, without lock
root -X PUT "http://127.0.0.1:$BPORT/plain" >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: Bucket
metadata: {name: plain, namespace: tenant}
spec: {cluster: store, objectLock: true}
YAML
until_true '[[ $(jp bucket/plain {.status.phase}) == Error ]]' || true
expect "object lock on an existing bucket refused" "$(jp bucket/plain '{.status.message}' | grep -c 'only when a bucket is made')" 1
k -n tenant patch bucket plain --type merge -p '{"spec":{"objectLock":null,"versioning":false,"lifecycle":[{"id":"x"}]}}' >/dev/null
until_true '[[ $(jp bucket/plain {.status.message}) == *"does nothing"* ]]' || true
expect "invalid settings reported" "$(jp bucket/plain '{.status.message}')" "lifecycle rule x does nothing: give it expireDays or another action"
k -n tenant patch bucket plain --type json -p '[{"op":"remove","path":"/spec/lifecycle"}]' >/dev/null
until_true '[[ $(jp bucket/plain {.status.phase}) == Ready ]]' || true
expect "versioning false on a never-versioned bucket" "$(jp bucket/plain '{.status.phase}')/$(xml "$(root "http://127.0.0.1:$BPORT/plain?versioning")" Status)" Ready/
k -n tenant delete bucket reports plain >/dev/null
expect "deleting a Bucket leaves the bucket" "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$rootu:$rootp" -I "$B")" 200

echo "== monitoring: a metrics user, its token and a ServiceMonitor, once the Prometheus Operator is there"
until_true '[[ $(jp bc/store {.status.monitoring.phase}) == NotInstalled ]]' || true
expect "no Prometheus Operator: said so" "$(jp bc/store '{.status.monitoring.phase}')" NotInstalled
# the ServiceMonitor kind, as the Prometheus Operator installs it (its schema left open)
k apply -f - >/dev/null <<YAML
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: servicemonitors.monitoring.coreos.com}
spec:
  group: monitoring.coreos.com
  scope: Namespaced
  names: {kind: ServiceMonitor, listKind: ServiceMonitorList, plural: servicemonitors, singular: servicemonitor}
  versions:
    - name: v1
      served: true
      storage: true
      schema: {openAPIV3Schema: {type: object, x-kubernetes-preserve-unknown-fields: true}}
YAML
until_true '[[ $(jp bc/store {.status.monitoring.phase}) == Ready ]]' || true
expect "monitoring ready" "$(jp bc/store '{.status.monitoring.phase}')" Ready
[[ $(jp bc/store '{.status.monitoring.phase}') == Ready ]] || echo "    status.monitoring: $(jp bc/store '{.status.monitoring.message}'); cluster: $(jp bc/store '{.status.conditions[0].message}')"
expect "the ServiceMonitor scrapes three endpoints" "$(jp servicemonitor/store '{range .spec.endpoints[*]}{.path} {end}')" \
  "/minio/v2/metrics/node /minio/v2/metrics/cluster /minio/v2/metrics/bucket "
expect "on the headless Service" "$(jp servicemonitor/store '{.spec.selector.matchLabels.buckets\.io/service}')" headless
expect "the headless Service carries the label" "$(jp svc/store-hl '{.metadata.labels.buckets\.io/service}')" headless
expect "owned by the cluster" "$(jp servicemonitor/store '{.metadata.ownerReferences[0].kind}')" BucketsCluster
TOKEN=$(jp secret/store-prometheus '{.data.token}' | base64 -d)
PAK=$(jp secret/store-prometheus '{.data.accessKey}' | base64 -d)
PSK=$(jp secret/store-prometheus '{.data.secretKey}' | base64 -d)
scrape() { curl -s -o /dev/null -w '%{http_code}' ${1:+-H "Authorization: Bearer $1"} "http://127.0.0.1:$BPORT/minio/v2/metrics/$2"; }
expect "the token scrapes the node metrics" "$(scrape "$TOKEN" node)" 200
expect "and the cluster's" "$(scrape "$TOKEN" cluster)" 200
expect "and the buckets'" "$(scrape "$TOKEN" bucket)" 200
expect "nothing without it" "$(scrape "" node)" 403
expect "the metrics user reads no data" \
  "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$PAK:$PSK" "http://127.0.0.1:$BPORT/photos/a.txt")" 403
# the user gone from the servers: made again with the same secret, so the token keeps working
curl -s -o /dev/null --aws-sigv4 "aws:amz:us-east-1:s3" --user "$rootu:$rootp" -X DELETE \
  "http://127.0.0.1:$BPORT/minio/admin/v3/remove-user?accessKey=$PAK"
expect "the user removed" "$(scrape "$TOKEN" node)" 403
until_true '[[ $(scrape "$TOKEN" node) == 200 ]]' || true
expect "the operator puts it back" "$(scrape "$TOKEN" node)" 200
expect "with the same token" "$(jp secret/store-prometheus '{.data.token}' | base64 -d)" "$TOKEN"
k -n tenant patch bc store --type merge -p '{"spec":{"monitoring":{"enabled":false}}}' >/dev/null
until_true '! k -n tenant get servicemonitor store' || true
expect "off: the ServiceMonitor goes" "$(k -n tenant get servicemonitor store -o name 2>/dev/null || echo gone)" gone
expect "and the status says so" "$(jp bc/store '{.status.monitoring.phase}')" Disabled
k -n tenant patch bc store --type json -p '[{"op":"remove","path":"/spec/monitoring"}]' >/dev/null

echo "== the KMS: Secrets, the console's Role, trials, KES"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: kmsc, namespace: tenant}
spec:
  image: bucketsd:test
  console: {enabled: true}
  kms: {kes: {image: kes:test}}
  pools: [{servers: 4, volumesPerServer: 1}]
YAML
until_true '[[ $(jp bc/kmsc "{.status.kms.phase}") == NotConfigured ]]' || true
expect "KMS waits for settings" "$(jp bc/kmsc '{.status.kms.phase}')" NotConfigured
for s in kmsc-kms kmsc-kms-candidate kmsc-kes-tls kmsc-kes-identity; do
  expect "Secret $s" "$(k -n tenant get secret $s -o name 2>/dev/null)" "secret/$s"
done
expect "KES's certificate names its Service" \
  "$(jp secret/kmsc-kes-tls '{.data.tls\.crt}' | base64 -d | openssl x509 -noout -ext subjectAltName | grep -o 'kmsc-kes.tenant.svc.cluster.local' | head -1)" \
  kmsc-kes.tenant.svc.cluster.local
expect "API keys" "$(jp secret/kmsc-kes-identity '{.data.client}' | base64 -d | cut -c1-7)" "kes:v1:"
expect "the console's account" "$(jp deploy/kmsc-console '{.spec.template.spec.serviceAccountName}')" kmsc-console
ck() { "$BIN/kubectl" --server "https://127.0.0.1:$APORT" --token console-token --insecure-skip-tls-verify -n tenant "$@"; }
expect "the console may not read the root credentials" "$(ck get secret kmsc-root -o name 2>&1 | grep -o Forbidden | head -1)" Forbidden
expect "nor another cluster" "$(ck get bc store -o name 2>&1 | grep -o Forbidden | head -1)" Forbidden
expect "nor write status" "$(ck patch bc kmsc --subresource=status --type=merge -p '{"status":{"kms":{"test":{"phase":"Passed"}}}}' 2>&1 | grep -o Forbidden | head -1)" Forbidden
settings='{"backend":"vault","vault":{"endpoint":"https://vault.example.com:8200","prefix":"buckets/kmsc","approle":{"id":"r","secret":"s"}}}'
cand=$(printf '{"testId":"t1","settings":%s,"keyName":"buckets-default","createKey":true,"requiredKeys":[]}' "$settings")
ck get secret kmsc-kms-candidate -o json | python3 -c 'import json,sys,base64
s=json.load(sys.stdin); s["data"]={"candidate.json": base64.b64encode(sys.argv[1].encode()).decode()}; print(json.dumps(s))' "$cand" >"$WORK/cand.json"
expect "the console writes a candidate" "$(ck replace -f "$WORK/cand.json" -o name 2>&1)" secret/kmsc-kms-candidate
expect "and asks for a trial" "$(ck annotate bc kmsc buckets.io/kms-test=t1 -o name 2>&1)" bucketscluster.buckets.io/kmsc
until_true '[[ $(jp bc/kmsc "{.status.kms.test.phase}") == Running ]]'
expect "trial running" "$(jp bc/kmsc '{.status.kms.test.id} {.status.kms.test.phase}')" "t1 Running"
expect "trial KES, one replica" "$(jp deploy/kmsc-kes-test '{.spec.replicas}')" 1
expect "trial runs as KES's account" "$(jp deploy/kmsc-kes-test '{.spec.template.spec.serviceAccountName}')" kmsc-kes
expect "trial config names Vault" "$(jp secret/kmsc-kes-test-config '{.data.config\.yaml}' | base64 -d | grep -o 'https://vault.example.com:8200')" \
  https://vault.example.com:8200
# plays the kubelet: the image cannot be pulled
k -n tenant apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: kmsc-kes-test-x, labels: {buckets.io/kes: kmsc-kes-test}}
spec: {containers: [{name: kes, image: kes:test}]}
YAML
k -n tenant patch pod kmsc-kes-test-x --subresource=status --type=merge -p '{"status":{"containerStatuses":[{"name":"kes",
  "image":"kes:test","imageID":"","ready":false,"restartCount":0,
  "state":{"waiting":{"reason":"ImagePullBackOff","message":"Back-off pulling image \"kes:test\""}}}]}}' >/dev/null
until_true '[[ $(jp bc/kmsc "{.status.kms.test.phase}") == Failed ]]'
expect "trial fails" "$(jp bc/kmsc '{.status.kms.test.phase}')" Failed
expect "saying why" "$(jp bc/kmsc '{.status.kms.test.message}' | grep -o 'The KES image kes:test cannot be pulled')" \
  "The KES image kes:test cannot be pulled"
expect "step by step" "$(jp bc/kmsc '{.status.kms.test.steps[1].name}: {.status.kms.test.steps[1].status}')" \
  "Start KES with these settings: failed"
until_true '! k -n tenant get deploy kmsc-kes-test'
expect "the trial server is gone" "$(k -n tenant get deploy kmsc-kes-test -o name 2>/dev/null || echo gone)" gone
# settings applied: the live KES
ck get secret kmsc-kms -o json | python3 -c 'import json,sys,base64
s=json.load(sys.stdin); s["data"]={"settings.json": base64.b64encode(sys.argv[1].encode()).decode()}; print(json.dumps(s))' "$settings" >"$WORK/live.json"
expect "the console writes the settings" "$(ck replace -f "$WORK/live.json" -o name 2>&1)" secret/kmsc-kms
until_true 'k -n tenant get deploy kmsc-kes'
expect "KES, two replicas" "$(jp deploy/kmsc-kes '{.spec.replicas}')" 2
expect "KES's Service" "$(jp svc/kmsc-kes '{.spec.ports[0].port}')" 7373
expect "KES pods stay out of the S3 Service" "$(jp deploy/kmsc-kes '{.spec.template.metadata.labels.buckets\.io/cluster}')" ""
until_true '[[ -n $(jp bc/kmsc "{.status.kms.backend}") ]]'
expect "status names the key store" "$(jp bc/kmsc '{.status.kms.backend}')" "HashiCorp Vault at https://vault.example.com:8200"
expect "storage servers wait for KES" "$(jp sts/kmsc-pool-0 '{.spec.template.spec.containers[0].env[?(@.name=="MINIO_KMS_KES_ENDPOINT")].value}')" ""
# KES "ready" with no server behind it: the default key cannot be made, and bucketsd still waits
k -n tenant patch deploy kmsc-kes --subresource=status --type=merge -p '{"status":{"replicas":2,"readyReplicas":2}}' >/dev/null
until_true '[[ $(jp bc/kmsc "{.status.kms.phase}") == Error ]]'
expect "the default key cannot be created" "$(jp bc/kmsc '{.status.kms.message}' | grep -o 'The default key buckets-default' | head -1)" \
  "The default key buckets-default"
expect "storage servers still wait" "$(jp sts/kmsc-pool-0 '{.spec.template.spec.containers[0].env[?(@.name=="MINIO_KMS_KES_ENDPOINT")].value}')" ""
expect "not activated" "$(jp bc/kmsc '{.status.kms.activated}')" ""
k -n tenant delete bc kmsc >/dev/null

echo "== an adopted tenant's KES (scripts/adopt-minio.sh): its key, its account, servers wait for KES"
k -n tenant create serviceaccount tenant-kes >/dev/null
# the tenant's own KES certificate, which a rollback needs as it is
k -n tenant create secret tls adoptk-kes-tls --cert="$WORK/certs/apiserver.crt" --key="$WORK/certs/apiserver.key" >/dev/null
tenant_tls=$(jp secret/adoptk-kes-tls '{.data.tls\.crt}' | sha256sum)
k -n tenant create secret generic adoptk-kms --from-literal=settings.json="$settings" >/dev/null
k -n tenant label secret adoptk-kms buckets.io/cluster=adoptk >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: adoptk, namespace: tenant}
spec:
  image: bucketsd:test
  kms:
    kes:
      image: kes:test
      keyName: minio-key
      createKey: false
      name: adoptk-buckets-kes
      serviceAccountName: tenant-kes
      tolerations: [{key: storage, operator: Exists}]
  pools: [{servers: 4, volumesPerServer: 1}]
YAML
until_true '[[ $(jp bc/adoptk "{.status.phase}") == WaitingForKMS ]]'
expect "the cluster waits for KMS" "$(jp bc/adoptk '{.status.phase}')" WaitingForKMS
expect "no servers yet" "$(k -n tenant get sts adoptk-pool-0 -o name 2>/dev/null || echo none)" none
until_true 'k -n tenant get deploy adoptk-buckets-kes'
expect "KES under its own name" "$(jp deploy/adoptk-buckets-kes '{.spec.template.spec.serviceAccountName}')" tenant-kes
expect "no account of its own" "$(k -n tenant get sa adoptk-buckets-kes -o name 2>/dev/null || echo none)" none
expect "where the tenant's KES ran" "$(jp deploy/adoptk-buckets-kes '{.spec.template.spec.tolerations[0].key}')" storage
expect "its certificate" "$(jp secret/adoptk-buckets-kes-tls '{.data.tls\.crt}' | base64 -d | openssl x509 -noout -ext subjectAltName | grep -o 'adoptk-buckets-kes.tenant.svc.cluster.local' | head -1)" \
  adoptk-buckets-kes.tenant.svc.cluster.local
expect "the tenant's certificate untouched" "$(jp secret/adoptk-kes-tls '{.data.tls\.crt}' | sha256sum)" "$tenant_tls"
expect "nothing named like the tenant's KES" "$(k -n tenant get deploy,svc adoptk-kes -o name 2>/dev/null || echo none)" none
k -n tenant patch deploy adoptk-buckets-kes --subresource=status --type=merge -p '{"status":{"replicas":2,"readyReplicas":2}}' >/dev/null
until_true '[[ $(jp bc/adoptk "{.status.kms.phase}") == Error ]]'
expect "the key is not made" "$(jp bc/adoptk '{.status.kms.message}' | grep -o 'The default key minio-key' | head -1)" "The default key minio-key"
expect "saying why the servers wait" "$(jp bc/adoptk '{.status.conditions[?(@.type=="Ready")].message}' | grep -o 'the servers start once KES serves key minio-key')" \
  "the servers start once KES serves key minio-key"
expect "still no servers" "$(k -n tenant get sts adoptk-pool-0 -o name 2>/dev/null || echo none)" none
k -n tenant delete bc adoptk >/dev/null

echo "== identity settings from the console: Secrets, not managed, refused while spec.env sets sign-in"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: idc, namespace: tenant}
spec:
  image: bucketsd:test
  console: {enabled: true}
  pools: [{servers: 4, volumesPerServer: 1}]
YAML
until_true '[[ $(jp bc/idc "{.status.identity.phase}") == NotManaged ]]'
expect "nothing saved: not managed" "$(jp bc/idc '{.status.identity.phase}')" NotManaged
for sec in idc-identity idc-identity-candidate; do expect "Secret $sec" "$(jp secret/$sec '{.metadata.name}')" "$sec"; done
expect "the console mounts its sign-in settings" "$(jp deploy/idc-console '{.spec.template.spec.volumes[?(@.name=="identity")].secret.secretName}')" \
  idc-identity-console
expect "the console may update the settings" "$(k -n tenant auth can-i update secret/idc-identity --as=system:serviceaccount:tenant:idc-console)" yes
expect "but not the console's own copy" "$(k -n tenant auth can-i get secret/idc-identity-console --as=system:serviceaccount:tenant:idc-console)" no
idsettings='{"openid":{"provider":"entra","tenantId":"t-1","clientId":"app","clientSecret":"s"}}'
k -n tenant create secret generic idc-identity --from-literal=settings.json="$idsettings" --dry-run=client -o yaml | k apply -f - >/dev/null
until_true '[[ $(jp bc/idc "{.status.identity.phase}") == Error ]]'
expect "saved, but no servers answer" "$(jp bc/idc '{.status.identity.phase}')" Error
expect "status names the provider" "$(jp bc/idc '{.status.identity.description}')" "Microsoft Entra ID (tenant t-1)"
expect "the console's copy waits for the servers" "$(k -n tenant get secret idc-identity-console -o name 2>/dev/null || echo none)" none
k -n tenant patch bc idc --type=merge -p '{"spec":{"env":[{"name":"MINIO_IDENTITY_OPENID_CLIENT_ID","value":"x"}]}}' >/dev/null
until_true '[[ $(jp bc/idc "{.status.identity.phase}") == Conflict ]]'
expect "spec.env setting sign-in too: refused" "$(jp bc/idc '{.status.identity.message}' | grep -o 'spec.env MINIO_IDENTITY_OPENID_CLIENT_ID')" \
  "spec.env MINIO_IDENTITY_OPENID_CLIENT_ID"
k -n tenant delete bc idc >/dev/null

echo "== spec.tls.certManager: refused without cert-manager, then Issuers and Certificates"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: certs, namespace: tenant}
spec:
  image: bucketsd:test
  tls: {certManager: {dnsNames: [s3.example.com]}}
  pools: [{servers: 4, volumesPerServer: 1}]
YAML
until_true '[[ $(jp bc/certs "{.status.conditions[0].reason}") == CertManagerMissing ]]' || true
expect "without cert-manager: said so" "$(jp bc/certs '{.status.conditions[0].reason}')" CertManagerMissing
expect "and nothing started" "$(k -n tenant get sts certs-pool-0 -o name 2>/dev/null || echo none)" none
for kind in Certificate Issuer; do # cert-manager's kinds (schemas left open)
  lower=$(echo "$kind" | tr 'A-Z' 'a-z')
  k apply -f - >/dev/null <<YAML
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: ${lower}s.cert-manager.io}
spec:
  group: cert-manager.io
  scope: Namespaced
  names: {kind: $kind, listKind: ${kind}List, plural: ${lower}s, singular: $lower}
  versions:
    - name: v1
      served: true
      storage: true
      subresources: {status: {}}
      schema: {openAPIV3Schema: {type: object, x-kubernetes-preserve-unknown-fields: true}}
YAML
done
until_true 'k -n tenant get certificate certs-tls' || true
expect "the cluster's own CA chain" "$(k -n tenant get issuer -o name | sort | tr '\n' ' ')" \
  "issuer.cert-manager.io/certs-ca issuer.cert-manager.io/certs-selfsigned "
expect "its CA certificate" "$(jp certificate/certs-ca '{.spec.isCA} {.spec.issuerRef.name}')" "true certs-selfsigned"
expect "the servers' certificate, from it" "$(jp certificate/certs-tls '{.spec.secretName} {.spec.issuerRef.name}')" "certs-tls certs-ca"
expect "with the extra name" "$(jp certificate/certs-tls '{.spec.dnsNames[6]}')" s3.example.com
expect "owned by the cluster" "$(jp certificate/certs-tls '{.metadata.ownerReferences[0].kind}')" BucketsCluster
until_true 'k -n tenant get sts certs-pool-0' || true
expect "the servers mount it" "$(jp sts/certs-pool-0 '{.spec.template.spec.volumes[?(@.name=="certs")].projected.sources[0].secret.name}')" certs-tls
expect "and serve HTTPS" "$(jp sts/certs-pool-0 '{.spec.template.spec.containers[0].readinessProbe.httpGet.scheme}')" HTTPS
until_true '[[ $(jp bc/certs "{.status.tls.phase}") == Issuing ]]' || true
expect "status.tls: not issued yet (no cert-manager here to issue it)" "$(jp bc/certs '{.status.tls.phase} {.status.tls.certificates[0].name}')" "Issuing certs-tls"
# what cert-manager would report once issued
k -n tenant patch certificate certs-tls --subresource=status --type merge \
  -p '{"status":{"conditions":[{"type":"Ready","status":"True"}],"notAfter":"2027-01-04T00:00:00Z"}}' >/dev/null
until_true '[[ $(jp bc/certs "{.status.tls.phase}") == Ready ]]' || true
expect "status.tls: ready, and until when" "$(jp bc/certs '{.status.tls.phase} {.status.tls.certificates[0].notAfter}')" "Ready 2027-01-04T00:00:00Z"
k -n tenant delete bc certs --wait=false >/dev/null

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
