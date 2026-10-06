#!/usr/bin/env bash
# Buckets, replication and site replication as resources, on a real cluster
# (docs/design/declarative-buckets.md). Four one-server BucketsClusters:
#  - store and dr: a Bucket on store with its settings, replicated to dr; an
#    object carried across, a setting changed by hand put back;
#  - east and west: a BucketsSiteReplication between them; a bucket, a policy
#    and a user made on east reach west, and the replication stops when one
#    site is left.
#
#   REGISTRY=ghcr.io/storscale BUCKETS_TAG=<tag> tests/e2e-k8s/declarative.sh
#
# KUBECONTEXT  the cluster (default: the current context)
# NS           a namespace it creates and deletes (default buckets-decl-test)
# AVOID_NODES  node names the pods must not run on
# KEEP=1       leaves the namespace
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-decl-test}
[[ -n ${REGISTRY:-} && -n ${BUCKETS_TAG:-} ]] || { echo "set REGISTRY and BUCKETS_TAG"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
cleanup() {
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS"; return; fi
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall decl-operator >/dev/null 2>&1 || true
  kc delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
}
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf 'ok    %s\n' "$1"; else
    fail=$((fail + 1))
    printf 'FAIL  %s: got %q want %q\n' "$1" "$2" "$3"
  fi
}
until_true() { # condition [tries, 5 s apart]
  for _ in $(seq "${2:-60}"); do eval "$1" >/dev/null 2>&1 && return 0; sleep 5; done
  return 1
}
AFF=
if [[ -n ${AVOID_NODES:-} ]]; then
  AFF=$(python3 -c 'import json,sys; print(json.dumps({"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"NotIn","values":sys.argv[1:]}]}]}}}))' $AVOID_NODES)
fi

echo "== the operator and four clusters"
kc create namespace "$NS" >/dev/null
kc apply --server-side --force-conflicts -f "$ROOT/operator/deploy/crds/" >/dev/null
# checks every 30 seconds, so drift is put back while the test waits
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install decl-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 --set monitoring.rules.enabled=false --set monitoring.dashboards.enabled=false \
  --set-json 'extraEnv=[{"name":"BUCKETS_OPERATOR_DRIFT_MS","value":"30000"}]' \
  ${AFF:+--set-json affinity="$AFF"} --skip-crds --wait --timeout 5m >/dev/null
for c in store dr east west; do
  k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: $c}
spec:
  image: $REGISTRY/bucketsd:$BUCKETS_TAG
  monitoring: {enabled: false}
  pools:
    - servers: 1
      volumesPerServer: 4
      volumeClaimTemplate: {resources: {requests: {storage: 1Gi}}}
      ${AFF:+affinity: $AFF}
YAML
done
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: client}
spec:
  ${AFF:+affinity: $AFF}
  containers: [{name: c, image: curlimages/curl:8.16.0, command: [sleep, infinity]}]
YAML
k wait --for=condition=Ready pod/client --timeout=300s >/dev/null
for c in store dr east west; do
  until_true "[[ \$(k get bc $c -o jsonpath='{.status.phase} {.status.readyServersText}') == 'Ready 1/1' ]]" 120 || true
  expect "$c ready" "$(k get bc $c -o jsonpath='{.status.phase} {.status.readyServersText}')" "Ready 1/1"
done
user() { k get secret "$1-root" -o jsonpath='{.data.rootUser}' | base64 -d; }
pass_() { k get secret "$1-root" -o jsonpath='{.data.rootPassword}' | base64 -d; }
# s3 <cluster> <curl args> <path>: a request to the cluster's Service, signed as its root
s3() {
  local c=$1
  shift
  local args=("$@") last=${*: -1}
  unset 'args[${#args[@]}-1]'
  k exec client -- curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$(user "$c"):$(pass_ "$c")" "${args[@]}" \
    "http://$c.$NS.svc:9000$last"
}
xml() { sed -n "s:.*<$2>\([^<]*\)</$2>.*:\1:p" <<<"$1" | head -1; }

echo "== a Bucket with its settings, replicated to another cluster"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: Bucket
metadata: {name: reports}
spec:
  cluster: store
  versioning: true
  quota: 1Gi
  lifecycle:
    - {id: tmp, prefix: tmp/, expireDays: 7}
  replication: {target: {cluster: dr}}
YAML
until_true "[[ \$(k get bucket reports -o jsonpath='{.status.phase}') == Ready ]]" || true
expect "Bucket ready" "$(k get bucket reports -o jsonpath='{.status.phase}: {.status.message}')" "Ready: bucket reports matches its spec"
expect "versioned" "$(xml "$(s3 store /reports?versioning)" Status)" Enabled
expect "lifecycle rule" "$(xml "$(s3 store /reports?lifecycle)" ID)" tmp
expect "quota" "$(s3 store /minio/admin/v3/get-bucket-quota?bucket=reports | sed -n 's/.*"quota":\([0-9]*\).*/\1/p')" 1073741824
expect "target bucket versioned on dr" "$(xml "$(s3 dr /reports?versioning)" Status)" Enabled
s3 store -X PUT --data "carried across" /reports/one.txt >/dev/null
until_true "[[ \$(s3 dr /reports/one.txt) == 'carried across' ]]" 24 || true
expect "an object carried across to dr" "$(s3 dr /reports/one.txt)" "carried across"
expect "replication status" "$(s3 store -I /reports/one.txt | tr -d '\r' | sed -n 's/^[Xx]-[Aa]mz-[Rr]eplication-[Ss]tatus: //p')" COMPLETED
s3 store -X DELETE /reports?lifecycle >/dev/null
until_true "[[ \$(xml \"\$(s3 store /reports?lifecycle)\" ID) == tmp ]]" 24 || true
expect "lifecycle removed by hand, put back" "$(xml "$(s3 store /reports?lifecycle)" ID)" tmp
expect "and named as drift" "$(k get bucket reports -o jsonpath='{.status.drift[*].field}')" lifecycle

echo "== site replication between two clusters"
s3 east -X PUT /shared >/dev/null # east has the data
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsSiteReplication
metadata: {name: pair}
spec:
  sites: [{cluster: west}, {cluster: east}]
YAML
until_true "[[ \$(k get bsr pair -o jsonpath='{.status.phase}') == Ready ]]" || true
expect "BucketsSiteReplication ready" "$(k get bsr pair -o jsonpath='{.status.message}')" "2 sites replicate: west, east"
until_true "[[ \$(s3 west -o /dev/null -w '%{http_code}' -I /shared) == 200 ]]" 24 || true
expect "east's bucket on west" "$(s3 west -o /dev/null -w '%{http_code}' -I /shared)" 200
k create secret generic carol-creds --from-literal=accessKey=carol --from-literal=secretKey=carolsecret123 >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsPolicy
metadata: {name: shared-ro}
spec:
  cluster: east
  policy:
    Version: "2012-10-17"
    Statement: [{Effect: Allow, Action: ["s3:GetObject"], Resource: ["arn:aws:s3:::shared/*"]}]
---
apiVersion: buckets.io/v1alpha1
kind: BucketsUser
metadata: {name: carol}
spec: {cluster: east, credsSecret: {name: carol-creds}, policies: [shared-ro]}
---
apiVersion: buckets.io/v1alpha1
kind: Bucket
metadata: {name: made-on-east}
spec: {cluster: east, versioning: true}
YAML
until_true "[[ \$(k get bucketsuser carol -o jsonpath='{.status.phase}') == Ready ]]" || true
until_true "[[ \$(s3 west -o /dev/null -w '%{http_code}' -I /made-on-east) == 200 ]]" 24 || true
expect "a Bucket made on east is on west" "$(s3 west -o /dev/null -w '%{http_code}' -I /made-on-east)" 200
until_true "s3 west /minio/admin/v3/list-canned-policies | grep -q shared-ro" 24 || true
expect "a BucketsPolicy made on east is on west" "$(s3 west /minio/admin/v3/list-canned-policies | grep -c '"shared-ro"')" 1
s3 east -X PUT --data hello /shared/hello.txt >/dev/null
until_true "[[ \$(s3 west /shared/hello.txt) == hello ]]" 24 || true
code=$(k exec client -- curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user carol:carolsecret123 \
  "http://west.$NS.svc:9000/shared/hello.txt")
expect "a BucketsUser made on east signs in on west" "$code" 200
k patch bsr pair --type merge -p '{"spec":{"sites":[{"cluster":"west"}]}}' >/dev/null
until_true "[[ \$(s3 west /minio/admin/v3/site-replication/info | sed -n 's/.*\"enabled\":\([a-z]*\).*/\1/p') == false ]]" 24 || true
expect "one site left: stopped" "$(s3 west /minio/admin/v3/site-replication/info | sed -n 's/.*"enabled":\([a-z]*\).*/\1/p')" false

errs=$(k logs deploy/decl-operator-buckets-operator 2>/dev/null | grep -c '"level":"ERROR"' || true)
expect "no operator errors" "$errs" 0
echo "declarative: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
