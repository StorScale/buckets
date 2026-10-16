#!/usr/bin/env bash
# Rolling updates of a 4-server cluster on a real cluster, and what they must
# leave behind: every server with its OpenID provider, one leader lock, and no
# warnings that keep coming once the cluster is Ready. Twice:
#  - a plain rollout (a change to the servers' environment);
#  - a rollout while the OpenID provider is down, which then comes back: the
#    servers take it up without a restart.
# Both bugs fixed in 1.20.1 only showed after a rollout: a server that failed
# to fetch its provider at startup went without it, and a leader lock its
# peers forgot after restarting warned every 10 s.
#
#   REGISTRY=ghcr.io/storscale BUCKETS_TAG=<tag> tests/e2e-k8s/rolling.sh
#
# KUBECONTEXT  the cluster (default: the current context)
# NS           a namespace it creates and deletes (default buckets-rolling-test)
# AVOID_NODES  node names the pods must not run on
# KEEP=1       leaves the namespace
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-rolling-test}
[[ -n ${REGISTRY:-} && -n ${BUCKETS_TAG:-} ]] || { echo "set REGISTRY and BUCKETS_TAG"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-rolling-XXXXXX")
cleanup() {
  rm -rf "$WORK"
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS"; return; fi
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall rolling-operator >/dev/null 2>&1 || true
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
SERVERS="store-pool-0-0 store-pool-0-1 store-pool-0-2 store-pool-0-3"
ISS="http://idp.$NS.svc:8080"

echo "== the operator, an OpenID provider and a 4-server cluster"
kc create namespace "$NS" >/dev/null
kc apply --server-side --force-conflicts -f "$ROOT/operator/deploy/crds/" >/dev/null
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install rolling-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 --set monitoring.rules.enabled=false --set monitoring.dashboards.enabled=false \
  ${AFF:+--set-json affinity="$AFF"} --skip-crds --wait --timeout 5m >/dev/null
# The provider: a discovery document and a JWKS with one RSA key, served as files.
openssl genrsa -out "$WORK/rsa.pem" 2048 2>/dev/null
mod=$(openssl rsa -in "$WORK/rsa.pem" -noout -modulus | cut -d= -f2)
n=$(python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).rstrip(b"=").decode())' "$mod")
mkdir -p "$WORK/srv"
echo "{\"issuer\":\"$ISS\",\"jwks_uri\":\"$ISS/jwks\"}" >"$WORK/srv/openid-configuration"
echo "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rs1\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"$n\",\"e\":\"AQAB\"}]}" >"$WORK/srv/jwks"
k create configmap idp --from-file="$WORK/srv/openid-configuration" --from-file="$WORK/srv/jwks" >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: idp}
spec:
  replicas: 1
  selector: {matchLabels: {app: idp}}
  template:
    metadata: {labels: {app: idp}}
    spec:
      ${AFF:+affinity: $AFF}
      containers:
        - name: idp
          image: python:3.12-alpine
          command: [sh, -c, "mkdir -p /srv/.well-known && cp /idp/openid-configuration /srv/.well-known/ && cp /idp/jwks /srv/ && exec python3 -m http.server 8080 -d /srv"]
          ports: [{containerPort: 8080}]
          readinessProbe: {httpGet: {path: /jwks, port: 8080}, periodSeconds: 2}
          volumeMounts: [{name: idp, mountPath: /idp}]
      volumes: [{name: idp, configMap: {name: idp}}]
---
apiVersion: v1
kind: Service
metadata: {name: idp}
spec:
  selector: {app: idp}
  ports: [{port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata: {name: client}
spec:
  ${AFF:+affinity: $AFF}
  containers: [{name: c, image: curlimages/curl:8.16.0, command: [sleep, infinity]}]
YAML
k rollout status deploy/idp --timeout=300s >/dev/null
k wait --for=condition=Ready pod/client --timeout=300s >/dev/null
env_json() { # the servers' environment, with ROLL=$1 to make each change roll them
  echo "[{\"name\":\"MINIO_IDENTITY_OPENID_CONFIG_URL\",\"value\":\"$ISS/.well-known/openid-configuration\"},{\"name\":\"MINIO_IDENTITY_OPENID_CLIENT_ID\",\"value\":\"buckets-app\"},{\"name\":\"ROLL\",\"value\":\"$1\"}]"
}
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: store}
spec:
  image: $REGISTRY/bucketsd:$BUCKETS_TAG
  monitoring: {enabled: false}
  env: $(env_json 0)
  pools:
    - servers: 4
      volumesPerServer: 2
      volumeClaimTemplate: {resources: {requests: {storage: 1Gi}}}
      ${AFF:+affinity: $AFF}
YAML
ready() { [[ $(k get bc store -o jsonpath='{.status.phase} {.status.readyServersText}') == 'Ready 4/4' ]]; }
until_true ready 120 || true
expect "cluster ready" "$(k get bc store -o jsonpath='{.status.phase} {.status.readyServersText}')" "Ready 4/4"

# rolled: every server runs the StatefulSet's latest revision and the cluster is Ready
rolled() {
  local rev
  rev=$(k get sts store-pool-0 -o jsonpath='{.status.updateRevision}')
  [[ -n $rev ]] || return 1
  for p in $SERVERS; do
    [[ $(k get pod "$p" -o jsonpath='{.metadata.labels.controller-revision-hash} {.status.containerStatuses[0].ready}' 2>/dev/null) == "$rev true" ]] || return 1
  done
  ready
}
roll() { # value: changes the environment, waits for the servers to be replaced
  k patch bc store --type merge -p "{\"spec\":{\"env\":$(env_json "$1")}}" >/dev/null
  until_true '[[ $(k get bc store -o jsonpath={.status.phase}) != Ready ]] || ! rolled' 24 || true
  until_true rolled 180 || true
}
with_provider() { # servers whose log (this run of the server) says OpenID is configured
  local c=0
  for p in $SERVERS; do k logs "$p" -c bucketsd 2>/dev/null | grep -q "identity_openid: OpenID configured" && c=$((c + 1)); done
  echo $c
}
failed_fetch() { # servers whose log has the failed fetch
  local c=0
  for p in $SERVERS; do k logs "$p" -c bucketsd 2>/dev/null | grep -q '"ERROR".*identity_openid' && c=$((c + 1)); done
  echo $c
}
# quiet <seconds>: the warnings and errors the servers logged in the last <seconds>, after waiting as long
# (none is the answer wanted)
quiet() {
  sleep "$1"
  for p in $SERVERS; do
    k logs "$p" -c bucketsd --since="${1}s" 2>/dev/null | grep -E '"level":"(WARN|ERROR)"' | sed "s/^/$p: /" || true
  done
}
openid_lines() { # what each server logged about its OpenID provider, for a failure
  for p in $SERVERS; do k logs "$p" -c bucketsd 2>/dev/null | grep identity_openid | sed "s/^/$p: /" || true; done
}
leader_locks() { # holders of the leader lock, from the cluster's top locks
  local u pw
  u=$(k get secret store-root -o jsonpath='{.data.rootUser}' | base64 -d)
  pw=$(k get secret store-root -o jsonpath='{.data.rootPassword}' | base64 -d)
  k exec client -- curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$u:$pw" \
    "http://store.$NS.svc:9000/minio/admin/v3/top/locks?count=1000" | grep -o '"resource":"[^"]*leader.lock"' | wc -l | tr -d ' '
}
until_true '[[ $(with_provider) == 4 ]]' 24 || openid_lines
expect "every server has the provider" "$(with_provider)" 4

echo "== a rollout"
roll 1
expect "rolled out" "$(rolled && echo yes || echo no)" yes
until_true '[[ $(with_provider) == 4 ]]' 24 || openid_lines
expect "every server has the provider after it" "$(with_provider)" 4
expect "nothing keeps warning a minute after" "$(quiet 60)" ""
expect "one leader lock" "$(leader_locks)" 1

echo "== a rollout while the provider is down"
k scale deploy/idp --replicas=0 >/dev/null
until_true '[[ -z $(k get pods -l app=idp -o name) ]]' 24 || true
roll 2
expect "rolled out" "$(rolled && echo yes || echo no)" yes
expect "every server failed to fetch the provider" "$(failed_fetch)" 4
expect "and has none" "$(with_provider)" 0
k scale deploy/idp --replicas=1 >/dev/null
k rollout status deploy/idp --timeout=300s >/dev/null
until_true '[[ $(with_provider) == 4 ]]' 24 || openid_lines # retries are at most a minute apart
expect "the provider back: every server takes it up, unrestarted" "$(with_provider)" 4
expect "no server restarted" "$(k get pods $SERVERS -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{end}')" 0000
expect "nothing keeps warning a minute after" "$(quiet 60)" ""
expect "one leader lock" "$(leader_locks)" 1

echo "rolling: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
