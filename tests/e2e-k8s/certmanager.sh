#!/usr/bin/env bash
# spec.tls.certManager on a real cluster with cert-manager: a cluster with a
# CA of its own comes up (its servers trust each other's issued certificates),
# S3 and the console answer over HTTPS verified against that CA, a renewed
# certificate is served without any pod restarting; and, with ISSUER set, a
# cluster whose certificates come from that ClusterIssuer does the same.
#
#   REGISTRY=ghcr.io/storscale BUCKETS_TAG=<tag> [ISSUER=cluster-issuer] tests/e2e-k8s/certmanager.sh
#
# KUBECONTEXT  the cluster (default: the current context)
# NS           a namespace it creates and deletes (default buckets-certs-test)
# AVOID_NODES  node names the pods must not run on
# KEEP=1       leaves the namespace
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-certs-test}
[[ -n ${REGISTRY:-} && -n ${BUCKETS_TAG:-} ]] || { echo "set REGISTRY and BUCKETS_TAG"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
cleanup() {
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS"; return; fi
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall certs-operator >/dev/null 2>&1 || true
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
AFF=
if [[ -n ${AVOID_NODES:-} ]]; then
  AFF=$(python3 -c 'import json,sys; print(json.dumps({"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"NotIn","values":sys.argv[1:]}]}]}}}))' $AVOID_NODES)
fi

echo "== the operator"
kc create namespace "$NS" >/dev/null
kc apply --server-side --force-conflicts -f "$ROOT/operator/deploy/crds/" >/dev/null
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install certs-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 --set monitoring.rules.enabled=false --set monitoring.dashboards.enabled=false \
  ${AFF:+--set-json affinity="$AFF"} --skip-crds --wait --timeout 5m >/dev/null

cluster() { # name tls-yaml
  k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: $1}
spec:
  image: $REGISTRY/bucketsd:$BUCKETS_TAG
  tls: $2
  monitoring: {enabled: false}
  pools:
    - servers: 4
      volumesPerServer: 1
      volumeClaimTemplate: {resources: {requests: {storage: 1Gi}}}
      ${AFF:+affinity: $AFF}
  console: {enabled: true, image: "$REGISTRY/buckets-console:$BUCKETS_TAG", tls: $2${AFF:+, affinity: $AFF}}
YAML
}
ready() { # name
  for _ in $(seq 120); do [[ $(k get bc "$1" -o jsonpath='{.status.phase} {.status.readyServersText}' 2>/dev/null) == "Ready 4/4" ]] && break; sleep 5; done
  k rollout status "deploy/$1-console" --timeout=300s >/dev/null
  for _ in $(seq 60); do [[ $(k get bc "$1" -o jsonpath='{.status.tls.phase}') == Ready ]] && break; sleep 5; done
}

# a client that checks HTTPS against a CA, and reads a server's certificate serial
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: client}
spec:
  ${AFF:+affinity: $AFF}
  containers: [{name: c, image: python:3.12-slim, command: [sleep, infinity]}]
YAML
k wait --for=condition=Ready pod/client --timeout=300s >/dev/null
https() { # url ca-secret -> status, verified against that Secret's ca.crt
  k get secret "$2" -o jsonpath='{.data.ca\.crt}' | base64 -d | k exec -i client -- sh -c 'cat > /tmp/ca.crt' >/dev/null
  k exec client -- python3 -c '
import ssl, sys, urllib.request
ctx = ssl.create_default_context(cafile="/tmp/ca.crt")
try: print(urllib.request.urlopen(sys.argv[1], context=ctx, timeout=20).status)
except Exception as e: print(type(e).__name__, e)' "$1"
}
serial() { # host port -> the certificate it serves, by serial
  k exec client -- python3 -c '
import socket, ssl, sys
ctx = ssl._create_unverified_context()
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=20) as s, ctx.wrap_socket(s, server_hostname=sys.argv[1]) as t:
    import hashlib; print(hashlib.sha256(t.getpeercert(True)).hexdigest()[:16])' "$1" "$2"
}
restarts() { k get pods -l buckets.io/cluster="$1" -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{" "}{end}'; }

echo "== a CA of the cluster's own"
cluster own "{certManager: {}}"
ready own
expect "the servers came up over TLS (they trust each other's certificates)" "$(k get bc own -o jsonpath='{.status.phase} {.status.readyServersText}')" "Ready 4/4"
expect "status.tls" "$(k get bc own -o jsonpath='{.status.tls.phase} {range .status.tls.certificates[*]}{.name}={.ready} {end}')" \
  "Ready own-tls=true own-console-tls=true "
expect "its CA chain" "$(k get issuer -o name | sort | tr '\n' ' ')" "issuer.cert-manager.io/own-ca issuer.cert-manager.io/own-selfsigned "
expect "S3 over HTTPS, verified" "$(https "https://own.$NS.svc:9000/minio/health/live" own-tls)" 200
expect "the console too" "$(https "https://own-console.$NS.svc:9090/healthz" own-console-tls)" 200
expect "a per-server name" "$(https "https://own-pool-0-2.own-hl.$NS.svc.cluster.local:9000/minio/health/live" own-tls)" 200

echo "== a renewal is served without restarting anything"
before=$(serial "own-pool-0-1.own-hl.$NS.svc.cluster.local" 9000)
was=$(restarts own)
k delete secret own-tls >/dev/null # cert-manager issues it again, with a new key
for _ in $(seq 60); do
  now=$(serial "own-pool-0-1.own-hl.$NS.svc.cluster.local" 9000 2>/dev/null || true)
  [[ -n $now && $now != "$before" ]] && break
  sleep 5
done
expect "the server serves the new certificate" "$([[ -n $now && $now != "$before" ]] && echo renewed || echo "same: $now")" renewed
expect "no pod restarted" "$(restarts own)" "$was"
expect "and HTTPS still verifies" "$(https "https://own.$NS.svc:9000/minio/health/live" own-tls)" 200

if [[ -n ${ISSUER:-} ]]; then
  echo "== certificates from ClusterIssuer $ISSUER"
  cluster corp "{certManager: {issuerRef: {name: $ISSUER, kind: ClusterIssuer}}}"
  ready corp
  expect "ready" "$(k get bc corp -o jsonpath='{.status.phase} {.status.readyServersText} {.status.tls.phase}')" "Ready 4/4 Ready"
  expect "issued by it" "$(k get certificate corp-tls -o jsonpath='{.spec.issuerRef.kind}/{.spec.issuerRef.name}')" "ClusterIssuer/$ISSUER"
  expect "no CA of its own" "$(k get issuer -o name | grep -c corp || true)" 0
  expect "S3 over HTTPS, verified" "$(https "https://corp.$NS.svc:9000/minio/health/live" corp-tls)" 200
fi

echo "certmanager: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
