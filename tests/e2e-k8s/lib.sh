# Shared by the kind e2e scripts: checks, the kind cluster with the Buckets
# images and operator, and an in-cluster client pod ("cli") that reaches
# Services by DNS, so traffic takes the Service path a real client would.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
NAME=${KIND_CLUSTER:-buckets-e2e}
for t in docker kind kubectl; do command -v $t >/dev/null || { echo "needs $t"; exit 2; }; done
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
# Retries a check whose outcome converges (replication, healing).
eventually() { # name want tries cmd...
  local name=$1 want=$2 tries=$3 got=
  shift 3
  for _ in $(seq "$tries"); do got=$("$@" 2>/dev/null || true); [[ "$got" == "$want" ]] && break; sleep 2; done
  expect "$name" "$got" "$want"
}
finish() { echo "$(basename "$0" .sh): $pass passed, $fail failed"; [[ $fail -eq 0 ]]; }

# Images (bucketsd, the operator, the console and the client), the cluster,
# and the operator. TOOLS_BINS names extra linux binaries for the client.
setup_cluster() {
  echo "== images and cluster"
  docker build -q -f "$ROOT/docker/Dockerfile.bucketsd" -t buckets/bucketsd:e2e "$ROOT" >/dev/null
  docker build -q -f "$ROOT/docker/Dockerfile.operator" -t buckets/buckets-operator:e2e "$ROOT" >/dev/null
  docker build -q -f "$ROOT/docker/Dockerfile.console" -t buckets/buckets-console:e2e "$ROOT" >/dev/null
  local ctx
  ctx=$(mktemp -d)
  mkdir "$ctx/bin" && touch "$ctx/bin/.keep"
  for b in ${TOOLS_BINS:-}; do cp "$b" "$ctx/bin/"; done
  docker build -q -f "$ROOT/tests/e2e-k8s/tools/Dockerfile" -t buckets/e2e-tools:e2e "$ctx" >/dev/null
  rm -rf "$ctx"
  kind get clusters | grep -qx "$NAME" || kind create cluster --name "$NAME" --wait 120s
  for img in buckets/bucketsd:e2e buckets/buckets-operator:e2e buckets/buckets-console:e2e buckets/e2e-tools:e2e "$@"; do
    kind load docker-image --name "$NAME" "$img" >/dev/null
  done
  kubectl apply -f "$ROOT/operator/deploy/crds/" >/dev/null
  kubectl apply -f "$ROOT/operator/deploy/operator.yaml" >/dev/null
  kubectl -n buckets-system set image deploy/buckets-operator operator=buckets/buckets-operator:e2e >/dev/null
  kubectl -n buckets-system rollout status deploy/buckets-operator --timeout=180s >/dev/null
}

# The client pod in namespace $1.
start_cli() {
  kubectl create ns "$1" >/dev/null 2>&1 || true
  kubectl -n "$1" get pod cli >/dev/null 2>&1 ||
    kubectl -n "$1" run cli --image=buckets/e2e-tools:e2e --image-pull-policy=Never --restart=Never \
      --command -- sleep infinity >/dev/null
  kubectl -n "$1" wait --for=condition=Ready pod/cli --timeout=120s >/dev/null
}

# A BucketsCluster's root credentials: creds <ns> <name> -> "user password".
creds() {
  echo "$(kubectl -n "$1" get secret "$2-root" -o jsonpath='{.data.rootUser}' | base64 -d)" \
    "$(kubectl -n "$1" get secret "$2-root" -o jsonpath='{.data.rootPassword}' | base64 -d)"
}
wait_bc() { kubectl -n "$1" wait --for=jsonpath='{.status.phase}'=Ready "bc/$2" --timeout="${3:-600}s" >/dev/null; }
