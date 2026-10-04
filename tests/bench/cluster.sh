#!/usr/bin/env bash
# MinIO and Buckets under the same concurrent load, on the same Kubernetes
# volumes and nodes: a MinIO tenant (4 servers x 2 drives, StatefulSet as the
# MinIO Operator lays one out, plain HTTP) is load-tested with s3bench from a
# client pod, adopted in place by Buckets (scripts/adopt-minio.sh) and tested
# again, then rolled back (scripts/rollback-to-minio.sh) and tested a third
# time, so the second MinIO round shows how far the storage itself drifted.
#
#   S3BENCH=/path/to/s3bench MINIO_IMAGE=<mirror>/minio:RELEASE.2024-10-13T13-34-11Z \
#     REGISTRY=ghcr.io/storscale BUCKETS_TAG=1.1.0 tests/bench/cluster.sh
#
# S3BENCH      tests/bench/s3bench built for linux/amd64, static:
#                (cd tests/bench/s3bench && go mod init s3bench && go mod tidy &&
#                 CGO_ENABLED=0 GOOS=linux go build -o /tmp/s3bench .)
# MINIO_IMAGE  a MinIO image the cluster can pull (MinIO publishes none any more)
# REGISTRY, BUCKETS_TAG   the bucketsd and buckets-operator images
# KUBECONTEXT  the cluster (default: the current context)
# NS           a namespace it creates and deletes (default buckets-bench)
# CASES        "size:clients ..." (default "10485760:16 1048576:32 65536:32")
# DURATION     per phase (default 15s)
# DRIVE_SIZE   per drive (default 20Gi); STORAGE_CLASS (default: the cluster's)
# AVOID_NODES  node names the pods must not run on
# KEEP=1       leaves the namespace
# Results: a table at the end, and one JSON line per run in $RESULTS if set.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-bench}
T=minio
CASES=${CASES:-"10485760:16 1048576:32 65536:32"}
DURATION=${DURATION:-15s}
DRIVE_SIZE=${DRIVE_SIZE:-20Gi}
for v in S3BENCH MINIO_IMAGE REGISTRY BUCKETS_TAG; do
  [[ -n ${!v:-} ]] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d'; echo; echo "set $v"; exit 2; }
done
[[ -x $S3BENCH ]] || { echo "S3BENCH ($S3BENCH) is not an executable"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
WORK=$(mktemp -d)
OUT=$WORK/results.jsonl
cleanup() {
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS and $WORK"; return; fi
  local pv
  for pv in $(k get pvc -o jsonpath='{range .items[*]}{.spec.volumeName}{" "}{end}' 2>/dev/null || true); do
    kc patch pv "$pv" -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' >/dev/null 2>&1 || true
  done
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall bench-operator >/dev/null 2>&1 || true
  kc delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
AFF=
if [[ -n ${AVOID_NODES:-} ]]; then
  AFF=$(python3 -c 'import json,sys; print(json.dumps({"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"NotIn","values":sys.argv[1:]}]}]}}}))' $AVOID_NODES)
fi
SC=${STORAGE_CLASS:+\"storageClassName\": \"$STORAGE_CLASS\",}
AK=benchroot
SK=$(openssl rand -hex 16)

echo "== a MinIO tenant: 4 servers x 2 drives of $DRIVE_SIZE"
kc create namespace "$NS" >/dev/null
printf 'export MINIO_ROOT_USER=%s\nexport MINIO_ROOT_PASSWORD=%s\n' "$AK" "$SK" > "$WORK/config.env"
k create secret generic $T-env-configuration --from-file=config.env="$WORK/config.env" >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata: {name: $T-hl, labels: {v1.min.io/tenant: $T}}
    spec:
      clusterIP: None
      publishNotReadyAddresses: true
      selector: {v1.min.io/tenant: $T}
      ports: [{name: http-minio, port: 9000, targetPort: 9000}]
  - apiVersion: v1
    kind: Service
    metadata: {name: $T, labels: {v1.min.io/tenant: $T}}
    spec:
      selector: {v1.min.io/tenant: $T}
      ports: [{name: http-minio, port: 9000, targetPort: 9000}]
  - apiVersion: apps/v1
    kind: StatefulSet
    metadata: {name: $T-pool-0, labels: {v1.min.io/tenant: $T, v1.min.io/pool: pool-0}}
    spec:
      serviceName: $T-hl
      replicas: 4
      podManagementPolicy: Parallel
      selector: {matchLabels: {v1.min.io/tenant: $T, v1.min.io/pool: pool-0}}
      template:
        metadata: {labels: {v1.min.io/tenant: $T, v1.min.io/pool: pool-0}}
        spec:
          securityContext: {runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, runAsNonRoot: true, fsGroupChangePolicy: OnRootMismatch}
          ${AFF:+affinity: $AFF}
          containers:
            - name: minio
              image: $MINIO_IMAGE
              args: [server]
              env:
                - {name: MINIO_VOLUMES, value: "http://$T-pool-0-{0...3}.$T-hl.$NS.svc.cluster.local:9000/export{0...1}/data"}
                - {name: MINIO_CONFIG_ENV_FILE, value: /tmp/minio/config.env}
              ports: [{containerPort: 9000}]
              readinessProbe: {httpGet: {path: /minio/health/ready, port: 9000}, periodSeconds: 5}
              volumeMounts:
                - {name: data0, mountPath: /export0}
                - {name: data1, mountPath: /export1}
                - {name: cfg, mountPath: /tmp/minio}
          volumes:
            - {name: cfg, secret: {secretName: $T-env-configuration}}
      volumeClaimTemplates:
        - metadata: {name: data0}
          spec: {$SC accessModes: [ReadWriteOnce], resources: {requests: {storage: $DRIVE_SIZE}}}
        - metadata: {name: data1}
          spec: {$SC accessModes: [ReadWriteOnce], resources: {requests: {storage: $DRIVE_SIZE}}}
  - apiVersion: v1
    kind: Pod
    metadata: {name: bench}
    spec:
      ${AFF:+affinity: $AFF}
      containers: [{name: bench, image: alpine:3.22, command: [sleep, infinity]}]
YAML
for i in 0 1 2 3; do
  for _ in $(seq 60); do k get pod "$T-pool-0-$i" >/dev/null 2>&1 && break; sleep 5; done
done
k wait --for=condition=Ready pod -l v1.min.io/tenant=$T --timeout=900s >/dev/null
k wait --for=condition=Ready pod/bench --timeout=300s >/dev/null
k cp "$S3BENCH" bench:/s3bench >/dev/null
k exec bench -- chmod 755 /s3bench
echo "   servers on: $(k get pods -l v1.min.io/tenant=$T -o jsonpath='{range .items[*]}{.spec.nodeName}{" "}{end}')"
echo "   client on:  $(k get pod bench -o jsonpath='{.spec.nodeName}')"

round() { # label
  local c size clients out
  echo "== $1"
  for c in $CASES; do
    size=${c%%:*} clients=${c##*:}
    out=$(k exec bench -- /s3bench -endpoint "$T.$NS.svc.cluster.local:9000" -access "$AK" -secret "$SK" \
      -size "$size" -concurrent "$clients" -duration "$DURATION" -bucket "bench-$size")
    echo "{\"server\": \"$1\", \"size\": $size, \"clients\": $clients, \"phases\": $out}" >>"$OUT"
    python3 "$ROOT/tests/bench/warpfmt.py" "$1" "$size" "$clients" "$out" | sed 's/^/   /'
  done
}

round "MinIO"

echo "== Buckets adopts the tenant in place (same volumes)"
kc apply -f "$ROOT/operator/deploy/crds/" >/dev/null
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install bench-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 ${AFF:+--set-json affinity="$AFF"} --wait --timeout 5m >/dev/null
"$ROOT/scripts/adopt-minio.sh" -n "$NS" -t "$T" ${KUBECONTEXT:+--context $KUBECONTEXT} --state "$WORK/state" \
  --image "$REGISTRY/bucketsd:$BUCKETS_TAG" --apply > "$WORK/adopt.log" 2>&1 || { cat "$WORK/adopt.log"; exit 1; }
echo "   servers on: $(k get pods -l buckets.io/cluster=$T -o jsonpath='{range .items[*]}{.spec.nodeName}{" "}{end}')"
round "Buckets"

echo "== back to MinIO (same volumes)"
"$ROOT/scripts/rollback-to-minio.sh" -n "$NS" -t "$T" ${KUBECONTEXT:+--context $KUBECONTEXT} --state "$WORK/state" --apply \
  > "$WORK/rollback.log" 2>&1 || { cat "$WORK/rollback.log"; exit 1; }
round "MinIO again"

[[ -n ${RESULTS:-} ]] && cat "$OUT" >>"$RESULTS"
echo "== summary (MiB/s; ops/s for objects under 1 MiB)"
python3 - "$OUT" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
servers = list(dict.fromkeys(r["server"] for r in rows))
cases = list(dict.fromkeys((r["size"], r["clients"]) for r in rows))
def val(r, op):
    p = next((p for p in r["phases"] if p["op"] == op), None)
    if not p: return "-"
    if p.get("errors"): return "errors: %d" % p["errors"]
    return "%.0f" % (p["ops_per_s"] if r["size"] < 1 << 20 else p["mib_per_s"])
def size(b):
    return "%d MiB" % (b >> 20) if b >= 1 << 20 else "%d KiB" % (b >> 10)
print("| Case | " + " | ".join(f"{s} {op}" for op in ("PUT", "GET") for s in servers) + " |")
print("|---" * (1 + 2 * len(servers)) + "|")
for c in cases:
    byserver = {r["server"]: r for r in rows if (r["size"], r["clients"]) == c}
    cells = [val(byserver[s], op) if s in byserver else "-" for op in ("PUT", "GET") for s in servers]
    print(f"| {size(c[0])} x {c[1]} clients | " + " | ".join(cells) + " |")
PY
