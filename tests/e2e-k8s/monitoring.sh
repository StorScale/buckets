#!/usr/bin/env bash
# Monitoring on a real cluster with the Prometheus Operator (e.g. Rancher
# monitoring): the chart installs the alert rules and dashboards, the operator
# a ServiceMonitor for a new cluster, and the cluster's Prometheus scrapes it.
# Every dashboard query gets data. Then a drive is made to fail (its
# .minio.sys/tmp unwritable, from an ephemeral container as the server's user)
# and BucketsDriveOffline must fire, then clear once the drive works again.
#
#   REGISTRY=ghcr.io/storscale BUCKETS_TAG=<tag> tests/e2e-k8s/monitoring.sh
#
# KUBECONTEXT  the cluster (default: the current context)
# NS           a namespace it creates and deletes (default buckets-monitoring-test)
# PROM_NS, PROM_SVC   the Prometheus Service to query (default cattle-monitoring-system,
#              rancher-monitoring-prometheus, port 9090)
# AVOID_NODES  node names the pods must not run on
# KEEP=1       leaves the namespace
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-monitoring-test}
PROM_NS=${PROM_NS:-cattle-monitoring-system}
PROM_SVC=${PROM_SVC:-rancher-monitoring-prometheus}
PPORT=${PPORT:-19099}
[[ -n ${REGISTRY:-} && -n ${BUCKETS_TAG:-} ]] || { echo "set REGISTRY and BUCKETS_TAG"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
WORK=$(mktemp -d)
PF=
cleanup() {
  [[ -n $PF ]] && kill "$PF" 2>/dev/null || true
  rm -rf "$WORK"
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS"; return; fi
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall mon-operator >/dev/null 2>&1 || true
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

echo "== the operator, with the alert rules and dashboards"
kc create namespace "$NS" >/dev/null
kc apply --server-side --force-conflicts -f "$ROOT/operator/deploy/crds/" >/dev/null
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install mon-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 --set monitoring.dashboards.namespace="$NS" ${AFF:+--set-json affinity="$AFF"} \
  --wait --timeout 5m >/dev/null
expect "the alert rules" "$(k get prometheusrule -o name | wc -l | tr -d ' ')" 1
expect "four dashboards" "$(k get configmap -l grafana_dashboard=1 -o name | wc -l | tr -d ' ')" 4

echo "== a cluster, with its ServiceMonitors"
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: mon}
spec:
  image: $REGISTRY/bucketsd:$BUCKETS_TAG
  env: [{name: BUCKETS_DRIVE_CHECK_INTERVAL, value: "5"}]
  pools:
    - servers: 4
      volumesPerServer: 1
      volumeClaimTemplate: {resources: {requests: {storage: 2Gi}}}
      ${AFF:+affinity: $AFF}
  console: {enabled: true, image: "$REGISTRY/buckets-console:$BUCKETS_TAG"${AFF:+, affinity: $AFF}}
YAML
for _ in $(seq 120); do [[ $(k get bc mon -o jsonpath='{.status.phase} {.status.readyServersText}' 2>/dev/null) == "Ready 4/4" ]] && break; sleep 5; done
for _ in $(seq 60); do [[ $(k get bc mon -o jsonpath='{.status.monitoring.phase}') == Ready ]] && break; sleep 5; done
expect "status.monitoring" "$(k get bc mon -o jsonpath='{.status.monitoring.phase}')" Ready
expect "the ServiceMonitors" "$(k get servicemonitor -o name | sort | tr '\n' ' ')" "servicemonitor.monitoring.coreos.com/mon servicemonitor.monitoring.coreos.com/mon-console "

echo "== Prometheus scrapes it"
kc -n "$PROM_NS" port-forward "svc/$PROM_SVC" "$PPORT:9090" >/dev/null 2>&1 &
PF=$!
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PPORT/-/ready" && break; sleep 0.2; done
q() { # PromQL -> the result as JSON
  python3 - "http://127.0.0.1:$PPORT" "$1" <<'PY'
import json, sys, urllib.parse, urllib.request
base, query = sys.argv[1], sys.argv[2]
r = json.load(urllib.request.urlopen(base + "/api/v1/query?" + urllib.parse.urlencode({"query": query}), timeout=60))
print(json.dumps(r["data"]["result"]))
PY
}
scalar() { q "$1" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["value"][1] if r else "none")'; }
UP="count(up{namespace=\"$NS\", buckets_cluster=\"mon\"} == 1)"
for _ in $(seq 60); do [[ $(scalar "$UP") == 13 ]] && break; sleep 10; done
expect "13 targets up: 4 servers x 3 endpoints, and the console" "$(scalar "$UP")" 13
expect "series labelled by scope" "$(q "count by (scope) (up{namespace=\"$NS\", buckets_cluster=\"mon\"})" | python3 -c '
import json,sys; print(sorted((r["metric"].get("scope","-"), r["value"][1]) for r in json.load(sys.stdin)))')" \
  "[('-', '1'), ('bucket', '4'), ('cluster', '4'), ('node', '4')]"
rules() { # how many of our rules Prometheus has loaded, and whether BucketsDriveOffline is one
  python3 - "http://127.0.0.1:$PPORT" "$NS" <<'PY'
import json, sys, urllib.request
r = json.load(urllib.request.urlopen(sys.argv[1] + "/api/v1/rules", timeout=60))
names = {rule["name"] for g in r["data"]["groups"] if sys.argv[2] in g["file"] for rule in g["rules"]}
print(len(names), "BucketsDriveOffline" in names)
PY
}
for _ in $(seq 30); do [[ $(rules) == "13 True" ]] && break; sleep 10; done
expect "the rules are loaded" "$(rules)" "13 True"

echo "== traffic, so the dashboards have something to show"
AK=$(k get secret mon-root -o jsonpath='{.data.rootUser}' | base64 -d)
SK=$(k get secret mon-root -o jsonpath='{.data.rootPassword}' | base64 -d)
k run traffic --restart=Never --image=amazon/aws-cli:2.22.35 ${AFF:+--overrides="{\"spec\":{\"affinity\":$AFF}}"} \
  --env AWS_ACCESS_KEY_ID="$AK" --env AWS_SECRET_ACCESS_KEY="$SK" --env AWS_DEFAULT_REGION=us-east-1 \
  --command -- sh -c "E=http://mon.$NS.svc:9000; aws --endpoint-url \$E s3 mb s3://dash >/dev/null;
    for i in \$(seq 1 40); do head -c 20000 /dev/urandom > /tmp/o; aws --endpoint-url \$E s3 cp --quiet /tmp/o s3://dash/o\$i; done;
    for i in \$(seq 1 20); do aws --endpoint-url \$E s3 cp --quiet s3://dash/o\$i /tmp/g; aws --endpoint-url \$E s3 cp --quiet s3://dash/missing\$i /tmp/g || true; done" >/dev/null
k wait --for=jsonpath='{.status.phase}'=Succeeded pod/traffic --timeout=600s >/dev/null || true
unset AK SK
sleep 90 # two scrapes, and a scanner cycle for the bucket usage

echo "== every dashboard query has data"
python3 - "http://127.0.0.1:$PPORT" "$NS" "$ROOT/operator/helm/buckets-operator/monitoring/dashboards" <<'PY' > "$WORK/dash.txt"
import glob, json, sys, urllib.parse, urllib.request
base, ns, ddir = sys.argv[1:4]
# with no KMS, no replication, nothing to heal and no failed console sign-ins, these legitimately have no series
optional = ("kms_request", "replication_", "heal_objects", "rejected_timestamp", "rejected_invalid", "usage_version_total", "quota_total")
empty, total = [], 0
def walk(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if k == "expr" and isinstance(x, str): yield x
            else: yield from walk(x)
    elif isinstance(v, list):
        for x in v: yield from walk(x)
for f in sorted(glob.glob(ddir + "/*.json")):
    for e in walk(json.load(open(f))):
        e = e.replace("$namespace", ns).replace("$cluster", "mon")
        total += 1
        r = json.load(urllib.request.urlopen(base + "/api/v1/query?" + urllib.parse.urlencode({"query": e}), timeout=60))
        if r["status"] != "success": empty.append(("error", f.split("/")[-1], e)); continue
        if not r["data"]["result"] and not any(o in e for o in optional): empty.append(("empty", f.split("/")[-1], e))
print(total)
for x in empty: print(*x)
PY
expect "dashboard queries with data (of $(head -1 "$WORK/dash.txt"))" "$(tail -n +2 "$WORK/dash.txt" | wc -l | tr -d ' ')" 0
tail -n +2 "$WORK/dash.txt" | sed 's/^/     /'

echo "== a failing drive raises BucketsDriveOffline"
POD=mon-pool-0-1
debug() { # name command: as the server's user, in the server's process namespace
  kc -n "$NS" debug "$POD" --image=busybox:1.36 --target=bucketsd -c "$1" --profile=restricted \
    --custom=<(echo '{"securityContext":{"runAsUser":65532,"runAsGroup":65532,"runAsNonRoot":true}}') -- sh -c "$2" >/dev/null
  for _ in $(seq 60); do
    [[ $(k get pod "$POD" -o jsonpath="{.status.ephemeralContainerStatuses[?(@.name==\"$1\")].state.terminated.reason}") == Completed ]] && return 0
    sleep 2
  done
  return 1
}
debug drivefail 'chmod 555 /proc/1/root/data0/.minio.sys/tmp'
OFF="max(minio_cluster_drive_offline_total{namespace=\"$NS\", buckets_cluster=\"mon\", scope=\"cluster\"})"
for _ in $(seq 30); do [[ $(scalar "$OFF") == 1 ]] && break; sleep 10; done
expect "the metrics see it offline" "$(scalar "$OFF")" 1
FIRING="ALERTS{alertname=\"BucketsDriveOffline\", namespace=\"$NS\", buckets_cluster=\"mon\", alertstate=\"firing\"}"
start=$(date +%s)
for _ in $(seq 60); do [[ $(scalar "$FIRING") == 1 ]] && break; sleep 10; done
expect "BucketsDriveOffline fires" "$(scalar "$FIRING")" 1
echo "     after $(($(date +%s) - start))s (the rule waits 5 minutes)"
debug drivefix 'chmod 755 /proc/1/root/data0/.minio.sys/tmp'
for _ in $(seq 60); do [[ $(scalar "$FIRING") == none && $(scalar "$OFF") == 0 ]] && break; sleep 10; done
expect "and clears once the drive works again" "$(scalar "$FIRING") $(scalar "$OFF")" "none 0"

echo "monitoring: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
