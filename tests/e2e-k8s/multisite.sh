#!/usr/bin/env bash
# Two Buckets clusters and a MinIO site on one kind cluster, each in its own
# namespace and reached by Service DNS, as separate sites would be:
#  - bucket replication, active-active between Buckets and MinIO: new
#    objects both ways, multipart, delete markers, existing objects (resync);
#  - three-site site replication (Buckets, MinIO, Buckets) set up from a
#    Buckets site: the initial sync, then buckets, objects, bucket metadata
#    and IAM changed on any site reaching the others;
#  - a decommission on a multi-server Buckets site: a pool is added and
#    the first retired, started and followed through servers that forward
#    to the pool's owner, with data kept and still replicating.
# Needs docker, kind, kubectl, and linux builds of MinIO and mc for the
# node's architecture (MINIO_LINUX, MC_LINUX; tests/e2e-k8s/README.md).
#   tests/e2e-k8s/multisite.sh       (KEEP_CLUSTER=1 leaves the cluster up)
set -euo pipefail
source "$(dirname "$0")/lib.sh"
MINIO_LINUX=${MINIO_LINUX:-${TMPDIR:-/tmp}/buckets-tools/linux/minio}
MC_LINUX=${MC_LINUX:-${TMPDIR:-/tmp}/buckets-tools/linux/mc}
for b in "$MINIO_LINUX" "$MC_LINUX"; do [[ -x $b ]] || { echo "multisite: skipped (no $b)"; exit 0; }; done
cleanup() { [[ -n "${KEEP_CLUSTER:-}" ]] || kind delete cluster --name "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
NS=ms
USR=rootadmin
PW=rootsecret123
KMS="e2e-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
url() { # site -> its S3 endpoint inside the cluster
  case $1 in
  a) echo http://a.ms-a.svc.cluster.local:9000 ;;
  b) echo http://b.ms-b.svc.cluster.local:9000 ;;
  m) echo http://m.ms-m.svc.cluster.local:9000 ;;
  esac
}

TOOLS_BINS="$MINIO_LINUX $MC_LINUX" setup_cluster
kubectl delete ns ms ms-a ms-b ms-m --ignore-not-found >/dev/null # a kept cluster's last run
start_cli $NS
# in the client pod: mc, a shell, and "mc stat --json <path> | jq -r <expr>"
mc() { kubectl -n $NS exec cli -- mc "$@"; }
sh_() { kubectl -n $NS exec cli -- sh -c "$@"; }
statj() { kubectl -n $NS exec cli -- sh -c 'mc stat --json "$1" | jq -r "$2"' _ "$1" "$2"; }
versions() { kubectl -n $NS exec cli -- sh -c 'mc ls --versions --json "$1" | jq -r ".versionId"' _ "$1"; }
cat_() { mc cat "$1" 2>/dev/null; }
has() { mc stat "$1" >/dev/null 2>&1 && echo yes || echo no; }

echo "== sites"
for s in a b; do
  kubectl create ns ms-$s >/dev/null 2>&1 || true
  kubectl -n ms-$s create secret generic root --from-literal=rootUser=$USR --from-literal=rootPassword=$PW \
    >/dev/null 2>&1 || true
  kubectl -n ms-$s apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: $s}
spec:
  image: buckets/bucketsd:e2e
  credsSecret: {name: root}
  env:
    - {name: MINIO_KMS_SECRET_KEY, value: "$KMS"}
    - {name: BUCKETS_REPLICATION_MRF_DELAY_MS, value: "500"}
    - {name: BUCKETS_SITE_REPLICATION_HEAL_INTERVAL, value: "5"}
  pools:
    - servers: 2
      volumesPerServer: 2
      volumeClaimTemplate: {resources: {requests: {storage: 1Gi}}}
YAML
done
kubectl create ns ms-m >/dev/null 2>&1 || true
kubectl -n ms-m apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: m}
spec:
  replicas: 1
  selector: {matchLabels: {app: m}}
  template:
    metadata: {labels: {app: m}}
    spec:
      containers:
        - name: minio
          image: buckets/e2e-tools:e2e
          imagePullPolicy: Never
          command: [minio, server, --quiet, --address, ":9000", "/data/d{1...4}"]
          env:
            - {name: MINIO_ROOT_USER, value: $USR}
            - {name: MINIO_ROOT_PASSWORD, value: $PW}
            - {name: MINIO_KMS_SECRET_KEY, value: "$KMS"}
            - {name: MINIO_CI_CD, value: "on"}
            - {name: MINIO_BROWSER, value: "off"}
          ports: [{containerPort: 9000}]
          readinessProbe: {httpGet: {path: /minio/health/ready, port: 9000}, periodSeconds: 2}
          volumeMounts: [{name: data, mountPath: /data}]
      volumes: [{name: data, emptyDir: {}}]
---
apiVersion: v1
kind: Service
metadata: {name: m}
spec:
  selector: {app: m}
  ports: [{port: 9000, targetPort: 9000}]
YAML
wait_bc ms-a a
wait_bc ms-b b
kubectl -n ms-m rollout status deploy/m --timeout=180s >/dev/null
for s in a b m; do mc alias set $s "$(url $s)" $USR $PW >/dev/null; done
expect "three sites up" "$(for s in a b m; do mc ready $s >/dev/null 2>&1 && echo -n $s; done)" abm

echo "== bucket replication, Buckets <-> MinIO (active-active)"
mc mb a/rrb m/rrb >/dev/null
mc version enable a/rrb >/dev/null
mc version enable m/rrb >/dev/null
sh_ 'echo existing | mc pipe a/rrb/existing' >/dev/null
for pair in "a m" "m a"; do
  set -- $pair
  remote="http://$USR:$PW@$(url $2 | sed 's|^http://||')/rrb"
  expect "replicate add $1 -> $2" "$(mc replicate add $1/rrb --remote-bucket "$remote" --priority 1 \
    --replicate delete,delete-marker,existing-objects 2>&1)" \
    "Replication configuration rule applied to $1/rrb successfully."
done
sh_ 'echo from-a | mc pipe --attr x-amz-meta-color=blue a/rrb/fa' >/dev/null
sh_ 'head -c 20000000 /dev/urandom >/tmp/big && mc cp /tmp/big m/rrb/big' >/dev/null
BIG=$(sh_ 'md5sum </tmp/big | cut -d" " -f1')
eventually "a's object on MinIO" from-a 30 cat_ m/rrb/fa
eventually "MinIO's multipart object on a" "$BIG" 30 sh_ 'mc cat a/rrb/big | md5sum | cut -d" " -f1'
expect "same version on MinIO" "$(statj m/rrb/fa .versionID)" "$(statj a/rrb/fa .versionID)"
expect "same ETag on a" "$(statj a/rrb/big .etag)" "$(statj m/rrb/big .etag)"
expect "metadata kept" "$(statj m/rrb/fa '.metadata["X-Amz-Meta-Color"]')" blue
expect "replica on MinIO" "$(statj m/rrb/fa .replicationStatus)" REPLICA
expect "replica on a" "$(statj a/rrb/big .replicationStatus)" REPLICA
sleep 2 # no ping-pong: still one version on each side
expect "one version of fa on a" "$(versions a/rrb/fa | wc -l | tr -d ' ')" 1
expect "one version of big on MinIO" "$(versions m/rrb/big | wc -l | tr -d ' ')" 1
mc rm m/rrb/fa >/dev/null
marker() { kubectl -n $NS exec cli -- sh -c 'mc ls --versions --json "$1" | jq -r "select(.isDeleteMarker) | .versionId"' _ "$1"; }
eventually "MinIO's delete marker on a" "$(marker m/rrb/fa)" 30 marker a/rrb/fa
ARN=$(kubectl -n $NS exec cli -- sh -c 'mc replicate ls a/rrb --json | jq -r .rule.Destination.Bucket')
mc replicate resync start a/rrb --remote-bucket "$ARN" >/dev/null 2>&1 || true
eventually "existing object reaches MinIO (resync)" existing 30 cat_ m/rrb/existing
expect "existing object keeps its version" "$(statj m/rrb/existing .versionID)" "$(statj a/rrb/existing .versionID)"

# Site replication wants the joining sites empty: the buckets go.
for s in a m; do
  mc replicate rm --all --force $s/rrb >/dev/null 2>&1 || true
  mc rb --force $s/rrb >/dev/null 2>&1 || true
done
expect "buckets removed" "$(mc ls a m 2>/dev/null | wc -l | tr -d ' ')" 0

echo "== three-site site replication (Buckets, MinIO, Buckets)"
mc mb a/pre >/dev/null
sh_ 'echo before | mc pipe a/pre/obj' >/dev/null
sh_ 'printf %s "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::pre/*\"]}]}" >/tmp/p1.json'
mc admin policy create a p1 /tmp/p1.json >/dev/null
mc admin user add a e2euser1 user1secret123 >/dev/null
mc admin policy attach a p1 --user e2euser1 >/dev/null
out=$(mc admin replicate add a m b 2>&1 || true)
expect "replicate add" "$(grep -c 'successfully' <<<"$out")" 1
expect "three sites in the group" "$(kubectl -n $NS exec cli -- sh -c 'mc admin replicate info a --json | jq ".sites | length"')" 3
for s in m b; do
  eventually "initial sync: bucket on $s" yes 30 sh_ "mc ls $s | grep -q ' pre/\$' && echo yes"
  eventually "initial sync: policy on $s" p1 30 sh_ "mc admin policy info $s p1 --json | jq -r .policy"
  eventually "initial sync: user's policy on $s" p1 30 sh_ "mc admin user info $s e2euser1 --json | jq -r .policyName"
done
# objects from before the join follow by the scanner's replication heal
for s in m b; do eventually "initial sync: object on $s" before 150 cat_ $s/pre/obj; done
mc mb m/from-m >/dev/null
for s in a b; do eventually "bucket made on MinIO reaches $s" yes 30 sh_ "mc ls $s | grep -q ' from-m/\$' && echo yes"; done
sh_ 'echo from-b | mc pipe b/from-m/obj' >/dev/null
for s in a m; do eventually "object put on b reaches $s" from-b 30 cat_ $s/from-m/obj; done
expect "same version everywhere" "$(statj a/from-m/obj .versionID)$(statj m/from-m/obj .versionID)" \
  "$(statj b/from-m/obj .versionID)$(statj b/from-m/obj .versionID)"
mc admin user add m e2euser2 user2secret123 >/dev/null
for s in a b; do eventually "user made on MinIO reaches $s" enabled 30 sh_ "mc admin user info $s e2euser2 --json | jq -r .userStatus"; done
mc admin policy create b p2 /tmp/p1.json >/dev/null
for s in a m; do eventually "policy made on b reaches $s" p2 30 sh_ "mc admin policy info $s p2 --json | jq -r .policy"; done
mc tag set a/pre "team=e2e" >/dev/null
for s in m b; do eventually "bucket tags set on a reach $s" e2e 30 sh_ "mc tag list $s/pre --json | jq -r .tagset.team"; done
mc admin user remove b e2euser1 >/dev/null
for s in a m; do eventually "user removed on b is gone from $s" gone 30 sh_ "mc admin user info $s e2euser1 >/dev/null 2>&1 && echo there || echo gone"; done

echo "== decommission on a multi-server site"
for i in 1 2 3 4 5; do sh_ "echo obj$i | mc pipe a/pre/o$i" >/dev/null; done
kubectl -n ms-a patch bc a --type=json \
  -p '[{"op":"add","path":"/spec/pools/-","value":{"name":"more","servers":2,"volumesPerServer":2,"volumeClaimTemplate":{"resources":{"requests":{"storage":"1Gi"}}}}}]' >/dev/null
sleep 10
wait_bc ms-a a
expect "four servers" "$(kubectl -n ms-a get bc a -o jsonpath='{.status.readyServersText}')" 4/4
eventually "both pools listed" 2 10 sh_ "mc admin decommission status a --json | jq length"
P0=$(sh_ 'mc admin decommission status a --json | jq -r ".[0].cmdline"')
expect "the first pool is named by its argument" "${P0:0:17}" "http://a-pool-0-{"
# The first pool's first server runs the decommission: the request goes to
# a server of the new pool, and status to another of the old, so both are
# forwarded to it.
mc alias set a-more-1 http://a-more-1.a-hl.ms-a.svc.cluster.local:9000 $USR $PW >/dev/null
mc alias set a-pool-0-1 http://a-pool-0-1.a-hl.ms-a.svc.cluster.local:9000 $USR $PW >/dev/null
expect "start (forwarded)" "$(mc admin decommission start a-more-1 "$P0" 2>&1)" "Decommission started successfully for \`$P0\`."
state() { kubectl -n $NS exec cli -- sh -c 'mc admin decommission status a-pool-0-1 "$1" --json |
  jq -r ".decommissionInfo | if .complete then \"complete\" elif .failed then \"failed\" elif .canceled then \"canceled\" else \"running\" end"' _ "$P0"; }
eventually "decommission completes" complete 150 state
for i in 1 2 3 4 5; do got=$(cat_ a/pre/o$i); [[ $got == obj$i ]] || break; done
expect "objects readable after the decommission" "$got" obj5
expect "site-replicated object still there" "$(cat_ a/from-m/obj)" from-b
sh_ 'echo after | mc pipe a/pre/after' >/dev/null
for s in m b; do eventually "a new object still replicates to $s" after 30 cat_ $s/pre/after; done

finish
