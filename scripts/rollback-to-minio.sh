#!/usr/bin/env bash
# Hands a tenant adopted with scripts/adopt-minio.sh back to MinIO, on the
# same drives: deletes the BucketsCluster (its PVCs stay: they are not owned
# by it) and restores the Tenant, or the StatefulSets and Services, saved in
# the adoption's state directory.
#
#   scripts/rollback-to-minio.sh -n <namespace> -t <tenant> --state <dir> [--context <ctx>] [--apply]
#     [--restore-reclaim]
#
# The drives' PersistentVolumes stay Retain unless --restore-reclaim puts back
# the policies they had before the adoption. Without --apply it only checks.
set -euo pipefail

NS= TENANT= CTX= STATE= APPLY= RESTORE= TIMEOUT=900
while [[ $# -gt 0 ]]; do
  case $1 in
    -n) NS=$2; shift 2 ;;
    -t) TENANT=$2; shift 2 ;;
    --context) CTX=$2; shift 2 ;;
    --state) STATE=$2; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --restore-reclaim) RESTORE=1; shift ;;
    --timeout) TIMEOUT=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n $NS && -n $TENANT && -n $STATE ]] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 2; }
k() { kubectl ${CTX:+--context "$CTX"} -n "$NS" "$@"; }
kc() { kubectl ${CTX:+--context "$CTX"} "$@"; }
die() { echo "rollback-to-minio: $*" >&2; exit 1; }
say() { echo "== $*"; }

[[ -f $STATE/plan.json && -f $STATE/stopped ]] || die "$STATE holds no adoption (plan.json and stopped are written by adopt-minio.sh --apply)"
field() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($1)" "$STATE/plan.json"; }
CLAIMS=$(field '" ".join(c["pvc"] for c in d["claims"])')
PODS=$(field '" ".join(d["pods"])')
for c in $CLAIMS; do k get pvc "$c" -o name >/dev/null 2>&1 || die "PVC $c is missing: do not roll back, investigate first"; done
if [[ -f $STATE/tenant.json ]]; then SAVED="the Tenant"; else SAVED="the StatefulSets and Services"; fi
say "rolling $NS/$TENANT back to MinIO: delete the BucketsCluster, restore $SAVED from $STATE"
echo "   drives: $(wc -w <<<"$CLAIMS") PVCs, all present"
if [[ -z $APPLY ]]; then echo; echo "dry run: nothing changed. Run again with --apply to roll back."; exit 0; fi

# ---- 1. stop Buckets, keep the PVCs ------------------------------------------
say "1/3 deleting the BucketsCluster (the PVCs stay)"
k delete bc "$TENANT" --ignore-not-found --wait=true >/dev/null
running() { for p in $PODS; do k get pod "$p" -o name 2>/dev/null; done; }
for _ in $(seq 150); do [[ -z $(running) ]] && break; sleep 2; done
[[ -z $(running) ]] || die "Buckets pods are still running: $(running | tr '\n' ' ')"
for c in $CLAIMS; do k get pvc "$c" -o name >/dev/null || die "PVC $c is gone"; done
# a carried-over KES: its settings (credentials) and config.env's copy go too; the
# tenant's own KES comes back with it, its keys never moved
for s in "$TENANT-kms" "$TENANT-kms-candidate" "$TENANT-buckets-config"; do
  [[ $(k get secret "$s" -o jsonpath='{.metadata.labels.buckets\.io/cluster}' 2>/dev/null) == "$TENANT" ]] &&
    k delete secret "$s" >/dev/null
done

# ---- 2. MinIO back on the same drives ----------------------------------------
say "2/3 restoring $SAVED"
clean() { # drops what the API server owns, so the objects can be created again
  python3 -c '
import json, sys
d = json.load(sys.stdin)
for o in d.get("items", [d]):
    m = o.get("metadata", {})
    for key in ("uid", "resourceVersion", "creationTimestamp", "generation", "managedFields", "ownerReferences"):
        m.pop(key, None)
    (m.get("annotations") or {}).pop("kubectl.kubernetes.io/last-applied-configuration", None)
    o.pop("status", None)
    spec = o.get("spec", {})
    if o.get("kind") == "Service":
        for key in ("clusterIP", "clusterIPs"):
            if spec.get(key) != "None":
                spec.pop(key, None)
print(json.dumps(d))'
}
if [[ -f $STATE/tenant.json ]]; then
  clean < "$STATE/tenant.json" | k create -f - >/dev/null
else
  clean < "$STATE/services.json" | k create -f - >/dev/null
  clean < "$STATE/statefulsets.json" | k create -f - >/dev/null
fi
for p in $PODS; do
  k wait --for=condition=Ready "pod/$p" --timeout="${TIMEOUT}s" >/dev/null 2>&1 || {
    for _ in $(seq 60); do k get pod "$p" -o name >/dev/null 2>&1 && break; sleep 2; done
    k wait --for=condition=Ready "pod/$p" --timeout="${TIMEOUT}s" >/dev/null || die "MinIO pod $p is not Ready"
  }
done

# ---- 3. reclaim policies -------------------------------------------------------
if [[ -n $RESTORE ]]; then
  say "3/3 restoring the PersistentVolumes' reclaim policies"
  while read -r pv policy; do
    kc patch pv "$pv" -p "{\"spec\":{\"persistentVolumeReclaimPolicy\":\"$policy\"}}" >/dev/null
  done < "$STATE/reclaim.txt"
else
  say "3/3 the PersistentVolumes stay Retain (--restore-reclaim puts back $(awk '{print $2}' "$STATE/reclaim.txt" | sort | uniq -c | tr -s ' ' | sed 's/^ //' | paste -sd, -))"
fi
mv "$STATE/stopped" "$STATE/rolled-back"
rm -f "$STATE/done"
say "rolled back: $NS/$TENANT runs on MinIO again ($(wc -w <<<"$PODS") pods Ready)"
