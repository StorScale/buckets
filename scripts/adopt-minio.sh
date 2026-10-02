#!/usr/bin/env bash
# Hands a MinIO tenant's volumes to a BucketsCluster, in place: the same
# StatefulSet, Service and PVC names, the same drives, no data copied.
#
#   scripts/adopt-minio.sh -n <namespace> -t <tenant> [--context <ctx>] [--state <dir>] [--apply]
#     [--image <bucketsd image>] [--configuration <secret>] [--tls <secret>]
#
# The tenant is a MinIO Operator Tenant (tenants.minio.min.io) or, without the
# MinIO Operator, StatefulSets <tenant>-<pool> laid out the way it lays them
# out (MINIO_VOLUMES in their environment or config.env). Without --apply it
# only checks and prints the plan and the BucketsCluster it would create.
# With --apply it:
#   1. saves the tenant's objects in --state (for scripts/rollback-to-minio.sh)
#   2. sets every drive's PersistentVolume to Retain, so no step can lose data
#   3. stops MinIO: deletes the Tenant (or its StatefulSets and Services);
#      the PVCs stay, and are never deleted by this script
#   4. creates the BucketsCluster and waits for it to be Ready
# A BucketsCluster operator must be watching the namespace. Reads go on while
# MinIO stops and Buckets starts: plan a short outage.
set -euo pipefail

NS= TENANT= CTX= STATE= APPLY= TIMEOUT=900
BUCKETS_IMAGE=${BUCKETS_IMAGE:-} CONFIG_SECRET= TLS_SECRET=
while [[ $# -gt 0 ]]; do
  case $1 in
    -n) NS=$2; shift 2 ;;
    -t) TENANT=$2; shift 2 ;;
    --context) CTX=$2; shift 2 ;;
    --state) STATE=$2; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --image) BUCKETS_IMAGE=$2; shift 2 ;;
    --configuration) CONFIG_SECRET=$2; shift 2 ;;
    --tls) TLS_SECRET=$2; shift 2 ;;
    --timeout) TIMEOUT=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n $NS && -n $TENANT ]] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 2; }
STATE=${STATE:-adopt-$NS-$TENANT}
k() { kubectl ${CTX:+--context "$CTX"} -n "$NS" "$@"; }
kc() { kubectl ${CTX:+--context "$CTX"} "$@"; }
die() { echo "adopt-minio: $*" >&2; exit 1; }
say() { echo "== $*"; }

# ---- what is there --------------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
k get tenants.minio.min.io "$TENANT" -o json > "$WORK/tenant.json" 2>/dev/null || : > "$WORK/tenant.json"
k get statefulsets -o json > "$WORK/sts.json"
k get services -o json > "$WORK/svc.json"
k get persistentvolumeclaims -o json > "$WORK/pvc.json"
[[ -n $(k get bucketsclusters "$TENANT" -o name 2>/dev/null || true) ]] && die "a BucketsCluster $TENANT already exists in $NS"

export TENANT NS BUCKETS_IMAGE CONFIG_SECRET TLS_SECRET WORK
python3 - > "$WORK/plan.json" <<'PY'
import json, os, re, sys

tenant, ns = os.environ["TENANT"], os.environ["NS"]
def load(name):
    with open(os.path.join(os.environ["WORK"], name)) as f:
        text = f.read()
    return json.loads(text) if text.strip() else None
tj = load("tenant.json")
sts_all = load("sts.json")["items"]
pvcs = {p["metadata"]["name"]: p for p in load("pvc.json")["items"]}
svcs = {v["metadata"]["name"]: v for v in load("svc.json")["items"]}

def secret_at(tmpl, container, path):
    """The Secret a container sees at path (a file or a directory under a mount)."""
    for m in container.get("volumeMounts", []):
        mp = m["mountPath"].rstrip("/")
        if path == mp or path.startswith(mp + "/"):
            v = next((v for v in tmpl.get("volumes", []) if v["name"] == m["name"]), {})
            if (v.get("secret") or {}).get("secretName"):
                return v["secret"]["secretName"]
            for src in (v.get("projected") or {}).get("sources", []):
                if "secret" in src:
                    return src["secret"]["name"]
    return None
problems, notes = [], []

# The tenant's pools: from the Tenant, else from its StatefulSets.
sts = sorted((s for s in sts_all if s["metadata"]["name"].startswith(tenant + "-")
              and any(re.fullmatch(r"data\d+", t["metadata"]["name"]) for t in s["spec"].get("volumeClaimTemplates", []))),
             key=lambda s: s["metadata"]["name"])
if tj:
    tspec = tj["spec"]
    pools = [(p["name"], p["servers"], p["volumesPerServer"], p) for p in tspec["pools"]]
    mount_path, sub_path = tspec.get("mountPath", "/export"), tspec.get("subPath", "")
    tls = (tspec.get("externalCertSecret") or [{}])[0].get("name")
    config = (tspec.get("configuration") or {}).get("name")
    sc = pools[0][3].get("securityContext") or {}
    if tspec.get("requestAutoCert", True) and not tls:
        problems.append("the tenant uses the MinIO Operator's automatic certificate; give it an externalCertSecret first")
    if tspec.get("kes"):
        problems.append("the tenant encrypts with KES, which this script does not carry over yet: without it "
                        "Buckets cannot read encrypted objects (see docs/migration.md)")
    if (tspec.get("features") or {}).get("bucketDNS"):
        notes.append("bucket DNS (MINIO_DNS_WEBHOOK_ENDPOINT) is not carried over")
    source = "Tenant"
else:
    if not sts:
        print(json.dumps({"problems": [f"no Tenant {tenant} and no StatefulSets {tenant}-<pool> with data<n> claims in {ns}"]}))
        sys.exit(0)
    pools, mount_path, sub_path, tls, config, sc = [], None, "", None, None, {}
    for s in sts:
        tmpl = s["spec"]["template"]["spec"]
        c = tmpl["containers"][0]
        env = {e["name"]: e.get("value", "") for e in c.get("env", [])}
        vols = env.get("MINIO_VOLUMES", "")
        m = re.search(r"\.svc\.[^/]+:\d+(/[^{ ]*)\{0\.\.\.\d+\}(\S*)", vols)
        if not m:
            problems.append(f"{s['metadata']['name']}: no MINIO_VOLUMES with drive ellipses in its environment")
            continue
        mount_path, sub_path = m.group(1), m.group(2)
        nvol = len([t for t in s["spec"]["volumeClaimTemplates"] if re.fullmatch(r"data\d+", t["metadata"]["name"])])
        pools.append((s["metadata"]["name"][len(tenant) + 1:], s["spec"]["replicas"], nvol, s))
        sc = tmpl.get("securityContext") or {}
        # where MinIO reads them: MINIO_CONFIG_ENV_FILE and --certs-dir
        if env.get("MINIO_CONFIG_ENV_FILE"):
            config = config or secret_at(tmpl, c, env["MINIO_CONFIG_ENV_FILE"])
        args = c.get("args", [])
        if "--certs-dir" in args[:-1]:
            tls = tls or secret_at(tmpl, c, args[args.index("--certs-dir") + 1])
    source = "StatefulSets"

# The drives: every PVC there, not owned by what will be deleted, and its PV.
claims = []
for pname, servers, nvol, _ in pools:
    for i in range(servers):
        for d in range(nvol):
            n = f"data{d}-{tenant}-{pname}-{i}"
            p = pvcs.get(n)
            if not p:
                problems.append(f"PVC {n} is missing")
                continue
            if p.get("status", {}).get("phase") != "Bound":
                problems.append(f"PVC {n} is not Bound")
            for o in p["metadata"].get("ownerReferences", []):
                problems.append(f"PVC {n} is owned by {o['kind']} {o['name']}: deleting it would delete the data")
            claims.append({"pvc": n, "pv": p["spec"].get("volumeName")})

config = os.environ.get("CONFIG_SECRET") or config
tls = os.environ.get("TLS_SECRET") or tls
if not config:
    problems.append("no configuration Secret (config.env with the root credentials) found; name it with --configuration")
# the S3 Service's port as clients know it
svc = svcs.get(tenant)
port = (svc["spec"]["ports"][0]["port"] if svc else None) or (443 if tls else 80)
bc = {"apiVersion": "buckets.io/v1alpha1", "kind": "BucketsCluster",
      "metadata": {"name": tenant, "namespace": ns,
                   "annotations": {"buckets.io/adopted-from": f"{source} {tenant}"}},
      "spec": {"configuration": {"name": config},
               "drives": {"mountPath": mount_path or "/export", **({"subPath": sub_path} if sub_path else {})},
               "securityContext": {k: sc[k] for k in ("runAsUser", "runAsGroup", "fsGroup") if k in sc},
               "servicePort": port,
               "pools": []}}
if os.environ.get("BUCKETS_IMAGE"):
    bc["spec"]["image"] = os.environ["BUCKETS_IMAGE"]
if tls:
    bc["spec"]["tls"] = {"certSecret": {"name": tls}}
for pname, servers, nvol, src in pools:
    pool = {"name": pname, "servers": servers, "volumesPerServer": nvol}
    tmpl = (src.get("volumeClaimTemplate") or {}).get("spec") if source == "Tenant" else \
        next((t["spec"] for t in src["spec"]["volumeClaimTemplates"] if t["metadata"]["name"] == "data0"), None)
    if tmpl:
        pool["volumeClaimTemplate"] = {k: v for k, v in tmpl.items() if k in ("storageClassName", "resources", "accessModes")}
    # where the pool's pods may run, as MinIO's did
    sched = src if source == "Tenant" else src["spec"]["template"]["spec"]
    for key in ("nodeSelector", "tolerations", "affinity"):
        if sched.get(key):
            pool[key] = sched[key]
    bc["spec"]["pools"].append(pool)
print(json.dumps({"source": source, "pools": [(p[0], p[1], p[2]) for p in pools], "claims": claims,
                  "pods": [f"{tenant}-{p[0]}-{i}" for p in pools for i in range(p[1])],
                  "problems": problems, "notes": notes, "bucketscluster": bc,
                  "statefulsets": [s["metadata"]["name"] for s in sts]}))
PY
field() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($1)" "$WORK/plan.json"; }

say "MinIO tenant $NS/$TENANT ($(field 'd.get("source","?")'))"
field '"\n".join(f"   pool {p}: {s} servers x {v} drives" for p,s,v in d.get("pools",[]))'
# PVs and their reclaim policies
PVS=$(field '" ".join(c["pv"] for c in d.get("claims",[]))')
declare -A RECLAIM=()
for pv in $PVS; do RECLAIM[$pv]=$(kc get pv "$pv" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'); done
deleting=0; for pv in $PVS; do [[ ${RECLAIM[$pv]} == Retain ]] || deleting=$((deleting + 1)); done
echo "   drives: $(wc -w <<<"$PVS") PVCs; $deleting of their PVs would be deleted with their PVC (set to Retain first)"
problems=$(field '"\n".join(d.get("problems",[]))')
notes=$(field '"\n".join(d.get("notes",[]))')
[[ -n $notes ]] && { say "notes"; sed 's/^/   /' <<<"$notes"; }
if [[ -n $problems ]]; then say "cannot adopt"; sed 's/^/   /' <<<"$problems"; exit 1; fi

say "the BucketsCluster"
field 'json.dumps(d["bucketscluster"], indent=2)' | sed 's/^/   /'
if [[ -z $APPLY ]]; then echo; echo "dry run: nothing changed. Run again with --apply to adopt."; exit 0; fi

# ---- 1. save what rollback needs ------------------------------------------
say "1/4 saving the tenant to $STATE"
mkdir -p "$STATE"
[[ -e $STATE/done ]] && die "$STATE already holds an adoption; use another --state"
field 'json.dumps(d, indent=2)' > "$STATE/plan.json"
for pv in $PVS; do echo "$pv ${RECLAIM[$pv]}"; done > "$STATE/reclaim.txt"
if [[ $(field 'd["source"]') == Tenant ]]; then
  k get tenants.minio.min.io "$TENANT" -o json > "$STATE/tenant.json"
else
  k get sts -o json | python3 -c "
import json,sys; names=sys.argv[1].split()
items=[s for s in json.load(sys.stdin)['items'] if s['metadata']['name'] in names]
print(json.dumps({'apiVersion':'v1','kind':'List','items':items}))" "$(field '" ".join(d["statefulsets"])')" > "$STATE/statefulsets.json"
  k get services -o json | python3 -c "
import json,sys; t=sys.argv[1]
items=[s for s in json.load(sys.stdin)['items'] if s['metadata']['name'] in (t, t+'-hl', t+'-console')]
print(json.dumps({'apiVersion':'v1','kind':'List','items':items}))" "$TENANT" > "$STATE/services.json"
fi

# ---- 2. no step may lose data ---------------------------------------------
say "2/4 setting the drives' PersistentVolumes to Retain"
for pv in $PVS; do
  [[ ${RECLAIM[$pv]} == Retain ]] || kc patch pv "$pv" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null
done
for pv in $PVS; do
  [[ $(kc get pv "$pv" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}') == Retain ]] || die "PV $pv is not Retain"
done

# ---- 3. stop MinIO, keep the PVCs ------------------------------------------
say "3/4 stopping MinIO (the PVCs stay)"
if [[ $(field 'd["source"]') == Tenant ]]; then
  k delete tenants.minio.min.io "$TENANT" --wait=true >/dev/null
fi
for s in $(field '" ".join(d["statefulsets"])'); do k delete sts "$s" --ignore-not-found --wait=true >/dev/null; done
for svc in "$TENANT" "$TENANT-hl" "$TENANT-console"; do k delete svc "$svc" --ignore-not-found >/dev/null; done
PODS=$(field '" ".join(d["pods"])')
running() { for p in $PODS; do k get pod "$p" -o name 2>/dev/null; done; }
for _ in $(seq 150); do [[ -z $(running) ]] && break; sleep 2; done
[[ -z $(running) ]] || die "MinIO pods are still running: $(running | tr '\n' ' ')"
for c in $(field '" ".join(c["pvc"] for c in d["claims"])'); do k get pvc "$c" -o name >/dev/null || die "PVC $c is gone"; done
touch "$STATE/stopped"

# ---- 4. Buckets on the same drives -----------------------------------------
say "4/4 creating the BucketsCluster"
field 'json.dumps(d["bucketscluster"])' | k apply -f - >/dev/null
k wait --for=jsonpath='{.status.phase}'=Ready "bc/$TENANT" --timeout="${TIMEOUT}s" >/dev/null || {
  echo "not Ready after ${TIMEOUT}s; the drives are untouched. Look at:"
  echo "  kubectl -n $NS get bc,pods; kubectl -n $NS logs $TENANT-<pool>-0"
  echo "or roll back: scripts/rollback-to-minio.sh -n $NS -t $TENANT --state $STATE --apply"
  exit 1
}
touch "$STATE/done"
say "adopted: $NS/$TENANT runs on Buckets ($(k get bc "$TENANT" -o jsonpath='{.status.readyServersText}') servers)"
echo "   rollback: scripts/rollback-to-minio.sh -n $NS -t $TENANT --state $STATE --apply"
