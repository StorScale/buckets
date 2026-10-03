#!/usr/bin/env bash
# Hands a MinIO tenant's volumes to a BucketsCluster, in place: the same
# StatefulSet, Service and PVC names, the same drives, no data copied.
#
#   scripts/adopt-minio.sh -n <namespace> -t <tenant> [--context <ctx>] [--state <dir>] [--apply]
#     [--image <bucketsd image>] [--configuration <secret>] [--tls <secret>]
#     [--kes-image <buckets-kes image>] [--check-kes]
#
# The tenant is a MinIO Operator Tenant (tenants.minio.min.io) or, without the
# MinIO Operator, StatefulSets <tenant>-<pool> laid out the way it lays them
# out (MINIO_VOLUMES in their environment or config.env). Without --apply it
# only checks and prints the plan and the BucketsCluster it would create.
# With --apply it:
#   1. with KES: has buckets-kes read the tenant's default key, using the
#      tenant's own KES configuration, in a one-off pod (stops here if it cannot)
#   2. saves the tenant's objects in --state (for scripts/rollback-to-minio.sh)
#   3. sets every drive's PersistentVolume to Retain, so no step can lose data
#   4. stops MinIO: deletes the Tenant (or its StatefulSets and Services);
#      the PVCs stay, and are never deleted by this script
#   5. creates the BucketsCluster and waits for it to be Ready
# KES: a tenant that encrypts with KES (spec.kes, or a <tenant>-kes StatefulSet
# beside MINIO_KMS_KES_* settings) keeps its keys where they are. Where they are
# and how to sign in become Secret <tenant>-kms; spec.kms.kes names the default
# key (never created: a missing key means the settings point elsewhere), KES's
# account and where its pods run; the servers start once buckets-kes serves the
# key. --kes-image is the buckets-kes image, set in spec.kms.kes.image (default:
# the operator's BUCKETS_KES_IMAGE, not set in the spec); --check-kes runs step 1 in a dry run too (a pod, nothing
# else changes). The tenant's own KES StatefulSet is left as it is (a deleted
# Tenant takes it along; rollback brings it back).
# A BucketsCluster operator must be watching the namespace. Reads go on while
# MinIO stops and Buckets starts: plan a short outage.
set -euo pipefail

NS= TENANT= CTX= STATE= APPLY= TIMEOUT=900
BUCKETS_IMAGE=${BUCKETS_IMAGE:-} CONFIG_SECRET= TLS_SECRET= KES_IMAGE=${BUCKETS_KES_IMAGE:-} CHECK_KES= KES_PIN=${BUCKETS_KES_IMAGE:+1}
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
    --kes-image) KES_IMAGE=$2 KES_PIN=1; shift 2 ;;
    --check-kes) CHECK_KES=1; shift ;;
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

# the buckets-kes image the operator runs, unless named
if [[ -z $KES_IMAGE ]]; then
  KES_IMAGE=$(kc get deployments -A -o json 2>/dev/null | python3 -c '
import json,sys
for d in json.load(sys.stdin)["items"]:
    for c in d["spec"]["template"]["spec"]["containers"]:
        for e in c.get("env", []):
            if e["name"] == "BUCKETS_KES_IMAGE" and e.get("value"): print(e["value"]); sys.exit()' || true)
fi

export TENANT NS BUCKETS_IMAGE CONFIG_SECRET TLS_SECRET WORK KES_IMAGE KES_PIN CTX
SCRIPTS=$(cd "$(dirname "$0")" && pwd) python3 - > "$WORK/plan.json" <<'PY'
import base64, json, os, re, subprocess, sys
sys.dont_write_bytecode = True  # nothing left behind in scripts/
sys.path.insert(0, os.environ["SCRIPTS"])
import adopt_kes

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

_cache = {}
def read(kind, name):
    """A Secret's or ConfigMap's data, decoded; None if it cannot be read. Never printed."""
    if not name:
        return None
    if (kind, name) not in _cache:
        cmd = ["kubectl"] + (["--context", os.environ["CTX"]] if os.environ.get("CTX") else []) + \
              ["-n", ns, "get", kind, name, "-o", "json"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(r.stdout).get("data", {}) if r.returncode == 0 else None
        if data is not None and kind == "secret":
            data = {k: base64.b64decode(v).decode("utf-8", "replace") for k, v in data.items()}
        _cache[(kind, name)] = data
    return _cache[(kind, name)]
read_secret = lambda n: read("secret", n)
read_configmap = lambda n: read("configmap", n)

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
    image = tspec.get("image", "")
    if tspec.get("requestAutoCert", True) and not tls:
        problems.append("the tenant uses the MinIO Operator's automatic certificate; give it an externalCertSecret first")
    kes_key = (tspec.get("kes") or {}).get("keyName") if tspec.get("kes") else None
    uses_kes = bool(tspec.get("kes"))
    if (tspec.get("features") or {}).get("bucketDNS"):
        notes.append("bucket DNS (MINIO_DNS_WEBHOOK_ENDPOINT) is not carried over")
    source = "Tenant"
else:
    if not sts:
        print(json.dumps({"problems": [f"no Tenant {tenant} and no StatefulSets {tenant}-<pool> with data<n> claims in {ns}"]}))
        sys.exit(0)
    pools, mount_path, sub_path, tls, config, sc, image = [], None, "", None, None, {}, ""
    kes_key, uses_kes = None, False
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
        image = image or c.get("image", "")
        sc = tmpl.get("securityContext") or {}
        # where MinIO reads them: MINIO_CONFIG_ENV_FILE and --certs-dir
        if env.get("MINIO_CONFIG_ENV_FILE"):
            config = config or secret_at(tmpl, c, env["MINIO_CONFIG_ENV_FILE"])
        if env.get("MINIO_KMS_KES_ENDPOINT"):
            uses_kes, kes_key = True, kes_key or env.get("MINIO_KMS_KES_KEY_NAME")
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

# KES: settings in config.env count too (MinIO without its operator)
config_env = (read_secret(config) or {}).get("config.env", "") if config else ""
m = re.search(r"^\s*(?:export\s+)?MINIO_KMS_KES_ENDPOINT=", config_env, re.M)
if m:
    uses_kes = True
    k = re.search(r"^\s*(?:export\s+)?MINIO_KMS_KES_KEY_NAME=[\"']?([^\"'\n]+)", config_env, re.M)
    kes_key = kes_key or (k.group(1).strip() if k else None)
kms = None
if uses_kes:
    try:
        import yaml
        load_yaml = yaml.safe_load
    except ImportError:
        load_yaml = None
        problems.append("carrying KES over reads its YAML configuration: install PyYAML (pip install pyyaml)")
    kes_sts = next((x for x in sts_all if x["metadata"]["name"] == tenant + "-kes"), None)
    if load_yaml:
        kms = adopt_kes.carry(tenant, kes_sts, kes_key, os.environ.get("KES_IMAGE"), read_secret, read_configmap, load_yaml)
        problems.extend(kms["problems"])
        notes.extend(kms["notes"])
        cmd = ["kubectl"] + (["--context", os.environ["CTX"]] if os.environ.get("CTX") else []) + \
              ["-n", ns, "get", "secrets,services,deployments,serviceaccounts", "-o", "json"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        # names only: the Secrets' data is dropped unread
        existing = [{"kind": o["kind"], "metadata": o["metadata"]} for o in json.loads(r.stdout)["items"]] \
            if r.returncode == 0 else []
        for c in adopt_kes.collisions(tenant, existing):
            problems.append("%s exists and is not Buckets': the carried-over KMS needs that name" % c)
        if not os.environ.get("KES_IMAGE"):
            problems.append("no buckets-kes image: name it with --kes-image (or set the operator's BUCKETS_KES_IMAGE)")
        if not os.environ.get("KES_PIN") and kms.get("kes"):
            kms["kes"].pop("image", None)  # the operator's own, which follows its upgrades
        # Buckets' KES replaces config.env's KMS settings (they would override it)
        clean, gone = adopt_kes.without_kms_lines(config_env)
        if gone:
            notes.append("config.env's MINIO_KMS_* settings stay with MinIO: Buckets reads a copy without them "
                         "(Secret %s-buckets-config)" % tenant)
            kms["configCopy"] = {"name": tenant + "-buckets-config", "configEnv": clean}
            config = tenant + "-buckets-config"
        # credentials: into their own file, never the plan (the plan is saved and printed)
        with open(os.path.join(os.environ["WORK"], "kms-secrets.json"), "w") as f:
            json.dump({"settings": kms.pop("settings", None), "configCopy": kms.pop("configCopy", None)}, f)
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
# MinIO before RELEASE.2024-10-29 refuses xl.meta metaVersion 3, Buckets' default:
# write 2 while a rollback to that MinIO must stay possible.
rel = re.search(r"RELEASE\.(\d{4}-\d{2}-\d{2})T", image)
if not rel or rel.group(1) < "2024-10-29":
    bc["spec"]["env"] = [{"name": "BUCKETS_XL_META_VERSION", "value": "2"}]
    notes.append(("MinIO %s predates RELEASE.2024-10-29" % rel.group(0).rstrip("T") if rel else
                  "the MinIO release of %r is unknown" % image) +
                 ": Buckets writes xl.meta metaVersion 2 (BUCKETS_XL_META_VERSION) so a rollback can read "
                 "what it writes; remove it once there is no going back")
if tls:
    bc["spec"]["tls"] = {"certSecret": {"name": tls}}
if kms and kms.get("kes"):
    bc["spec"]["kms"] = {"kes": kms["kes"]}
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
                  "kms": {k: kms[k] for k in ("summary", "serviceAccount", "checkPod") if kms and k in kms} if kms else None,
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
HAS_KES=$(field '"yes" if d.get("kms") else ""')
if [[ -n $HAS_KES ]]; then
  say "KES"
  echo "   Secret $TENANT-kms: $(field 'd["kms"]["summary"]') (credentials from the tenant's KES, not shown)"
fi

# buckets-kes reads the default key with the tenant's own KES configuration, in a one-off pod
check_kes() {
  local pod="$TENANT-buckets-kes-check"
  k delete pod "$pod" --ignore-not-found --wait=true >/dev/null
  field 'json.dumps(d["kms"]["checkPod"])' | k apply -f - >/dev/null
  local phase=""
  for _ in $(seq 90); do
    phase=$(k get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [[ $phase == Succeeded || $phase == Failed ]] && break
    sleep 2
  done
  k logs "$pod" 2>/dev/null | tail -5 | sed 's/^/   /'
  [[ $phase == Succeeded || $phase == Failed ]] || k get pod "$pod" -o jsonpath='{range .status.containerStatuses[*]}   {.state.waiting.reason}: {.state.waiting.message}{"\n"}{end}' 2>/dev/null
  k delete pod "$pod" --ignore-not-found --wait=false >/dev/null
  [[ $phase == Succeeded ]]
}
if [[ -n $HAS_KES && -z $APPLY && -n $CHECK_KES ]]; then
  say "checking that buckets-kes reads the tenant's key (a one-off pod)"
  if check_kes; then echo "   ok"; else echo "   buckets-kes cannot read the key with these settings: adoption would stop here"; exit 1; fi
fi
if [[ -z $APPLY ]]; then
  echo
  [[ -n $HAS_KES && -z $CHECK_KES ]] && echo "dry run: nothing changed (--check-kes also has buckets-kes read the tenant's key first). Run again with --apply to adopt." \
    || echo "dry run: nothing changed. Run again with --apply to adopt."
  exit 0
fi

# ---- 1. the keys before anything else ----------------------------------------
if [[ -n $HAS_KES ]]; then
  say "1/5 checking that buckets-kes reads the tenant's key (a one-off pod)"
  check_kes || die "buckets-kes cannot read the tenant's default key with its KES settings; nothing changed"
else
  say "1/5 no KES to check"
fi

# ---- 2. save what rollback needs ------------------------------------------
say "2/5 saving the tenant to $STATE"
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

# ---- 3. no step may lose data ---------------------------------------------
say "3/5 setting the drives' PersistentVolumes to Retain"
for pv in $PVS; do
  [[ ${RECLAIM[$pv]} == Retain ]] || kc patch pv "$pv" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null
done
for pv in $PVS; do
  [[ $(kc get pv "$pv" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}') == Retain ]] || die "PV $pv is not Retain"
done

# ---- 4. stop MinIO, keep the PVCs ------------------------------------------
say "4/5 stopping MinIO (the PVCs stay)"
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

# ---- 5. Buckets on the same drives -----------------------------------------
say "5/5 creating the BucketsCluster"
if [[ -n $HAS_KES ]]; then
  # the key store settings (and config.env's copy without KMS lines), straight from the plan's private
  # file; applied server side, so no last-applied annotation repeats them
  python3 - "$WORK/kms-secrets.json" "$TENANT" "$NS" <<'PY' | k apply --server-side --field-manager=adopt-minio -f - >/dev/null
import json, sys
p, t, ns = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
items = [{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
          "metadata": {"name": t + "-kms", "namespace": ns, "labels": {"buckets.io/cluster": t}},
          "stringData": {"settings.json": json.dumps(p["settings"])}}]
if p.get("configCopy"):
    items.append({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": {"name": p["configCopy"]["name"], "namespace": ns, "labels": {"buckets.io/cluster": t}},
                  "stringData": {"config.env": p["configCopy"]["configEnv"]}})
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
PY
fi
field 'json.dumps(d["bucketscluster"])' | k apply -f - >/dev/null
k wait --for=jsonpath='{.status.phase}'=Ready "bc/$TENANT" --timeout="${TIMEOUT}s" >/dev/null || {
  echo "not Ready after ${TIMEOUT}s; the drives are untouched. Look at:"
  echo "  kubectl -n $NS get bc,pods; kubectl -n $NS logs $TENANT-<pool>-0"
  [[ -n $HAS_KES ]] && echo "  KES: kubectl -n $NS get bc $TENANT -o jsonpath='{.status.kms.message}'"
  echo "or roll back: scripts/rollback-to-minio.sh -n $NS -t $TENANT --state $STATE --apply"
  exit 1
}
touch "$STATE/done"
say "adopted: $NS/$TENANT runs on Buckets ($(k get bc "$TENANT" -o jsonpath='{.status.readyServersText}') servers)"
echo "   rollback: scripts/rollback-to-minio.sh -n $NS -t $TENANT --state $STATE --apply"
