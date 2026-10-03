# SPDX-License-Identifier: AGPL-3.0-or-later
"""Carrying a MinIO tenant's KES over to a BucketsCluster (scripts/adopt-minio.sh).

The tenant's KES keeps its keys in a key store (Vault, AWS, Azure, Google);
buckets-kes reads them there as KES stored them. What moves is where the keys
are and how to sign in: the KES configuration's "keystore", turned into the
settings the console writes (Secret <tenant>-kms, settings.json; see
src/kms/kesutil.h), plus the default key's name, the account KES runs as (a
Vault Kubernetes role names it) and where its pods may run.

The KES StatefulSet (<tenant>-kes, as the MinIO Operator names it) is read as
it runs: its --config file, the files it mounts (a Vault CA among them), the
environment ${VAR} references in the configuration resolve against.

Everything returned that holds credentials (settings) is for the Secret only:
never print it or write it to the adoption's state."""
import copy
import re

KES_SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
VAR = re.compile(r"\$\{([^}]+)\}")


def container_env(c, read_secret, read_configmap):
    """The container's environment: names to values; None where it cannot be read."""
    env = {}
    for e in c.get("env", []):
        if "value" in e:
            env[e["name"]] = e["value"]
            continue
        vf = e.get("valueFrom") or {}
        ref = vf.get("secretKeyRef") or vf.get("configMapKeyRef")
        if ref:
            data = (read_secret if "secretKeyRef" in vf else read_configmap)(ref["name"]) or {}
            env[e["name"]] = data.get(ref["key"])
        else:
            env[e["name"]] = None  # fieldRef and the like: nothing a key store setting would use
    return env


def mounted_files(tmpl, c, read_secret):
    """Every file the container sees from Secrets: path -> text."""
    files = {}
    vols = {v["name"]: v for v in tmpl.get("volumes", [])}
    for m in c.get("volumeMounts", []):
        v = vols.get(m["name"], {})
        sources = []
        if v.get("secret"):
            sources.append((v["secret"].get("secretName"), v["secret"].get("items")))
        for src in (v.get("projected") or {}).get("sources", []):
            if "secret" in src:
                sources.append((src["secret"].get("name"), src["secret"].get("items")))
        base = m["mountPath"].rstrip("/")
        for name, items in sources:
            data = read_secret(name) or {}
            pairs = [(i["key"], i.get("path", i["key"])) for i in items] if items else [(k, k) for k in data]
            for key, path in pairs:
                if key in data and data[key] is not None:
                    files[base + "/" + path] = data[key]
            if m.get("subPath"):  # a single file mounted from the volume
                sub = m["subPath"]
                hit = next((data[k] for k, p in pairs if p == sub and k in data), None)
                if hit is not None:
                    files[base] = hit
    return files


def config_path(c):
    args = list(c.get("args", [])) + list(c.get("command", []))
    for i, a in enumerate(args):
        if a.startswith("--config="):
            return a.split("=", 1)[1]
        if a == "--config" and i + 1 < len(args):
            return args[i + 1]
    return None


def expand(value, env, missing):
    """${VAR} in every string, as KES's env[T] reads them."""
    if isinstance(value, dict):
        return {k: expand(v, env, missing) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v, env, missing) for v in value]
    if isinstance(value, str):
        def one(m):
            v = env.get(m.group(1))
            if v is None:
                missing.add(m.group(1))
                return ""
            return v
        return VAR.sub(one, value)
    return value


def s(v):
    return "" if v is None else str(v)


def keystore_settings(ks, files):
    """KES's keystore -> (the console's settings, problems)."""
    problems = []
    if not isinstance(ks, dict) or len(ks) != 1:
        return None, ["the KES configuration has no single keystore"]
    kind, conf = next(iter(ks.items()))
    conf = conf or {}
    if kind == "vault":
        out = {"endpoint": s(conf.get("endpoint")),
               # KES's defaults when left out: the "kv" engine, API version 1
               "engine": s(conf.get("engine")) or "kv",
               "version": s(conf.get("version")) or "v1"}
        for k in ("namespace", "prefix"):
            if conf.get(k):
                out[k] = s(conf[k])
        ar, k8s = conf.get("approle") or {}, conf.get("kubernetes") or {}
        if ar.get("id") or ar.get("secret"):
            out["auth"] = "approle"
            out["approle"] = {"engine": s(ar.get("engine")) or "approle", "id": s(ar.get("id")), "secret": s(ar.get("secret"))}
            if ar.get("namespace"):
                out["approle"]["namespace"] = s(ar["namespace"])
        elif k8s.get("role"):
            out["auth"] = "kubernetes"
            out["kubernetes"] = {"engine": s(k8s.get("engine")) or "kubernetes", "role": s(k8s["role"])}
            if k8s.get("namespace"):
                out["kubernetes"]["namespace"] = s(k8s["namespace"])
            jwt = s(k8s.get("jwt"))
            if jwt and "/" not in jwt:
                problems.append("KES signs in to Vault with a JWT written into its configuration; buckets-kes uses its "
                                "pods' service account token: point the Vault role at that account instead")
        else:
            problems.append("the Vault keystore has no AppRole or Kubernetes sign-in")
        tr = conf.get("transit") or {}
        if tr.get("key"):
            out["transit"] = {"engine": s(tr.get("engine")) or "transit", "key": s(tr["key"])}
        tls = conf.get("tls") or {}
        if tls.get("key") or tls.get("cert"):
            problems.append("KES signs in to Vault with a client certificate (tls.key, tls.cert), which buckets-kes "
                            "does not support yet")
        if tls.get("ca"):
            ca = files.get(s(tls["ca"]))
            if ca is None:
                problems.append("the Vault CA %s is not in a Secret the KES pods mount" % tls["ca"])
            else:
                out["caCert"] = ca
        return {"backend": "vault", "vault": out}, problems
    if kind == "aws":
        sm = conf.get("secretsmanager") or {}
        cr = sm.get("credentials") or {}
        out = {"region": s(sm.get("region"))}
        for k, src in (("endpoint", sm.get("endpoint")), ("kmsKey", sm.get("kmskey")), ("accessKey", cr.get("accesskey")),
                       ("secretKey", cr.get("secretkey")), ("sessionToken", cr.get("token"))):
            if src:
                out[k] = s(src)
        if not out["region"]:
            problems.append("the AWS keystore names no region")
        return {"backend": "aws", "aws": out}, problems
    if kind == "azure":
        kv = conf.get("keyvault") or {}
        out = {"endpoint": s(kv.get("endpoint"))}
        cr, mi = kv.get("credentials"), kv.get("managed_identity")
        if cr:
            out.update({"auth": "secret", "tenantId": s(cr.get("tenant_id")), "clientId": s(cr.get("client_id")),
                        "clientSecret": s(cr.get("client_secret"))})
        elif mi is not None:
            out.update({"auth": "managedIdentity", "managedIdentityClientId": s((mi or {}).get("client_id"))})
        else:
            problems.append("the Azure keystore has no credentials or managed identity")
        return {"backend": "azure", "azure": out}, problems
    if kind == "gcp":
        sm = conf.get("secretmanager") or {}
        cr = sm.get("credentials") or {}
        out = {"projectId": s(sm.get("project_id"))}
        if sm.get("endpoint"):
            out["endpoint"] = s(sm["endpoint"])
        if cr.get("client_email") and cr.get("private_key"):
            import json
            out["credentials"] = json.dumps({"type": "service_account", "project_id": out["projectId"],
                                             "client_email": s(cr["client_email"]), "client_id": s(cr.get("client_id")),
                                             "private_key_id": s(cr.get("private_key_id")),
                                             "private_key": s(cr["private_key"])})
        else:
            problems.append("the Google keystore has no service account key in its configuration (workload identity "
                            "through gcpCredentialSecretName is not carried over)")
        return {"backend": "gcp", "gcp": out}, problems
    if kind == "fs":
        return None, ["KES keeps its keys in files on its own pods (the fs keystore): move them to a key store first"]
    return None, ["KES's %s keystore is not one buckets-kes supports (Vault, AWS, Azure, Google)" % kind]


def carry(tenant, kes_sts, key_name, kes_image, read_secret, read_configmap, load_yaml):
    """The carry-over plan: problems, notes, settings (credentials!), the BucketsCluster's
    spec.kms.kes and a pre-flight pod that has buckets-kes read the default key."""
    problems, notes = [], []
    out = {"problems": problems, "notes": notes}
    if not kes_sts:
        problems.append("the tenant uses KES, but there is no KES StatefulSet %s-kes to carry over" % tenant)
        return out
    tmpl = kes_sts["spec"]["template"]["spec"]
    c = tmpl["containers"][0]
    path = config_path(c)
    files = mounted_files(tmpl, c, read_secret)
    if not path or path not in files:
        problems.append("%s: its KES configuration (--config %s) is not in a Secret it mounts"
                        % (kes_sts["metadata"]["name"], path))
        return out
    try:
        conf = load_yaml(files[path]) or {}
    except Exception as e:  # noqa: BLE001 - any YAML error is the same problem here
        problems.append("the KES configuration cannot be read: %s" % e)
        return out
    env = container_env(c, read_secret, read_configmap)
    missing = set()
    ks = expand(conf.get("keystore"), env, missing)
    if missing:
        problems.append("the KES configuration reads %s from an environment that cannot be resolved here"
                        % ", ".join(sorted(missing)))
    settings, ps = keystore_settings(ks, files)
    problems.extend(ps)
    if not key_name:
        problems.append("the tenant names no default key (spec.kes.keyName or MINIO_KMS_KES_KEY_NAME)")
    sa = tmpl.get("serviceAccountName") or tmpl.get("serviceAccount") or "default"
    kes = {"keyName": key_name, "createKey": False, "name": kes_name(tenant), "serviceAccountName": sa}
    for k in ("nodeSelector", "tolerations", "affinity"):
        if tmpl.get(k):
            kes[k] = tmpl[k]
    if kes_image:
        kes["image"] = kes_image
    out.update({"settings": settings, "kes": kes, "serviceAccount": sa,
                "summary": summarize(settings) if settings else ""})
    # the pre-flight: buckets-kes reads the default key with the tenant's own configuration
    spec = {k: copy.deepcopy(tmpl[k]) for k in ("volumes", "serviceAccountName", "securityContext", "imagePullSecrets",
                                                "nodeSelector", "tolerations", "affinity") if tmpl.get(k)}
    spec["restartPolicy"] = "Never"
    spec["containers"] = [{"name": "check", "image": kes_image or "", "args": ["check", "--config", path, "--key", key_name or ""],
                           "env": copy.deepcopy(c.get("env", [])), "volumeMounts": copy.deepcopy(c.get("volumeMounts", []))}]
    out["checkPod"] = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "%s-buckets-kes-check" % tenant}, "spec": spec}
    notes.append("KES carries over: buckets-kes reads key %s from %s, signed in as the tenant's KES (account %s)"
                 % (key_name, out["summary"], sa))
    return out


def kes_name(tenant):
    """The BucketsCluster's KES servers: not <tenant>-kes, the tenant's own (its StatefulSet,
    Service and certificate Secret <tenant>-kes-tls stay for a rollback)."""
    return tenant + "-buckets-kes"


def names_needed(tenant):
    """(kind, name) of everything the carried-over KMS makes in the namespace."""
    k = kes_name(tenant)
    return ([("Secret", n) for n in (tenant + "-kms", tenant + "-kms-candidate", tenant + "-buckets-config",
                                     k + "-tls", k + "-identity")] +
            [(kind, n) for kind in ("Service", "Deployment") for n in (k, k + "-test")] +
            [("ServiceAccount", k)])


def collisions(tenant, existing):
    """existing: objects in the namespace (kind, metadata). Names the KMS needs that something
    else already has; a previous run's (labelled buckets.io/cluster: <tenant>) do not count."""
    have = {(o["kind"], o["metadata"]["name"]): o for o in existing}
    out = []
    for kind, name in names_needed(tenant):
        o = have.get((kind, name))
        if o and (o["metadata"].get("labels") or {}).get("buckets.io/cluster") != tenant:
            out.append("%s %s" % (kind, name))
    return out


def summarize(settings):
    b = settings.get("backend")
    v = settings.get(b) or {}
    if b == "vault":
        how = "AppRole" if v.get("auth") == "approle" else "Kubernetes role %s" % (v.get("kubernetes") or {}).get("role")
        return "Vault at %s (%s %s, prefix %s, %s)" % (v.get("endpoint"), v.get("engine"), v.get("version"),
                                                      v.get("prefix") or "none", how)
    if b == "aws":
        return "AWS Secrets Manager in %s" % v.get("region")
    if b == "azure":
        return "Azure Key Vault %s" % v.get("endpoint")
    if b == "gcp":
        return "Google Secret Manager, project %s" % v.get("projectId")
    return b or "?"


def without_kms_lines(config_env):
    """config.env without its MINIO_KMS_* lines (Buckets' KES replaces them), and whether any went."""
    keep, gone = [], False
    for line in config_env.splitlines():
        if re.match(r"\s*(export\s+)?(MINIO|BUCKETS)_KMS_", line):
            gone = True
            continue
        keep.append(line)
    return "\n".join(keep) + ("\n" if config_env.endswith("\n") else ""), gone
