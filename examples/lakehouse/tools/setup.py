"""Configure the lakehouse example: Buckets, then Ranger.

Buckets
  - buckets `warehouse` (Iceberg tables) and `scratch` (people's own files);
  - policy `lakehouse-engine` (the warehouse, read and write) for the engines'
    service accounts, `trino-svc` and `nessie-svc`;
  - policies `analysts` and `engineers`, named after the Keycloak groups people
    sign in with: `scratch` only. Nobody but the engines can read the warehouse,
    so Ranger's masks and row filters can't be bypassed by reading the files.

Ranger
  - Keycloak's users and groups, copied over (what Ranger's usersync does
    against LDAP or Entra ID in a real deployment);
  - the Trino service `lakehouse` and its policies (see POLICIES below).

Safe to run again: everything is created or updated in place.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

import requests

env = os.environ
KEYCLOAK = "http://keycloak:8080"
REALM = "lakehouse"
RANGER = "http://ranger-admin:6080"
RANGER_AUTH = ("admin", env["RANGER_PASSWORD"])
SERVICE = "lakehouse"
PLUGIN_USER = "trino-plugin"  # Trino's Ranger plugin signs in as this user


def log(msg):
    print(f"setup: {msg}", flush=True)


def wait_for(name, url, ok=lambda r: r.status_code == 200, auth=None, timeout=600):
    deadline = time.time() + timeout
    while True:
        try:
            r = requests.get(url, auth=auth, timeout=5)
            if ok(r):
                return
        except requests.RequestException:
            pass
        if time.time() > deadline:
            sys.exit(f"setup: {name} did not come up ({url})")
        time.sleep(2)


# --- Buckets -----------------------------------------------------------------

def mc(*args, check=True):
    r = subprocess.run(["mc", "--no-color", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"setup: mc {' '.join(args)} failed:\n{r.stdout}{r.stderr}")
    return r


def policy(name, statements):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"Version": "2012-10-17", "Statement": statements}, f)
    mc("admin", "policy", "create", "buckets", name, f.name)


def bucket_rw(bucket):
    return [
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"],
         "Resource": [f"arn:aws:s3:::{bucket}"]},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                       "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
         "Resource": [f"arn:aws:s3:::{bucket}/*"]},
    ]


def setup_buckets():
    wait_for("Buckets", "http://buckets:9000/minio/health/live")
    mc("alias", "set", "buckets", "http://buckets:9000", env["BUCKETS_ROOT_USER"], env["BUCKETS_ROOT_PASSWORD"])
    for b in ("warehouse", "scratch"):
        mc("mb", "--ignore-existing", f"buckets/{b}")
    policy("lakehouse-engine", bucket_rw("warehouse"))
    for group in ("analysts", "engineers"):
        policy(group, bucket_rw("scratch"))
    for user, secret in ((env["TRINO_S3_ACCESS_KEY"], env["TRINO_S3_SECRET_KEY"]),
                         (env["NESSIE_S3_ACCESS_KEY"], env["NESSIE_S3_SECRET_KEY"])):
        mc("admin", "user", "add", "buckets", user, secret)
        mc("admin", "policy", "attach", "buckets", "lakehouse-engine", "--user", user, check=False)  # fails if attached
    log("Buckets: buckets warehouse and scratch, engine accounts, group policies")


# --- Keycloak -> Ranger users and groups ---------------------------------------

def keycloak_people():
    """{user: [groups]} from the realm, as an admin would sync them."""
    tok = requests.post(f"{KEYCLOAK}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": env["KEYCLOAK_ADMIN_PASSWORD"]}, timeout=10)
    tok.raise_for_status()
    h = {"Authorization": f"Bearer {tok.json()['access_token']}"}
    base = f"{KEYCLOAK}/admin/realms/{REALM}"
    people = {}
    for u in requests.get(f"{base}/users?max=1000", headers=h, timeout=10).json():
        groups = requests.get(f"{base}/users/{u['id']}/groups", headers=h, timeout=10).json()
        people[u["username"]] = sorted(g["name"] for g in groups)
    return people


def ranger(method, path, **kw):
    r = requests.request(method, RANGER + path, auth=RANGER_AUTH, timeout=30,
                         headers={"Accept": "application/json"}, **kw)
    if r.status_code >= 400:
        raise RuntimeError(f"Ranger {method} {path}: {r.status_code} {r.text[:500]}")
    return r.json() if r.text.strip() else None


def sync_people(people):
    groups = {g["name"]: g["id"] for g in ranger("GET", "/service/xusers/groups?pageSize=1000")["vXGroups"]}
    for name in sorted({g for gs in people.values() for g in gs} - set(groups)):
        groups[name] = ranger("POST", "/service/xusers/groups", json={"name": name, "description": "from Keycloak"})["id"]
    users = {u["name"]: u for u in ranger("GET", "/service/xusers/users?pageSize=1000")["vXUsers"]}
    for name, gs in sorted(people.items()):
        ids = [groups[g] for g in gs]
        if name in users:
            u = ranger("GET", f"/service/xusers/secure/users/{users[name]['id']}")
            u["groupIdList"] = ids
            ranger("PUT", f"/service/xusers/secure/users/{u['id']}", json=u)
        else:
            ranger("POST", "/service/xusers/secure/users", json={
                "name": name, "firstName": name, "password": env["RANGER_PASSWORD"] + name,
                "userRoleList": ["ROLE_USER"], "groupIdList": ids, "status": 1, "userSource": 1})
    log("Ranger: users " + ", ".join(f"{u} ({', '.join(g) or 'no group'})" for u, g in sorted(people.items())))


# --- Ranger: the Trino service and its policies ---------------------------------

def res(**kw):
    return {k: {"values": v if isinstance(v, list) else [v], "isExcludes": False, "isRecursive": False}
            for k, v in kw.items()}


def allow(accesses, groups=(), users=()):
    return {"groups": list(groups), "users": list(users), "delegateAdmin": False,
            "accesses": [{"type": a, "isAllowed": True} for a in accesses]}


ICEBERG = "iceberg"
POLICIES = [
    # Everyone who may use Trino at all: run queries, and act as themselves.
    {"name": "run queries", "resources": res(queryid="*"),
     "policyItems": [allow(["execute"], groups=["analysts", "engineers"])]},
    {"name": "act as yourself", "resources": res(trinouser="{USER}"),
     "policyItems": [allow(["impersonate"], users=["{USER}"])]},
    # Engineers own the Iceberg catalog: create schemas and tables, load data.
    # Analysts may only see that it's there. (Ranger allows one access policy
    # per resource, so the catalog's policy has an item for each group.)
    {"name": "iceberg catalog", "resources": res(catalog=ICEBERG),
     "policyItems": [allow(["all"], groups=["engineers"]), allow(["use", "show"], groups=["analysts"])]},
    {"name": "engineers: iceberg schemas", "resources": res(catalog=ICEBERG, schema="*"),
     "policyItems": [allow(["all"], groups=["engineers"])]},
    {"name": "engineers: iceberg tables", "resources": res(catalog=ICEBERG, schema="*", table="*", column="*"),
     "policyItems": [allow(["all"], groups=["engineers"])]},
    # Analysts read one table, sales.orders, and nothing else.
    {"name": "analysts: sales schema", "resources": res(catalog=ICEBERG, schema="sales"),
     "policyItems": [allow(["use", "show"], groups=["analysts"])]},
    {"name": "analysts: sales.orders", "resources": res(catalog=ICEBERG, schema="sales", table="orders", column="*"),
     "policyItems": [allow(["select", "show"], groups=["analysts"])]},
    # ... with card numbers masked to their last four digits,
    {"name": "analysts: mask card numbers", "policyType": 1,
     "resources": res(catalog=ICEBERG, schema="sales", table="orders", column="card_number"),
     "dataMaskPolicyItems": [{**allow(["select"], groups=["analysts"]),
                              "dataMaskInfo": {"dataMaskType": "MASK_SHOW_LAST_4"}}]},
    # ... and only the EU's orders.
    {"name": "analysts: EU orders only", "policyType": 2,
     "resources": res(catalog=ICEBERG, schema="sales", table="orders"),
     "rowFilterPolicyItems": [{**allow(["select"], groups=["analysts"]),
                               "rowFilterInfo": {"filterExpr": "region = 'EU'"}}]},
]


def setup_ranger():
    users = {u["name"] for u in ranger("GET", "/service/xusers/users?pageSize=1000")["vXUsers"]}
    if PLUGIN_USER not in users:
        ranger("POST", "/service/xusers/secure/users", json={
            "name": PLUGIN_USER, "firstName": "Trino plugin", "password": env["RANGER_PLUGIN_PASSWORD"],
            "userRoleList": ["ROLE_USER"], "status": 1, "userSource": 0})
    service = {
        "name": SERVICE, "type": "trino", "description": "Trino on Buckets",
        "configs": {"username": "trino", "password": "unused",
                    "jdbc.driverClassName": "io.trino.jdbc.TrinoDriver",
                    "jdbc.url": "jdbc:trino://trino:8443",
                    # only the plugin's user may download policies, tags and users
                    "policy.download.auth.users": PLUGIN_USER,
                    "tag.download.auth.users": PLUGIN_USER,
                    "userstore.download.auth.users": PLUGIN_USER}}
    found = ranger("GET", f"/service/public/v2/api/service?serviceName={SERVICE}")
    if found:
        ranger("PUT", f"/service/public/v2/api/service/{found[0]['id']}", json={**found[0], **service})
    else:
        ranger("POST", "/service/public/v2/api/service", json=service)
    existing = {p["name"]: p for p in ranger("GET", f"/service/public/v2/api/service/{SERVICE}/policy")}
    wanted = {p["name"] for p in POLICIES}
    for name, p in existing.items():  # Ranger's default policies, and any of ours since removed
        if name not in wanted:
            ranger("DELETE", f"/service/public/v2/api/policy/{p['id']}")
    for p in POLICIES:
        body = {"service": SERVICE, "isEnabled": True, "policyType": 0, **p}
        if p["name"] in existing:
            ranger("PUT", f"/service/public/v2/api/policy/{existing[p['name']]['id']}", json=body)
        else:
            ranger("POST", "/service/public/v2/api/policy", json=body)
    log(f"Ranger: service {SERVICE} with {len(POLICIES)} policies")


if __name__ == "__main__":
    setup_buckets()
    # Unauthenticated: five failed sign-ins in five minutes lock Ranger's admin.
    wait_for("Ranger", f"{RANGER}/login.jsp")
    sync_people(keycloak_people())
    setup_ranger()
    log("done")
