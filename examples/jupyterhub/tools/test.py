"""End-to-end checks for the JupyterHub example: docker compose run --rm test

People sign in through Keycloak's own login form, as in a browser. Then code
runs in each person's notebook kernel, in their own container, through the
Jupyter Server API:

  1. Keycloak sign-in: bob (engineers) and alice (analysts) get in, with their
     Keycloak groups mirrored in the hub; bob administers the hub, alice
     doesn't; carol (no group) is refused;
  2. each notebook gets its person's own token and Buckets credentials, and no
     keys of any kind;
  3. each person reads and writes home/<them>/ only;
  4. analysts read the shared datasets, and only engineers write them;
  5. what notebooks write is in Buckets, under each person's prefix.
"""
import html
import json
import os
import re
import time
import uuid

import requests
import websocket

from lakekit import check, finish, keys, s3_root

HUB = "http://jupyterhub:8000"


def sign_in(user):
    """Sign in through Keycloak's login form; returns (session, final response)."""
    s = requests.Session()
    r = s.get(f"{HUB}/hub/oauth_login", timeout=30)
    form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', r.text)
    r = s.post(html.unescape(form.group(1)), timeout=120,
               data={"username": user, "password": os.environ["LAKEHOUSE_USER_PASSWORD"], "credentialId": ""})
    return s, r


def hub_xsrf(s):
    """The hub's XSRF cookie. A running notebook server sets one of its own, under /user/<name>/."""
    return next((c.value for c in s.cookies if c.name == "_xsrf" and c.path.startswith("/hub")), "")


def hub_api(s, method, path, **kw):
    r = s.request(method, f"{HUB}/hub/api{path}", headers={"X-XSRFToken": hub_xsrf(s)}, timeout=30, **kw)
    r.raise_for_status()
    return r.json() if r.text.strip() else None


def server_token(s, user):
    """An API token for the person's own notebook server, as they could make one in the hub."""
    t = hub_api(s, "POST", f"/users/{user}/tokens", json={
        "note": "end-to-end checks", "expires_in": 3600,
        "scopes": [f"access:servers!user={user}", f"servers!user={user}", f"read:users!user={user}"]})
    return t["token"]


def wait_for_server(s, user, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        server = hub_api(s, "GET", f"/users/{user}")["servers"].get("")
        if not server:
            hub_api(s, "POST", f"/users/{user}/server")
        elif server["ready"]:
            return
        time.sleep(2)
    raise TimeoutError(f"{user}'s notebook server didn't start")


def run(user, token, code):
    """Run code in a new kernel on the person's server; returns its stdout."""
    auth = {"Authorization": f"token {token}"}
    base = f"{HUB}/user/{user}/api"
    kernel = requests.post(f"{base}/kernels", headers=auth, json={"name": "python3"}, timeout=60).json()["id"]
    ws = websocket.create_connection(f"ws://jupyterhub:8000/user/{user}/api/kernels/{kernel}/channels",
                                     header=[f"Authorization: token {token}"], timeout=120)
    msg_id = uuid.uuid4().hex
    ws.send(json.dumps({
        "header": {"msg_id": msg_id, "username": user, "session": uuid.uuid4().hex,
                   "msg_type": "execute_request", "version": "5.3"},
        "parent_header": {}, "metadata": {}, "channel": "shell",
        "content": {"code": code, "silent": False, "store_history": False, "user_expressions": {},
                    "allow_stdin": False, "stop_on_error": True}}))
    out, err = [], None
    while True:
        m = json.loads(ws.recv())
        if m.get("parent_header", {}).get("msg_id") != msg_id:
            continue
        t = m["msg_type"]
        if t == "stream":
            out.append(m["content"]["text"])
        elif t == "error":
            err = "\n".join(m["content"]["traceback"])
        elif t == "status" and m["content"]["execution_state"] == "idle":
            break
    ws.close()
    requests.delete(f"{base}/kernels/{kernel}", headers=auth, timeout=30)
    if err:
        raise RuntimeError(f"{user}'s notebook: {re.sub(r'\x1b\[[0-9;]*m', '', err)}")
    return "".join(out)


# Runs in a person's notebook: what they can and can't do in Buckets.
NOTEBOOK = r'''
import base64, io, json, os
import pandas as pd
import buckets_lake
from botocore.exceptions import ClientError

def code(fn):
    try:
        fn(); return "OK"
    except ClientError as e:
        return e.response["Error"]["Code"]

me = buckets_lake.username()
other = OTHER
claims = json.loads(base64.urlsafe_b64decode(buckets_lake.token().split(".")[1] + "=="))
s3 = buckets_lake.s3()
orders = pd.read_parquet(io.BytesIO(s3.get_object(Bucket="datasets", Key="sales/orders.parquet")["Body"].read()))
print(json.dumps({
    "user": me,
    "token_user": claims.get("preferred_username"), "token_groups": claims.get("groups"),
    "token_aud": claims.get("aud"),
    "keys_in_env": sorted(k for k in os.environ if k.startswith(("AWS_", "MINIO_", "BUCKETS_ROOT"))),
    "put_own": code(lambda: s3.put_object(Bucket="home", Key=f"{me}/notes.txt", Body=f"{me}'s notes".encode())),
    "list_own": code(lambda: s3.list_objects_v2(Bucket="home", Prefix=f"{me}/")),
    "get_other": code(lambda: s3.get_object(Bucket="home", Key=f"{other}/notes.txt")),
    "list_other": code(lambda: s3.list_objects_v2(Bucket="home", Prefix=f"{other}/")),
    "put_other": code(lambda: s3.put_object(Bucket="home", Key=f"{other}/hello.txt", Body=b"hi")),
    "orders": len(orders),
    "write_datasets": code(lambda: s3.put_object(Bucket="datasets", Key=f"from-{me}.txt", Body=b"x")),
}))
'''


def notebook_checks(user, other):
    s, r = sign_in(user)
    me = hub_api(s, "GET", "/user")
    wait_for_server(s, user)
    out = run(user, server_token(s, user), NOTEBOOK.replace("OTHER", repr(other)))
    return me, json.loads(out.strip().splitlines()[-1])


def main():
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            if requests.get(f"{HUB}/hub/health", timeout=5).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(2)

    # bob first: alice's checks read bob's prefix, so it must exist.
    bob, b = notebook_checks("bob", other="alice")
    alice, a = notebook_checks("alice", other="bob")

    # 1. Keycloak sign-in, groups and hub roles.
    check("people sign in to JupyterHub with Keycloak, and their groups come along",
          alice["groups"] == ["analysts"] and bob["groups"] == ["engineers"],
          f"alice {alice['groups']}, bob {bob['groups']}")
    check("Keycloak's engineers group administers the hub, and analysts don't",
          bob["admin"] is True and alice["admin"] is False, f"bob admin={bob['admin']}, alice admin={alice['admin']}")
    _, r = sign_in("carol")
    check("people in neither group can't sign in", r.status_code == 403, f"HTTP {r.status_code}")

    # 2. Each notebook works as its person, with no keys.
    check("each notebook gets its own person's Keycloak token",
          a["token_user"] == "alice" and b["token_user"] == "bob" and "lakehouse" in (a["token_aud"] or []),
          f"alice's notebook: {a['token_user']} {a['token_groups']}; bob's: {b['token_user']} {b['token_groups']}")
    check("notebooks hold no keys", not a["keys_in_env"] and not b["keys_in_env"],
          f"credential variables: {a['keys_in_env'] + b['keys_in_env'] or 'none'}")

    # 3. A private home prefix each.
    check("each person reads and writes their own home prefix",
          a["put_own"] == a["list_own"] == b["put_own"] == "OK", f"alice {a['put_own']}, bob {b['put_own']}")
    check("nobody reads or writes another person's prefix",
          {a["get_other"], a["list_other"], a["put_other"]} == {"AccessDenied"},
          f"alice on bob's: GetObject {a['get_other']}, ListObjects {a['list_other']}, PutObject {a['put_other']}")

    # 4. Shared datasets: groups decide.
    check("analysts and engineers read the shared datasets", a["orders"] == b["orders"] == 6,
          f"{a['orders']} orders read with pandas")
    check("only engineers write the shared datasets",
          a["write_datasets"] == "AccessDenied" and b["write_datasets"] == "OK",
          f"alice {a['write_datasets']}, bob {b['write_datasets']}")

    # 5. In Buckets.
    homes = keys(s3_root(), "home")
    check("the notebooks' files are in Buckets, each under its person's prefix",
          {"alice/notes.txt", "bob/notes.txt"} <= set(homes), ", ".join(sorted(homes)))
    finish()


if __name__ == "__main__":
    main()
