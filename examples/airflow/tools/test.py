"""End-to-end checks for the Airflow example: docker compose run --rm test

People sign in through Keycloak's own login form, as in a browser, then use
Airflow's REST API with the token the sign-in gave them, as Airflow's UI does:

  1. Keycloak sign-in: bob (engineers) and alice (analysts) get in, with their
     groups as their Airflow roles (Op, Viewer); carol (no group) is refused;
  2. the roles mean what they say: alice can't trigger a pipeline, bob can;
  3. bob's run of sales_ingest succeeds, and its tasks ran as the pipelines'
     service account, not as bob: in Buckets (landing/ only, through STS) and
     in Trino, where Ranger applies, and audits, the pipelines group's policies;
  4. Airflow holds no S3 keys or Trino password: its one connection is the
     service account's Keycloak client.
"""
import html
import os
import re
import time

import requests

from lakekit import audited, check, finish, keys, s3_root, sql

AIRFLOW = "http://airflow:8090"
SERVICE_ACCOUNT = "service-account-airflow-pipelines"


def sign_in(user):
    """Sign in through Keycloak's form; returns (session, API headers or None)."""
    s = requests.Session()
    r = s.get(f"{AIRFLOW}/auth/login/keycloak?next=", timeout=30)
    form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', r.text)
    s.post(html.unescape(form.group(1)), timeout=120,
           data={"username": user, "password": os.environ["LAKEHOUSE_USER_PASSWORD"], "credentialId": ""})
    token = s.cookies.get("_token")
    return s, ({"Authorization": f"Bearer {token}"} if token else None)


def api(h, method, path, **kw):
    return requests.request(method, f"{AIRFLOW}/api/v2{path}", headers=h, timeout=60, **kw)


def wait_for_dag(h, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = api(h, "GET", "/dags/sales_ingest")
        if r.ok:
            return True
        time.sleep(3)
    return False


def main():
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if requests.get(f"{AIRFLOW}/api/v2/monitor/health", timeout=5).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(2)

    # 1. Sign-in and roles.
    _, bob = sign_in("bob")
    _, alice = sign_in("alice")
    _, carol = sign_in("carol")
    check("people sign in to Airflow with Keycloak", bob is not None and alice is not None,
          f"bob {'signed in' if bob else 'no token'}, alice {'signed in' if alice else 'no token'}")
    check("people in neither group can't sign in", carol is None, "carol got no session token" if carol is None else "carol got in")

    # 2. Roles decide who runs pipelines.
    check("the pipeline is loaded", wait_for_dag(bob), "sales_ingest")
    a = api(alice, "POST", "/dags/sales_ingest/dagRuns", json={"logical_date": None})
    check("analysts (Viewer) can't trigger a pipeline", a.status_code == 403, f"alice: HTTP {a.status_code}")
    b = api(bob, "POST", "/dags/sales_ingest/dagRuns", json={"logical_date": None})
    run = b.json().get("dag_run_id") if b.ok else None
    check("engineers (Op) trigger it", run is not None, f"bob: HTTP {b.status_code}" + (f", run {run}" if run else f" {b.text[:200]}"))

    # 3. The run, as the pipelines' service account.
    state = None
    deadline = time.time() + 300
    while run and time.time() < deadline:
        state = api(bob, "GET", f"/dags/sales_ingest/dagRuns/{run}").json().get("state")
        if state in ("success", "failed"):
            break
        time.sleep(3)
    check("bob's run succeeds", state == "success", f"state {state}")
    x = api(bob, "GET", f"/dags/sales_ingest/dagRuns/{run}/taskInstances/load_orders/xcomEntries/return_value").json() if run else {}
    result = x.get("value") or {}
    if isinstance(result, str):
        import ast
        result = ast.literal_eval(result)
    check("its tasks ran in Trino as the pipelines' service account, not as bob",
          result.get("trino_user") == SERVICE_ACCOUNT, f"current_user: {result.get('trino_user')}")
    landed = [k for k in keys(s3_root(), "landing", "sales/") if run and run.replace(":", "-").replace("+", "-") in k]
    check("... and landed its file in Buckets with STS credentials, landing/ only",
          landed and result.get("warehouse") == "AccessDenied",
          f"{', '.join(landed) or 'nothing landed'}; the same credentials on warehouse: {result.get('warehouse')}")
    count = sql("bob", "SELECT count(*) FROM orders WHERE id IN (101, 102)", catalog="iceberg", schema="sales")[0][0]
    check("the orders it loaded are in the lakehouse", count == 2 and result.get("inserted") == 2,
          f"{count} new orders in iceberg.sales.orders, {result.get('orders')} in all")
    hits = audited(SERVICE_ACCOUNT, allowed=True)
    check("Ranger's audit log records the pipeline's queries under the service account", hits > 0,
          f"{hits} allowed requests by {SERVICE_ACCOUNT}")

    # 4. What Airflow holds.
    conns = api(bob, "GET", "/connections").json().get("connections", [])
    kinds = sorted(f"{c['connection_id']} ({c['conn_type']})" for c in conns)
    check("Airflow holds no S3 keys or Trino password: one Keycloak client",
          kinds == ["keycloak_pipelines (http)"], ", ".join(kinds) or "none")
    finish()


if __name__ == "__main__":
    main()
