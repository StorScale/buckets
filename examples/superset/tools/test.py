"""End-to-end checks for the Superset example: docker compose run --rm test

People sign in through Keycloak's own login form, as in a browser, then use
Superset's API as the web UI does:

  1. Keycloak sign-in: alice (analysts) and bob (engineers) get in, with their
     Keycloak groups as their Superset roles; carol (no group) is refused;
  2. the roles mean what they say: engineers create datasets, analysts don't;
  3. SQL Lab runs each person's queries in Trino as that person, so Ranger's
     policies follow them: alice gets EU orders only, card numbers masked, and
     no payroll; bob gets everything;
  4. Ranger's audit log records the queries under the person's name.
"""
import html
import os
import re
import time

import requests

from lakekit import audited_denials, check, finish

SS = "http://superset:8088"


def sign_in(user):
    """Sign in through Keycloak's login form; returns the Superset session."""
    s = requests.Session()
    r = s.get(f"{SS}/login/keycloak?next=", timeout=30)
    form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', r.text)
    s.post(html.unescape(form.group(1)), timeout=120,
           data={"username": user, "password": os.environ["LAKEHOUSE_USER_PASSWORD"], "credentialId": ""})
    return s


def headers(s):
    csrf = s.get(f"{SS}/api/v1/security/csrf_token/", timeout=30).json()["result"]
    return {"X-CSRFToken": csrf, "Referer": f"{SS}/sqllab/"}


def database_id(s):
    return next(d["id"] for d in s.get(f"{SS}/api/v1/database/", timeout=30).json()["result"]
                if d["database_name"] == "Lakehouse (Trino)")


def sql_lab(s, statement):
    """Run a statement in SQL Lab; returns (rows, error message)."""
    r = s.post(f"{SS}/api/v1/sqllab/execute/", headers=headers(s), timeout=120, json={
        "database_id": database_id(s), "sql": statement, "catalog": "iceberg", "schema": "sales",
        "runAsync": False, "client_id": os.urandom(5).hex(), "tab": "checks", "queryLimit": 1000,
        "select_as_cta": False, "ctas_method": "TABLE"})
    j = r.json()
    if r.ok:
        return j["data"], None
    return None, "; ".join(e.get("message", "") for e in j.get("errors", [])) or str(j)


def roles(s):
    return sorted(s.get(f"{SS}/api/v1/me/roles/", timeout=30).json()["result"]["roles"])


def create_dataset(s):
    r = s.post(f"{SS}/api/v1/dataset/", headers=headers(s), timeout=120, json={
        "database": database_id(s), "catalog": "iceberg", "schema": "sales", "table_name": "orders"})
    if r.status_code == 422 and "already exists" in r.text:
        return 201
    return r.status_code


def main():
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if requests.get(f"{SS}/health", timeout=5).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(2)

    alice, bob = sign_in("alice"), sign_in("bob")

    # 1. Keycloak sign-in, groups as roles.
    ra, rb = roles(alice), roles(bob)
    check("people sign in to Superset with Keycloak, and their groups become roles",
          {"sql_lab", "Lakehouse SQL"} <= set(ra) and "Alpha" not in ra and {"Alpha", "Lakehouse SQL"} <= set(rb),
          f"alice {ra}, bob {rb}")
    carol = sign_in("carol")
    me = carol.get(f"{SS}/api/v1/me/", timeout=30).status_code
    check("people in neither group can't sign in", me == 401, f"carol's session: HTTP {me}")

    # 2. Roles decide what people may build.
    a, b = create_dataset(alice), create_dataset(bob)
    check("engineers create datasets, and analysts can't", b == 201 and a in (401, 403), f"bob HTTP {b}, alice HTTP {a}")

    # 3. Queries run as the person, so Ranger's policies follow them.
    rows, err = sql_lab(alice, "SELECT id, region, card_number FROM orders ORDER BY id")
    check("SQL Lab runs alice's query as alice: Ranger's row filter (EU only)",
          rows is not None and {r["region"] for r in rows} == {"EU"} and len(rows) == 3,
          err or f"{len(rows)} rows, regions {sorted({r['region'] for r in rows})}")
    check("... and Ranger's column mask (card numbers' last four digits)",
          rows is not None and all(r["card_number"].startswith("XXXX") for r in rows), err or rows[0]["card_number"])
    rows, err = sql_lab(alice, "SELECT * FROM payroll")
    check("... and Ranger's denials (no payroll)", rows is None and "Access Denied" in (err or ""),
          (err or "").split("message=")[-1].split(", query_id")[0])
    rows, err = sql_lab(bob, "SELECT id, region, card_number FROM orders ORDER BY id")
    check("bob's queries run as bob: every order, unmasked",
          rows is not None and len(rows) == 6 and not any(r["card_number"].startswith("X") for r in rows),
          err or f"{len(rows)} rows, first card {rows[0]['card_number']}")

    # 4. Trino and Ranger see the person, not Superset.
    hits = audited_denials("alice")
    check("Ranger's audit log records alice's denied query under her own name", hits > 0,
          f"{hits} denied requests by alice")
    finish()


if __name__ == "__main__":
    main()
