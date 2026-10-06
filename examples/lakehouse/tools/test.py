"""End-to-end checks for the lakehouse example: docker compose run --rm test

  1. bob (engineers) creates Iceberg tables through Trino, loads them and
     changes one, and Nessie records each change as a commit;
  2. the tables' data and metadata are files in Buckets' warehouse bucket;
  3. alice (analysts) reads sales.orders through Trino with Ranger's row filter
     (EU only) and column mask (card numbers' last four digits), and is denied
     everything else;
  4. carol (no group) is denied by Ranger;
  5. alice signs in to Buckets with the same Keycloak token: her own bucket
     works, the warehouse's files are refused, so she can't read around Ranger;
  6. Ranger's audit log has the denials.
"""
import os
import re
import sys
import time
import uuid

import boto3
import requests
import trino
from botocore.config import Config
from botocore.exceptions import ClientError

env = os.environ
KEYCLOAK_TOKEN = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
BUCKETS = "http://buckets:9000"
failures = []


def check(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {name}{f'  ({detail})' if detail else ''}", flush=True)
    if not ok:
        failures.append(name)


def token(user):
    r = requests.post(KEYCLOAK_TOKEN, data={"grant_type": "password", "client_id": "lakehouse",
                                            "username": user, "password": env["LAKEHOUSE_USER_PASSWORD"]}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def sql(user, statement):
    conn = trino.dbapi.connect(host="trino", port=8443, http_scheme="https", user=user,
                               auth=trino.auth.JWTAuthentication(token(user)), verify="/tls/cert.pem",
                               catalog="iceberg", schema="sales")
    cur = conn.cursor()
    cur.execute(statement)
    return cur.fetchall()


def denied(user, statement):
    """The Trino error if Ranger refuses the statement, else None."""
    try:
        sql(user, statement)
    except trino.exceptions.TrinoUserError as e:
        if e.error_name == "PERMISSION_DENIED":
            return e.message
        raise
    return None


def s3(**creds):
    return boto3.client("s3", endpoint_url=BUCKETS, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}), **creds)


def code(fn):
    try:
        fn()
        return "OK"
    except ClientError as e:
        return e.response["Error"]["Code"]


def wait_for_trino():
    deadline = time.time() + 300
    while True:
        try:
            if requests.get("https://trino:8443/v1/info", verify="/tls/cert.pem", timeout=5).json()["starting"] is False:
                return
        except (requests.RequestException, ValueError, KeyError):
            pass
        if time.time() > deadline:
            sys.exit("test: Trino did not start")
        time.sleep(2)


ORDERS = [
    (1, "Ana", "4111111111111111", "EU", 120.50, "2026-09-01"),
    (2, "Ben", "5500000000000004", "US", 75.00, "2026-09-02"),
    (3, "Chloe", "340000000000009", "EU", 310.25, "2026-09-03"),
    (4, "Dev", "6011000000000004", "APAC", 42.00, "2026-09-04"),
    (5, "Eva", "3530111333300000", "EU", 18.99, "2026-09-05"),
    (6, "Finn", "4012888888881881", "US", 99.95, "2026-09-06"),
]


def main():
    wait_for_trino()

    # 1. Engineers build the tables.
    sql("bob", "CREATE SCHEMA IF NOT EXISTS iceberg.sales")
    for t in ("orders", "payroll"):
        sql("bob", f"DROP TABLE IF EXISTS {t}")
    sql("bob", "CREATE TABLE orders (id bigint, customer varchar, card_number varchar, region varchar, "
               "amount decimal(10,2), order_date date)")
    values = ", ".join(f"({i}, '{c}', '{n}', '{r}', {a}, DATE '{d}')" for i, c, n, r, a, d in ORDERS)
    sql("bob", f"INSERT INTO orders VALUES {values}")
    sql("bob", "INSERT INTO orders VALUES (7, 'Gus', '4222222222222', 'EU', 64.10, DATE '2026-09-07')")
    sql("bob", "UPDATE orders SET amount = 130.50 WHERE id = 1")
    now = sql("bob", "SELECT count(*), max(amount) FILTER (WHERE id = 1) FROM orders")[0]
    check("engineers create, load and change an Iceberg table", now[0] == 7 and float(now[1]) == 130.5,
          f"{now[0]} rows, order 1 now {now[1]}")
    # Nessie keeps a table's history as catalog commits (like git), not as Iceberg snapshots.
    log = requests.get("http://nessie:19120/api/v2/trees/main/history", params={"max-records": 50}, timeout=10).json()
    changes = [e for e in log["logEntries"] if "sales.orders" in e["commitMeta"].get("message", "")]
    check("Nessie records every change as a commit", len(changes) >= 4,
          f"{len(changes)} commits for sales.orders on branch main")
    sql("bob", "CREATE TABLE payroll (employee varchar, salary decimal(10,2))")
    sql("bob", "INSERT INTO payroll VALUES ('Ana', 5000.00)")

    # 2. The table is files in Buckets.
    root = s3(aws_access_key_id=env["BUCKETS_ROOT_USER"], aws_secret_access_key=env["BUCKETS_ROOT_PASSWORD"])
    keys = [o["Key"] for p in root.get_paginator("list_objects_v2").paginate(Bucket="warehouse", Prefix="sales/")
            for o in p.get("Contents", [])]
    data = [k for k in keys if k.endswith(".parquet") and "/orders" in k]
    meta = [k for k in keys if k.endswith(".metadata.json") and "/orders" in k]
    check("the table's data and metadata are in Buckets", data and meta,
          f"{len(data)} Parquet files, {len(meta)} metadata files under s3://warehouse/sales/")

    # 3. Analysts: one table, EU rows only, card numbers masked.
    rows = sql("alice", "SELECT id, region, card_number FROM orders ORDER BY id")
    regions = {r[1] for r in rows}
    check("Ranger's row filter: analysts see only EU orders", regions == {"EU"} and len(rows) == 4,
          f"{len(rows)} rows, regions {sorted(regions)}")
    cards = {i: n for i, _, n, *_ in ORDERS} | {7: "4222222222222"}
    masked = all(r[2] != cards[r[0]] and r[2].endswith(cards[r[0]][-4:]) for r in rows)
    check("Ranger's column mask: analysts see only card numbers' last four digits", masked, rows[0][2])
    msg = denied("alice", "SELECT * FROM payroll")
    check("analysts can't read other tables", msg, msg)
    msg = denied("alice", "CREATE TABLE notes (t varchar)")
    check("analysts can't create tables", msg, msg)
    msg = denied("alice", "INSERT INTO orders VALUES (8, 'Hal', '4000', 'EU', 1, DATE '2026-09-08')")
    check("analysts can't write to sales.orders", msg, msg)

    # 4. No group, no access.
    msg = denied("carol", "SELECT count(*) FROM orders")
    check("people in neither group are denied", msg, msg)

    # 5. Buckets: people sign in with the same token, and can't read the warehouse.
    sts = boto3.client("sts", endpoint_url=BUCKETS, region_name="us-east-1",
                       aws_access_key_id="unused", aws_secret_access_key="unused")
    c = sts.assume_role_with_web_identity(RoleArn="arn:minio:iam:::role/lakehouse", RoleSessionName="alice",
                                          WebIdentityToken=token("alice"), DurationSeconds=900)["Credentials"]
    alice = s3(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
               aws_session_token=c["SessionToken"])
    key = f"alice/{uuid.uuid4().hex}.txt"
    wrote = code(lambda: alice.put_object(Bucket="scratch", Key=key, Body=b"my notes"))
    check("analysts sign in to Buckets with their Keycloak token and use their own bucket", wrote == "OK", wrote)
    got = code(lambda: alice.get_object(Bucket="warehouse", Key=data[0]))
    listed = code(lambda: alice.list_objects_v2(Bucket="warehouse"))
    check("analysts can't read the warehouse's files directly", got == "AccessDenied" and listed == "AccessDenied",
          f"GetObject {got}, ListObjects {listed}")

    # 6. Ranger's audit log (Solr) has the denials. The plugin sends audits in batches.
    deadline = time.time() + 90
    hits = 0
    while time.time() < deadline and not hits:
        r = requests.get("http://ranger-solr:8983/solr/ranger_audits/select",
                         params={"q": "reqUser:carol AND result:0", "rows": 0}, timeout=10)
        hits = r.json()["response"]["numFound"] if r.ok else 0
        if not hits:
            time.sleep(5)
    check("Ranger's audit log records the denials", hits > 0, f"{hits} denied requests by carol")

    print()
    if failures:
        sys.exit(f"{len(failures)} of the checks failed")
    print("all checks passed")


if __name__ == "__main__":
    main()
