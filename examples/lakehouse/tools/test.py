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
import functools
import uuid

import requests

from lakekit import (audited_denials, check, code, finish, keys, s3_as, s3_root, wait_for_trino)
from lakekit import denied as _denied, sql as _sql

# Every statement here runs in the iceberg catalog's sales schema.
sql = functools.partial(_sql, catalog="iceberg", schema="sales")
denied = functools.partial(_denied, catalog="iceberg", schema="sales")


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
    files = keys(s3_root(), "warehouse", "sales/")
    data = [k for k in files if k.endswith(".parquet") and "/orders" in k]
    meta = [k for k in files if k.endswith(".metadata.json") and "/orders" in k]
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
    alice = s3_as("alice")
    key = f"alice/{uuid.uuid4().hex}.txt"
    wrote = code(lambda: alice.put_object(Bucket="scratch", Key=key, Body=b"my notes"))
    check("analysts sign in to Buckets with their Keycloak token and use their own bucket", wrote == "OK", wrote)
    got = code(lambda: alice.get_object(Bucket="warehouse", Key=data[0]))
    listed = code(lambda: alice.list_objects_v2(Bucket="warehouse"))
    check("analysts can't read the warehouse's files directly", got == "AccessDenied" and listed == "AccessDenied",
          f"GetObject {got}, ListObjects {listed}")

    # 6. Ranger's audit log (Solr) has the denials.
    hits = audited_denials("carol")
    check("Ranger's audit log records the denials", hits > 0, f"{hits} denied requests by carol")
    finish()


if __name__ == "__main__":
    main()
