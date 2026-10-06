"""End-to-end checks for the Dremio example: docker compose run --rm test

  1. Dremio reads the lakehouse's Iceberg tables, which Trino wrote, through
     the same Nessie catalog, and both engines agree on the data;
  2. Dremio reads the table as it was at an earlier Nessie commit;
  3. Dremio reads raw Parquet files in Buckets;
  4. Dremio's Buckets account may only read: Buckets refuses Dremio's writes,
     and the table is unchanged;
  5. people's access to the data stays where it's governed: Trino and Ranger
     still mask and filter for analysts.
"""
import requests

from dremio import Dremio
from lakekit import ORDERS, check, finish, sql

NESSIE = "http://nessie:19120/api/v2"


def trino(user, statement):
    return sql(user, statement, catalog="iceberg", schema="sales")


def main():
    d = Dremio()

    # 1. One catalog, two engines.
    rows, err = d.sql("SELECT count(*) AS n, sum(amount) AS total FROM lakehouse.sales.orders")
    t = trino("bob", "SELECT count(*), sum(amount) FROM orders")[0]
    check("Dremio reads the lakehouse's Iceberg table through Nessie", rows and rows[0]["n"] == len(ORDERS),
          err or f"{rows[0]['n']} rows")
    check("Dremio and Trino agree on the table", rows and abs(float(rows[0]["total"]) - float(t[1])) < 0.005,
          err or f"total {rows[0]['total']} in Dremio, {t[1]} in Trino")

    # 2. Nessie's history, from Dremio.
    log = requests.get(f"{NESSIE}/trees/main/history", params={"max-records": 100}, timeout=10).json()["logEntries"]
    created = next(e["commitMeta"]["hash"] for e in log if e["commitMeta"]["message"] == "Create ICEBERG_TABLE sales.orders")
    then, err = d.sql(f'SELECT count(*) AS n FROM lakehouse.sales.orders AT COMMIT "{created}"')
    check("Dremio reads the table at an earlier Nessie commit", then and then[0]["n"] == 0,
          err or f"{then[0]['n']} rows at commit {created[:12]} (when it was created), {rows[0]['n']} now")

    # 3. Raw files in Buckets.
    raw, err = d.sql('SELECT count(*) AS n, count(DISTINCT region) AS regions FROM buckets.datasets.sales."orders.parquet"')
    check("Dremio reads raw Parquet files in Buckets", raw and raw[0]["n"] == len(ORDERS),
          err or f"{raw[0]['n']} rows, {raw[0]['regions']} regions in datasets/sales/orders.parquet")

    # 4. Read-only, enforced by Buckets.
    _, err = d.sql("INSERT INTO lakehouse.sales.orders VALUES (9, 'Zed', '4000', 'EU', 1.00, DATE '2026-09-09')")
    check("Buckets refuses Dremio's writes (its account may only read)",
          err is not None and "AccessDenied" in err and "403" in err,
          (err or "the insert succeeded").splitlines()[0][:120])
    after = trino("bob", "SELECT count(*) FROM orders")[0][0]
    check("the refused write leaves the table unchanged", after == len(ORDERS), f"{after} rows in Trino")

    # 5. People's access is governed in Trino and Ranger.
    seen = trino("alice", "SELECT region, card_number FROM orders")
    check("analysts still get Ranger's masks and filters through Trino",
          {r[0] for r in seen} == {"EU"} and all(r[1].startswith("XXXX") for r in seen),
          f"alice: {len(seen)} EU rows, cards {seen[0][1]}")
    finish()


if __name__ == "__main__":
    main()
