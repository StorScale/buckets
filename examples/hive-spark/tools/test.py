"""End-to-end checks for the Hive Metastore and Spark example:
docker compose run --rm test

  1. Spark writes a partitioned Hive table, sales.orders, through the metastore;
     Trino reads it, partitions and all;
  2. Trino adds rows to it, and Spark reads them;
  3. Spark builds an Iceberg table from it, analytics.daily_revenue; Trino reads
     and changes it; both read its earlier snapshot (time travel);
  4. all of it is files in Buckets' warehouse bucket;
  5. Ranger governs Trino: alice (analysts) gets EU orders with card numbers
     masked, and the revenue table, and nothing else; carol (no group) nothing;
  6. alice signs in to Buckets with her Keycloak token: the warehouse's files
     are refused, so she can't read around Ranger;
  7. Ranger's audit log has the denials.
"""
import uuid

from pyspark.sql import SparkSession

from lakekit import audited_denials, check, code, denied, finish, keys, s3_as, s3_root, sql, wait_for_trino

def hive(statement, user="bob"):
    return sql(user, statement, catalog="hive", schema="sales")


def iceberg(statement, user="bob"):
    return sql(user, statement, catalog="iceberg", schema="analytics")


ORDERS = [
    (1, "Ana", "4111111111111111", 120.50, "2026-09-01", "EU"),
    (2, "Ben", "5500000000000004", 75.00, "2026-09-02", "US"),
    (3, "Chloe", "340000000000009", 310.25, "2026-09-03", "EU"),
    (4, "Dev", "6011000000000004", 42.00, "2026-09-04", "APAC"),
    (5, "Eva", "3530111333300000", 18.99, "2026-09-05", "EU"),
    (6, "Finn", "4012888888881881", 99.95, "2026-09-06", "US"),
]
GUS = (7, "Gus", "4222222222222", 64.10, "2026-09-07", "EU")


def main():
    wait_for_trino()
    spark = SparkSession.builder.remote("sc://spark:15002").getOrCreate()
    run = spark.sql

    # 1. Spark writes a partitioned Hive table; Trino reads it.
    for db in ("sales", "hr"):
        run(f"CREATE DATABASE IF NOT EXISTS {db}")
    for t in ("sales.orders", "hr.payroll"):
        run(f"DROP TABLE IF EXISTS {t}")
    run("CREATE TABLE sales.orders (id BIGINT, customer STRING, card_number STRING, amount DECIMAL(10,2), "
        "order_date DATE) PARTITIONED BY (region STRING) STORED AS PARQUET")
    values = ", ".join(f"({i}, '{c}', '{n}', {a}, DATE '{d}', '{r}')" for i, c, n, a, d, r in ORDERS)
    run(f"INSERT INTO sales.orders VALUES {values}")
    run("CREATE TABLE hr.payroll (employee STRING, salary DECIMAL(10,2)) STORED AS PARQUET")
    run("INSERT INTO hr.payroll VALUES ('Ana', 5000.00)")
    count = hive("SELECT count(*) FROM orders")[0][0]
    parts = sorted(r[0] for r in hive('SELECT region FROM "orders$partitions"'))
    check("Spark writes a partitioned Hive table, and Trino reads it", count == 6 and parts == ["APAC", "EU", "US"],
          f"{count} rows in partitions {', '.join(parts)}")

    # 2. Trino writes; Spark reads.
    i, c, n, a, d, r = GUS
    hive(f"INSERT INTO orders VALUES ({i}, '{c}', '{n}', {a}, DATE '{d}', '{r}')")
    run("REFRESH TABLE sales.orders")
    seen = run("SELECT count(*) AS n FROM sales.orders WHERE region = 'EU'").collect()[0]["n"]
    check("Trino adds rows, and Spark reads them", seen == 4, f"Spark sees {seen} EU orders")

    # 3. An Iceberg table: Spark builds it, Trino changes it, both time travel.
    run("CREATE NAMESPACE IF NOT EXISTS iceberg.analytics")
    run("DROP TABLE IF EXISTS iceberg.analytics.daily_revenue")
    run("CREATE TABLE iceberg.analytics.daily_revenue USING iceberg AS "
        "SELECT order_date, region, sum(amount) AS revenue FROM sales.orders GROUP BY order_date, region")
    first = run("SELECT snapshot_id FROM iceberg.analytics.daily_revenue.snapshots").collect()[0]["snapshot_id"]
    rows = iceberg("SELECT count(*), sum(revenue) FROM daily_revenue")[0]
    iceberg("UPDATE daily_revenue SET revenue = revenue * 2 WHERE region = 'US'")
    now = run("SELECT sum(revenue) AS r FROM iceberg.analytics.daily_revenue").collect()[0]["r"]
    then_spark = run(f"SELECT sum(revenue) AS r FROM iceberg.analytics.daily_revenue VERSION AS OF {first}").collect()[0]["r"]
    then_trino = iceberg(f"SELECT sum(revenue) FROM daily_revenue FOR VERSION AS OF {first}")[0][0]
    check("Spark builds an Iceberg table, and Trino reads and changes it", rows[0] == 7 and now > rows[1],
          f"{rows[0]} rows; revenue {rows[1]}, then {now} after Trino's update")
    check("both engines read the table's first snapshot (time travel)", then_spark == then_trino == rows[1],
          f"Spark {then_spark}, Trino {then_trino}")

    # 4. All of it is files in Buckets.
    files = keys(s3_root(), "warehouse", "hive/")
    orders = [k for k in files if k.startswith("hive/sales.db/orders/region=")]
    ice = [k for k in files if k.startswith("hive/analytics.db/daily_revenue/") and k.endswith(".metadata.json")]
    check("the tables are files in Buckets", orders and ice,
          f"{len(orders)} files under hive/sales.db/orders/region=*, {len(ice)} Iceberg metadata files")

    # 5. Ranger: analysts get EU orders, masked, and the revenue table; nothing else.
    rows = hive("SELECT id, region, card_number FROM orders ORDER BY id", user="alice")
    regions = {r[1] for r in rows}
    check("Ranger's row filter: analysts see only EU orders", regions == {"EU"} and len(rows) == 4,
          f"{len(rows)} rows, regions {sorted(regions)}")
    cards = {o[0]: o[2] for o in ORDERS + [GUS]}
    masked = all(r[2] != cards[r[0]] and r[2].endswith(cards[r[0]][-4:]) for r in rows)
    check("Ranger's column mask: analysts see only card numbers' last four digits", masked, rows[0][2])
    revenue = iceberg("SELECT count(*) FROM daily_revenue", user="alice")[0][0]
    check("analysts read the Iceberg revenue table", revenue == 7, f"{revenue} rows")
    msg = denied("alice", "SELECT * FROM hr.payroll", catalog="hive")
    check("analysts can't read other tables", msg, msg)
    msg = denied("alice", "INSERT INTO sales.orders VALUES (8, 'Hal', '4000', 1, DATE '2026-09-08', 'EU')", catalog="hive")
    check("analysts can't write", msg, msg)
    msg = denied("carol", "SELECT count(*) FROM sales.orders", catalog="hive")
    check("people in neither group are denied", msg, msg)

    # 6. Buckets: the warehouse's files are the engines' only.
    alice = s3_as("alice")
    wrote = code(lambda: alice.put_object(Bucket="scratch", Key=f"alice/{uuid.uuid4().hex}.txt", Body=b"notes"))
    got = code(lambda: alice.get_object(Bucket="warehouse", Key=orders[0]))
    check("analysts use their own bucket, and can't read the warehouse's files",
          wrote == "OK" and got == "AccessDenied", f"scratch PutObject {wrote}, warehouse GetObject {got}")

    # 7. Ranger's audit log has the denials.
    hits = audited_denials("carol")
    check("Ranger's audit log records the denials", hits > 0, f"{hits} denied requests by carol")
    finish()


if __name__ == "__main__":
    main()
