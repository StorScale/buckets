"""Land a day's orders in Buckets, then load them into the lakehouse's
iceberg.sales.orders through Trino. Both tasks run as the pipelines' own
identity (lakehouse_identity), not as whoever triggered the run."""
import csv
import io

import pendulum
from botocore.exceptions import ClientError

from airflow.sdk import dag, get_current_context, task

NEW_ORDERS = [
    (101, "Gus", "4222222222222", "EU", 64.10, "2026-09-07"),
    (102, "Hana", "4000056655665556", "APAC", 212.00, "2026-09-07"),
]


@dag(schedule=None, start_date=pendulum.datetime(2026, 9, 1, tz="UTC"), catchup=False,
     tags=["lakehouse"], doc_md=__doc__)
def sales_ingest():

    @task
    def land_orders():
        from lakehouse_identity import buckets_s3
        s3 = buckets_s3()
        run = get_current_context()["run_id"].replace(":", "-").replace("+", "-")
        buf = io.StringIO()
        csv.writer(buf).writerows(NEW_ORDERS)
        key = f"sales/orders-{run}.csv"
        s3.put_object(Bucket="landing", Key=key, Body=buf.getvalue().encode())
        try:                                        # the pipelines' policy covers landing/ only
            s3.list_objects_v2(Bucket="warehouse")
            warehouse = "OK"
        except ClientError as e:
            warehouse = e.response["Error"]["Code"]
        return {"key": key, "warehouse": warehouse}

    @task
    def load_orders(landed):
        from lakehouse_identity import buckets_s3, trino
        body = buckets_s3().get_object(Bucket="landing", Key=landed["key"])["Body"].read().decode()
        rows = list(csv.reader(io.StringIO(body)))
        cur = trino().cursor()
        cur.execute("SELECT current_user")
        me = cur.fetchall()[0][0]
        cur.execute("DELETE FROM orders WHERE id IN (" + ", ".join(r[0] for r in rows) + ")")
        cur.fetchall()
        values = ", ".join(f"({i}, '{c}', '{n}', '{r}', {a}, DATE '{d}')" for i, c, n, r, a, d in rows)
        cur.execute(f"INSERT INTO orders VALUES {values}")
        cur.fetchall()
        cur.execute("SELECT count(*) FROM orders")
        return {"trino_user": me, "inserted": len(rows), "orders": cur.fetchall()[0][0], **landed}

    load_orders(land_orders())


sales_ingest()
