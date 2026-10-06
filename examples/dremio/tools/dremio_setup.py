"""Configure the Dremio example, after the lakehouse's own setup:

  - data: iceberg.sales.orders and iceberg.sales.payroll, written through Trino
    by bob, so they're in the Nessie catalog Dremio reads too; and a Parquet
    file, datasets/sales/orders.parquet, for Dremio to read as raw files;
  - Buckets: Dremio's service account, dremio-svc, which may read the
    warehouse and the datasets bucket, and write nothing;
  - Dremio: its first administrator, and two sources:
      lakehouse: the Nessie catalog (Iceberg tables in s3://warehouse/);
      buckets:   the datasets bucket, raw files.

Safe to run again.
"""
import io

import pandas as pd
import requests

from dremio import DREMIO, Dremio
from lakekit import ORDERS, env, load_sales_tables, log, s3_root, setup_buckets


def read_only(*buckets):
    return [
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
         "Resource": [f"arn:aws:s3:::{b}" for b in buckets]},
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{b}/*" for b in buckets]},
    ]


S3_PROPS = [  # Buckets, as S3-compatible storage
    {"name": "fs.s3a.endpoint", "value": "buckets:9000"},
    {"name": "fs.s3a.path.style.access", "value": "true"},
    {"name": "fs.s3a.connection.ssl.enabled", "value": "false"},
    {"name": "dremio.s3.compat", "value": "true"},
]
SOURCES = {
    "lakehouse": {"type": "NESSIE", "config": {
        "nessieEndpoint": "http://nessie:19120/api/v2", "nessieAuthType": "NONE",
        "storageProvider": "AWS", "awsRootPath": "warehouse",
        "credentialType": "ACCESS_KEY", "awsAccessKey": env["DREMIO_S3_ACCESS_KEY"],
        "awsAccessSecret": env["DREMIO_S3_SECRET_KEY"], "secure": False, "propertyList": S3_PROPS}},
    "buckets": {"type": "S3", "config": {
        "credentialType": "ACCESS_KEY", "accessKey": env["DREMIO_S3_ACCESS_KEY"],
        "accessSecret": env["DREMIO_S3_SECRET_KEY"], "secure": False, "compatibilityMode": True,
        "rootPath": "/", "whitelistedBuckets": ["datasets"], "propertyList": S3_PROPS},
        "metadataPolicy": {"autoPromoteDatasets": True, "authTTLMs": 86400000, "namesRefreshMs": 3600000,
                           "datasetRefreshAfterMs": 3600000, "datasetExpireAfterMs": 10800000,
                           "datasetUpdateMode": "PREFETCH_QUERIED", "deleteUnavailableDatasets": True}},
}


def first_admin():
    """Dremio's first user, the administrator (only possible once)."""
    r = requests.put(f"{DREMIO}/apiv2/bootstrap/firstuser", timeout=30,
                     headers={"Authorization": "_dremionull", "Content-Type": "application/json"},
                     json={"userName": "admin", "firstName": "Dremio", "lastName": "Admin",
                           "email": "admin@example.com", "createdAt": 0,
                           "password": env["DREMIO_ADMIN_PASSWORD"]})
    if r.status_code not in (200, 400, 409):   # 400 or 409: there's one already
        r.raise_for_status()


def sources(d):
    for name, spec in SOURCES.items():
        body = {"entityType": "source", "name": name, **spec}
        try:
            current = d.api("GET", f"/catalog/by-path/{name}")
            d.api("PUT", f"/catalog/{current['id']}", json={**body, "id": current["id"], "tag": current["tag"]})
        except RuntimeError as e:
            if " 404 " not in str(e):
                raise
            d.api("POST", "/catalog", json=body)


if __name__ == "__main__":
    load_sales_tables()
    setup_buckets(buckets=["datasets"], policies={"dremio-read": read_only("warehouse", "datasets")},
                  accounts=[(env["DREMIO_S3_ACCESS_KEY"], env["DREMIO_S3_SECRET_KEY"], "dremio-read")])
    df = pd.DataFrame(ORDERS, columns=["id", "customer", "card_number", "region", "amount", "order_date"])
    buf = io.BytesIO()
    df.drop(columns=["card_number"]).to_parquet(buf, index=False)
    s3_root().put_object(Bucket="datasets", Key="sales/orders.parquet", Body=buf.getvalue())
    log("Buckets: datasets/sales/orders.parquet")

    first_admin()
    sources(Dremio())
    log(f"Dremio: sources {', '.join(SOURCES)}")
    log("done")
