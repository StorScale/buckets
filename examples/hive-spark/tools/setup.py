"""Configure the Hive Metastore and Spark example: Buckets, then Ranger.

Buckets
  - buckets `warehouse` (Hive and Iceberg tables) and `scratch` (people's own files);
  - policy `lakehouse-engine` (the warehouse, read and write) for the service
    accounts of Spark, Trino and the metastore: `spark-svc`, `trino-svc`, `hms-svc`;
  - policies `analysts` and `engineers`, named after the Keycloak groups people
    sign in with: `scratch` only.

Ranger: Keycloak's users and groups, and the Trino service `lakehouse` with the
policies below, over two catalogs: `hive` (Hive tables) and `iceberg`.

Safe to run again: everything is created or updated in place.
"""
from lakekit import BASE_POLICIES, allow, bucket_rw, env, log, res, setup_buckets, setup_people_and_ranger


def engineers_own(catalog):
    """Engineers do anything in the catalog; analysts may only see it's there.
    (Ranger allows one access policy per resource, so the catalog's policy has
    an item for each group.)"""
    return [
        {"name": f"{catalog} catalog", "resources": res(catalog=catalog),
         "policyItems": [allow(["all"], groups=["engineers"]), allow(["use", "show"], groups=["analysts"])]},
        {"name": f"engineers: {catalog} schemas", "resources": res(catalog=catalog, schema="*"),
         "policyItems": [allow(["all"], groups=["engineers"])]},
        {"name": f"engineers: {catalog} tables", "resources": res(catalog=catalog, schema="*", table="*", column="*"),
         "policyItems": [allow(["all"], groups=["engineers"])]},
    ]


def analysts_read(catalog, schema, table):
    return [
        {"name": f"analysts: {catalog}.{schema}", "resources": res(catalog=catalog, schema=schema),
         "policyItems": [allow(["use", "show"], groups=["analysts"])]},
        {"name": f"analysts: {catalog}.{schema}.{table}",
         "resources": res(catalog=catalog, schema=schema, table=table, column="*"),
         "policyItems": [allow(["select", "show"], groups=["analysts"])]},
    ]


POLICIES = BASE_POLICIES + engineers_own("hive") + engineers_own("iceberg") + [
    # Analysts read hive.sales.orders, which Spark writes: EU rows only, card
    # numbers masked to their last four digits. hive.hr is engineers' only.
    *analysts_read("hive", "sales", "orders"),
    {"name": "analysts: mask card numbers", "policyType": 1,
     "resources": res(catalog="hive", schema="sales", table="orders", column="card_number"),
     "dataMaskPolicyItems": [{**allow(["select"], groups=["analysts"]),
                              "dataMaskInfo": {"dataMaskType": "MASK_SHOW_LAST_4"}}]},
    {"name": "analysts: EU orders only", "policyType": 2,
     "resources": res(catalog="hive", schema="sales", table="orders"),
     "rowFilterPolicyItems": [{**allow(["select"], groups=["analysts"]),
                               "rowFilterInfo": {"filterExpr": "region = 'EU'"}}]},
    # ... and the Iceberg table of daily revenue, which has no personal data.
    *analysts_read("iceberg", "analytics", "daily_revenue"),
]

if __name__ == "__main__":
    setup_buckets(
        buckets=["warehouse", "scratch"],
        policies={"lakehouse-engine": bucket_rw("warehouse"),
                  "analysts": bucket_rw("scratch"), "engineers": bucket_rw("scratch")},
        accounts=[(env[f"{e}_S3_ACCESS_KEY"], env[f"{e}_S3_SECRET_KEY"], "lakehouse-engine")
                  for e in ("TRINO", "SPARK", "HMS")])
    setup_people_and_ranger(POLICIES)
    log("done")
