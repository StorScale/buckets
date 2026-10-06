"""Configure the lakehouse example: Buckets, then Ranger.

Buckets
  - buckets `warehouse` (Iceberg tables) and `scratch` (people's own files);
  - policy `lakehouse-engine` (the warehouse, read and write) for the engines'
    service accounts, `trino-svc` and `nessie-svc`;
  - policies `analysts` and `engineers`, named after the Keycloak groups people
    sign in with: `scratch` only. Nobody but the engines can read the warehouse,
    so Ranger's masks and row filters can't be bypassed by reading the files.

Ranger
  - Keycloak's users and groups, copied over;
  - the Trino service `lakehouse` and its policies (see POLICIES below).

Safe to run again: everything is created or updated in place.
"""
from lakekit import BASE_POLICIES, allow, bucket_rw, env, log, res, setup_buckets, setup_people_and_ranger

ICEBERG = "iceberg"
POLICIES = BASE_POLICIES + [
    # Engineers own the Iceberg catalog: create schemas and tables, load data.
    # Analysts may only see that it's there. (Ranger allows one access policy
    # per resource, so the catalog's policy has an item for each group.)
    {"name": "iceberg catalog", "resources": res(catalog=ICEBERG),
     "policyItems": [allow(["all"], groups=["engineers"]), allow(["use", "show"], groups=["analysts"])]},
    {"name": "engineers: iceberg schemas", "resources": res(catalog=ICEBERG, schema="*"),
     "policyItems": [allow(["all"], groups=["engineers"])]},
    {"name": "engineers: iceberg tables", "resources": res(catalog=ICEBERG, schema="*", table="*", column="*"),
     "policyItems": [allow(["all"], groups=["engineers"])]},
    # Analysts read one table, sales.orders, and nothing else.
    {"name": "analysts: sales schema", "resources": res(catalog=ICEBERG, schema="sales"),
     "policyItems": [allow(["use", "show"], groups=["analysts"])]},
    {"name": "analysts: sales.orders", "resources": res(catalog=ICEBERG, schema="sales", table="orders", column="*"),
     "policyItems": [allow(["select", "show"], groups=["analysts"])]},
    # ... with card numbers masked to their last four digits,
    {"name": "analysts: mask card numbers", "policyType": 1,
     "resources": res(catalog=ICEBERG, schema="sales", table="orders", column="card_number"),
     "dataMaskPolicyItems": [{**allow(["select"], groups=["analysts"]),
                              "dataMaskInfo": {"dataMaskType": "MASK_SHOW_LAST_4"}}]},
    # ... and only the EU's orders.
    {"name": "analysts: EU orders only", "policyType": 2,
     "resources": res(catalog=ICEBERG, schema="sales", table="orders"),
     "rowFilterPolicyItems": [{**allow(["select"], groups=["analysts"]),
                               "rowFilterInfo": {"filterExpr": "region = 'EU'"}}]},
]

if __name__ == "__main__":
    setup_buckets(
        buckets=["warehouse", "scratch"],
        policies={"lakehouse-engine": bucket_rw("warehouse"),
                  "analysts": bucket_rw("scratch"), "engineers": bucket_rw("scratch")},
        accounts=[(env["TRINO_S3_ACCESS_KEY"], env["TRINO_S3_SECRET_KEY"], "lakehouse-engine"),
                  (env["NESSIE_S3_ACCESS_KEY"], env["NESSIE_S3_SECRET_KEY"], "lakehouse-engine")])
    setup_people_and_ranger(POLICIES)
    log("done")
