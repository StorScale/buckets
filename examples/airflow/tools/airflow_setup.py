"""Configure the lakehouse for Airflow's pipelines, after the lakehouse's own setup:

  - Buckets: the landing bucket, and the policy "pipelines" (named after the
    Keycloak group the pipelines' service account is in): landing/, read and
    write, and nothing else;
  - Ranger: the service account as a user in group "pipelines" (Keycloak
    doesn't list service accounts among its users), and the lakehouse's
    policies plus the pipelines group: run queries, and read, insert and
    delete in iceberg.sales.orders;
  - data: iceberg.sales.orders and iceberg.sales.payroll.

Safe to run again.
"""
import copy
import importlib.util

from lakekit import allow, bucket_rw, keycloak_people, load_sales_tables, log, res, setup_buckets, setup_ranger, sync_people

spec = importlib.util.spec_from_file_location("lakehouse_setup", "/lakehouse/setup.py")
lakehouse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lakehouse)

SERVICE_ACCOUNT = "service-account-airflow-pipelines"
GROUP = "pipelines"


def grant(policies, name, resources, item, policy_type=0):
    """Add an item to the policy on these resources, or a new policy. (Ranger
    allows one policy of each type per resource.)"""
    for p in policies:
        if p["resources"] == resources and p.get("policyType", 0) == policy_type:
            p["policyItems"] = p.get("policyItems", []) + [item]
            return
    policies.append({"name": name, "resources": resources, "policyItems": [item]})


POLICIES = copy.deepcopy(lakehouse.POLICIES)
grant(POLICIES, "run queries", res(queryid="*"), allow(["execute"], groups=[GROUP]))
grant(POLICIES, "iceberg catalog", res(catalog="iceberg"), allow(["use", "show"], groups=[GROUP]))
grant(POLICIES, "pipelines: sales schema", res(catalog="iceberg", schema="sales"), allow(["use", "show"], groups=[GROUP]))
grant(POLICIES, "pipelines: sales.orders", res(catalog="iceberg", schema="sales", table="orders", column="*"),
      allow(["select", "insert", "delete", "show"], groups=[GROUP]))

if __name__ == "__main__":
    setup_buckets(buckets=["landing"], policies={GROUP: bucket_rw("landing")}, accounts=[])
    sync_people({**keycloak_people(), SERVICE_ACCOUNT: [GROUP]})
    setup_ranger(POLICIES)
    load_sales_tables()
    log("done")
