"""End-to-end checks for the monitoring example: docker compose run --rm test

  1. Prometheus scrapes all three of Buckets' metrics endpoints, as a
     metrics-only user, which can read no data;
  2. the Helm chart's alert rules load, with no errors;
  3. the four Grafana dashboards' queries return data from Prometheus;
  4. a failed drive (here, emptied under load) shows up: Buckets reports it
     offline and the erasure set degraded, and the alerts for both start.
     (Rerun on the same stack, this checks the drive that is already offline.)
"""
import glob
import json
import os
import re
import time

import requests
from botocore.exceptions import ClientError

from lakekit import check, env, finish, s3

PROM = "http://prometheus:9090/api/v1"
GRAFANA = "http://grafana:3000"
DASHBOARDS = "/dashboards/*.json"
VARS = {"$namespace": "local", "$cluster": "store", "${namespace}": "local", "${cluster}": "store",
        "$__rate_interval": "1m", "$__interval": "15s", "$__range": "10m", "${__rate_interval}": "1m"}


def query(expr):
    r = requests.get(f"{PROM}/query", params={"query": expr}, timeout=30).json()
    return r["data"]["result"] if r.get("status") == "success" else None


def value(expr):
    res = query(expr)
    return float(res[0]["value"][1]) if res else None


def wait(fn, timeout, every=5):
    deadline = time.time() + timeout
    while True:
        got = fn()
        if got or time.time() > deadline:
            return got
        time.sleep(every)


def alerts():
    return {a["labels"]["alertname"]: a["state"]
            for a in requests.get(f"{PROM}/alerts", timeout=30).json()["data"]["alerts"]}


def dashboard_queries():
    """{dashboard title: [(panel title, expr)]}, from the dashboards Grafana loaded."""
    auth = ("admin", env["GRAFANA_ADMIN_PASSWORD"])
    out = {}
    for d in requests.get(f"{GRAFANA}/api/search", params={"type": "dash-db", "query": "Buckets"},
                          auth=auth, timeout=30).json():
        dash = requests.get(f"{GRAFANA}/api/dashboards/uid/{d['uid']}", auth=auth, timeout=30).json()["dashboard"]
        panels = [p for p in dash["panels"] if p.get("type") != "row"]
        out[dash["title"]] = [(p.get("title", ""), t["expr"]) for p in panels for t in p.get("targets", []) if t.get("expr")]
    return out


def main():
    # 1. Scraping, as a metrics-only user.
    up = wait(lambda: (lambda r: r if r and len(r) == 3 and all(x["value"][1] == "1" for x in r) else None)(query("up")), 120)
    check("Prometheus scrapes Buckets' node, cluster and bucket metrics",
          up is not None, ", ".join(sorted(f"{x['metric']['job']} up" for x in (up or []))) or "not all up")
    try:
        s3(aws_access_key_id=env["PROMETHEUS_USER"], aws_secret_access_key=env["PROMETHEUS_SECRET"]).list_objects_v2(Bucket="photos")
        denied = "allowed"
    except ClientError as e:
        denied = e.response["Error"]["Code"]
    check("... as a metrics-only user, which can read no data", denied == "AccessDenied", f"ListObjects: {denied}")

    # 2. The alert rules.
    rules = [r for g in requests.get(f"{PROM}/rules", timeout=30).json()["data"]["groups"] for r in g["rules"]]
    bad = [r["name"] for r in rules if r.get("health") != "ok"]
    check("the Helm chart's alert rules load, with no errors", rules and not bad,
          f"{len(rules)} rules" + (f"; unhealthy: {bad}" if bad else ""))

    # 3. The dashboards' queries.
    dashboards = wait(dashboard_queries, 60)
    total = with_data = 0
    empty = []
    for title, targets in sorted(dashboards.items()):
        for panel, expr in targets:
            for k, v in VARS.items():
                expr = expr.replace(k, v)
            res = query(expr)
            total += 1
            if res:
                with_data += 1
            else:
                empty.append(f"{title.split(' / ')[-1]}: {panel}")
    check("Grafana has the four dashboards", len(dashboards) == 4, ", ".join(sorted(dashboards)))
    # Panels for what this example doesn't run (replication, the KMS, the
    # console's sign-ins) have nothing to show.
    check("the dashboards' queries return data", with_data >= total * 0.6,
          f"{with_data} of {total} queries; empty: {'; '.join(empty[:8])}{' ...' if len(empty) > 8 else ''}")

    # 4. A failed drive.
    if (value("max(minio_cluster_drive_offline_total)") or 0) == 0:
        for p in glob.glob("/drive3/*") + glob.glob("/drive3/.*"):
            os.system(f"rm -rf '{p}'")
    offline = wait(lambda: (value("max(minio_cluster_drive_offline_total)") or 0) >= 1, 180)
    check("an emptied drive shows up as offline", offline,
          f"drives online {value('max(minio_cluster_drive_online_total)'):.0f}, offline "
          f"{value('max(minio_cluster_drive_offline_total)'):.0f}")
    started = wait(lambda: (lambda a: a if {"BucketsDriveOffline", "BucketsErasureSetDegraded"} <= set(a) else None)(alerts()), 180)
    check("the drive-offline and degraded-set alerts start", started,
          ", ".join(f"{k} {v}" for k, v in sorted((started or alerts()).items())) or "no alerts")
    finish()


if __name__ == "__main__":
    main()
