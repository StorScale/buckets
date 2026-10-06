"""End-to-end checks for the monitoring example: docker compose run --rm test

  1. Prometheus scrapes all three of Buckets' metrics endpoints, as a
     metrics-only user, which can read no data;
  2. the Helm chart's alert rules load, with no errors;
  3. the four Grafana dashboards' queries return data from Prometheus;
  4. a failed drive (here, emptied under load, as a replaced disk looks) shows
     up: Buckets reports it offline and the erasure set degraded, and the
     alerts for both start.

Buckets should also format the empty drive back into its slot and heal it,
but under write load that still loses a race at times (writes that reach the
drive before Buckets notices it changed make it look like a drive holding
data), so this doesn't check it yet.
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

    # 3. The dashboards' queries. Bucket usage comes from Buckets' scanner, a
    # little after startup, so this waits for the data to arrive.
    dashboards = wait(dashboard_queries, 60)

    def coverage():
        total, empty = 0, []
        for title, targets in sorted(dashboards.items()):
            for panel, expr in targets:
                for k, v in VARS.items():
                    expr = expr.replace(k, v)
                total += 1
                if not query(expr):
                    empty.append(f"{title.split(' / ')[-1]}: {panel}")
        return total, empty

    deadline = time.time() + 240
    while True:
        total, empty = coverage()
        # Panels for what this example doesn't run (replication, the KMS, the
        # console's sign-ins) have nothing to show.
        if total - len(empty) >= total * 0.75 or time.time() > deadline:
            break
        time.sleep(10)
    check("Grafana has the four dashboards", len(dashboards) == 4, ", ".join(sorted(dashboards)))
    check("the dashboards' queries return data", total - len(empty) >= total * 0.75,
          f"{total - len(empty)} of {total} queries; empty: {'; '.join(sorted(set(empty)))}")

    # 4. A failed drive.
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
