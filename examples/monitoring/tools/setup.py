"""Configure the monitoring example's Buckets, as docs/monitoring.md describes:

  - a metrics-only user for Prometheus (policy buckets-prometheus, allowed only
    admin:Prometheus), and its bearer token from `mc admin prometheus generate`,
    in the file Prometheus reads (/token/token);
  - buckets with data for the dashboards: photos (versioned), logs (with a
    quota) and backups.

Safe to run again.
"""
import io
import os
import re

from lakekit import env, log, mc, s3_root, setup_buckets

PROMETHEUS_POLICY = [{"Effect": "Allow", "Action": ["admin:Prometheus"], "Resource": ["arn:aws:s3:::*"]}]

setup_buckets(buckets=["photos", "logs", "backups"], policies={"buckets-prometheus": PROMETHEUS_POLICY},
              accounts=[(env["PROMETHEUS_USER"], env["PROMETHEUS_SECRET"], "buckets-prometheus")])
mc("version", "enable", "buckets/photos")
mc("quota", "set", "buckets/logs", "--size", "2GiB")

# The token, generated with an alias for the metrics user (not root).
mc("alias", "set", "metrics", "http://buckets:9000", env["PROMETHEUS_USER"], env["PROMETHEUS_SECRET"])
out = mc("admin", "prometheus", "generate", "metrics").stdout
token = re.search(r"bearer_token:\s*(\S+)", out).group(1)
os.makedirs("/token", exist_ok=True)
with open("/token/token", "w") as f:
    f.write(token)
os.chmod("/token/token", 0o644)
log("Prometheus: metrics user, and its token in /token/token")

s3 = s3_root()
for i in range(40):
    s3.put_object(Bucket="photos", Key=f"2026/10/img-{i:04d}.jpg", Body=os.urandom(64 * 1024 * (1 + i % 8)))
for i in range(20):
    s3.put_object(Bucket="backups", Key=f"db/dump-{i:03d}.bin", Body=io.BytesIO(os.urandom(1024 * 1024)))
log("data: photos, logs, backups")
log("done")
