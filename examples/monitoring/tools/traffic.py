"""S3 traffic for the monitoring example's dashboards, forever, of a bounded
size: uploads of several sizes, downloads, listings, overwrites and deletes, requests for
objects that don't exist, and now and then a request with bad credentials."""
import os
import random
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from lakekit import BUCKETS, s3_root

s3 = s3_root()
stranger = boto3.client("s3", endpoint_url=BUCKETS, region_name="us-east-1",
                        aws_access_key_id="NOT-A-REAL-KEY", aws_secret_access_key="not-a-real-secret",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
SIZES = [4 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20]
print("traffic: running", flush=True)
n = 0
while True:
    n += 1
    try:
        op = random.random()
        if op < 0.25:
            s3.put_object(Bucket="logs", Key=f"app/{time.strftime('%H%M')}/{n}.log", Body=os.urandom(random.choice(SIZES[:2])))
        elif op < 0.40:
            s3.put_object(Bucket="photos", Key=f"2026/10/img-{random.randrange(60):04d}.jpg",
                          Body=os.urandom(random.choice(SIZES[1:4])))
        elif op < 0.75:
            s3.get_object(Bucket="photos", Key=f"2026/10/img-{random.randrange(40):04d}.jpg")["Body"].read()
        elif op < 0.85:
            s3.list_objects_v2(Bucket=random.choice(["photos", "logs", "backups"]), MaxKeys=100)
        elif op < 0.92:
            s3.head_object(Bucket="photos", Key=f"missing/{n}.jpg")          # 404s
        elif op < 0.97:                                                       # keeps logs/ from growing
            keys = [o["Key"] for o in s3.list_objects_v2(Bucket="logs", MaxKeys=10).get("Contents", [])]
            for k in keys[:6]:
                s3.delete_object(Bucket="logs", Key=k)
        else:
            stranger.list_objects_v2(Bucket="photos")                         # rejected: bad credentials
    except ClientError:
        pass
    except Exception as e:  # a restart or a drive being replaced: keep going
        print(f"traffic: {type(e).__name__}: {e}", flush=True)
        time.sleep(1)
    time.sleep(0.03)
