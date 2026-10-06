"""Buckets from a JupyterHub notebook, as the person who signed in.

    import buckets_lake
    s3 = buckets_lake.s3()                       # a boto3 S3 client
    s3.put_object(Bucket="home", Key=f"{buckets_lake.username()}/notes.txt", Body=b"...")

    import io, pandas as pd                      # pandas, through the same client
    df = pd.read_parquet(io.BytesIO(s3.get_object(Bucket="datasets", Key="sales/orders.parquet")["Body"].read()))

No keys live in the notebook. The hub keeps the person's Keycloak tokens (and
refreshes them); this asks the hub for the current one with the server's own
API token, then exchanges it with Buckets' STS (AssumeRoleWithWebIdentity)
for temporary credentials. Their policies follow the person's Keycloak
groups, and their private prefix is home/<username>/. The credentials renew
themselves before they expire.
"""
import datetime
import os

import boto3
import requests
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

ENDPOINT = os.environ.get("BUCKETS_ENDPOINT", "http://buckets:9000")
REGION = os.environ.get("BUCKETS_REGION", "us-east-1")
DURATION = 3600


def username():
    """The signed-in person's name, as Keycloak gives it (preferred_username)."""
    return os.environ["JUPYTERHUB_USER"]


def _hub_user():
    # /users/<name>, not /user: the hub fills in auth_state only on the former.
    r = requests.get(f"{os.environ['JUPYTERHUB_API_URL']}/users/{username()}", timeout=10,
                     headers={"Authorization": f"token {os.environ['JUPYTERHUB_API_TOKEN']}"})
    r.raise_for_status()
    return r.json()


def token():
    """The person's current Keycloak access token, from the hub (which refreshes it)."""
    state = _hub_user().get("auth_state") or {}
    if "access_token" not in state:
        raise RuntimeError("the hub gave no access token: is admin:auth_state!user in the server role?")
    return state["access_token"]


def _fetch():
    sts = boto3.client("sts", endpoint_url=ENDPOINT, region_name=REGION,
                       aws_access_key_id="unused", aws_secret_access_key="unused")
    c = sts.assume_role_with_web_identity(RoleArn="arn:minio:iam:::role/jupyterhub", RoleSessionName=username(),
                                          WebIdentityToken=token(), DurationSeconds=DURATION)["Credentials"]
    return {"access_key": c["AccessKeyId"], "secret_key": c["SecretAccessKey"], "token": c["SessionToken"],
            "expiry_time": c["Expiration"].astimezone(datetime.timezone.utc).isoformat()}


def session():
    """A boto3 session whose credentials renew themselves through the hub and STS."""
    core = get_session()
    core._credentials = RefreshableCredentials.create_from_metadata(
        metadata=_fetch(), refresh_using=_fetch, method="buckets-sts")
    core.set_config_variable("region", REGION)
    return boto3.Session(botocore_session=core)


def s3():
    """A boto3 S3 client for Buckets, as the signed-in person."""
    return session().client("s3", endpoint_url=ENDPOINT, config=Config(s3={"addressing_style": "path"}))

