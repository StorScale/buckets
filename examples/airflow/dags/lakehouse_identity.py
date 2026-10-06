"""How this example's pipelines reach the lakehouse: as their own identity, a
Keycloak service account (client airflow-pipelines, in group "pipelines").

Airflow keeps one secret, the client's, in the connection keycloak_pipelines.
Each task gets a short-lived access token for the service account (client
credentials), and then
  - buckets_s3(): Buckets credentials, exchanged for the token through STS,
    with the policies of the token's groups ("pipelines");
  - trino(): a Trino connection signed in with the token, so Ranger applies
    the pipelines group's policies and records the service account by name.
No S3 keys and no Trino password are stored anywhere in Airflow.
"""
import boto3
import requests
import trino as trino_client
from botocore.config import Config

from airflow.sdk import BaseHook

BUCKETS = "http://buckets:9000"
REALM = "lakehouse"


def token():
    c = BaseHook.get_connection("keycloak_pipelines")
    r = requests.post(f"http://{c.host}:{c.port}/realms/{REALM}/protocol/openid-connect/token", timeout=30,
                      data={"grant_type": "client_credentials", "client_id": c.login, "client_secret": c.password})
    r.raise_for_status()
    return r.json()["access_token"]


def buckets_s3(access_token=None):
    sts = boto3.client("sts", endpoint_url=BUCKETS, region_name="us-east-1",
                       aws_access_key_id="unused", aws_secret_access_key="unused")
    c = sts.assume_role_with_web_identity(RoleArn="arn:minio:iam:::role/airflow", RoleSessionName="airflow",
                                          WebIdentityToken=access_token or token(), DurationSeconds=900)["Credentials"]
    return boto3.client("s3", endpoint_url=BUCKETS, region_name="us-east-1",
                        aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                        aws_session_token=c["SessionToken"], config=Config(s3={"addressing_style": "path"}))


def trino(schema="sales"):
    return trino_client.dbapi.connect(
        host="trino", port=8443, http_scheme="https", verify="/tls/cert.pem",
        user="service-account-airflow-pipelines", auth=trino_client.auth.JWTAuthentication(token()),
        catalog="iceberg", schema=schema)
