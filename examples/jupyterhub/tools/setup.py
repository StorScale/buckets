"""Configure the JupyterHub example's Buckets: buckets, policies, a dataset.

  - `home`: everyone's own files, under home/<their Keycloak username>/. One
    policy statement covers everyone, through the policy variable
    ${jwt:preferred_username}, so nobody can read anyone else's prefix.
  - `datasets`: shared data. Analysts read it; engineers read and write it.

The policies are named after the Keycloak groups people sign in with
(MINIO_IDENTITY_OPENID_CLAIM_NAME=groups), so a person's groups are their
permissions. There are no service accounts: notebooks reach Buckets as the
person who signed in. Safe to run again.
"""
import io

import pandas as pd

from lakekit import log, s3_root, setup_buckets

ME = "${jwt:preferred_username}"


def own_home():
    """Read and write home/<username>/, list only that prefix."""
    return [
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::home"],
         "Condition": {"StringLike": {"s3:prefix": [f"{ME}/*", ME]}}},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                       "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
         "Resource": [f"arn:aws:s3:::home/{ME}/*"]},
    ]


def datasets(write):
    actions = ["s3:GetObject"] + (["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"] if write else [])
    return [
        {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::datasets"]},
        {"Effect": "Allow", "Action": actions, "Resource": ["arn:aws:s3:::datasets/*"]},
    ]


if __name__ == "__main__":
    setup_buckets(buckets=["home", "datasets"],
                  policies={"analysts": own_home() + datasets(write=False),
                            "engineers": own_home() + datasets(write=True)},
                  accounts=[])
    orders = pd.DataFrame({
        "id": [1, 2, 3, 4, 5, 6],
        "region": ["EU", "US", "EU", "APAC", "EU", "US"],
        "amount": [120.50, 75.00, 310.25, 42.00, 18.99, 99.95],
        "order_date": pd.to_datetime(["2026-09-01", "2026-09-02", "2026-09-03",
                                      "2026-09-04", "2026-09-05", "2026-09-06"]),
    })
    buf = io.BytesIO()
    orders.to_parquet(buf, index=False)
    s3_root().put_object(Bucket="datasets", Key="sales/orders.parquet", Body=buf.getvalue())
    log("Buckets: datasets/sales/orders.parquet (6 orders)")
    log("done")
