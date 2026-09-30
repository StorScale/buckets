#!/usr/bin/env python3
"""SSE through KES, MinIO against bucketsd (see kes.sh).

usage: kes_cases.py BASE_PORT ACCESS SECRET fresh|swapped

fresh: both servers write encrypted objects and answer the KMS APIs; swapped:
each server, now on the other's drives, reads what the other wrote.
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

from adminlib import Score, compare, curl, err_view, setup

BASE, AK, SK, PHASE = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
setup(AK, SK)
S3 = (f"http://127.0.0.1:{BASE}", f"http://127.0.0.1:{BASE + 1}")
DATA = bytes(range(256)) * 4000
MC = os.environ.get("MC")
MC_CFG = os.path.join(tempfile.gettempdir(), f"kes-mc-{BASE}")


def mc(*args):
    return subprocess.run([MC, "--config-dir", MC_CFG, *args], capture_output=True, text=True)


if MC:  # IAM and config data are sealed with the KMS too
    for i, base in enumerate(S3):
        mc("alias", "set", f"k{i}", base, AK, SK)


def view(c, h, b):
    keep = ("x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id", "content-length")
    hv = {k: h.get(k) for k in keep if h.get(k)}
    if c >= 400:
        return c, hv, err_view(c, b)
    return c, hv, hashlib.sha256(b).hexdigest() if b else ""


if PHASE == "fresh":
    for name, key, hdrs in [("SSE-S3", "s3.bin", ("x-amz-server-side-encryption: AES256",)),
                            ("SSE-KMS, the default key", "kms.bin", ("x-amz-server-side-encryption: aws:kms",)),
                            ("SSE-KMS, another key", "kms2.bin", ("x-amz-server-side-encryption: aws:kms",
                                                                  "x-amz-server-side-encryption-aws-kms-key-id: other-key")),
                            ("SSE-KMS, no such key", "nokey.bin", ("x-amz-server-side-encryption: aws:kms",
                                                                   "x-amz-server-side-encryption-aws-kms-key-id: nosuchkey"))]:
        res = []
        for base in S3:
            curl(f"{base}/kesb", "PUT")
            put = view(*curl(f"{base}/kesb/{key}", "PUT", DATA, headers=hdrs))
            get = view(*curl(f"{base}/kesb/{key}"))
            res.append((put[0], put[1], get))
        compare(f"PUT and GET, {name}", *res)
    # the KMS APIs
    for name, method, path in [("status", "GET", "/minio/kms/v1/status"), ("version", "GET", "/minio/kms/v1/version"),
                               ("apis", "GET", "/minio/kms/v1/apis"),
                               ("create a key", "POST", "/minio/kms/v1/key/create?key-id=new-key"),
                               ("create it again", "POST", "/minio/kms/v1/key/create?key-id=new-key"),
                               ("list keys", "GET", "/minio/kms/v1/key/list?pattern=*"),
                               ("key status", "GET", "/minio/kms/v1/key/status?key-id=my-key"),
                               ("key status, no such key", "GET", "/minio/kms/v1/key/status?key-id=nosuchkey"),
                               ("admin status", "POST", "/minio/admin/v3/kms/status")]:
        res = []
        for i, base in enumerate(S3):
            # the servers share their KES: each creates a key of its own
            c, h, b = curl(base + path.replace("key-id=new-key", f"key-id=new-key-{i}"), method)
            body = b.decode(errors="replace")
            body = re.sub(r"127\.0\.0\.1:\d+", "<addr>", body)
            body = re.sub(r'"RequestId":"[^"]*"|<RequestId>[^<]*</RequestId>|"HostId":"[^"]*"|<HostId>[^<]*</HostId>',
                          "", body)
            res.append((c, h.get("content-type"), body if "create" not in name or c >= 400 else ""))
        compare(f"KMS API, {name}", *res)
    if MC:
        res = []
        for i in range(2):
            a = mc("admin", "user", "add", f"k{i}", "kesuser", "kessecret123").returncode
            b = mc("admin", "config", "set", f"k{i}", "api", "requests_max=123").returncode
            res.append((a, b))
        compare("IAM user and config written", *res)
else:
    if MC:
        res = []
        for i in range(2):
            u = mc("admin", "user", "info", f"k{i}", "kesuser", "--json")
            cfg = mc("admin", "config", "get", f"k{i}", "api").stdout
            res.append((u.returncode, '"status":"enabled"' in u.stdout, "requests_max=123" in cfg))
        compare("the other's IAM user and config", *res)
    for key in ("s3.bin", "kms.bin", "kms2.bin"):
        res = [view(*curl(f"{base}/kesb/{key}")) for base in S3]
        compare(f"read the other's {key}", *res)

print(f"kes ({PHASE}): {Score.passed} passed, {Score.failed} failed")
sys.exit(1 if Score.failed else 0)
