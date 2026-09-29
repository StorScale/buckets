#!/usr/bin/env python3
"""Snowball uploads (PutObjectExtract), differentially: tar archives, plain
and compressed (gzip, bzip2, and with SELGEN zstd, lz4, s2), extracted by
MinIO and bucketsd alike: the objects, their contents and the errors.

usage: snowball_cases.py MINIO_URL BUCKETS_URL ACCESS SECRET
"""
import bz2
import gzip
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile

MINIO, BUCKETS, AK, SK = sys.argv[1:5]
SELGEN = os.environ.get("SELGEN")


def curl(url, method="GET", data=None, headers=()):
    args = ["curl", "-s", "-X", method, "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", f"{AK}:{SK}", "-o", "-",
            "-w", "\n%{http_code}"]
    for h in headers:
        args += ["-H", h]
    if data is not None:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        args += ["--data-binary", "@" + f.name]
    out = subprocess.run(args + [url], capture_output=True).stdout
    body, _, code = out.rpartition(b"\n")
    return int(code or 0), body


def archive(n):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.PAX_FORMAT) as t:
        for i in range(n):
            data = (f"file {i}\n" * (i * 50 + 1)).encode()
            info = tarfile.TarInfo(f"dir{i % 3}/f{i}.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        d = tarfile.TarInfo("emptydir")
        d.type = tarfile.DIRTYPE
        t.addfile(d)
    return b.getvalue()


def state(base, bucket):
    code, body = curl(f"{base}/{bucket}?list-type=2")
    keys = re.findall(rb"<Key>(.*?)</Key>", body)
    out = []
    for k in keys:
        _, data = curl(f"{base}/{bucket}/{k.decode()}")
        out.append((k.decode(), len(data), hash(data)))
    return out


TAR = archive(12)
CASES = [("plain", TAR), ("gzip", gzip.compress(TAR)), ("bzip2", bz2.compress(TAR)),
         ("truncated-gzip", gzip.compress(TAR)[:300]), ("bad-gzip", b"\x1f\x8b\x08" + b"\x00" * 64),
         ("truncated-tar", TAR[:1500])]
if SELGEN:
    for ct in ("zstd", "lz4", "s2"):
        CASES.append((ct, subprocess.run([SELGEN, ct], input=TAR, capture_output=True).stdout))

passed = failed = 0
for i, (name, data) in enumerate(CASES):
    bucket = f"snow{i}"
    res = []
    for base in (MINIO, BUCKETS):
        curl(f"{base}/{bucket}", "PUT")
        code, body = curl(f"{base}/{bucket}/archive.tar", "PUT", data, ("X-Amz-Meta-Snowball-Auto-Extract: true",
                                                                        "X-Amz-Meta-Minio-Snowball-Prefix: in"))
        m = re.search(rb"<Code>(.*?)</Code>.*?<Message>(.*?)</Message>", body, re.S)
        # what a failed upload extracted depends on MinIO's background writers: compare it on success only
        res.append((code, m.group(1).decode() if m else "", m.group(2).decode() if m else "",
                    state(base, bucket) if code == 200 else None))
    if res[0] == res[1]:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL  {name}\n        minio:   {res[0]!r}\n        buckets: {res[1]!r}")
print(f"snowball: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
