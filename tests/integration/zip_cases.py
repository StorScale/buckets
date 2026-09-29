#!/usr/bin/env python3
"""Files inside zip archives (x-minio-extract), against MinIO: GET, HEAD and
ListObjectsV2 of archive.zip/... answer alike, and each server reads the
archive index (x-minio-internal-archive-info) the other stored.

usage: zip_cases.py MINIO_URL BUCKETS_URL ACCESS SECRET phase
  phase "fresh": upload and compare; "swapped": the servers now run on each
  other's drives, compare again without uploading.
"""
import io
import re
import urllib.parse
import subprocess
import sys
import tempfile
import zipfile

MINIO, BUCKETS, AK, SK, PHASE = sys.argv[1:6]
B = "ziptest"


def curl(url, method="GET", data=None, headers=()):
    args = ["curl", "-s", "-X", method, "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", f"{AK}:{SK}", "-D", "-",
            "-o", "-"]
    if method == "HEAD":
        args = ["curl", "-s", "-I", "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", f"{AK}:{SK}"]
    for h in headers:
        args += ["-H", h]
    if data is not None:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        args += ["--data-binary", "@" + f.name]
    out = subprocess.run(args + [url], capture_output=True).stdout
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    code = int(lines[0].split()[1]) if lines and lines[0] else 0
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return code, hdrs, body


class NoSeek(io.RawIOBase):
    """A stream zipfile cannot seek back in: it writes data descriptors."""
    def __init__(self):
        self.b = bytearray()
    def writable(self):
        return True
    def write(self, d):
        self.b += d
        return len(d)


def archives():
    out = {}
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("hello.txt", "hello world\n")
        z.writestr(zipfile.ZipInfo("stored.json"), '{"a": 1}')
        z.writestr("dir/deep/page.zzq", "<html><body>hi</body></html>", compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("dir/bin.zzq", bytes(range(256)) * 10, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("dir/empty.txt", "")
        z.writestr("dir/", "")
        z.writestr("img.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100, compress_type=zipfile.ZIP_DEFLATED)
        z.comment = b"a comment at the end"
    out["small.zip"] = b.getvalue()
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for i in range(40):
            z.writestr(f"f/{i % 4}/file{i:03d}.txt", f"file {i}\n" * (i + 1))
    out["forty.zip"] = b.getvalue()
    ns = NoSeek()
    with zipfile.ZipFile(ns, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for i in range(5):
            z.writestr(f"stream{i}.txt", f"streamed {i}\n" * 100)
    out["descriptor.zip"] = bytes(ns.b)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        with z.open("z64.txt", "w", force_zip64=True) as f:
            f.write(b"zip64 entry\n" * 1000)
        z.writestr("plain.txt", "plain\n")
    out["zip64.zip"] = b.getvalue()
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_STORED) as z:
        for i in range(26000):
            z.writestr(f"many/{i:05d}.txt", f"{i}\n")
    out["many.zip"] = b.getvalue()
    out["notzip.zip"] = b"this is not a zip archive" * 10
    return out


GETS = {
    "small.zip": ["hello.txt", "stored.json", "dir/deep/page.zzq", "dir/bin.zzq", "dir/empty.txt", "img.png", "nope.txt",
                  "dir/"],
    "forty.zip": ["f/1/file005.txt", "f/3/file039.txt"],
    "descriptor.zip": ["stream0.txt", "stream4.txt"],
    "zip64.zip": ["z64.txt", "plain.txt"],
    "many.zip": ["many/00000.txt", "many/12345.txt", "many/25999.txt", "many/26000.txt"],
    "notzip.zip": ["x.txt"],
}
KEEP = ("content-type", "content-length", "etag", "accept-ranges", "x-amz-version-id", "content-disposition")


def view(code, h, body, head=False):
    hv = tuple((k, h[k]) for k in KEEP if k in h) + (("has-last-modified", "last-modified" in h),)
    if code != 200:
        m = re.search(rb"<Code>(.*?)</Code>(?:.*?<Message>(.*?)</Message>)?", body, re.S)
        return (code, m.groups() if m else None) if not head else (code,)
    return (code, hv, None if head else (len(body), hash(body)))


def listing(base, q):
    code, _, body = curl(f"{base}/{B}?list-type=2&{q}", headers=("x-minio-extract: true",))
    body = re.sub(rb"<LastModified>.*?</LastModified>", b"", body)
    body = re.sub(rb"<RequestId>.*?</RequestId><HostId>.*?</HostId>", b"", body)
    body = re.sub(rb"<DisplayName>.*?</DisplayName>", b"", body)  # the owner is named after each server
    return code, body


passed = failed = 0


def compare(name, a, b):
    global passed, failed
    if a == b:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL  {name}\n        minio:   {a!r}\n        buckets: {b!r}")


arch = archives()
if PHASE == "fresh":
    for base in (MINIO, BUCKETS):
        curl(f"{base}/{B}", "PUT")
        for name, data in arch.items():
            curl(f"{base}/{B}/{name}", "PUT", data)
        # indexed on upload, and an encrypted one
        curl(f"{base}/{B}/put-indexed.zip", "PUT", arch["small.zip"], ("x-minio-extract: true",))
        curl(f"{base}/{B}/sse.zip", "PUT", arch["forty.zip"], ("X-Amz-Server-Side-Encryption: AES256",))
GETS["put-indexed.zip"] = ["hello.txt", "img.png"]
GETS["sse.zip"] = ["f/2/file006.txt"]
for name, files in GETS.items():
    for f in files:
        url = f"{B}/{name}/{f}"
        res = [view(*curl(f"{b}/{url}", headers=("x-minio-extract: true",))) for b in (MINIO, BUCKETS)]
        compare(f"GET {name}/{f}", *res)
        res = [view(*curl(f"{b}/{url}", "HEAD", headers=("x-minio-extract: true",)), head=True) for b in (MINIO, BUCKETS)]
        compare(f"HEAD {name}/{f}", *res)
for q in ["prefix=small.zip/", "prefix=small.zip/&delimiter=/", "prefix=small.zip/dir/&delimiter=/",
          "prefix=forty.zip/f/&delimiter=/", "prefix=forty.zip/&max-keys=7", "prefix=forty.zip/&start-after=forty.zip/f/2",
          "prefix=many.zip/many/1&max-keys=3", "prefix=nosuch.zip/", "prefix=notzip.zip/", "prefix=sse.zip/f/1/",
          "prefix=small.zip/&fetch-owner=true", "prefix=small.zip/&encoding-type=url"]:
    compare(f"LIST {q}", listing(MINIO, q), listing(BUCKETS, q))
# continuation: the token the server gave back
code, body = listing(MINIO, "prefix=forty.zip/&max-keys=5")
tm = re.search(rb"<NextContinuationToken>(.*?)</NextContinuationToken>", body)
code, body = listing(BUCKETS, "prefix=forty.zip/&max-keys=5")
tb = re.search(rb"<NextContinuationToken>(.*?)</NextContinuationToken>", body)
if tm and tb:
    compare("LIST continuation", listing(MINIO, "prefix=forty.zip/&max-keys=5&continuation-token=" + urllib.parse.quote(tm.group(1).decode(), safe="")),
            listing(BUCKETS, "prefix=forty.zip/&max-keys=5&continuation-token=" + urllib.parse.quote(tb.group(1).decode(), safe="")))
else:
    compare("LIST continuation tokens", bool(tm), bool(tb))
# errors
for h in (("Range: bytes=0-3",), ()):
    res = [view(*curl(f"{b}/{B}/small.zip/hello.txt", headers=("x-minio-extract: true",) + h)) for b in (MINIO, BUCKETS)]
    compare(f"GET with {h}", *res)
res = [view(*curl(f"{b}/{B}/small.zip/hello.txt?partNumber=1", headers=("x-minio-extract: true",))) for b in (MINIO, BUCKETS)]
compare("GET with partNumber", *res)
res = [view(*curl(f"{b}/{B}/nosuch.zip/hello.txt", headers=("x-minio-extract: true",))) for b in (MINIO, BUCKETS)]
compare("GET in a missing archive", *res)
res = [view(*curl(f"{b}/{B}/small.zip/hello.txt")) for b in (MINIO, BUCKETS)]
compare("GET without the header", *res)
print(f"zip ({PHASE}): {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
