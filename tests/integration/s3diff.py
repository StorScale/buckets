# SPDX-License-Identifier: AGPL-3.0-or-later
"""Differential S3 checks: run a scenario (a list of requests) against a
server and print a normalized transcript -- status, selected headers and
the XML body with volatile values (version IDs, dates, request IDs)
replaced -- so two servers can be diffed.

  python3 s3diff.py ENDPOINT ACCESS SECRET SCENARIO.json

A scenario is a JSON list of steps:
  {"method": "PUT", "path": "/b/k", "query": "versionId=$v1", "body": "x",
   "headers": {...}, "save": {"v1": "x-amz-version-id"}, "show": ["x-amz-delete-marker"]}
"$name" in path, query or body is replaced by a value saved earlier.
"""
import json
import urllib.parse
import re
import subprocess
import sys

ep, ak, sk, scenario = sys.argv[1:5]
steps = json.load(open(scenario))
saved = {}
ids = {}


def sub(s):
    return re.sub(r"\$([a-z0-9_]+)", lambda m: saved.get(m.group(1), ""), s or "")


def norm_id(v):
    if v in ("", "null"):
        return v
    if v not in ids:
        ids[v] = "V%d" % (len(ids) + 1)
    return ids[v]


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def norm_body(b):
    b = UUID.sub(lambda m: norm_id(m.group(0)), b)
    b = re.sub(r"<(LastModified|RequestId|HostId|Resource)>[^<]*</\1>", r"<\1/>", b)
    b = re.sub(r"<Owner>.*?</Owner>", "<Owner/>", b)
    b = re.sub(r"<\?xml[^>]*\?>", "", b)
    b = re.sub(r"\[minio_cache:[^\]]*\]", "", b)  # MinIO's metacache hint in markers
    b = re.sub(r">\s+<", "><", b.strip())
    return b


for i, st in enumerate(steps):
    q = sub(st.get("query", ""))
    url = ep + sub(st["path"]) + ("?" + q if q else "")
    open("/tmp/.s3diff.body", "w").close()
    cmd = ["curl", "-s", "-g", "-D", "-", "-o", "/tmp/.s3diff.body", "-X", st["method"],
           "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", ak + ":" + sk]
    for k, v in st.get("headers", {}).items():
        cmd += ["-H", "%s: %s" % (k, sub(v))]
    if st.get("md5"):
        import base64
        import hashlib
        cmd += ["-H", "Content-MD5: " + base64.b64encode(hashlib.md5(sub(st.get("body", "")).encode()).digest()).decode()]
    if "body" in st:
        cmd += ["--data-binary", sub(st["body"])]
        if not any(k.lower() == "content-type" for k in st.get("headers", {})):
            cmd += ["-H", "Content-Type: application/octet-stream"]
    elif st["method"] in ("PUT", "POST"):
        cmd += ["--data-binary", ""]
    cmd.append(url)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    lines = out.replace("\r", "").split("\n")
    status = lines[0].split(" ")[1] if lines and len(lines[0].split(" ")) > 1 else "?"
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    body = open("/tmp/.s3diff.body", errors="replace").read()
    for name, h in st.get("save", {}).items():
        if h.startswith("xml:"):
            m = re.search("<%s>([^<]*)</%s>" % (h[4:], h[4:]), body)
            saved[name] = urllib.parse.quote(m.group(1), safe="") if m else ""
        else:
            saved[name] = hdrs.get(h.lower(), "")
    shown = []
    for h in st.get("show", []) + ["x-amz-version-id", "x-amz-delete-marker"]:
        if h in hdrs and h not in [s.split("=")[0] for s in shown]:
            v = hdrs[h]
            shown.append("%s=%s" % (h, norm_id(v) if h.endswith("version-id") else v))
    line = "%02d %s %s -> %s %s" % (i, st["method"], st.get("label", st["path"]), status, " ".join(shown))
    print(line)
    if st.get("body_out", False) or status[0] not in "2" or st["method"] == "GET":
        nb = norm_body(body)
        if nb:
            print("   " + nb[:2000])
