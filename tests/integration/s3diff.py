# SPDX-License-Identifier: AGPL-3.0-or-later
"""Differential S3 checks: run a scenario (a list of requests) against a
server and print a normalized transcript -- status, selected headers and
the XML body with volatile values (version IDs, dates, request IDs)
replaced -- so two servers can be diffed.

  python3 s3diff.py ENDPOINT ACCESS SECRET SCENARIO.json

A scenario is a JSON list of steps:
  {"method": "PUT", "path": "/b/k", "query": "versionId=$v1", "body": "x",
   "headers": {...}, "save": {"v1": "x-amz-version-id"}, "show": ["x-amz-delete-marker"]}
"$name" in path, query or body is replaced by a value saved earlier; "repeat": N
sends the body N times over. SCENARIO.env next to a scenario holds extra
server environment (VAR=value lines), applied by s3diff.sh.
"""
import datetime
import hashlib
import hmac
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


def sign(method, path, query, headers, body):
    """SigV4 headers for the request (curl's --aws-sigv4 orders x-amz-tagging
    after x-amz-tagging-directive, which no server accepts)."""
    now = datetime.datetime.utcnow()
    amzdate, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    h = {k.lower(): v.strip() for k, v in headers.items()}
    h["host"] = urllib.parse.urlparse(ep).netloc
    h["x-amz-date"] = amzdate
    h["x-amz-content-sha256"] = hashlib.sha256(body).hexdigest()
    q = lambda v: urllib.parse.quote(v, safe="-_.~")
    pairs = []
    for part in query.split("&") if query else []:
        k, _, v = part.partition("=")
        pairs.append((q(urllib.parse.unquote(k)), q(urllib.parse.unquote(v))))
    cq = "&".join("%s=%s" % kv for kv in sorted(pairs))
    names = sorted(k for k in h if k in ("host", "content-md5", "content-type") or k.startswith("x-amz-"))
    creq = "\n".join([method, urllib.parse.quote(urllib.parse.unquote(path), safe="/-_.~"), cq,
                      "".join("%s:%s\n" % (k, h[k]) for k in names), ";".join(names), h["x-amz-content-sha256"]])
    scope = "%s/us-east-1/s3/aws4_request" % day
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(creq.encode()).hexdigest()])
    key = ("AWS4" + sk).encode()
    for m in (day, "us-east-1", "s3", "aws4_request"):
        key = hmac.new(key, m.encode(), hashlib.sha256).digest()
    sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
    out = {k: h[k] for k in ("x-amz-date", "x-amz-content-sha256")}
    out["Authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        ak, scope, ";".join(names), sig)
    return out


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def norm_body(b):
    b = UUID.sub(lambda m: norm_id(m.group(0)), b)
    # upload IDs embed the deployment ID
    b = re.sub(r"<(UploadId|UploadIdMarker|NextUploadIdMarker)>([^<]+)</\1>",
               lambda m: "<%s>%s</%s>" % (m.group(1), norm_id(m.group(2)), m.group(1)), b)
    b = re.sub(r"<(Initiated|LastModified|RequestId|HostId|Resource)>[^<]*</\1>", r"<\1/>", b)
    # dates computed from "now" (default retention)
    b = re.sub(r"<RetainUntilDate>20[0-8][0-9]-[^<]*</RetainUntilDate>", "<RetainUntilDate>(now+)</RetainUntilDate>", b)
    b = re.sub(r"<Owner>.*?</Owner>", "<Owner/>", b)
    b = re.sub(r'"(RequestId|HostId|Resource)":"[^"]*"', r'"\1":""', b)  # admin JSON errors
    b = re.sub(r'"lastUpdate":"[0-9]{4}-[^"]*"', '"lastUpdate":"(time)"', b)
    b = re.sub(r"<\?xml[^>]*\?>", "", b)
    b = re.sub(r"\[minio_cache:[^\]]*\]", "", b)  # MinIO's metacache hint in markers
    b = re.sub(r">\s+<", "><", b.strip())
    return b


for i, st in enumerate(steps):
    if "sleep" in st:  # {"sleep": seconds}: let background work (the scanner) run
        import time
        time.sleep(st["sleep"])
        continue
    q = sub(st.get("query", ""))
    url = ep + sub(st["path"]) + ("?" + q if q else "")
    open("/tmp/.s3diff.body", "w").close()
    verb = ["-I"] if st["method"] == "HEAD" else ["-X", st["method"]]  # -X HEAD waits for a body
    hdrs_in = {k: sub(v) for k, v in st.get("headers", {}).items()}
    body = sub(st["body"]).encode() * st.get("repeat", 1) if "body" in st else b""
    if st.get("md5"):
        import base64
        hdrs_in["Content-MD5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
    if "body" in st and not any(k.lower() == "content-type" for k in hdrs_in):
        hdrs_in["Content-Type"] = "application/octet-stream"
    elif "body" not in st and st["method"] in ("PUT", "POST"):
        hdrs_in.setdefault("Content-Type", "application/x-www-form-urlencoded")  # what curl sends
    hdrs_in.update(sign(st["method"], sub(st["path"]), q, hdrs_in, body))
    cmd = ["curl", "-s", "-g", "-D", "-", "-o", "/tmp/.s3diff.body"] + verb
    for k, v in hdrs_in.items():
        cmd += ["-H", "%s: %s" % (k, v)]
    if "body" in st or st["method"] in ("PUT", "POST"):
        with open("/tmp/.s3diff.req", "wb") as f:  # large bodies do not fit on a command line
            f.write(body)
        cmd += ["--data-binary", "@/tmp/.s3diff.req"]
    cmd.append(url)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    lines = out.replace("\r", "").split("\n")
    status = lines[0].split(" ")[1] if lines and len(lines[0].split(" ")) > 1 else "?"
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    body = "" if st["method"] == "HEAD" else open("/tmp/.s3diff.body", errors="replace").read()
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
        for pat in st.get("mask", []):  # values that legitimately differ, such as compressed sizes
            nb = re.sub(pat, "(masked)", nb)
        if nb:
            print("   " + nb[:2000])
