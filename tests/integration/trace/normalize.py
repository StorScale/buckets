# SPDX-License-Identifier: AGPL-3.0-or-later
"""A trace stream (JSON lines and keep-alive spaces) -> one normalized line
per record: volatile values (times, durations, IDs, sizes that depend on the
server's own headers) replaced."""
import base64
import json
import re
import sys

VOL_REQ = {"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256", "User-Agent", "Content-Md5"}
VOL_RESP = {"X-Amz-Request-Id", "X-Amz-Id-2", "Server", "Date", "X-Ratelimit-Limit", "X-Ratelimit-Remaining",
            "Last-Modified", "x-amz-version-id", "X-Amz-Version-Id", "Etag", "ETag"}
ids = {}


def nid(v):
    ids.setdefault(v, "V%d" % (len(ids) + 1))
    return ids[v]


text = sys.stdin.read()
if text.startswith("HTTP "):
    text = text.split("\n", 1)[1]
dec = json.JSONDecoder()
i = 0
while i < len(text):
    while i < len(text) and text[i] in " \n\r\t":
        i += 1
    if i >= len(text):
        break
    rec, i = dec.raw_decode(text, i)
    for k in ("time", "dur", "bytes", "nodename"):
        rec[k] = "(v)"
    h = rec.get("http", {})
    for part in ("request", "response"):
        p = h.get(part, {})
        p["time"] = "(v)"
        for k in list(p.get("headers", {})):
            if k in (VOL_REQ if part == "request" else VOL_RESP):
                p["headers"][k] = "(v)"
        if "body" in p:
            body = base64.b64decode(p["body"]).decode("utf-8", "replace")
            body = re.sub(r"<(RequestId|HostId|LastModified|Initiated|UploadId)>[^<]*</\1>", r"<\1/>", body)
            p["body"] = body
    rq = h.get("request", {})
    if "rawquery" in rq:
        rq["rawquery"] = re.sub(r"(uploadId|versionId)=([^&]+)", lambda m: m.group(1) + "=" + nid(m.group(2)), rq["rawquery"])
    st = h.get("stats", {})
    for k in ("latency", "timetofirstbyte", "inputbytes"):
        if k in st:
            st[k] = "(v)"
    s = json.dumps(rec, separators=(",", ":"))
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lambda m: nid(m.group(0)), s)
    print(s)
