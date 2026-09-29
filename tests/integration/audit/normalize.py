# SPDX-License-Identifier: AGPL-3.0-or-later
"""Webhook sink log (webhooksink.py) of audit posts -> one normalized line
per entry: the POST's path and Authorization, then the entry with volatile
values replaced (times, IDs, durations, header sizes)."""
import json
import re
import sys

VOLATILE = {"time", "requestID", "deploymentid"}
API_VOLATILE = {"timeToFirstByte", "timeToFirstByteInNS", "timeToResponse", "timeToResponseInNS", "txHeaders"}
REQ_VOLATILE = {"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256", "User-Agent", "Content-Md5"}
RESP_VOLATILE = {"X-Amz-Request-Id", "X-Amz-Id-2", "Server", "Date", "X-Ratelimit-Limit", "X-Ratelimit-Remaining",
                 "X-Amz-Version-Id", "Last-Modified"}
ids = {}


def nid(v):
    ids.setdefault(v, "V%d" % (len(ids) + 1))
    return ids[v]


def normalize(e):
    for k in VOLATILE:
        if k in e:
            e[k] = "(v)"
    for k in API_VOLATILE:
        if k in e.get("api", {}):
            e["api"][k] = "(v)"
    for k in REQ_VOLATILE:
        if k in e.get("requestHeader", {}):
            e["requestHeader"][k] = "(v)"
    for k in list(e.get("responseHeader", {})):
        if k in RESP_VOLATILE:
            e["responseHeader"][k] = "(v)"
    # tags record the object layer's operations, which follow each
    # server's own internals: their keys are compared, not their values
    if "tags" in e:
        e["tags"] = sorted(k for k in e["tags"] if k != "GetObjectInfo") + (["retention=" + e["tags"]["retention"]] if "retention" in e["tags"] else [])
        if not e["tags"]:
            del e["tags"]
    rq = e.get("requestQuery", {})
    for k in ("versionId", "uploadId"):
        if k in rq:
            rq[k] = nid(rq[k])
    s = json.dumps(e, separators=(",", ":"))
    return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lambda m: nid(m.group(0)), s)


path = auth = ""
for raw in sys.stdin.read().split("\n"):
    if raw.startswith("/"):  # a POST: "<path> <Authorization> <Content-Type>"
        parts = raw.split(" ")
        path, auth = parts[0], " ".join(parts[1:-1])
    elif raw.startswith("{"):
        print(path, auth, normalize(json.loads(raw)))
