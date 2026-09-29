# SPDX-License-Identifier: AGPL-3.0-or-later
"""A protocol mock's log (one JSON array per line: connection number, then
the command's fields) -> each connection's commands as a block, blocks in a
stable order, with the volatile parts of event records replaced (times,
sequencers, request/host/deployment IDs, UUIDs) and our client name spelled
as MinIO's. stdin -> stdout."""
import json
import re
import sys

ids = {}


def nid(m):
    ids.setdefault(m.group(0), "V%d" % (len(ids) + 1))
    return ids[m.group(0)]


def clean(s):
    s = re.sub(r'"(eventTime|EventTime)":"[^"]*"', r'"\1":"(t)"', s)
    s = re.sub(r'"sequencer":"[0-9A-F]+"', '"sequencer":"(seq)"', s)
    s = re.sub(r'"(x-amz-request-id|x-amz-id-2|x-minio-deployment-id)":"([^"]+)"', r'"\1":"(v)"', s)
    return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", nid, s)


blocks = {}
for line in sys.stdin:
    rec = json.loads(line)
    fields = ["Buckets" if f == "MinIO" else clean(f) if isinstance(f, str) else f for f in rec[1:]]
    for f in fields:  # NSQ's IDENTIFY: the host's names and the client library
        if isinstance(f, dict):
            for k in ("client_id", "hostname", "long_id", "short_id", "user_agent"):
                if k in f:
                    f[k] = "(v)"
    blocks.setdefault(rec[0], []).append(json.dumps(fields))
for b in sorted("\n".join(v) for v in blocks.values()):
    print(b)
    print("--")
