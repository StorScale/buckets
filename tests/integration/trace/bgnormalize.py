# SPDX-License-Identifier: AGPL-3.0-or-later
"""Background trace records (scanner, healing, ILM) -> the distinct record
shapes, sorted. Which cycle scans which folder is timing (and MinIO's
bloom-filter heuristics), so scanner records keep their function, the path
with the drive and work root abstracted, and their custom keys; heal and ILM
records keep everything but times and durations.

  python3 bgnormalize.py WORKROOT < trace.raw"""
import json
import os
import re
import sys

root = os.path.normpath(sys.argv[1])


def drive(s):
    s = s.replace(root + "/", "<root>/")
    return re.sub(r"<root>/[^/ ]+/d\d+", "<drive>", s)


shapes = set()
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    r = json.loads(line)
    for k in ("time", "dur", "nodename"):
        r.pop(k, None)
    if r["type"] == 16:  # scanner
        r["path"] = drive(r["path"])
        r["custom"] = sorted(r.get("custom", {}))
    else:
        r = json.loads(drive(json.dumps(r)))
    shapes.add(json.dumps(r, sort_keys=True))
for s in sorted(shapes):
    print(s)
