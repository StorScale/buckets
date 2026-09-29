# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replaces the volatile values of event records (times, sequencers,
request, host and deployment IDs, version IDs) and keeps the rest (key
order, escaping, spacing) as sent. The records of one request (DeleteObjects)
are put in key order: both servers hand events to several send workers, so
their order within a request is not fixed. stdin -> stdout."""
import re
import sys

ids = {}


def nid(m):
    ids.setdefault(m.group(0), "V%d" % (len(ids) + 1))
    return ids[m.group(0)]


# units: a sink POST is its header line and its body; listeners, one line each
lines = sys.stdin.readlines()
units, i = [], 0
while i < len(lines):
    if lines[i].startswith("/") and i + 1 < len(lines):
        units.append(lines[i] + lines[i + 1])
        i += 2
    else:
        units.append(lines[i])
        i += 1


def request_id(u):
    m = re.search(r'"x-amz-request-id":"([^"]+)"', u)
    return m.group(1) if m else None


def key(u):
    m = re.search(r'"key":"([^"]*)"', u)
    return m.group(1) if m else ""


ordered, i = [], 0
while i < len(units):
    j = i + 1
    rid = request_id(units[i])
    while rid and j < len(units) and request_id(units[j]) == rid:
        j += 1
    ordered.extend(sorted(units[i:j], key=key) if j - i > 1 else units[i:j])
    i = j

for u in ordered:
    u = re.sub(r'"eventTime":"[^"]*"', '"eventTime":"(t)"', u)
    u = re.sub(r'"sequencer":"[0-9A-F]+"', '"sequencer":"(seq)"', u)
    u = re.sub(r'"(x-amz-request-id|x-amz-id-2|x-minio-deployment-id)":"([^"]+)"', r'"\1":"(v)"', u)
    u = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", nid, u)
    sys.stdout.write(u)
