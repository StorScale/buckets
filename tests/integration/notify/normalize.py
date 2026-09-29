# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replaces the volatile values of event records (times, sequencers,
request, host and deployment IDs, version IDs) and keeps the rest (key
order, escaping, spacing) as sent. stdin -> stdout."""
import re
import sys

ids = {}


def nid(m):
    ids.setdefault(m.group(0), "V%d" % (len(ids) + 1))
    return ids[m.group(0)]


for line in sys.stdin:
    line = re.sub(r'"eventTime":"[^"]*"', '"eventTime":"(t)"', line)
    line = re.sub(r'"sequencer":"[0-9A-F]+"', '"sequencer":"(seq)"', line)
    line = re.sub(r'"(x-amz-request-id|x-amz-id-2|x-minio-deployment-id)":"([^"]+)"', r'"\1":"(v)"', line)
    line = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", nid, line)
    sys.stdout.write(line)
