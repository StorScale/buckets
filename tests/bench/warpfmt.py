#!/usr/bin/env python3
"""Formats s3bench's JSON for tests/bench/warp.sh: kind size clients json."""
import json
import sys

kind, size, conc, raw = sys.argv[1:5]
for p in json.loads(raw):
    err = ""
    if p["errors"]:
        err = "  errors %d: %s" % (p["errors"], p.get("first_error", "")[:60])
    print("%-8s %7d KiB x%3s %-4s %8.1f MiB/s %8.1f op/s  p50 %7.1f ms  p99 %7.1f ms%s"
          % (kind, int(size) // 1024, conc, p["op"], p["mib_per_s"], p["ops_per_s"], p["p50_ms"], p["p99_ms"], err))
