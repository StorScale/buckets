#!/usr/bin/env python3
"""Formats s3bench's JSON for tests/bench/warp.sh: kind size clients json.
With --warp, reads warp's text reports on stdin and prints them as that JSON."""
import json
import re
import sys


def from_warp(text):
    """warp's 'Report: PUT' / 'Report: GET' blocks (the phase's own op only)."""
    phases = []
    for m in re.finditer(r"Report: (PUT|GET)\. Concurrency: \d+\. Ran: [^\n]*\n(.*?)(?=Report:|\Z)", text, re.S):
        op, body = m.group(1), m.group(2)
        avg = re.search(r"Average: ([\d.]+) MiB/s, ([\d.]+) obj/s", body)
        reqs = re.search(r"50%: ([\d.]+)(ms|s|µs).*?99%: ([\d.]+)(ms|s|µs)", body)
        errs = re.search(r"Errors: (\d+)", body)

        def ms(v, u):
            return float(v) * {"ms": 1, "s": 1000, "µs": 0.001}[u]

        phases.append({"op": op, "ops": 0, "errors": int(errs.group(1)) if errs else 0,
                       "mib_per_s": float(avg.group(1)) if avg else 0.0, "ops_per_s": float(avg.group(2)) if avg else 0.0,
                       "p50_ms": ms(reqs.group(1), reqs.group(2)) if reqs else 0.0,
                       "p99_ms": ms(reqs.group(3), reqs.group(4)) if reqs else 0.0,
                       "first_error": "" if avg else text.strip().splitlines()[-1][:200] if text.strip() else "no output"})
    if not phases:
        phases.append({"op": "WARP", "ops": 0, "errors": 1, "mib_per_s": 0, "ops_per_s": 0, "p50_ms": 0, "p99_ms": 0,
                       "first_error": (text.strip().splitlines() or ["no output"])[-1][:200]})
    return phases


if sys.argv[1:] == ["--warp"]:
    print(json.dumps(from_warp(sys.stdin.read())))
    sys.exit(0)

kind, size, conc, raw = sys.argv[1:5]
for p in json.loads(raw):
    err = ""
    if p["errors"]:
        err = "  errors %d: %s" % (p["errors"], p.get("first_error", "")[:60])
    print("%-8s %7d KiB x%3s %-4s %8.1f MiB/s %8.1f op/s  p50 %7.1f ms  p99 %7.1f ms%s"
          % (kind, int(size) // 1024, conc, p["op"], p["mib_per_s"], p["ops_per_s"], p["p50_ms"], p["p99_ms"], err))
