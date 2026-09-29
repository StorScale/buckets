#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compares two s3-tests JUnit reports (a MinIO baseline and bucketsd):
totals, and the tests whose outcome differs.

  python3 tests/conformance/s3-tests-compare.py .conformance/minio.xml .conformance/buckets.xml

Exits non-zero when bucketsd passes fewer tests than the baseline, or fails a
test the baseline passes (the Phase 5 gate)."""
import sys
import xml.etree.ElementTree as ET


def outcomes(path):
    res = {}
    for tc in ET.parse(path).getroot().iter("testcase"):
        name = tc.get("name")
        kids = {c.tag for c in tc}
        if "skipped" in kids:
            res[name] = "skip"
        elif "failure" in kids or "error" in kids:
            res[name] = "fail"
        else:
            res[name] = "pass"
    return res


base, cand = outcomes(sys.argv[1]), outcomes(sys.argv[2])
for label, r in (("minio", base), ("buckets", cand)):
    counts = {k: sum(1 for v in r.values() if v == k) for k in ("pass", "fail", "skip")}
    print("%-8s %4d pass %4d fail %4d skip" % (label, counts["pass"], counts["fail"], counts["skip"]))
regressions = sorted(n for n, v in base.items() if v == "pass" and cand.get(n) != "pass")
gains = sorted(n for n, v in cand.items() if v == "pass" and base.get(n) != "pass")
print("\nfail on bucketsd, pass on MinIO (%d):" % len(regressions))
for n in regressions:
    print("  " + n)
print("\npass on bucketsd, fail on MinIO (%d):" % len(gains))
for n in gains:
    print("  " + n)
bp = sum(1 for v in base.values() if v == "pass")
cp = sum(1 for v in cand.values() if v == "pass")
sys.exit(1 if regressions or cp < bp else 0)
