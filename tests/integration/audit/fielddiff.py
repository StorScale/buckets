# SPDX-License-Identifier: AGPL-3.0-or-later
"""Field-by-field differences between two normalized audit logs."""
import json
import sys
from collections import Counter


def load(fn):
    out = []
    for line in open(fn):
        i = line.index("{")
        out.append((line[:i].strip(), json.loads(line[i:])))
    return out


def flat(d, pre=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from flat(v, pre + k + ".")
        else:
            yield pre + k, v


a, b = load(sys.argv[1]), load(sys.argv[2])
diffs = Counter()
examples = {}
if len(a) != len(b):
    print("entry counts differ: %d vs %d" % (len(a), len(b)))
for (ha, ea), (hb, eb) in zip(a, b):
    if ha != hb:
        diffs["(post header)"] += 1
        examples.setdefault("(post header)", (ha, hb))
    fa, fb = dict(flat(ea)), dict(flat(eb))
    name = ea.get("api", {}).get("name", "?")
    for k in sorted(set(fa) | set(fb)):
        if fa.get(k, "<absent>") != fb.get(k, "<absent>"):
            diffs[k] += 1
            examples.setdefault(k, (name, fa.get(k, "<absent>"), fb.get(k, "<absent>")))
for k, n in diffs.most_common():
    print("%3d  %-45s e.g. %s" % (n, k, examples[k]))
