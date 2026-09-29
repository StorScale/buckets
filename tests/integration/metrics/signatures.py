# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prometheus text -> one line per metric family and label-name set:
"name type {label,...}" (sorted), plus "(help) name: text" lines when
--help is given. The metrics gate diffs these between MinIO and bucketsd."""
import re
import sys

show_help = "--help" in sys.argv
types, helps, sigs = {}, {}, set()
for line in sys.stdin:
    line = line.rstrip("\n")
    m = re.match(r"# (HELP|TYPE) (\S+) ?(.*)", line)
    if m:
        (helps if m.group(1) == "HELP" else types)[m.group(2)] = m.group(3)
        continue
    if not line or line.startswith("#"):
        continue
    m = re.match(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? ", line)
    if not m:
        continue
    name, labels = m.group(1), m.group(3) or ""
    keys = sorted(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="(?:[^"\\]|\\.)*"', labels))
    fam = name
    for suf in ("_sum", "_count", "_bucket"):
        if name.endswith(suf) and name[: -len(suf)] in types:
            fam = name[: -len(suf)]
    sigs.add("%s %s {%s}" % (name, types.get(fam, "?"), ",".join(keys)))
for s in sorted(sigs):
    print(s)
if show_help:
    for n in sorted(helps):
        print("(help) %s: %s" % (n, helps[n]))
