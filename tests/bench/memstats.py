#!/usr/bin/env python3
"""Memory of the servers' pods for tests/bench/cluster.sh, in bytes.

  memstats.py cadvisor NAMESPACE POD_PREFIX   a kubelet's cAdvisor metrics on stdin -> "pod rss working_set" lines
  memstats.py median                          those lines on stdin -> {"pod": [rss, working_set]}, the median of each
  memstats.py round LABEL BEFORE PEAK AFTER   idle before (median JSON), samples during (lines), idle after -> a
                                              results line: {"server": LABEL, "memory": {pod: {...}}}
  memstats.py show                            a results line on stdin -> one line per pod

The pod-level series (container="", the pod's own cgroup) is read, so clusters that label containers and clusters
that don't are read alike. RSS is anonymous memory, what the process itself holds. The working set adds the page
cache that can't be dropped at once, and is what the kubelet compares with limits and evictions."""
import json
import re
import statistics
import sys


def cadvisor(ns, prefix):
    line_re = re.compile(r'^container_memory_(rss|working_set_bytes)\{([^}]*)\} (\S+)')
    label_re = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
    mem = {}
    for line in sys.stdin:
        m = line_re.match(line)
        if not m:
            continue
        labels = dict(label_re.findall(m.group(2)))
        pod = labels.get("pod", "")
        if labels.get("namespace") == ns and pod.startswith(prefix) and labels.get("container", "") == "":
            mem.setdefault(pod, {})[m.group(1)] = int(float(m.group(3)))
    for pod, v in sorted(mem.items()):
        if "rss" in v and "working_set_bytes" in v:
            print(pod, v["rss"], v["working_set_bytes"])


def samples(f):
    by = {}
    for line in f:
        pod, rss, ws = line.split()
        by.setdefault(pod, []).append((int(rss), int(ws)))
    return by


def median():
    print(json.dumps({pod: [statistics.median(r for r, _ in v), statistics.median(w for _, w in v)]
                      for pod, v in samples(sys.stdin).items()}))


def round_(label, before, peak, after):
    before, after = json.load(open(before)), json.load(open(after))
    peak = {pod: [max(r for r, _ in v), max(w for _, w in v)] for pod, v in samples(open(peak)).items()}
    out = {}
    for pod in sorted(set(before) | set(peak) | set(after)):
        out[pod] = {}
        for when, d in (("idle", before), ("peak", peak), ("after", after)):
            rss, ws = d.get(pod, [0, 0])
            out[pod][f"{when}_rss"], out[pod][f"{when}_ws"] = int(rss), int(ws)
    print(json.dumps({"server": label, "memory": out}))


def show():
    mib = lambda b: b / (1 << 20)
    for pod, m in json.loads(sys.stdin.read())["memory"].items():
        print("%-16s RSS idle %5.0f MiB, peak %5.0f MiB, after %5.0f MiB; working set peak %5.0f MiB"
              % (pod, mib(m["idle_rss"]), mib(m["peak_rss"]), mib(m["after_rss"]), mib(m["peak_ws"])))


cmd, args = sys.argv[1], sys.argv[2:]
{"cadvisor": cadvisor, "median": median, "round": round_, "show": show}[cmd](*args)
