#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every metric the shipped alert rules and Grafana dashboards use is one that
bucketsd (or consoled) exports, on the endpoint the query asks for: a selector
with scope="cluster" must name a metric of /minio/v2/metrics/cluster, and
scope="node" one of /minio/v2/metrics/node (src/metrics/minio-catalog.tsv,
extra-catalog.tsv). So no alert or panel can watch a metric that never comes.

With PROMTOOL set (a promtool binary), every dashboard query must also parse:
each becomes a recording rule for `promtool check rules`.

  [PROMTOOL=...] python3 tests/monitoring/check_metrics.py"""
import json, os, re, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MON = os.path.join(ROOT, "operator", "helm", "buckets-operator", "monitoring")

# consoled's own metrics (src/console/console.c)
CONSOLE = {"buckets_console_logins_failed_total"}
# labels the ServiceMonitor adds, not metrics
LABELS = {"buckets_cluster"}
# Prometheus' own series
PROMETHEUS = {"up"}


def catalog():
    """{metric: {v2 endpoint group, ...}}"""
    out = {}
    for f in ("minio-catalog.tsv", "extra-catalog.tsv"):
        for line in open(os.path.join(ROOT, "src", "metrics", f)):
            if line.startswith("#") or not line.strip():
                continue
            col = line.rstrip("\n").split("\t")
            if len(col) >= 3 and col[0] == "V2":
                out.setdefault(col[2], set()).add(col[1])
    return out


def expressions():
    """(where, PromQL) pairs from the rules and the dashboards"""
    rules = open(os.path.join(MON, "rules.yaml")).read()
    for m in re.finditer(r"^\s+expr: (\|\n((?:\s{10,}.*\n)+)|(.*))", rules, re.M):
        yield "rules.yaml", m.group(2) or m.group(3)
    ddir = os.path.join(MON, "dashboards")
    for f in sorted(os.listdir(ddir)) if os.path.isdir(ddir) else []:
        d = json.load(open(os.path.join(ddir, f)))

        def walk(v):
            if isinstance(v, dict):
                for k, x in v.items():
                    if k in ("expr", "query") and isinstance(x, str):
                        yield x
                    elif k == "definition" and isinstance(x, str):
                        yield x
                    else:
                        yield from walk(x)
            elif isinstance(v, list):
                for x in v:
                    yield from walk(x)

        for e in walk(d):
            yield f, e


SELECTOR = re.compile(r"\b([a-z_][a-z0-9_]*)\s*(\{[^}]*\})?")
FUNCS = {"sum", "max", "min", "avg", "count", "rate", "increase", "irate", "by", "without", "and", "or", "unless",
         "predict_linear", "histogram_quantile", "label_values", "le", "on", "ignoring", "group_left", "group_right",
         "topk", "bottomk", "time", "vector", "scalar", "clamp_min", "clamp_max", "abs", "delta", "deriv", "offset",
         "avg_over_time", "max_over_time", "min_over_time", "sum_over_time", "changes", "resets", "bool", "label_replace",
         "absent", "sort", "sort_desc", "count_over_time", "quantile"}


def main():
    cat = catalog()
    problems, used = [], set()
    for where, expr in expressions():
        quoted = [m.span() for m in re.finditer(r'"[^"]*"', expr)]
        for m in SELECTOR.finditer(expr):
            if any(a <= m.start() < b for a, b in quoted):
                continue  # inside a label value
            name, sel = m.group(1), m.group(2) or ""
            if name in FUNCS or name in LABELS or name in PROMETHEUS:
                continue
            if not (name.startswith("minio_") or name.startswith("buckets_")):
                continue
            # in a by (...) list, a name is a label, not a metric
            if re.search(r"\b(by|without|on|ignoring)\s*\([^)]*$", expr[: m.start()]):
                continue
            base = name if name in cat else re.sub(r"_(bucket|count|sum)$", "", name)
            used.add(name)
            if name in CONSOLE:
                continue
            if base not in cat:
                problems.append(f"{where}: {name} is not a metric bucketsd exports")
                continue
            want = re.search(r'scope="(cluster|node|bucket)"', sel)
            if want and want.group(1) not in cat[base]:
                problems.append(f"{where}: {name} is not on the v2 {want.group(1)} endpoint (only {sorted(cat[base])})")
    promtool = os.environ.get("PROMTOOL")
    if promtool:
        queries = [e for w, e in expressions() if w != "rules.yaml"]
        rules = {"groups": [{"name": "dashboards", "rules": [
            {"record": f"dashboard_query_{i}", "expr": re.sub(r"\$(namespace|cluster|datasource)", "x", e)}
            for i, e in enumerate(queries) if not e.startswith("label_values(")]}]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            json.dump(rules, f)  # JSON is YAML
        r = subprocess.run([promtool, "check", "rules", f.name], capture_output=True, text=True)
        os.unlink(f.name)
        if r.returncode:
            problems.append("dashboard queries do not parse:\n" + r.stdout + r.stderr)
        else:
            print(f"queries: {len(rules['groups'][0]['rules'])} dashboard queries parse")
    for p in problems:
        print("FAIL:", p)
    print(f"metrics: {len(used)} used, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
