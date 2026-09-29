#!/usr/bin/env python3
"""Distributed-only admin APIs, a 4-node MinIO against a 4-node bucketsd
(see adminops-dist.sh).

usage: adminops_dist_cases.py BASE_PORT ACCESS SECRET WORK

MinIO's nodes listen on BASE+1..4, bucketsd's on BASE+11..14; node n's
drives are WORK/{m,b}/n<n>/d1..d2.
"""
import json
import os
import subprocess
import sys
import time

from adminlib import Score, admin, compare, curl, disk_view, err_view, heal_run, jbody, setup

BASE, AK, SK, WORK = int(sys.argv[1]), sys.argv[2], sys.argv[3], os.path.normpath(sys.argv[4])
setup(AK, SK)


def node(side, n):
    return f"http://127.0.0.1:{BASE + (0 if side == 'm' else 10) + n}"


SIDES = (("m", os.path.join(WORK, "m")), ("b", os.path.join(WORK, "b")))


def port_view(side, v):
    """Node addresses by their number (the two clusters use other ports)."""
    off = BASE + (0 if side == "m" else 10)
    s = json.dumps(v)
    for n in range(1, 5):
        s = s.replace(f"127.0.0.1:{off + n}", f"node{n}")
    return json.loads(s)


BIG = os.urandom(8 << 20)
for side, _ in SIDES:
    curl(f"{node(side, 1)}/lockb", "PUT")
    curl(f"{node(side, 1)}/lockb/big.bin", "PUT", BIG)
    curl(f"{node(side, 1)}/lockb/small.txt", "PUT", b"small")

# ---- top locks ----------------------------------------------------------------------------------------

def locks_view(side, entries):
    if not isinstance(entries, list):
        return entries
    out = []
    for e in entries:
        v = port_view(side, e)
        v["serverlist"] = sorted(v["serverlist"])
        if "leader" in v["resource"]:
            # which node wins the leader lock, and which servers granted it, is a race
            v["serverlist"] = len(v["serverlist"]) >= v["quorum"]
            v["owner"] = v["owner"].startswith("node")
        out.append((sorted(e.keys()), v["resource"], v["type"], v["source"] if "leader" in v["resource"] else "",
                    v["serverlist"], v["quorum"], v["owner"] if "leader" in v["resource"] else "",
                    len(v["id"]) > 0, isinstance(v["elapsed"], int) and v["elapsed"] > 0))
    return out



res = []
for side, _ in SIDES:
    c, h, b = admin(node(side, 1), "GET", "/top/locks")
    res.append((c, h.get("content-type"), locks_view(side, jbody(b))))
compare("top locks, only the leader's", *res)


def slow_get(side):
    """A GET read slowly holds the object's read lock meanwhile."""
    return subprocess.Popen(["curl", "-s", "--limit-rate", "200k", "--aws-sigv4", "aws:amz:us-east-1:s3", "--user",
                             f"{AK}:{SK}", "-o", "/dev/null", f"{node(side, 2)}/lockb/big.bin"])


res = []
for side, _ in SIDES:
    p = slow_get(side)
    time.sleep(1.5)
    out = []
    for q in ("", "?count=1", "?count=0", "?stale=true", "?count=-1"):
        c, _, b = admin(node(side, 1), "GET", "/top/locks" + q)
        out.append((q, c, locks_view(side, jbody(b))))
    # the same lock seen from another node
    c, _, b = admin(node(side, 3), "GET", "/top/locks")
    out.append(("node3", c, locks_view(side, jbody(b))))
    # its owner is the node serving the GET, the same one everywhere
    e1 = jbody(admin(node(side, 1), "GET", "/top/locks")[2])
    e3 = jbody(admin(node(side, 3), "GET", "/top/locks")[2])
    out.append(("same owner and id", [(x["owner"], x["id"]) for x in e1] == [(x["owner"], x["id"]) for x in e3]))
    c, _, b = admin(node(side, 1), "POST", "/force-unlock?paths=lockb/big.bin,lockb/nosuch")
    out.append(("force unlock", c, b))
    c, _, b = admin(node(side, 1), "GET", "/top/locks")
    out.append(("after unlock", c, locks_view(side, jbody(b))))
    p.kill()
    p.wait()
    res.append(out)
compare("top locks while a GET reads", *res)

for name, method, path in [("count not a number", "GET", "/top/locks?count=abc"),
                           ("count too big", "GET", "/top/locks?count=99999999999999999999"),
                           ("force unlock without paths", "POST", "/force-unlock"),
                           ("force unlock by GET", "GET", "/force-unlock?paths=x"),
                           ("top locks by POST", "POST", "/top/locks")]:
    res = []
    for side, _ in SIDES:
        c, _, b = admin(node(side, 1), method, path)
        res.append(port_view(side, err_view(c, b)) if c != 200 else (c, b))
    compare(name, *res)

# ---- heal sequences through another node ---------------------------------------------------------------

def drive_states(item, root):
    """(drive, before, after), by drive for a bucket (MinIO lists a node's drives in map order)."""
    out = []
    for b, a in zip(item["before"]["drives"], item["after"]["drives"]):
        path = b["endpoint"].split("127.0.0.1:")[1].split("/", 1)[1]
        out.append((os.path.relpath("/" + path, root), b["state"], a["state"]))
    return sorted(out) if item["type"] == "bucket" else out


R = {"recursive": True, "dryRun": False, "remove": False, "scanMode": 1}
res = []
for side, root in SIDES:
    os.remove(os.path.join(root, "n2", "d1", "lockb", "small.txt", "xl.meta"))
    code, _, body = admin(node(side, 1), "POST", "/heal/lockb", json.dumps(R))
    start = json.loads(body)
    tok = start["clientToken"]
    time.sleep(1.0)
    items = []
    # asked of node 3: it forwards to node 1, which runs the sequence
    c, _, b = admin(node(side, 3), "POST", f"/heal/lockb?clientToken={tok}")
    st = jbody(b)
    if isinstance(st, dict):
        items = st.get("Items") or []
        st = (st["Summary"], st["Settings"])
    c2, _, b2 = admin(node(side, 3), "POST", f"/heal/lockb?clientToken={tok.split(':')[0]}:9")
    res.append((tok.count(":"), tok.split(":")[-1], c, st,
                [(i["type"], i["object"], drive_states(i, root)) for i in items],
                port_view(side, err_view(c2, b2))))
compare("heal followed through another node", *res)

# ---- storage info and heal status across nodes ----------------------------------------------------------

res = []
for side, root in SIDES:
    c, _, b = admin(node(side, 2), "GET", "/storageinfo")
    j = json.loads(b)
    disks = []
    for d in j["Disks"]:
        v = disk_view(d, "")
        v["endpoint"] = port_view(side, v["endpoint"]).replace(root, "")
        v["path"] = v["path"].replace(root, "")
        disks.append(v)
    res.append((c, disks, j["Backend"]))
compare("storage info across nodes", *res)

res = []
for side, root in SIDES:
    c, h, b = admin(node(side, 2), "POST", "/background-heal/status")
    j = json.loads(b)
    sets = []
    for st in j["sets"]:
        ds = []
        for d in st["disks"]:
            v = disk_view(d, "")
            v["endpoint"] = port_view(side, v["endpoint"]).replace(root, "")
            v["path"] = v["path"].replace(root, "")
            ds.append(v)
        sets.append(dict(st, disks=ds))
    res.append((c, h.get("content-type"), j["offline_nodes"], j["HealDisks"], sets, j["sc_parity"]))
compare("background heal status across nodes", *res)

print(f"adminops-dist: {Score.passed} passed, {Score.failed} failed")
sys.exit(1 if Score.failed else 0)
