#!/usr/bin/env python3
"""The remaining admin APIs, MinIO against bucketsd (see adminops.sh).

usage: adminops_cases.py MINIO_URL BUCKETS_URL ACCESS SECRET MINIO_DRIVES BUCKETS_DRIVES

Each server's drives are <DRIVES>/d1..d4, so both can be damaged the same
way. Answers are compared after removing what differs by nature (tokens,
times, drive paths, disk usage figures).
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

MINIO, BUCKETS, AK, SK, MDRIVES, BDRIVES = sys.argv[1:7]
MDRIVES, BDRIVES = os.path.normpath(MDRIVES), os.path.normpath(BDRIVES)
SERVERS = ((MINIO, MDRIVES), (BUCKETS, BDRIVES))

from adminlib import (ADMIN, Score, admin, compare, curl, disk_view, err_view, heal_run, jbody,  # noqa: E402
                      setup)

setup(AK, SK)


def put(base, bucket, key, data):
    curl(f"{base}/{bucket}/{urllib.parse.quote(key)}", "PUT", data)


# ---- heal -----------------------------------------------------------------------------------------

def heal_case(name, path, opts, query="", prep=None, meta=False):
    res = []
    for base, root in SERVERS:
        if prep:
            prep(base, root)
        r = heal_run(base, root, path, opts, query)
        if meta and isinstance(r, tuple) and len(r) == 6:
            # the config objects themselves differ: compare their presence
            items = r[5]
            m = [i for i in items if i["type"] == "bucket-metadata"]
            rest = [i for i in items if i["type"] != "bucket-metadata"]
            base_id = rest[0]["resultId"] if rest else 0
            rest = [dict(i, resultId=i["resultId"] - base_id) for i in rest]
            r = r[:5] + (bool(m), all(i["detail"] == "" for i in m), rest)
        res.append(r)
    compare(f"heal {name}", *res)


def drive_obj(root, n, bucket, key):
    return os.path.join(root, f"d{n}", bucket, key)


def rm(p):
    if os.path.isdir(p):
        shutil.rmtree(p)
    elif os.path.exists(p):
        os.remove(p)


def part_files(root, bucket, key):
    return sorted(glob.glob(os.path.join(root, "d*", bucket, key, "*", "part.1")))


R = {"recursive": True, "dryRun": False, "remove": False, "scanMode": 1}
BIG = os.urandom(1200000)

for base, root in SERVERS:
    curl(f"{base}/healb", "PUT")
    put(base, "healb", "a/x.txt", b"hi")
    put(base, "healb", "a/y/z.txt", b"deep")
    put(base, "healb", "b.txt", b"yo")
    put(base, "healb", "big.bin", BIG)
    put(base, "healb", "rot.bin", BIG)
    put(base, "healb", "trunc.bin", BIG)

heal_case("healthy bucket", "healb", R)
heal_case("missing object on a drive", "healb", R, prep=lambda b, r: rm(drive_obj(r, 2, "healb", "b.txt")))
heal_case("missing xl.meta", "healb", R, prep=lambda b, r: rm(drive_obj(r, 3, "healb", "a/x.txt/xl.meta")))


def truncate(b, r):
    p = part_files(r, "healb", "trunc.bin")[0]
    with open(p, "r+b") as f:
        f.truncate(1000)


heal_case("truncated part", "healb", R, prep=truncate)


def rot(b, r):
    p = part_files(r, "healb", "rot.bin")[1]
    with open(p, "r+b") as f:
        f.seek(5000)
        f.write(b"X" * 64)


heal_case("bitrot, normal scan", "healb", R, prep=rot)
heal_case("bitrot, deep scan", "healb", dict(R, scanMode=2))
heal_case("missing bucket on a drive", "healb", R, prep=lambda b, r: rm(os.path.join(r, "d4", "healb")))
heal_case("dry run", "healb", dict(R, dryRun=True), prep=lambda b, r: rm(drive_obj(r, 1, "healb", "b.txt")))
heal_case("after the dry run", "healb", R)
heal_case("prefix", "healb/a/", R)
heal_case("prefix without slash", "healb/a", R)
heal_case("not recursive", "healb", dict(R, recursive=False))
heal_case("not recursive, prefix", "healb/a/", dict(R, recursive=False))
heal_case("object path", "healb/b.txt", R)
heal_case("no such bucket", "nosuchbucket", R)
heal_case("empty settings", "healb", {})
heal_case("pool and set", "healb", dict(R, pool=0, set=0))

for base, root in SERVERS:
    curl(f"{base}/healv", "PUT")
    curl(f"{base}/healv?versioning", "PUT",
         b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status>'
         b'</VersioningConfiguration>')
    for i in range(3):
        put(base, "healv", "v.txt", b"version %d" % i)
    curl(f"{base}/healv/v.txt", "DELETE")
    put(base, "healv", "w.txt", b"w")


def versions_view(r):
    # version IDs differ by nature: keep their order and shape
    if not isinstance(r, tuple) or len(r) != 6:
        return r
    items = []
    for it in r[5]:
        it = dict(it)
        if it["versionId"] not in ("", "null"):
            it["versionId"] = "<uuid>"
        items.append(it)
    return r[:5] + (items,)


res = []
for base, root in SERVERS:
    rm(drive_obj(root, 1, "healv", "v.txt"))
    res.append(versions_view(heal_run(base, root, "healv", R)))
compare("heal versions and a delete marker", *res)

# many objects: the sequence waits for its items to be collected
for base, root in SERVERS:
    curl(f"{base}/healmany", "PUT")
src = tempfile.mkdtemp()
for i in range(1010):
    with open(os.path.join(src, f"o{i:04d}"), "wb") as f:
        f.write(b"x")
MC = os.environ.get("MC", "mc")
cfg = tempfile.mkdtemp()
for alias, (base, _) in zip(("m", "b"), SERVERS):
    subprocess.run([MC, "--config-dir", cfg, "alias", "set", alias, base, AK, SK], capture_output=True)
    subprocess.run([MC, "--config-dir", cfg, "cp", "--recursive", "--quiet", src + "/", f"{alias}/healmany/"],
                   capture_output=True)
shutil.rmtree(src)

res = []
for base, root in SERVERS:
    out = []
    code, _, body = admin(base, "POST", "/heal/healmany", json.dumps(R))
    tok = json.loads(body)["clientToken"]
    time.sleep(1.5)  # it fills its buffer and waits
    # a second start on the same path, and on an overlapping one
    c2, _, b2 = admin(base, "POST", "/heal/healmany", json.dumps(R))
    j2 = jbody(b2)
    out.append(("again", c2, j2.get("clientToken") == tok if isinstance(j2, dict) and "clientToken" in j2 else j2))
    c3, _, b3 = admin(base, "POST", "/heal/healmany/o00", json.dumps(R))
    out.append(("overlap", err_view(c3, b3)))
    c3, _, b3 = admin(base, "POST", "/heal/", json.dumps(R))  # "." never overlaps
    out.append(("cluster-wide beside it", c3, sorted(jbody(b3).keys())))
    admin(base, "POST", "/heal/?forceStop", "{}")
    c4, _, b4 = admin(base, "POST", "/heal/healmany?clientToken=nosuchtoken")
    out.append(("bad token", err_view(c4, b4)))
    c5, _, b5 = admin(base, "POST", f"/heal/healmany?clientToken={tok}")
    st = json.loads(b5)
    out.append(("first batch", st["Summary"], len(st["Items"] or []), [i["resultId"] for i in st["Items"][:3]]))
    time.sleep(0.5)
    c5, _, b5 = admin(base, "POST", f"/heal/healmany?clientToken={tok}")
    st = json.loads(b5)
    out.append(("second batch", len(st["Items"] or []), (st["Items"] or [{}])[0].get("resultId")))
    c6, _, b6 = admin(base, "POST", "/heal/healmany?forceStart", json.dumps(R))
    j6 = jbody(b6)
    out.append(("force start", c6, sorted(j6.keys()) if isinstance(j6, dict) else j6, j6.get("clientToken") != tok))
    time.sleep(1.5)
    c7, _, b7 = admin(base, "POST", "/heal/healmany?forceStop", "{}")
    j7 = jbody(b7)
    out.append(("force stop", c7, sorted(j7.keys()), j7.get("clientToken") == j6.get("clientToken")))
    c8, _, b8 = admin(base, "POST", f"/heal/healmany?clientToken={j6['clientToken']}")
    out.append(("after stop", c8, jbody(b8)))
    res.append(out)
compare("heal sequence lifecycle", *res)

for name, path, data, query in [
    ("bad body", "healb", "not json", ""),
    ("empty body", "healb", "", ""),
    ("wrong type", "healb", '{"recursive":"yes"}', ""),
    ("start and stop", "healb", "{}", "?forceStart&forceStop"),
    ("token and start", "healb", "{}", "?clientToken=x&forceStart"),
    ("short bucket", "ab", "{}", ""),
    ("reserved bucket", "minio", "{}", ""),
    ("meta bucket", ".minio.sys", "{}", ""),
    ("bad prefix", "healb/a/../b", "{}", ""),
    ("double slash", "healb/a//b", "{}", ""),
    ("stop nothing", "healb", "{}", "?forceStop"),
    ("stop without a body", "healb", None, "?forceStop"),
    ("status nothing", "healb", None, "?clientToken=abc"),
]:
    res = []
    for base, root in SERVERS:
        c, _, b = admin(base, "POST", f"/heal/{path}{query}", data)
        j = jbody(b)
        if isinstance(j, dict) and "clientToken" in j:
            j = (j["clientToken"] == "unknown", j["clientAddress"])
        elif isinstance(j, dict) and "Summary" in j:
            j = (j["Summary"], j["StartTime"], j["Settings"], j["Items"])
        elif isinstance(j, dict):
            j = (j.get("Code"), j.get("Message"), j.get("BucketName"))
        res.append((c, j))
    compare(f"heal {name}", *res)

heal_case("the whole cluster", "", R, meta=True)

# ---- storage info and background heal status ------------------------------------------------------

res = []
for base, root in SERVERS:
    c, h, b = admin(base, "GET", "/storageinfo")
    j = json.loads(b)
    res.append((c, h.get("content-type"), sorted(j), [disk_view(d, root) for d in j["Disks"]], j["Backend"]))
compare("storage info", *res)

res = []
for base, root in SERVERS:
    c, h, b = admin(base, "POST", "/background-heal/status")
    j = json.loads(b)
    sets = [dict(st, disks=[disk_view(d, root) for d in st["disks"]]) for st in j["sets"]]
    res.append((c, h.get("content-type"), list(j), j["offline_nodes"], j["HealDisks"], sets, j["mrf"], j["sc_parity"]))
compare("background heal status", *res)

res = []
for base, root in SERVERS:
    c, h, b = admin(base, "GET", "/info")
    j = json.loads(b)
    res.append([sorted(d.get("metrics", {"none": 1})) for s in j["servers"] for d in s["drives"]])
    c, h, b = admin(base, "GET", "/info?metrics=true")
    j = json.loads(b)
    res[-1].append([sorted(d.get("metrics", {})) for s in j["servers"] for d in s["drives"]])
compare("server info drive metrics", *res)

for name, method, path in [("storage info by POST", "POST", "/storageinfo"),
                           ("top locks on one node", "GET", "/top/locks"),
                           ("force unlock on one node", "POST", "/force-unlock?paths=a/b"),
                           ("unknown admin API", "GET", "/no-such-api"),
                           ("heal status by GET", "GET", "/background-heal/status")]:
    res = []
    for base, root in SERVERS:
        c, _, b = admin(base, method, path)
        res.append(err_view(c, b))
    compare(name, *res)

# ---- bucket metadata export and import ---------------------------------------------------------------
import io  # noqa: E402
import re  # noqa: E402
import zipfile  # noqa: E402

MC_CFG = tempfile.mkdtemp()
for alias, (base, _) in zip(("m", "b"), SERVERS):
    subprocess.run([MC, "--config-dir", MC_CFG, "alias", "set", alias, base, AK, SK], capture_output=True)


def mc(*args):
    return subprocess.run([MC, "--config-dir", MC_CFG, *args], capture_output=True, text=True)


def config_view(name, data):
    """A configuration with what differs by nature (IDs, times, set order) taken out."""
    text = data.decode()
    if name.endswith("lifecycle.xml"):
        text = re.sub(r"<ID>[^<]*</ID>", "<ID/>", text)
        text = re.sub(r"<ExpiryUpdatedAt>[^<]*</ExpiryUpdatedAt>", "<ExpiryUpdatedAt/>", text)
    if name.endswith("tagging.xml"):
        return sorted(re.findall(r"<Tag>.*?</Tag>", text))
    if name.endswith("policy.json"):
        j = json.loads(text)
        for st in j.get("Statement") or []:
            for k in ("Action", "NotAction", "Resource", "NotResource"):
                if k in st:
                    st[k] = sorted(st[k])
        return j
    return text


def zip_view(body):
    try:
        z = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile:
        return ("not a zip", body[:200])
    return [(i.filename, i.compress_type, oct(i.external_attr >> 16), config_view(i.filename, z.read(i)))
            for i in z.infolist()]


for a in ("m", "b"):
    mc("mb", "--with-lock", f"{a}/metaa")
    mc("mb", f"{a}/metab")
    mc("anonymous", "set", "download", f"{a}/metaa")
    mc("ilm", "rule", "add", "--expire-days", "30", "--prefix", "logs/", f"{a}/metaa")
    mc("tag", "set", f"{a}/metaa", "k1=v1&k2=v2")
    mc("quota", "set", f"{a}/metaa", "--size", "1GiB")
    mc("retention", "set", "--default", "GOVERNANCE", "1d", f"{a}/metaa")
    mc("version", "enable", f"{a}/metab")
for base, _ in SERVERS:
    curl(f"{base}/metab?policy", "PUT", json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "ip", "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObject", "s3:DeleteObject"],
         "Resource": ["arn:aws:s3:::metab/*"], "Condition": {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
                                                           "StringLike": {"s3:prefix": ["a/*", "b/*"]}}}]}))

for q in ("", "?bucket=metaa", "?bucket=metab/", "?bucket=./metab", "?bucket=nosuchbucket"):
    res = []
    for base, _ in SERVERS:
        c, h, b = admin(base, "GET", "/export-bucket-metadata" + q)
        v = zip_view(b) if c == 200 else err_view(c, b)
        if q == "":  # only the buckets made here
            v = [x for x in v if x[0].split("/")[0] in ("metaa", "metab")] if isinstance(v, list) else v
        res.append((c, v))
    compare(f"export bucket metadata {q or '(all)'}", *res)


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
    return buf.getvalue()


LOCK = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>2</Days></DefaultRetention></Rule></ObjectLockConfiguration>"
IMPORT = make_zip([
    ("impa/object-lock.xml", LOCK),
    ("impa/policy.json", json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::impa/*"]}]})),
    ("impa/lifecycle.xml", "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status><Filter><Prefix>x/</Prefix></Filter><Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>"),
    ("impa/tagging.xml", "<Tagging><TagSet><Tag><Key>team</Key><Value>eng</Value></Tag></TagSet></Tagging>"),
    ("impa/quota.json", '{"quota":0,"size":5368709120,"rate":0,"requests":0,"quotatype":"hard"}'),
    ("impa/versioning.xml", '<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>'),
    ("impa/notification.xml", "<NotificationConfiguration></NotificationConfiguration>"),
    ("impa/bucket-encryption.xml", '<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>'),
    ("impa/replication.xml", "<ReplicationConfiguration></ReplicationConfiguration>"),
    ("impb/versioning.xml", '<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>'),
    ("impb/policy.json", json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::impb/*"}]})),
    ("impb/quota.json", '{"quota":"lots"}'),
    ("impb/object-lock.xml", "<ObjectLockConfiguration><ObjectLockEnabled>Nope</ObjectLockEnabled></ObjectLockConfiguration>"),
    ("impc/whatever.txt", "x"),
    ("toplevel.txt", "x"),
    ("metab/tagging.xml", "<Tagging><TagSet><Tag><Key>imported</Key><Value>yes</Value></Tag></TagSet></Tagging>"),
])
res = []
for base, _ in SERVERS:
    c, _, b = admin(base, "PUT", "/import-bucket-metadata", IMPORT)
    res.append((c, jbody(b)))
compare("import bucket metadata report", *res)

res = []
for base, _ in SERVERS:
    out = []
    for bucket in ("impa", "impb", "impc", "metab"):
        for sub in ("policy", "tagging", "lifecycle", "object-lock", "versioning", "encryption", "notification"):
            c, _, b = curl(f"{base}/{bucket}?{sub}")
            text = b.decode(errors="replace")
            text = re.sub(r"<(RequestId|HostId)>[^<]*</\1>", "", text)
            text = re.sub(r"<ExpiryUpdatedAt>[^<]*</ExpiryUpdatedAt>", "<ExpiryUpdatedAt/>", text)
            out.append((bucket, sub, c, config_view("policy.json", b) if sub == "policy" and c == 200 else text))
        c, _, b = admin(base, "GET", f"/get-bucket-quota?bucket={bucket}")
        out.append((bucket, "quota", c, jbody(b) if c == 200 else err_view(c, b)))
    res.append(out)
compare("configurations after the import", *res)

for name, body in [("not a zip", b"hello"), ("empty body", b""), ("empty zip", make_zip([]))]:
    res = []
    for base, _ in SERVERS:
        c, _, b = admin(base, "PUT", "/import-bucket-metadata", body)
        res.append(err_view(c, b) if c != 200 else (c, jbody(b)))
    compare(f"import {name}", *res)

# ---- inspect ------------------------------------------------------------------------------------------
DEC = os.environ.get("INSPECTDEC")
if DEC:
    keyfile = os.path.join(MC_CFG, "inspect.key")
    pub = subprocess.run([DEC, "genkey", keyfile], capture_output=True, text=True).stdout
    for base, root in SERVERS:
        put(base, "healb", "insp/one.txt", b"one")
        put(base, "healb", "insp/two.txt", b"two")

    def inspect_view(root, body, key=None):
        out = subprocess.run([DEC] + ([key] if key else []), input=body, capture_output=True).stdout
        j = json.loads(out)
        entries = []
        for e in j.get("entries") or []:
            name = re.sub(r"\S*/(m|b)/d", "<root>/d", e["name"])
            content = re.sub(r"\S*/(m|b)/d", "<root>/d", e["content"])
            if e["name"] == "cluster.info":
                content = sorted(json.loads(content))
            elif name.endswith((".json", "xl.meta")) or content.startswith("binary:"):
                content = "<data>"
            entries.append((name, e["mode"], e["method"], content))
        return j["format"], j.get("streams"), j.get("error"), j.get("zipError"), entries

    for name, q, with_key in [("an object's xl.meta", "volume=healb&file=insp/one.txt/xl.meta", False),
                              ("a pattern", "volume=healb&file=insp/*/xl.meta", False),
                              ("a recursive pattern", "volume=healb&file=insp/**", False),
                              ("a directory", "volume=healb&file=insp", False),
                              ("nothing matched", "volume=healb&file=nosuch", False),
                              ("encrypted to a key", "volume=healb&file=insp/two.txt/xl.meta", True),
                              ("encrypted, nothing matched", "volume=healb&file=nosuch*", True)]:
        res = []
        for base, root in SERVERS:
            qq = q + ("&public-key=" + urllib.parse.quote(pub, safe="") if with_key else "")
            c, h, b = admin(base, "GET", "/inspect-data?" + qq)
            res.append((c, inspect_view(root, b, keyfile if with_key else None) if c == 200 else err_view(c, b)))
        compare(f"inspect {name}", *res)

for name, q in [("no volume", "file=x"), ("no file", "volume=healb"), ("a parent path", "volume=healb&file=../x"),
                ("a bad public key", "volume=healb&file=x&public-key=%25%25%25")]:
    res = []
    for base, root in SERVERS:
        c, h, b = admin(base, "GET", "/inspect-data?" + q)
        v = err_view(c, b)
        if not isinstance(v[1], str):
            m = re.search(rb"<Code>(.*?)</Code><Message>(.*?)</Message>", b)
            v = (c, m.groups() if m else b[:100])
        res.append(v)
    compare(f"inspect {name}", *res)

# ---- speedtests ---------------------------------------------------------------------------------------

def speed_view(body):
    """Each streamed line's shape; the last one's servers, errors and counts."""
    lines = [json.loads(x) for x in body.decode().splitlines() if x.strip()]
    if not lines:
        return body[:200]
    last = lines[-1]
    def stats(st):
        return (sorted(st), sorted(st["responseTime"]), st["throughputPerSec"] > 0,
                [(x["endpoint"], x["err"], x["throughputPerSec"] > 0) for x in st["servers"] or []])
    return (lines[0]["version"] == "", sorted(last), last["servers"], last["disks"], last["size"],
            stats(last["PUTStats"]), stats(last["GETStats"]))


def endpoint_view(v, base):
    return json.loads(json.dumps(v).replace(base.split("//")[1], "<node>"))


for name, q in [("object", "/speedtest?size=262144&concurrent=2&duration=1s"),
                ("object, path", "/speedtest/object?size=262144&concurrent=2&duration=1s"),
                ("object, autotune", "/speedtest?size=262144&concurrent=2&duration=1s&autotune=true"),
                ("object, custom bucket", "/speedtest?size=262144&concurrent=2&duration=1s&bucket=healb")]:
    res = []
    for base, root in SERVERS:
        c, h, b = admin(base, "POST", q)
        v = speed_view(b) if c == 200 else err_view(c, b)
        if "autotune" in q and c == 200:
            v = v[:4] + v[5:]  # how far autotuning goes depends on the machine
        res.append((c, h.get("content-type"), endpoint_view(v, base)))
    compare(f"speedtest {name}", *res)

res = []
for base, root in SERVERS:
    c, h, b = admin(base, "POST", "/speedtest?size=999999999999999&concurrent=64")
    v = err_view(c, b)
    res.append((v[0], v[1], re.sub(r"[0-9.]+ [KMGTPE]?i?B", "<n>", v[2] or "")))
compare("speedtest without enough space", *res)

res = []
for base, root in SERVERS:
    c1, _, _ = curl(f"{base}/minio-perf-test-tmp-bucket")
    c2, _, b = curl(f"{base}/healb?list-type=2&prefix=speedtest/")
    res.append((c1, c2, b.count(b"<Key>")))
compare("speedtest cleans up", *res)

res = []
for base, root in SERVERS:
    c, h, b = admin(base, "POST", "/speedtest/drive?filesize=1048576&blocksize=65536")
    lines = [json.loads(x) for x in b.decode().splitlines() if x.strip()]
    last = lines[-1] if lines else {}
    for d in last.get("drivePerf") or []:
        d["path"] = os.path.relpath(d["path"], root)
        d["readThroughput"] = d["readThroughput"] > 0
        d["writeThroughput"] = d["writeThroughput"] > 0
    last.pop("version", None)
    res.append((c, h.get("content-type"), endpoint_view(last, base)))
compare("drive speedtest", *res)

# ---- network speedtests -------------------------------------------------------------------------------
for name, path in [("net on one node", "/speedtest/net"), ("site without site replication", "/speedtest/site")]:
    res = []
    for base, root in SERVERS:
        c, _, b = admin(base, "POST", path)
        res.append(err_view(c, b))
    compare(f"speedtest {name}", *res)

res = []
for base, root in SERVERS:
    body = subprocess.run(
        ["sh", "-c", f"head -c 20000000 /dev/zero | curl -s -o /dev/null -w '%{{http_code}}' -X POST "
                     f"-H 'Transfer-Encoding: chunked' -H 'X-Amz-Content-Sha256: UNSIGNED-PAYLOAD' --data-binary @- "
                     f"--aws-sigv4 aws:amz:us-east-1:s3 --user {AK}:{SK} {base}{ADMIN}/speedtest/client/devnull"],
        capture_output=True, text=True).stdout
    c, h, b = admin(base, "POST", "/speedtest/client/devnull/extratime")
    j = json.loads(b)
    res.append((body, c, h.get("content-type"), sorted(j), all(v > 0 for v in j.values())))
compare("client perf (devnull, extra time)", *res)

print(f"adminops: {Score.passed} passed, {Score.failed} failed")
sys.exit(1 if Score.failed else 0)
