"""Shared by the admin API comparison scripts (adminops_cases.py,
adminops_dist_cases.py): signed requests, and comparing two servers'
answers with a readable first difference."""
import json
import os
import subprocess
import tempfile
import time
import urllib.parse

AK = SK = ""
ADMIN = "/minio/admin/v3"


def setup(ak, sk):
    global AK, SK
    AK, SK = ak, sk


class Score:
    passed = failed = 0


def first_diff(a, b):
    """The first place two answers differ, for a readable failure."""
    if type(a) is type(b) and isinstance(a, (list, tuple)):
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return first_diff(x, y)
        if len(a) != len(b):
            return f"lengths {len(a)} != {len(b)}; extra: {(a[len(b):] or b[len(a):])[:2]!r}"
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if a.get(k) != b.get(k):
                return f"[{k}] " + first_diff(a.get(k), b.get(k))
    return f"\n        minio:   {a!r}\n        buckets: {b!r}"


def compare(name, a, b):
    if a == b:
        Score.passed += 1
        if os.environ.get("VERBOSE"):
            print(f"  ok    {name}")
    else:
        Score.failed += 1
        print(f"  FAIL  {name}: {first_diff(a, b)}")
        if os.environ.get("DEBUG"):
            print(f"        minio:   {a!r}\n        buckets: {b!r}")


def curl(url, method="GET", data=None, headers=()):
    args = ["curl", "-s", "--path-as-is", "-X", method, "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", f"{AK}:{SK}",
            "-D", "-", "-o", "-"]
    for h in headers:
        args += ["-H", h]
    if data is not None:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data if isinstance(data, bytes) else data.encode())
        f.close()
        args += ["--data-binary", "@" + f.name]
    out = subprocess.run(args + [url], capture_output=True).stdout
    head, _, body = out.partition(b"\r\n\r\n")
    while head.startswith(b"HTTP/1.1 100"):
        head, _, body = body.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return int(lines[0].split()[1]) if lines and lines[0] else 0, hdrs, body


def admin(base, method, path, data=None):
    return curl(base + ADMIN + path, method, data)


def jbody(body):
    try:
        return json.loads(body)
    except ValueError:
        return body[:200]


def err_view(code, body):
    j = jbody(body)
    if isinstance(j, dict) and "Code" in j:
        return code, j["Code"], j.get("Message"), j.get("BucketName"), j.get("Key")
    return code, j


# ---- views that drop what differs by nature ----------------------------------------------------

def drives_view(drives, root, sort):
    if drives is None:
        return None
    out = [(os.path.relpath(d["endpoint"], root) if d["endpoint"].startswith(root) else d["endpoint"], d["state"],
            d["uuid"]) for d in drives]
    return sorted(out) if sort else out


def item_view(it, root):
    v = dict(it)
    if v["versionId"] not in ("", "null"):
        v["versionId"] = "<uuid>"  # differs by nature
    v["before"] = drives_view(it["before"]["drives"], root, it["type"] == "bucket")
    v["after"] = drives_view(it["after"]["drives"], root, it["type"] == "bucket")
    return v


def heal_run(base, root, path, opts, query=""):
    """Starts a heal and collects every item until it ends."""
    code, _, body = admin(base, "POST", f"/heal/{path}{query}", json.dumps(opts))
    if code != 200:
        return ("start", err_view(code, body))
    start = json.loads(body)
    token = start["clientToken"]
    items, summary, detail, settings = [], None, None, None
    for _ in range(600):
        code, _, body = admin(base, "POST", f"/heal/{path}?clientToken={urllib.parse.quote(token)}")
        if code != 200:
            return ("status", err_view(code, body))
        st = json.loads(body)
        items += st.get("Items") or []
        summary, detail, settings = st["Summary"], st.get("Detail"), st["Settings"]
        if summary not in ("running", "not started"):
            break
        time.sleep(0.05)
    if detail and " opts(" in detail:
        detail = detail.split(" opts(")[0]  # MinIO prints its listing options with pointers
    return (sorted(start.keys()), start["clientAddress"], summary, detail, settings,
            [item_view(i, root) for i in items])


def disk_view(d, root):
    v = dict(d)
    for k in ("endpoint", "path"):
        if k in v and v[k].startswith(root):
            v[k] = os.path.relpath(v[k], root)
    for k in ("totalspace", "usedspace", "availspace", "used_inodes", "free_inodes"):
        if k in v:
            v[k] = "<n>"
    if "uuid" in v:
        v["uuid"] = "<uuid>"
    if "metrics" in v:
        m = v["metrics"]
        v["metrics"] = {k: sorted(m[k]) if k == "apiCalls" else "<m>" for k in m if k != "lastMinute"}
    return v
