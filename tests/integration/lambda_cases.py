#!/usr/bin/env python3
"""Object lambda (GET ?lambdaArn=), against MinIO: a local webhook plays the
lambda function, transforming the object it fetches through the presigned
URL; the servers' answers, and the events they send the function, agree.

usage: lambda_cases.py MINIO_URL BUCKETS_URL ACCESS SECRET WEBHOOK_PORT
"""
import http.server
import json
import re
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

MINIO, BUCKETS, AK, SK, WPORT = sys.argv[1:6]
EVENTS = []


class Lambda(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        ev = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        EVENTS.append((ev, self.headers.get("Authorization")))
        ctx = ev["getObjectContext"]
        try:
            data = urllib.request.urlopen(ctx["inputS3Url"]).read()
        except urllib.error.HTTPError:
            self.close_connection = True  # the function fails: no answer at all
            return
        mode = ev["userRequest"]["url"].split("?")[0].rsplit("/", 1)[-1]
        route, token, status, extra = ctx["outputRoute"], ctx["outputToken"], 200, {}
        body = data.upper()
        if mode == "badroute":
            route = "nope"
        elif mode == "badtoken":
            token = "0" * 64
        elif mode == "fwdstatus":
            extra = {"x-amz-fwd-status": "206", "x-amz-fwd-header-Content-Type": "text/x-upper",
                     "x-amz-fwd-header-x-amz-meta-transformed": "yes", "x-amz-fwd-header-Cache-Control": "no-store"}
        elif mode == "fwderror":
            extra = {"x-amz-fwd-status": "403", "x-amz-fwd-error-code": "NoWay", "x-amz-fwd-error-message": "the lambda says no"}
        elif mode == "fwderrornocode":
            extra = {"x-amz-fwd-status": "400", "x-amz-fwd-error-message": "message only"}
        elif mode == "fwderrorbare":
            extra = {"x-amz-fwd-status": "500"}
        elif mode == "badstatus":
            extra = {"x-amz-fwd-status": "two hundred"}
        self.send_response(status)
        self.send_header("x-amz-request-route", route)
        self.send_header("x-amz-request-token", token)
        for k, v in extra.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(WPORT)), Lambda)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def curl(url, method="GET", data=None, headers=()):
    args = ["curl", "-s", "-X", method, "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", f"{AK}:{SK}", "-D", "-", "-o", "-"]
    for h in headers:
        args += ["-H", h]
    if data is not None:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        args += ["--data-binary", "@" + f.name]
    out = subprocess.run(args + [url], capture_output=True).stdout
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return int(lines[0].split()[1]), hdrs, body


def view(code, h, body):
    keep = {k: h[k] for k in ("content-type", "x-amz-meta-transformed", "cache-control") if k in h}
    if code >= 300:
        m = re.search(rb"<Code>(.*?)</Code>.*?<Message>(.*?)</Message>", body, re.S)
        return code, keep, m.groups() if m else body[:120]
    return code, keep, body


def event_view(ev, authz):
    """The event with its per-request parts made comparable."""
    ctx = ev["getObjectContext"]
    u = urllib.request.urlparse(ctx["inputS3Url"])
    q = sorted(k for k in urllib.parse.parse_qs(u.query))
    hdrs = {k: v for k, v in ev["userRequest"]["headers"].items() if k not in ("X-Amz-Date", "Authorization", "User-Agent")}
    return (sorted(ev.keys()), ev["protocolVersion"], len(ctx["outputRoute"]) > 0, len(ctx["outputToken"]), u.path, q,
            ev["userIdentity"], ev["userRequest"]["url"], hdrs, authz)


import urllib.parse  # noqa: E402

passed = failed = 0


def compare(name, a, b):
    global passed, failed
    if a == b:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL  {name}\n        minio:   {a!r}\n        buckets: {b!r}")


ARN = "arn:minio:s3-object-lambda::fn:webhook"
for base in (MINIO, BUCKETS):
    curl(f"{base}/lam", "PUT")
    for k in ("plain", "badroute", "badtoken", "fwdstatus", "fwderror", "fwderrornocode", "fwderrorbare", "badstatus"):
        curl(f"{base}/lam/{k}", "PUT", b"hello lambda " + k.encode())
for key, q in [("plain", f"lambdaArn={ARN}"), ("plain", f"lambdaArn={ARN}&response-content-type=text%2Fplain"),
               ("badroute", f"lambdaArn={ARN}"), ("badtoken", f"lambdaArn={ARN}"), ("fwdstatus", f"lambdaArn={ARN}"),
               ("fwderror", f"lambdaArn={ARN}"), ("fwderrornocode", f"lambdaArn={ARN}"), ("fwderrorbare", f"lambdaArn={ARN}"),
               ("badstatus", f"lambdaArn={ARN}"), ("plain", "lambdaArn=arn:minio:s3-object-lambda::nosuch:webhook"),
               ("plain", "lambdaArn=arn:aws:lambda:x"), ("plain", "lambdaArn=arn:minio:s3-object-lambda::fn"),
               ("plain", "lambdaArn=arn:minio:s3-object-lambda::fn:other"), ("nosuchkey", f"lambdaArn={ARN}")]:
    res, evs = [], []
    for base in (MINIO, BUCKETS):
        n = len(EVENTS)
        res.append(view(*curl(f"{base}/lam/{key}?{urllib.parse.quote(q, safe='=&%')}", headers=("X-Test-Header: one",))))
        evs.append([event_view(*e) for e in EVENTS[n:]])
    compare(f"{key}?{q}", *res)
    compare(f"event for {key}?{q}", *evs)
print(f"lambda: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
