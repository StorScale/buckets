# SPDX-License-Identifier: AGPL-3.0-or-later
"""ListenNotification client for tests: a SigV4-signed GET that copies the
event stream to stdout until killed (or SECONDS pass).

  python3 listen.py ENDPOINT ACCESS SECRET PATH QUERY [SECONDS]
"""
import datetime
import hashlib
import hmac
import http.client
import sys
import time
import urllib.parse

ep, ak, sk, path, query = sys.argv[1:6]
limit = float(sys.argv[6]) if len(sys.argv) > 6 else 1e9
u = urllib.parse.urlparse(ep)
now = datetime.datetime.utcnow()
amzdate, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
q = lambda v: urllib.parse.quote(v, safe="-_.~")
pairs = sorted((q(urllib.parse.unquote(k)), q(urllib.parse.unquote(v)))
               for k, _, v in (p.partition("=") for p in query.split("&") if p))
cq = "&".join("%s=%s" % kv for kv in pairs)
empty = hashlib.sha256(b"").hexdigest()
h = {"host": u.netloc, "x-amz-content-sha256": empty, "x-amz-date": amzdate}
names = sorted(h)
creq = "\n".join(["GET", path, cq, "".join("%s:%s\n" % (k, h[k]) for k in names), ";".join(names), empty])
scope = "%s/us-east-1/s3/aws4_request" % day
sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(creq.encode()).hexdigest()])
key = ("AWS4" + sk).encode()
for m in (day, "us-east-1", "s3", "aws4_request"):
    key = hmac.new(key, m.encode(), hashlib.sha256).digest()
sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
h["Authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (ak, scope, ";".join(names), sig)
c = http.client.HTTPConnection(u.hostname, u.port, timeout=limit)
c.request("GET", path + "?" + cq, headers=h)
r = c.getresponse()
out = sys.stdout.buffer
out.write(("HTTP %d %s\n" % (r.status, r.getheader("Content-Type"))).encode())
out.flush()
end = time.time() + limit
try:
    while time.time() < end:
        b = r.read1(65536)
        if not b:
            break
        out.write(b)
        out.flush()
except Exception:
    pass
