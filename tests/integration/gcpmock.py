# SPDX-License-Identifier: AGPL-3.0-or-later
"""Google's OAuth token endpoint and Secret Manager's REST API, for the
buckets-kes tests: service account JWTs are checked (RS256, against the key's
public half; issuer, audience, scope, lifetime), and secrets, versions,
access, deletion and paged listing behave as Secret Manager's do.

  python3 gcpmock.py PORT PUBLIC_KEY_PEM CLIENT_EMAIL PROJECT"""
import base64, http.server, json, subprocess, sys, tempfile, time, urllib.parse

port, pubkey, email, project = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
secrets = {}  # name -> [versions' bytes]
tokens = set()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify(jwt):
    head, claims, sig = jwt.split(".")
    with tempfile.NamedTemporaryFile() as m, tempfile.NamedTemporaryFile() as sg:
        m.write((head + "." + claims).encode()); m.flush(); sg.write(b64d(sig)); sg.flush()
        ok = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubkey, "-signature", sg.name, m.name],
                            capture_output=True).returncode == 0
    c = json.loads(b64d(claims))
    h = json.loads(b64d(head))
    now = time.time()
    return (ok and h.get("alg") == "RS256" and c.get("iss") == email and c.get("aud") == "http://127.0.0.1:%d/token" % port
            and "cloud-platform" in c.get("scope", "") and c["iat"] <= now + 5 and c["exp"] > now)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj=None):
        body = json.dumps(obj if obj is not None else {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, status, msg):
        self.reply(code, {"error": {"code": code, "message": msg, "status": status}})

    def authed(self):
        if self.headers.get("Authorization", "")[7:] in tokens:
            return True
        self.err(401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
        return False

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n)

    def route(self):
        u = urllib.parse.urlparse(self.path)
        return u.path, urllib.parse.parse_qs(u.query)

    def do_GET(self):
        path, q = self.route()
        if path in ("/v1", "/v1/"):
            return self.reply(404)
        if not self.authed():
            return
        pre = "/v1/projects/%s/secrets" % project
        if path == pre:
            names = sorted(secrets)
            start = int(q.get("pageToken", ["0"])[0])
            size = int(q.get("pageSize", ["25"])[0])
            page = names[start:start + min(size, 2)]  # small pages: paging gets used
            out = {"secrets": [{"name": "projects/%s/secrets/%s" % (project, n)} for n in page]}
            if start + len(page) < len(names):
                out["nextPageToken"] = str(start + len(page))
            return self.reply(200, out)
        if path.startswith(pre + "/") and path.endswith(":access"):
            name, _, ver = path[len(pre) + 1:-len(":access")].partition("/versions/")
            vs = secrets.get(name)
            if not vs or not ver.isdigit() or int(ver) > len(vs):
                return self.err(404, "NOT_FOUND", "Secret Version [%s] not found." % path)
            return self.reply(200, {"payload": {"data": base64.b64encode(vs[int(ver) - 1]).decode()}})
        self.err(404, "NOT_FOUND", "not found")

    def do_POST(self):
        path, q = self.route()
        if path == "/token":
            form = urllib.parse.parse_qs(self.body().decode())
            if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"] or not verify(form["assertion"][0]):
                return self.reply(400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
            t = "ya29.%d" % len(tokens)
            tokens.add(t)
            return self.reply(200, {"access_token": t, "expires_in": 3599, "token_type": "Bearer"})
        if not self.authed():
            return
        pre = "/v1/projects/%s/secrets" % project
        body = json.loads(self.body() or b"{}")
        if path == pre:
            name = q.get("secretId", [""])[0]
            if name in secrets:
                return self.err(409, "ALREADY_EXISTS", "Secret [projects/%s/secrets/%s] already exists." % (project, name))
            if body.get("replication") != {"automatic": {}}:
                return self.err(400, "INVALID_ARGUMENT", "replication is required")
            secrets[name] = []
            return self.reply(200, {"name": "projects/%s/secrets/%s" % (project, name)})
        if path.startswith(pre + "/") and path.endswith(":addVersion"):
            name = path[len(pre) + 1:-len(":addVersion")]
            if name not in secrets:
                return self.err(404, "NOT_FOUND", "Secret not found")
            secrets[name].append(base64.b64decode(body["payload"]["data"]))
            return self.reply(200, {"name": "%s/%s/versions/%d" % (pre[4:], name, len(secrets[name]))})
        self.err(404, "NOT_FOUND", "not found")

    def do_DELETE(self):
        path, _ = self.route()
        if not self.authed():
            return
        name = path.rsplit("/", 1)[-1]
        if name not in secrets:
            return self.err(404, "NOT_FOUND", "Secret [%s] not found." % name)
        del secrets[name]
        self.reply(200, {})


http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
