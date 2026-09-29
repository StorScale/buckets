# SPDX-License-Identifier: AGPL-3.0-or-later
"""A minimal OpenID Connect provider for tests: discovery, JWKS (RSA), an
authorization endpoint that consents at once (redirecting back with a code)
and a token endpoint that trades the code for an RS256 ID token.

  python3 oidcmock.py PORT WORKDIR CLIENT_ID CLIENT_SECRET CLAIMS_JSON

WORKDIR/rsa.pem is created if missing. CLAIMS_JSON is merged into every ID
token (e.g. {"sub": "oidcuser", "policy": "readwrite"})."""
import base64, http.server, json, os, subprocess, sys, time, urllib.parse

port, work, client_id, client_secret, claims = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], json.loads(sys.argv[5])
iss = "http://127.0.0.1:%d" % port
key = os.path.join(work, "rsa.pem")
if not os.path.exists(key):
    subprocess.run(["openssl", "genrsa", "-out", key, "2048"], capture_output=True, check=True)
codes = {}


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk():
    mod = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"], capture_output=True, check=True).stdout
    n = bytes.fromhex(mod.decode().strip().split("=")[1])
    return {"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": b64(n), "e": "AQAB"}


def mint(extra):
    now = int(time.time())
    body = {"iss": iss, "aud": client_id, "iat": now, "exp": now + 600, **claims, **extra}
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
    payload = b64(json.dumps(body).encode())
    msg = (head + "." + payload).encode()
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=msg, capture_output=True, check=True).stdout
    return head + "." + payload + "." + b64(sig)


class H(http.server.BaseHTTPRequestHandler):
    def reply(self, status, doc=None, headers=()):
        b = json.dumps(doc).encode() if doc is not None else b""
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        if doc is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/.well-known/openid-configuration":
            self.reply(200, {"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
                             "jwks_uri": iss + "/jwks", "userinfo_endpoint": iss + "/userinfo"})
        elif u.path == "/jwks":
            self.reply(200, {"keys": [jwk()]})
        elif u.path == "/authorize":
            if q.get("client_id") != client_id or q.get("response_type") != "code":
                self.reply(400, {"error": "invalid_request"})
                return
            code = b64(os.urandom(12))
            codes[code] = (q.get("redirect_uri"), q.get("nonce"))
            sep = "&" if "?" in q["redirect_uri"] else "?"
            loc = "%s%scode=%s&state=%s" % (q["redirect_uri"], sep, code, urllib.parse.quote(q.get("state", "")))
            self.reply(302, headers=[("Location", loc)])
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        if self.path != "/token":
            self.reply(404, {"error": "not_found"})
            return
        entry = codes.pop(form.get("code"), None)
        if (not entry or form.get("grant_type") != "authorization_code" or form.get("client_id") != client_id
                or form.get("client_secret") != client_secret or form.get("redirect_uri") != entry[0]):
            self.reply(400, {"error": "invalid_grant"})
            return
        self.reply(200, {"access_token": b64(os.urandom(16)), "token_type": "Bearer", "expires_in": 600,
                         "id_token": mint({"nonce": entry[1]} if entry[1] else {})})

    def log_message(self, *a):
        pass


http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
