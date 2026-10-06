# SPDX-License-Identifier: AGPL-3.0-or-later
"""The browser and the admin for tests/e2e-k8s/identity.sh, run in a client pod:
drives the console's Sign-in page API, and signs in at Keycloak by filling in
its real login form.

  python3 identity_driver.py oidc|teams|removal|removal-key|removal-expect on|off|ldap|ldap-signin

Environment: CONSOLE (the console's URL), ROOT_USER, ROOT_PASSWORD, KEYCLOAK
(its base URL), LDAP_ADDR (host:port). Prints "ok <what>" or "FAIL <what>: ..."
lines, and exits 1 when anything failed."""
import html, http.cookiejar, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request

C, KC = os.environ["CONSOLE"], os.environ["KEYCLOAK"]
failed = 0


def expect(what, got, want):
    global failed
    if got == want:
        print("ok   ", what, flush=True)
    else:
        failed += 1
        print("FAIL ", what, ": got", repr(got), "want", repr(want), flush=True)


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, url, body=None, form=None, headers=None):
        h = dict(headers or {})
        data = None
        if body is not None:
            data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
        if form is not None:
            data, h["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
        if method != "GET" and url.startswith(C):
            h["X-Console-Request"] = "1"
        r = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with self.op.open(r, timeout=60) as resp:
                return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.geturl(), e.read().decode("utf-8", "replace")

    def api(self, method, path, body=None):
        st, _, text = self.req(method, C + path, body=body)
        try:
            return st, json.loads(text) if text else {}
        except ValueError:
            return st, {"raw": text}

    def login_root(self):
        st, _ = self.api("POST", "/api/v1/login", {"accessKey": os.environ["ROOT_USER"], "secretKey": os.environ["ROOT_PASSWORD"]})
        return st

    def keycloak(self, start_url, user, password):
        """Follows start_url to Keycloak's login form and signs in, as a browser does: the redirect back
        to the console is a cross-site navigation, so it carries no SameSite=Strict session cookie; a
        test sign-in's handoff page then posts its sealed tokens from the console, with the session.
        Returns the page the console ends on (for a test, the outcome's words)."""
        st, url, page = self.req("GET", start_url)
        m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page)
        if not m:
            return st, url, page
        noredir = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)
        r = urllib.request.Request(html.unescape(m.group(1)), method="POST",
                                   data=urllib.parse.urlencode({"username": user, "password": password, "credentialId": ""}).encode(),
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with noredir.open(r, timeout=60) as resp:
                return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")  # no redirect: the form again
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303):
                return e.code, e.geturl(), e.read().decode("utf-8", "replace")
            back = e.headers["Location"]
        strict = [c for c in self.jar if c.name == "buckets-session"]
        for c in strict:
            self.jar.clear(c.domain, c.path, c.name)
        st, url, page = self.req("GET", back)
        for c in strict:
            if not any(x.name == "buckets-session" for x in self.jar):
                self.jar.set_cookie(c)
        b = re.search(r"blob:'([A-Za-z0-9_-]+)'", page)
        if b:
            st, r = self.api("POST", "/api/v1/identity-config/test-finish", {"blob": b.group(1)})
            page = r.get("message", "") + (" passed:true" if r.get("passed") else " passed:false")
        return st, url, page


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def wait(what, fn, secs=240):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(3)
    return None


KC_SETTINGS = {"provider": "keycloak", "url": KC, "realm": "buckets", "clientId": "buckets-console", "clientSecret": "kcsecret"}


def oidc():
    b = Browser()
    expect("root signs in to the console", b.login_root(), 204)
    st, cfg = b.api("GET", "/api/v1/identity-config")
    expect("the Sign-in page is managed", (st, cfg.get("managed")), (200, True))
    expect("nothing applied yet", cfg.get("status", {}).get("phase"), "NotManaged")
    st, r = b.api("PUT", "/api/v1/identity-config/candidate", {"settings": {"openid": KC_SETTINGS}})
    expect("Keycloak settings saved", st, 200)
    # the test sign-in: Keycloak's real login form, back to the console's callback
    st, url, page = b.keycloak(C + "/api/v1/login/oidc?test=1", "kcuser", "kcpass123")
    expect("the test sign-in ends on the console's page", "Signed in as kcuser: the settings work." in page, True)
    if "Signed in as" not in page:
        print("     page:", re.sub(r"\s+", " ", page)[:400])
    st, cfg = b.api("GET", "/api/v1/identity-config")
    t = cfg.get("test", {}).get("openid", {})
    expect("the token's roles, matched to policies", (t.get("passed"), t.get("claimName"), t.get("policies")), (True, "roles", ["readwrite"]))
    expect("still signed in as root", b.api("GET", "/api/v1/session")[1].get("accessKey"), os.environ["ROOT_USER"])
    st, r = b.api("POST", "/api/v1/identity-config/apply", {"candidateHash": cfg.get("candidateHash")})
    expect("applied", (st, r.get("applied")), (200, True))
    phase = wait("the operator", lambda: (lambda s: s if s in ("Ready", "Error", "Conflict") else None)(
        b.api("GET", "/api/v1/identity-config")[1].get("status", {}).get("phase")))
    expect("the operator applied them to the servers", phase, "Ready")
    if phase != "Ready":
        print("     status:", b.api("GET", "/api/v1/identity-config")[1].get("status"))
    # the console takes them up from its mounted Secret, without a restart
    anon = Browser()
    m = wait("the console", lambda: (lambda d: d if d.get("oidc") else None)(anon.api("GET", "/api/v1/login-methods")[1]))
    expect("the console offers Keycloak sign-in", (m or {}).get("oidcName"), "Keycloak")
    # a real sign-in: Keycloak, the console, the servers' STS
    st, url, page = anon.keycloak(C + "/api/v1/login/oidc", "kcuser", "kcpass123")
    sess = anon.api("GET", "/api/v1/session")[1]
    expect("a real sign-in gives a session as kcuser", sess.get("accessKey"), "kcuser")
    st, _ = anon.api("GET", "/api/v1/s3/")
    expect("whose readwrite policy lists the buckets", st, 200)
    bad = Browser()
    st, url, page = bad.keycloak(C + "/api/v1/login/oidc", "kcuser", "wrong-password")
    expect("a wrong password stays at Keycloak", bad.api("GET", "/api/v1/session")[0], 401)


# ---- people who leave Keycloak ---------------------------------------------------------------------
STATE = "/tmp/removal.json"  # kcleaver's session and access key, between the steps


def removal():
    """Removal on, checked every minute: saved, the sign-in tested again (a new candidate), kcleaver looked up, applied."""
    b = Browser()
    expect("root signs in to the console", b.login_root(), 204)
    settings = dict(KC_SETTINGS, removal={"enabled": True, "intervalMinutes": 1})
    st, _ = b.api("PUT", "/api/v1/identity-config/candidate", {"settings": {"openid": settings}})
    expect("removal settings saved", st, 200)
    st, url, page = b.keycloak(C + "/api/v1/login/oidc?test=1", "kcuser", "kcpass123")
    expect("the sign-in tested again", "Signed in as kcuser" in page, True)
    st, r = b.api("POST", "/api/v1/identity-config/removal-test", {"user": "kcleaver"})
    expect("kcleaver looked up in Keycloak, through the client's service account",
           (st, r.get("passed"), r.get("state"), r.get("userPrincipalName")), (200, True, "active", "kcleaver"))
    if not r.get("passed"):
        print("     lookup:", r)
    cfg = b.api("GET", "/api/v1/identity-config")[1]
    st, r = b.api("POST", "/api/v1/identity-config/apply", {"candidateHash": cfg.get("candidateHash")})
    expect("applied", (st, r.get("applied")), (200, True))
    expect("the description says so", "people who leave removed" in (r.get("description") or ""), True)


def removal_key():
    """kcleaver signs in at Keycloak and makes an access key, as people do for their tools."""
    b = Browser()
    st, url, page = b.keycloak(C + "/api/v1/login/oidc", "kcleaver", "kcleave123")
    expect("kcleaver signs in", b.api("GET", "/api/v1/session")[1].get("accessKey"), "kcleaver")
    st, text = b.req("PUT", C + "/api/v1/admin/add-service-account", body={"name": "kcleaver-tool"},
                     headers={"X-Console-Encrypt": "1", "X-Console-Decrypt": "1"})[0::2]
    key = (json.loads(text).get("credentials") or {}).get("accessKey") if st == 200 else None
    expect("and makes an access key", bool(key), True)
    if not key:
        print("     add-service-account:", st, text[:300])
    cookies = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path} for c in b.jar]
    json.dump({"key": key, "cookies": cookies}, open(STATE, "w"))


def removal_expect(want):
    """kcleaver's access key comes to want (on|off) within the sync's minute or two; off, their session stops working too."""
    s = json.load(open(STATE))
    root = Browser()
    root.login_root()

    def status():
        st, text = root.req("GET", C + "/api/v1/admin/info-service-account?accessKey=" + urllib.parse.quote(s["key"]),
                            headers={"X-Console-Decrypt": "1"})[0::2]
        return json.loads(text).get("accountStatus") if st == 200 else None
    got = wait("the sync", lambda: (lambda v: v if v == want else None)(status()), secs=300) or status()
    expect("kcleaver's access key is " + want, got, want)
    if want == "off":
        b = Browser()
        for c in s["cookies"]:
            b.jar.set_cookie(http.cookiejar.Cookie(0, c["name"], c["value"], None, False, c["domain"], bool(c["domain"]),
                                                   c["domain"].startswith("."), c["path"], True, False, None, False, None, None, {}))
        st, _ = b.api("GET", "/api/v1/s3/")
        expect("and their console session no longer reaches the servers", st in (401, 403), True)


def teams():
    root = Browser()
    expect("root signs in to the console", root.login_root(), 204)
    for b in ("finance-reports", "hr-payroll"):
        expect("bucket " + b, root.req("PUT", C + "/api/v1/s3/" + b)[0], 200)
    team = {"name": "finance", "buckets": ["finance-reports"], "prefixes": ["finance-"], "levels": ["rw"]}
    st, r = root.api("PUT", "/api/v1/teams/finance", {"team": team})
    expect("the team saved", (st, r.get("name")), (200, "finance"))
    # kcteam's only role is team-finance-rw: a real sign-in through Keycloak
    b = Browser()
    b.keycloak(C + "/api/v1/login/oidc", "kcteam", "kcteam123")
    expect("kcteam signs in", b.api("GET", "/api/v1/session")[1].get("accessKey"), "kcteam")
    st, _, listing = b.req("GET", C + "/api/v1/s3/")
    names = re.findall(r"<Name>([^<]+)</Name>", listing)
    expect("kcteam sees only the team's buckets", (st, names), (200, ["finance-reports"]))
    st, _, _ = b.req("PUT", C + "/api/v1/s3/finance-reports/hello.txt", body="hi")
    expect("writes the team's bucket", st, 200)
    expect("not another bucket", b.req("GET", C + "/api/v1/s3/hr-payroll/")[0], 403)
    expect("nor creates buckets (rw)", b.req("PUT", C + "/api/v1/s3/finance-q1")[0], 403)
    # the access review: the role, and kcteam seen with it
    st, rv = root.api("GET", "/api/v1/access/bucket/finance-reports?level=write")
    role = [r for r in rv.get("rows", []) if r.get("kind") == "openid-role" and r.get("name") == "team-finance-rw"]
    seen = role[0].get("seen", []) if role else []
    expect("the review names the Keycloak role, and kcteam seen with it",
           (st, len(seen) == 1 and any(n in seen[0] for n in ("kcteam", "KC Team"))), (200, True))
    if role and len(seen) != 1:
        print("     seen:", seen)
    st, ck = root.api("POST", "/api/v1/access/check", {"who": {"kind": "openid", "roles": ["team-finance-rw"]},
                                                      "action": "s3:PutObject", "bucket": "hr-payroll", "object": "x"})
    expect("the check agrees: not another bucket", ck.get("decision"), "denied")
    st, r = root.api("DELETE", "/api/v1/teams/finance")
    expect("the team deleted", st, 204)
    expect("kcteam loses the bucket at once", b.req("GET", C + "/api/v1/s3/finance-reports/")[0], 403)


def ldap():
    b = Browser()
    expect("root signs in to the console", b.login_root(), 204)
    settings = {"openid": dict(KC_SETTINGS, clientSecret=""),  # the saved secret is kept
                "ldap": {"preset": "openldap", "serverAddr": os.environ["LDAP_ADDR"], "tls": "plain",
                         "lookupBindDn": "cn=readonly,dc=example,dc=org", "lookupBindPassword": "readonlypw",
                         "userSearchBase": "ou=People,dc=example,dc=org", "groupSearchBase": "ou=groups,dc=example,dc=org"}}
    st, r = b.api("PUT", "/api/v1/identity-config/candidate", {"settings": settings})
    expect("LDAP added to the settings", st, 200)
    st, r = b.api("POST", "/api/v1/identity-config/ldap-test", {"username": "alice", "password": "alice123"})
    expect("OpenLDAP finds alice and her group", (r.get("passed"), r.get("dn"), r.get("groups")),
           (True, "uid=alice,ou=People,dc=example,dc=org", ["cn=devs,ou=groups,dc=example,dc=org"]))
    st, r = b.api("POST", "/api/v1/identity-config/ldap-test", {"username": "alice", "password": "nope"})
    expect("a wrong password is refused", r.get("passed"), False)
    st, cfg = b.api("GET", "/api/v1/identity-config")
    st, r = b.api("POST", "/api/v1/identity-config/apply", {"candidateHash": cfg.get("candidateHash")})
    expect("new settings need a new sign-in test", r.get("code"), "NotTested")
    st, url, page = b.keycloak(C + "/api/v1/login/oidc?test=1", "kcuser", "kcpass123")
    expect("tested again", "the settings work" in page, True)
    st, cfg = b.api("GET", "/api/v1/identity-config")
    st, r = b.api("POST", "/api/v1/identity-config/apply", {"candidateHash": cfg.get("candidateHash")})
    expect("applied with LDAP", (st, r.get("applied")), (200, True))


def ldap_signin():
    b = Browser()
    m = wait("the console", lambda: (lambda d: d if d.get("ldap") else None)(b.api("GET", "/api/v1/login-methods")[1]))
    expect("the console offers LDAP sign-in", bool(m and m.get("ldap") and m.get("oidc")), True)
    # the servers bind to OpenLDAP as alice: no policy is attached to her yet, which the servers say after the bind
    st, r = b.api("POST", "/api/v1/login", {"accessKey": "alice", "secretKey": "alice123", "method": "ldap"})
    msg = (r.get("message") or "").lower()
    expect("the servers bind as alice, then find no policy for her", (st, "polic" in msg), (401, True))
    if "polic" not in msg:
        print("     reply:", st, r)
    st, r = b.api("POST", "/api/v1/login", {"accessKey": "alice", "secretKey": "wrong", "method": "ldap"})
    expect("a wrong LDAP password is refused before any policy", "polic" in (r.get("message") or "").lower(), False)
    b2 = Browser()
    st, url, page = b2.keycloak(C + "/api/v1/login/oidc", "kcuser", "kcpass123")
    expect("Keycloak sign-in still works", b2.api("GET", "/api/v1/session")[1].get("accessKey"), "kcuser")


if sys.argv[1] == "removal-expect":
    removal_expect(sys.argv[2])
else:
    {"oidc": oidc, "teams": teams, "removal": removal, "removal-key": removal_key, "ldap": ldap, "ldap-signin": ldap_signin}[sys.argv[1]]()
sys.exit(1 if failed else 0)
