# SPDX-License-Identifier: AGPL-3.0-or-later
"""A minimal Kubernetes API for the console's KMS settings tests, standing in
for the API server and for buckets-operator: one BucketsCluster and its KMS
Secrets, over HTTPS.

  python3 kubemock.py PORT WORKDIR NAMESPACE CLUSTER

Writes WORKDIR/kube-ca.pem (its certificate, the CA to trust). Like the
operator, it answers the cluster's buckets.io/kms-test annotation with a trial
in status.kms.test: running at first, then passed -- or failed, when the
settings' address or URL contains "unreachable" (Vault's own words), or the
default key is "missing-key" and may not be created. Applying settings
(spec.kms.kes) makes status.kms Ready. GET /_state shows what was stored, the
Secrets decoded, for assertions."""
import base64, copy, http.server, json, os, ssl, subprocess, sys, threading, time

port, work, ns, name = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
cert, key = os.path.join(work, "kube-ca.pem"), os.path.join(work, "kube-key.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert], capture_output=True, check=True)

lock = threading.Lock()
rv = [1]
cluster = {"apiVersion": "buckets.io/v1alpha1", "kind": "BucketsCluster",
           "metadata": {"name": name, "namespace": ns, "uid": "u-1", "resourceVersion": "1", "annotations": {}},
           "spec": {"pools": [{"servers": 4, "volumesPerServer": 1}], "console": {"enabled": True}},
           "status": {"kms": {"phase": "Off"}}}
secrets = {f"{name}-kms": {}, f"{name}-kms-candidate": {}}  # name -> data (base64 values)
trials = {}  # test id -> time started


def bump(obj):
    rv[0] += 1
    obj.setdefault("metadata", {})["resourceVersion"] = str(rv[0])


def secret_obj(sname):
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": sname, "namespace": ns, "resourceVersion": str(rv[0])}, "data": secrets[sname]}


def decoded(sname, k):
    v = secrets.get(sname, {}).get(k)
    return json.loads(base64.b64decode(v)) if v else None


def merge(dst, patch):
    for k, v in patch.items():
        if v is None:
            dst.pop(k, None)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


def operator():
    """What buckets-operator would report, once a second."""
    while True:
        time.sleep(0.5)
        with lock:
            kms = cluster["status"].setdefault("kms", {})
            want = cluster["metadata"].get("annotations", {}).get("buckets.io/kms-test")
            test = kms.get("test")
            if want and (not test or test.get("id") != want):
                trials[want] = time.time()
                kms["test"] = {"id": want, "phase": "Running", "startedAt": int(time.time()),
                               "steps": [{"name": "Check the settings", "status": "ok"},
                                         {"name": "Start KES with these settings", "status": "running"}]}
            elif test and test["phase"] == "Running" and time.time() - trials.get(test["id"], 0) > 1.5:
                cand = decoded(f"{name}-kms-candidate", "candidate.json") or {}
                s = cand.get("settings", {})
                where = json.dumps(s)
                if "unreachable" in where:
                    msg = ("Put \"https://unreachable:8200/v1/auth/approle/login\": dial tcp: lookup unreachable: "
                           "no such host")
                    test.update(phase="Failed", message="KES stopped: " + msg,
                                steps=[{"name": "Check the settings", "status": "ok"},
                                       {"name": "Start KES with these settings", "status": "failed",
                                        "message": "KES stopped: " + msg}])
                elif cand.get("keyName") == "missing-key" and not cand.get("createKey"):
                    m = "Key missing-key is not in this key store. Choose an existing key, or let Buckets create it."
                    test.update(phase="Failed", message=m,
                                steps=[{"name": "Check the settings", "status": "ok"},
                                       {"name": "Start KES with these settings", "status": "ok"},
                                       {"name": "Reach the key store", "status": "ok"},
                                       {"name": "Default key missing-key", "status": "failed", "message": m}])
                else:
                    test.update(phase="Passed", message="Every check passed.",
                                steps=[{"name": "Check the settings", "status": "ok"},
                                       {"name": "Start KES with these settings", "status": "ok"},
                                       {"name": "Reach the key store", "status": "ok"},
                                       {"name": "Default key " + cand.get("keyName", ""), "status": "ok",
                                        "message": "created" if cand.get("createKey") else "exists"},
                                       {"name": "Encrypt and decrypt with it", "status": "ok"}])
            kes = cluster["spec"].get("kms", {}).get("kes")
            live = decoded(f"{name}-kms", "settings.json")
            if kes is not None and live:
                kms.update(phase="Ready", message="2 of 2 KES servers ready", keyName=kes.get("keyName"),
                           keyReady=kes.get("keyName"), replicas=2, readyReplicas=2, activated=True, deployed=True)
                b = live.get("backend")
                kms["backend"] = {"vault": "HashiCorp Vault at " + live.get("vault", {}).get("endpoint", ""),
                                  "aws": "AWS Secrets Manager in " + live.get("aws", {}).get("region", "")}.get(b, b)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def route(self):
        p = self.path.split("?")[0]
        if p == f"/apis/buckets.io/v1alpha1/namespaces/{ns}/bucketsclusters/{name}":
            return "cluster", None
        pre = f"/api/v1/namespaces/{ns}/secrets/"
        if p.startswith(pre) and p[len(pre):] in secrets:
            return "secret", p[len(pre):]
        return None, None

    def authorized(self):
        if self.headers.get("Authorization") != "Bearer kubemock-token":
            self.reply(401, {"kind": "Status", "message": "Unauthorized"})
            return False
        return True

    def do_GET(self):
        if self.path == "/_state":
            with lock:
                return self.reply(200, {"cluster": cluster,
                                        "secrets": {k: {f: json.loads(base64.b64decode(v)) for f, v in d.items()}
                                                    for k, d in secrets.items()}})
        if not self.authorized():
            return
        kind, sname = self.route()
        with lock:
            if kind == "cluster":
                return self.reply(200, cluster)
            if kind == "secret":
                return self.reply(200, secret_obj(sname))
        self.reply(404, {"kind": "Status", "message": "not found"})

    def do_PATCH(self):
        if not self.authorized():
            return
        kind, _ = self.route()
        if kind != "cluster" or self.headers.get("Content-Type") != "application/merge-patch+json":
            return self.reply(403, {"kind": "Status", "message": "forbidden"})
        patch = self.body()
        with lock:
            patch.pop("status", None)  # the status subresource is the operator's
            merge(cluster, patch)
            bump(cluster)
            self.reply(200, cluster)

    def do_PUT(self):
        if not self.authorized():
            return
        kind, sname = self.route()
        if kind != "secret":
            return self.reply(403, {"kind": "Status", "message": "forbidden"})
        obj = self.body()
        with lock:
            if obj.get("metadata", {}).get("resourceVersion") != str(rv[0]):
                return self.reply(409, {"kind": "Status", "message": "the object has been modified"})
            data = dict(obj.get("data") or {})
            for k, v in (obj.get("stringData") or {}).items():
                data[k] = base64.b64encode(v.encode()).decode()
            secrets[sname] = data
            rv[0] += 1
            self.reply(200, secret_obj(sname))


threading.Thread(target=operator, daemon=True).start()
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
