#!/usr/bin/env python3
"""buckets-kes against a real KES server (see kes-diff.sh).

usage: kes_diff_cases.py BASE_PORT PHASE        (PHASE: fresh or swapped)

KES serves on BASE, buckets-kes on BASE+1, with the same config. Each case
sends the same request to both, as the same client, and compares status,
content type and body (timestamps, versions, random bytes normalized).
"""
import base64
import json
import os
import re
import subprocess
import sys

from adminlib import Score, compare

BASE, PHASE = int(sys.argv[1]), sys.argv[2]
URLS = (f"https://127.0.0.1:{BASE}", f"https://127.0.0.1:{BASE + 1}")
WORK = os.environ["WORK"]
SAVED = os.path.join(WORK, "ciphertexts.json")


REQ = subprocess.Popen([os.environ["KMSREQ"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def call(i, path, method="GET", body=None, client="admin", follow=False):
    """One HTTPS request as client (a certificate in WORK, or None), through kmsreq (Go's TLS)."""
    r = {"url": URLS[i] + path, "method": method, "follow": follow, "body": None, "cert": "", "key": ""}
    if client:
        r["cert"], r["key"] = f"{WORK}/{client}.crt", f"{WORK}/{client}.key"
    if body is not None:
        r["body"] = b64(body if isinstance(body, bytes) else json.dumps(body).encode())
    REQ.stdin.write(json.dumps(r) + "\n")
    REQ.stdin.flush()
    out = json.loads(REQ.stdout.readline())
    if out.get("error"):  # a handshake refused (KES: no client certificate)
        return 0, {}, out["error"].encode()
    return out["code"], out["headers"], base64.b64decode(out["body"] or "")


VOLATILE = {"created_at", "time", "uptime", "mem_heap_used", "mem_stack_used", "num_cpu", "num_cpu_used",
            "keystore_latency", "version", "commit"}


def norm(v):
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k in VOLATILE:
                out[k] = "<v>"
            elif k in ("plaintext", "ciphertext", "hmac") and isinstance(x, str):
                out[k] = f"<{len(base64.b64decode(x))} bytes>"
            else:
                out[k] = norm(x)
        return out
    if isinstance(v, list):
        return [norm(x) for x in v]
    return v


def view(code, hdrs, body):
    ct = hdrs.get("content-type", "")
    if "json" in ct and body.strip():
        try:
            return code, ct, norm(json.loads(body))
        except ValueError:
            pass
    return code, ct, body.decode(errors="replace")


def both(name, path, method="GET", body=None, client="admin", follow=False, fix=None):
    res = []
    for i in range(2):
        v = view(*call(i, path, method, body, client, follow))
        res.append(fix(v) if fix else v)
    if all(r[0] == 0 for r in res) and client:  # neither server answered: the harness failed, not a match
        res[1] = ("no answer",) + tuple(res[1][1:])
    compare(name, *res)
    return res


def b64(b):
    return base64.b64encode(b).decode()


def plain(i, path, body, client="admin"):
    code, _, out = call(i, path, "PUT", body, client)
    return code, (json.loads(out) if code == 200 else out.decode(errors="replace"))


KEY_AES = os.urandom(32)
KEY_CHACHA = os.urandom(32)

# the harness itself: a client both servers accept (a broken client would fail alike on both)
for i in range(2):
    code, _, body = call(i, "/v1/status")
    if code != 200:
        print(f"kes-diff: {'KES' if i == 0 else 'buckets-kes'} does not answer /v1/status: {code} {body[:200]!r}")
        sys.exit(1)

if PHASE == "fresh":
    # ---- the server ----
    both("version", "/version")
    both("status", "/v1/status")
    both("ready", "/v1/ready")
    both("APIs", "/v1/api", fix=lambda v: (v[0], v[1], sorted(v[2], key=lambda r: r["path"]) if isinstance(v[2], list) else v[2]))
    both("metrics", "/v1/metrics", fix=lambda v: (v[0], v[1].split(";")[0]))
    both("no such API", "/v1/nope")
    both("wrong method", "/v1/status", method="DELETE")
    both("POST for PUT", "/v1/key/create/via-post", method="POST")
    # KES refuses the handshake, buckets-kes the request: both reject it
    compare("no client certificate", True, call(0, "/v1/status", client=None)[0] in (0, 400)
            and call(1, "/v1/status", client=None)[0] in (0, 400))
    both("no policy", "/v1/status", client="stranger")
    # ---- keys ----
    both("create", "/v1/key/create/my-key", "PUT")
    both("create again", "/v1/key/create/my-key", "PUT")
    both("a preset key", "/v1/key/describe/preset-key")
    for bad in ["bad%20name", "-dash", "dash-", "_", "x" * 81, "a.b"]:
        both(f"create '{bad}'", f"/v1/key/create/{bad}", "PUT")
    both("describe", "/v1/key/describe/my-key")
    both("describe, no such key", "/v1/key/describe/nope")
    both("import AES256", "/v1/key/import/shared-aes", "PUT", {"key": b64(KEY_AES), "cipher": "AES256"})
    both("import ChaCha20", "/v1/key/import/shared-chacha", "PUT",
         {"key": b64(KEY_CHACHA), "cipher": "XCHACHA20-POLY1305"})
    both("import, other names", "/v1/key/import/shared-aes2", "PUT", {"key": b64(KEY_AES), "cipher": "AES256-GCM_SHA256"})
    both("describe ChaCha20", "/v1/key/describe/shared-chacha")
    both("import, bad cipher", "/v1/key/import/k2", "PUT", {"key": b64(KEY_AES), "cipher": "DES"})
    both("import, short key", "/v1/key/import/k2", "PUT", {"key": b64(KEY_AES[:16]), "cipher": "AES256"})
    both("import, no body", "/v1/key/import/k2", "PUT", b"")
    both("import, not JSON", "/v1/key/import/k2", "PUT", b"[oops")
    both("import, existing", "/v1/key/import/my-key", "PUT", {"key": b64(KEY_AES), "cipher": "AES256"})
    both("list *", "/v1/key/list/*")
    both("list shared", "/v1/key/list/shared")
    both("list shared*", "/v1/key/list/shared*")
    both("list (no prefix, redirected)", "/v1/key/list", follow=True)
    # KES redirects the bare path (307) to the subtree; buckets-kes answers it directly with what the
    # redirect leads to: the listing
    c0, h0, b0 = call(0, "/v1/key/list")
    compare("list, the bare path", (307, "/v1/key/list/"), (c0, h0.get("location")))
    compare("list, the bare path answered as KES's redirect would be",
            view(*call(0, "/v1/key/list", follow=True)), view(*call(1, "/v1/key/list")))
    both("list, bad pattern", "/v1/key/list/a*b")
    both("generate", "/v1/key/generate/my-key", "PUT", {"context": b64(b"ctx")})
    both("generate, no body", "/v1/key/generate/my-key", "PUT")
    both("generate, no such key", "/v1/key/generate/nope", "PUT", {})
    both("encrypt", "/v1/key/encrypt/my-key", "PUT", {"plaintext": b64(b"hello world" * 10)})
    both("encrypt, bad base64", "/v1/key/encrypt/my-key", "PUT", {"plaintext": "!!!"})
    both("decrypt, garbage", "/v1/key/decrypt/my-key", "PUT", {"ciphertext": b64(b"x" * 80)})
    both("decrypt, too short", "/v1/key/decrypt/my-key", "PUT", {"ciphertext": b64(b"x" * 10)})
    both("hmac", "/v1/key/hmac/my-key", "PUT", {"message": b64(b"msg")})
    both("delete", "/v1/key/delete/my-key", "DELETE")
    both("delete again", "/v1/key/delete/my-key", "DELETE")
    # ---- cryptography across the servers: the same key material on both ----
    for key, raw in [("shared-aes", KEY_AES), ("shared-chacha", KEY_CHACHA)]:
        for ctx in (b"", b"context!"):
            for src in range(2):
                dst = 1 - src
                msg = os.urandom(70)
                c, enc = plain(src, f"/v1/key/encrypt/{key}", {"plaintext": b64(msg), "context": b64(ctx)})
                if c != 200:
                    compare(f"{key}: encrypt on {'KES' if src == 0 else 'buckets-kes'}", 200, (c, enc))
                    continue
                c2, dec = plain(dst, f"/v1/key/decrypt/{key}", {"ciphertext": enc["ciphertext"], "context": b64(ctx)})
                compare(f"{key}: encrypted by {'KES' if src == 0 else 'buckets-kes'}, decrypted by the other "
                        f"(context {ctx!r})", (200, b64(msg)), (c2, dec.get("plaintext") if c2 == 200 else dec))
                c, gen = plain(src, f"/v1/key/generate/{key}", {"context": b64(ctx)})
                c2, dec = plain(dst, f"/v1/key/decrypt/{key}", {"ciphertext": gen["ciphertext"], "context": b64(ctx)})
                compare(f"{key}: generated by {'KES' if src == 0 else 'buckets-kes'}, decrypted by the other",
                        (200, gen["plaintext"]), (c2, dec.get("plaintext") if c2 == 200 else dec))
                c2, dec = plain(dst, f"/v1/key/decrypt/{key}", {"ciphertext": gen["ciphertext"], "context": b64(b"no")})
                c3, dec3 = plain(src, f"/v1/key/decrypt/{key}", {"ciphertext": gen["ciphertext"], "context": b64(b"no")})
                compare(f"{key}: the wrong context", (c3, dec3), (c2, dec))
        # the ciphertext forms of earlier KES versions, decrypted by both
        msg = os.urandom(32)
        _, enc = plain(0, f"/v1/key/encrypt/{key}", {"plaintext": b64(msg)})
        raw_ct = base64.b64decode(enc["ciphertext"])
        sealed, iv, nonce = raw_ct[:-28], raw_ct[-28:-12], raw_ct[-12:]
        alg = "AES-256-GCM-HMAC-SHA-256" if key == "shared-aes" else "ChaCha20Poly1305"
        legacy_json = json.dumps({"aead": alg, "iv": b64(iv), "nonce": b64(nonce), "bytes": b64(sealed)}).encode()
        def mp_str(s):
            return bytes([0xa0 | len(s)]) + s.encode()
        def mp_bin(b):
            return (bytes([0xc4, len(b)]) if len(b) < 256 else bytes([0xc5, len(b) >> 8, len(b) & 255])) + b
        legacy_msgp = (b"\x95" + mp_str("AES256" if key == "shared-aes" else "ChaCha20") + mp_str("")
                       + mp_bin(iv) + mp_bin(nonce) + mp_bin(sealed))
        for form, ct in [("JSON", legacy_json), ("msgpack", legacy_msgp)]:
            both(f"{key}: a {form} ciphertext", f"/v1/key/decrypt/{key}", "PUT", {"ciphertext": b64(ct)},
                 fix=lambda v, m=msg: (v[0], v[2].get("plaintext") if isinstance(v[2], dict) else v[2]))
            _, d = plain(1, f"/v1/key/decrypt/{key}", {"ciphertext": b64(ct)})
            compare(f"{key}: a {form} ciphertext gives the plaintext", b64(msg), d.get("plaintext"))
    # ---- policies ----
    for client in ["app", "ops"]:
        for method, path, body in [("PUT", "/v1/key/create/app-1", None), ("PUT", "/v1/key/create/other-1", None),
                                   ("PUT", "/v1/key/generate/app-1", {}), ("GET", "/v1/key/list/*", None),
                                   ("DELETE", "/v1/key/delete/app-1", None), ("GET", "/v1/status", None),
                                   ("GET", "/v1/policy/list/*", None)]:
            both(f"as {client}: {method} {path}", path, method, body, client=client)
    call(0, "/v1/key/create/app-secret-1", "PUT")
    call(1, "/v1/key/create/app-secret-1", "PUT")
    both("as ops: a denied decrypt", "/v1/key/decrypt/app-secret-1", "PUT", {"ciphertext": b64(b"x" * 60)}, client="ops")
    both("policy list", "/v1/policy/list/*")
    both("policy list a*", "/v1/policy/list/a*")
    both("policy describe", "/v1/policy/describe/ops")
    both("policy read", "/v1/policy/read/ops")
    both("policy read, none", "/v1/policy/read/nope")
    both("identity list", "/v1/identity/list/*")
    ids = {c: subprocess.run([os.environ["KES_CLIENT"], "identity", "of", f"{WORK}/{c}.crt"], capture_output=True,
                             text=True).stdout.split()[-1] for c in ["admin", "app", "ops", "stranger"]}
    both("identity describe, admin", f"/v1/identity/describe/{ids['admin']}")
    both("identity describe, app", f"/v1/identity/describe/{ids['app']}")
    both("identity describe, stranger", f"/v1/identity/describe/{ids['stranger']}")
    both("identity self, admin", "/v1/identity/self/describe")
    both("identity self, stranger", "/v1/identity/self/describe", client="stranger")
    # ---- KES's own CLI, with an API key (an Ed25519 client certificate) ----
    for args, want_ok in [(["key", "create", "-k", "app-cli"], True), (["key", "create", "-k", "app-cli"], False),
                          (["key", "info", "-k", "app-cli"], True), (["key", "ls", "-k"], True),
                          (["key", "create", "-k", "other-cli"], False)]:
        res = []
        for i in range(2):
            env = dict(os.environ, KES_API_KEY=os.environ["APIKEY"], KES_SERVER=URLS[i][8:])
            p = subprocess.run([os.environ["KES_CLIENT"]] + args, capture_output=True, text=True, env=env)
            out = re.sub(r"\d{4}-\d\d-\d\d[ T][0-9:.]+\S*|\d+ (seconds|minutes|hours|days)( ago)?", "<t>",
                         p.stdout + p.stderr)
            out = re.sub(r"127\.0\.0\.1:\d+", "<addr>", out)
            res.append((p.returncode, out))
        if want_ok and res[0][0] != 0:
            res[1] = ("KES itself failed: " + res[0][1][:200],) + res[1][1:]
        compare("kes CLI: " + " ".join(a for a in args if a != "-k"), *res)

    # KES answers its self-describe API for the admin only (a bug); buckets-kes answers everyone, in the
    # shape KES's client decodes
    env = dict(os.environ, KES_API_KEY=os.environ["APIKEY"], KES_SERVER=URLS[1][8:])
    p = subprocess.run([os.environ["KES_CLIENT"], "identity", "info", "-k"], capture_output=True, text=True, env=env)
    compare("kes CLI: identity info (buckets-kes)", (0, True), (p.returncode, "app" in p.stdout))
    # ciphertexts each server makes with a key only it has, for the swapped phase
    saved = {}
    for i, name in enumerate(["kes-key", "kms-key"]):
        call(i, f"/v1/key/create/{name}", "PUT")
        _, gen = plain(i, f"/v1/key/generate/{name}", {"context": b64(b"keep")})
        saved[name] = gen
    json.dump(saved, open(SAVED, "w"))
elif PHASE in ("swapped", "sealed"):
    # each server now serves the other's keystore: it decrypts what the other made
    saved = json.load(open(SAVED))
    if PHASE == "swapped":
        pairs = [("kms-key", 0), ("kes-key", 1)]  # KES has buckets-kes's keys, and vice versa
    else:
        pairs = [("kes-key", 1)]  # buckets-kes has KES's (unsealed) keys again
    for name, i in pairs:
        _, dec = plain(i, f"/v1/key/decrypt/{name}", {"ciphertext": saved[name]["ciphertext"], "context": b64(b"keep")})
        compare(f"{PHASE}: {name} decrypted by {'KES' if i == 0 else 'buckets-kes'}", saved[name]["plaintext"],
                dec.get("plaintext"))
        code, _, body = call(i, f"/v1/key/describe/{name}")
        compare(f"{PHASE}: {name} described", 200, code)
    both(f"{PHASE}: the preset key", "/v1/key/describe/preset-key")
    if PHASE == "sealed":
        call(1, "/v1/key/create/sealed-key", "PUT")
        entry = open(os.path.join(WORK, "kms-keys", "sealed-key")).read()
        compare("sealed: a new entry is sealed", True, entry.startswith("bkms1:"))
        kes_entry = open(os.path.join(WORK, "kms-keys", "kes-key")).read()
        compare("sealed: KES's entries are left as they are", False, kes_entry.startswith("bkms1:"))
        _, gen = plain(1, "/v1/key/generate/sealed-key", {"context": b64(b"s")})
        _, dec = plain(1, "/v1/key/decrypt/sealed-key", {"ciphertext": gen["ciphertext"], "context": b64(b"s")})
        compare("sealed: a sealed key works", gen["plaintext"], dec.get("plaintext"))

print(f"kes-diff ({PHASE}): {Score.passed} passed, {Score.failed} failed")
sys.exit(1 if Score.failed else 0)
