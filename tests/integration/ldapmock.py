# SPDX-License-Identifier: AGPL-3.0-or-later
"""A small LDAPv3 directory for tests: simple bind, search (the RFC 4515
filter subset MinIO uses), StartTLS, and LDAPS.

  python3 ldapmock.py PLAIN_PORT [TLS_PORT CERT KEY]

The directory is fixed (see DIRECTORY). Searches need a bound (non-anonymous)
connection, as most directories are configured."""
import socket
import ssl
import sys
import threading

BASE = "dc=example,dc=com"
DIRECTORY = [
    ("dc=example,dc=com", {"objectClass": ["top", "domain"], "dc": ["example"]}),
    ("ou=People,dc=example,dc=com", {"objectClass": ["organizationalUnit"], "ou": ["People"]}),
    ("ou=groups,dc=example,dc=com", {"objectClass": ["organizationalUnit"], "ou": ["groups"]}),
    ("ou=svc,dc=example,dc=com", {"objectClass": ["organizationalUnit"], "ou": ["svc"]}),
    ("cn=lookup,ou=svc,dc=example,dc=com", {"objectClass": ["person"], "cn": ["lookup"], "userPassword": ["lookup123"]}),
    ("uid=alice,ou=People,dc=example,dc=com",
     {"objectClass": ["inetOrgPerson"], "uid": ["alice"], "cn": ["Alice Smith"], "mail": ["alice@example.com"],
      "userPassword": ["alice123"]}),
    ("uid=bob,ou=People,dc=example,dc=com",
     {"objectClass": ["inetOrgPerson"], "uid": ["bob"], "cn": ["Bob"], "mail": ["bob@example.com"],
      "userPassword": ["bob123"]}),
    ("uid=carol,ou=People,dc=example,dc=com",
     {"objectClass": ["inetOrgPerson"], "uid": ["carol"], "cn": ["Carol"], "userPassword": ["carol123"]}),
    ("cn=Dave\\, Jr.,ou=People,dc=example,dc=com",
     {"objectClass": ["inetOrgPerson"], "uid": ["dave(jr)"], "cn": ["Dave, Jr."], "userPassword": ["dave123"]}),
    ("cn=devs,ou=groups,dc=example,dc=com",
     {"objectClass": ["groupOfNames"], "cn": ["devs"],
      "member": ["uid=alice,ou=People,dc=example,dc=com", "cn=Dave\\, Jr.,ou=People,dc=example,dc=com"]}),
    ("cn=admins,ou=groups,dc=example,dc=com",
     {"objectClass": ["groupOfNames"], "cn": ["admins"], "member": ["uid=bob,ou=People,dc=example,dc=com"]}),
]


def norm_dn(dn):
    """Lower-cased, with spaces around separators removed (enough here)."""
    out, i, esc = [], 0, False
    parts, cur = [], ""
    for ch in dn:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            cur += ch
            esc = True
        elif ch in ",;":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    for p in parts:
        k, _, v = p.partition("=")
        out.append(k.strip().lower() + "=" + v.strip().lower())
    return ",".join(out)


ENTRIES = {norm_dn(dn): (dn, attrs) for dn, attrs in DIRECTORY}

# ---- BER -------------------------------------------------------------------


def enc_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, val):
    return bytes([tag]) + enc_len(len(val)) + val


def enc_int(tag, v):
    return tlv(tag, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def enc_str(tag, s):
    return tlv(tag, s.encode() if isinstance(s, str) else s)


def dec(buf, i=0):
    """-> (tag, value bytes, next index) or None if incomplete."""
    if len(buf) - i < 2:
        return None
    tag, l = buf[i], buf[i + 1]
    j = i + 2
    if l & 0x80:
        k = l & 0x7F
        if len(buf) - j < k:
            return None
        l = int.from_bytes(buf[j:j + k], "big")
        j += k
    if len(buf) - j < l:
        return None
    return tag, buf[j:j + l], j + l


def dec_all(val):
    out, i = [], 0
    while i < len(val):
        t, v, i = dec(val, i)
        out.append((t, v))
    return out


def dec_int(v):
    return int.from_bytes(v, "big", signed=True) if v else 0

# ---- filters ------------------------------------------------------------------


def values_of(attrs, name):
    for k, v in attrs.items():
        if k.lower() == name.lower():
            return v
    return None


def eq(a, b, attr):
    if attr.lower() in ("member", "uniquemember"):
        return norm_dn(a) == norm_dn(b)
    return a.lower() == b.lower()


def matches(f, attrs):
    tag, val = f
    if tag in (0xA0, 0xA1):
        subs = [matches(x, attrs) for x in dec_all(val)]
        return all(subs) if tag == 0xA0 else any(subs)
    if tag == 0xA2:
        return not matches(dec_all(val)[0], attrs)
    if tag == 0x87:
        return values_of(attrs, val.decode()) is not None
    if tag in (0xA3, 0xA5, 0xA6, 0xA8):
        (_, a), (_, v) = dec_all(val)
        a, v = a.decode(), v.decode()
        vs = values_of(attrs, a) or []
        if tag == 0xA5:
            return any(x.lower() >= v.lower() for x in vs)
        if tag == 0xA6:
            return any(x.lower() <= v.lower() for x in vs)
        return any(eq(x, v, a) for x in vs)
    if tag == 0xA4:
        (_, a), (_, seq) = dec_all(val)
        vs = values_of(attrs, a.decode()) or []
        items = [(t, v.decode().lower()) for t, v in dec_all(seq)]
        for x in vs:
            x, pos, ok = x.lower(), 0, True
            for t, s in items:
                if t == 0x80:
                    ok = x.startswith(s)
                    pos = len(s)
                elif t == 0x81:
                    k = x.find(s, pos)
                    ok = k >= 0
                    pos = k + len(s)
                else:
                    ok = x.endswith(s) and len(x) - len(s) >= pos
                if not ok:
                    break
            if ok:
                return True
        return False
    raise ValueError("unsupported filter %x" % tag)

# ---- the protocol -------------------------------------------------------------------------


def result(op, code, msg=""):
    return tlv(op, enc_int(0x0A, code) + enc_str(0x04, "") + enc_str(0x04, msg))


class Conn:
    def __init__(self, sock, ctx):
        self.sock, self.ctx, self.buf, self.bound = sock, ctx, b"", None

    def send(self, mid, op):
        self.sock.sendall(tlv(0x30, enc_int(0x02, mid) + op))

    def serve(self):
        while True:
            d = dec(self.buf)
            if d is None:
                chunk = self.sock.recv(65536)
                if not chunk:
                    return
                self.buf += chunk
                continue
            _, msg, n = d
            self.buf = self.buf[n:]
            (_, mid), (op, body) = dec_all(msg)[:2]
            mid = dec_int(mid)
            if op == 0x42:  # unbind
                return
            if op == 0x60:
                self.bind(mid, body)
            elif op == 0x63:
                self.search(mid, body)
            elif op == 0x77:
                name = dec_all(body)[0][1].decode()
                if name == "1.3.6.1.4.1.1466.20037" and self.ctx:
                    self.send(mid, result(0x78, 0))
                    self.sock = self.ctx.wrap_socket(self.sock, server_side=True)
                else:
                    self.send(mid, result(0x78, 2, "unsupported extended operation"))
            else:
                self.send(mid, result(op + 1, 53, "unsupported"))

    def bind(self, mid, body):
        (_, ver), (_, name), (_, pw) = dec_all(body)[:3]
        name, pw = name.decode(), pw.decode()
        if not name and not pw:
            self.bound = None
            return self.send(mid, result(0x61, 0))
        e = ENTRIES.get(norm_dn(name))
        if not e or not pw or pw not in (values_of(e[1], "userPassword") or []):
            self.bound = None
            return self.send(mid, result(0x61, 49, "invalid credentials"))
        self.bound = name
        self.send(mid, result(0x61, 0))

    def search(self, mid, body):
        parts = dec_all(body)
        base = parts[0][1].decode()
        scope = dec_int(parts[1][1])
        flt = parts[6]
        wanted = [v.decode() for _, v in dec_all(parts[7][1])]
        if not self.bound:
            return self.send(mid, result(0x65, 50, "anonymous search is not allowed"))
        nb = norm_dn(base)
        if nb not in ENTRIES:
            return self.send(mid, result(0x65, 32, "no such object"))
        for key, (dn, attrs) in ENTRIES.items():
            inscope = (key == nb) if scope == 0 else \
                (key.endswith("," + nb) and "," not in key[:-len(nb) - 1]) if scope == 1 else \
                (key == nb or key.endswith("," + nb))
            if not inscope or not matches(flt, attrs):
                continue
            out = b""
            for k, vs in attrs.items():
                if k == "userPassword" or wanted == ["1.1"]:
                    continue
                if wanted and not any(w.lower() == k.lower() for w in wanted):
                    continue
                out += tlv(0x30, enc_str(0x04, k) + tlv(0x31, b"".join(enc_str(0x04, v) for v in vs)))
            self.send(mid, tlv(0x64, enc_str(0x04, dn) + tlv(0x30, out)))
        self.send(mid, result(0x65, 0))


def listen(port, ctx, wrap):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    while True:
        c, _ = s.accept()

        def run(c=c):
            try:
                if wrap:
                    c = ctx.wrap_socket(c, server_side=True)
                Conn(c, ctx).serve()
            except Exception:
                pass
            finally:
                c.close()
        threading.Thread(target=run, daemon=True).start()


if __name__ == "__main__":
    ctx = None
    if len(sys.argv) > 2:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[3], sys.argv[4])
        threading.Thread(target=listen, args=(int(sys.argv[2]), ctx, True), daemon=True).start()
    listen(int(sys.argv[1]), ctx, False)
