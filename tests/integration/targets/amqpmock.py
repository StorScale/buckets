# SPDX-License-Identifier: AGPL-3.0-or-later
"""An AMQP 0-9-1 broker stand-in for target tests: the connection handshake
(PLAIN and AMQPLAIN), channels, confirm mode, exchange declaration and
publishing (acknowledged when confirms are on); logs every method, content
header and body, decoded, one JSON array per line. Field tables are logged
with sorted keys, since clients write them in any order.

  python3 amqpmock.py PORT OUT"""
import json
import socketserver
import struct
import sys
import threading

port, out = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
conns = [0]


def log(conn, rec):
    with lock, open(out, "a") as f:
        f.write(json.dumps([conn] + rec) + "\n")


def shortstr(b, i):
    n = b[i]
    return b[i + 1:i + 1 + n].decode(), i + 1 + n


def longstr(b, i):
    n = struct.unpack(">I", b[i:i + 4])[0]
    return b[i + 4:i + 4 + n], i + 4 + n


def field(b, i):
    t = chr(b[i])
    i += 1
    if t == "S":
        v, i = longstr(b, i)
        return v.decode(), i
    if t == "t":
        return bool(b[i]), i + 1
    if t == "F":
        v, i = longstr(b, i)
        return table(v), i
    if t == "I":
        return struct.unpack(">i", b[i:i + 4])[0], i + 4
    if t == "l":
        return struct.unpack(">q", b[i:i + 8])[0], i + 8
    if t == "s":
        return struct.unpack(">h", b[i:i + 2])[0], i + 2
    if t == "b":
        return b[i], i + 1
    raise ValueError(t)


def table(b):
    d, i = {}, 0
    while i < len(b):
        k, i = shortstr(b, i)
        d[k], i = field(b, i)
    return dict(sorted(d.items()))


def enc_short(s):
    s = s.encode()
    return bytes([len(s)]) + s


def enc_long(b):
    return struct.pack(">I", len(b)) + b


class H(socketserver.StreamRequestHandler):
    def frame(self, typ, ch, payload):
        self.wfile.write(struct.pack(">BHI", typ, ch, len(payload)) + payload + b"\xce")

    def method(self, ch, cls, m, args=b""):
        self.frame(1, ch, struct.pack(">HH", cls, m) + args)

    def read_frame(self):
        h = self.rfile.read(7)
        if len(h) < 7:
            raise EOFError
        typ, ch, n = struct.unpack(">BHI", h)
        payload = self.rfile.read(n)
        self.rfile.read(1)
        return typ, ch, payload

    def handle(self):
        with lock:
            conns[0] += 1
            conn = conns[0]
        if self.rfile.read(8) != b"AMQP\x00\x00\x09\x01":
            return
        props = enc_short("product") + b"S" + enc_long(b"RabbitMQ")
        self.method(0, 10, 10, b"\x00\x09" + enc_long(props) + enc_long(b"PLAIN AMQPLAIN") + enc_long(b"en_US"))
        confirm, tags, pending = {}, {}, None
        try:
            while True:
                typ, ch, p = self.read_frame()
                if typ == 8:
                    continue  # heartbeats: timing
                if typ == 2:
                    weight, size, flags = struct.unpack(">HQH", p[2:14])
                    i, rec = 14, {}
                    if flags & 0x8000:
                        rec["content-type"], i = shortstr(p, i)
                    if flags & 0x2000:
                        v, i = longstr(p, i)
                        rec["headers"] = table(v)
                    if flags & 0x1000:
                        rec["delivery-mode"] = p[i]
                        i += 1
                    log(conn, ["HEADER", ch, size, rec])
                    pending, body = size, b""
                    if size == 0:
                        pending = None
                    continue
                if typ == 3:
                    body += p
                    if len(body) >= pending:
                        log(conn, ["BODY", ch, body.decode()])
                        pending = None
                        if confirm.get(ch):
                            tags[ch] = tags.get(ch, 0) + 1
                            self.method(ch, 60, 80, struct.pack(">QB", tags[ch], 0))
                    continue
                cls, m = struct.unpack(">HH", p[:4])
                a = p[4:]
                if (cls, m) == (10, 11):  # start-ok
                    t, i = longstr(a, 0)
                    mech, i = shortstr(a, i)
                    resp, i = longstr(a, i)
                    loc, i = shortstr(a, i)
                    cp = table(t)
                    for k in ("product", "version", "platform", "information"):
                        cp.pop(k, None)
                    log(conn, ["START-OK", cp, mech, resp.decode(errors="replace").replace("\0", "|"), loc])
                    self.method(0, 10, 30, struct.pack(">HIH", 2047, 131072, 60))
                elif (cls, m) == (10, 31):
                    log(conn, ["TUNE-OK"] + list(struct.unpack(">HIH", a[:8])))
                elif (cls, m) == (10, 40):
                    vh, _ = shortstr(a, 0)
                    log(conn, ["OPEN", vh])
                    self.method(0, 10, 41, enc_short(""))
                elif (cls, m) == (10, 50):
                    log(conn, ["CLOSE", struct.unpack(">H", a[:2])[0]])
                    self.method(0, 10, 51)
                    return
                elif (cls, m) == (20, 10):
                    log(conn, ["CHANNEL.OPEN", ch])
                    self.method(ch, 20, 11, enc_long(b""))
                elif (cls, m) == (20, 40):
                    log(conn, ["CHANNEL.CLOSE", ch, struct.unpack(">H", a[:2])[0]])
                    confirm.pop(ch, None)
                    tags.pop(ch, None)
                    self.method(ch, 20, 41)
                elif (cls, m) == (85, 10):
                    log(conn, ["CONFIRM.SELECT", ch, a[0]])
                    confirm[ch] = True
                    self.method(ch, 85, 11)
                elif (cls, m) == (40, 10):
                    ex, i = shortstr(a, 2)
                    et, i = shortstr(a, i)
                    bits = a[i]
                    args, i = longstr(a, i + 1)
                    log(conn, ["EXCHANGE.DECLARE", ch, ex, et, bits, table(args)])
                    if not bits & 16:
                        self.method(ch, 40, 11)
                elif (cls, m) == (60, 40):
                    ex, i = shortstr(a, 2)
                    rk, i = shortstr(a, i)
                    log(conn, ["BASIC.PUBLISH", ch, ex, rk, a[i]])
                else:
                    log(conn, ["METHOD", ch, cls, m, a.hex()])
        except (EOFError, OSError, ValueError, struct.error):
            return


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


S(("127.0.0.1", port), H).serve_forever()
