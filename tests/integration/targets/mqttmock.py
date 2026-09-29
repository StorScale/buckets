# SPDX-License-Identifier: AGPL-3.0-or-later
"""An MQTT broker stand-in for target tests (3.1.1 and 3.1, over TCP or a
WebSocket upgrade on the same port): acknowledges CONNECT, PUBLISH at every
QoS, PUBREL and PINGREQ, and logs each packet, one JSON array per line.

  python3 mqttmock.py PORT OUT"""
import base64
import hashlib
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


class H(socketserver.StreamRequestHandler):
    def raw_read(self, n):
        b = self.rfile.read(n)
        if len(b) < n:
            raise EOFError
        return b

    def read(self, n):
        if not self.ws:
            return self.raw_read(n)
        out = b""
        while len(out) < n:
            if not self.buf:
                h = self.raw_read(2)
                ln = h[1] & 127
                if ln == 126:
                    ln = struct.unpack(">H", self.raw_read(2))[0]
                elif ln == 127:
                    ln = struct.unpack(">Q", self.raw_read(8))[0]
                mask = self.raw_read(4) if h[1] & 128 else b"\0\0\0\0"
                data = self.raw_read(ln)
                self.buf = bytes(c ^ mask[i % 4] for i, c in enumerate(data))
                if h[0] & 15 == 8:
                    raise EOFError
            k = min(n - len(out), len(self.buf))
            out, self.buf = out + self.buf[:k], self.buf[k:]
        return out

    def write(self, data):
        if self.ws:
            data = bytes([0x82, len(data)]) + data if len(data) < 126 else bytes([0x82, 126]) + struct.pack(">H", len(data)) + data
        self.wfile.write(data)

    def handle(self):
        with lock:
            conns[0] += 1
            conn = conns[0]
        self.ws, self.buf = False, b""
        first = self.raw_read(1)
        if first == b"G":  # a WebSocket upgrade
            req = first + self.rfile.readline()
            hdrs = {}
            while True:
                line = self.rfile.readline().decode().strip()
                if not line:
                    break
                k, v = line.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
            log(conn, ["WEBSOCKET", req.decode().split(" ")[1], hdrs.get("sec-websocket-protocol", "")])
            acc = base64.b64encode(hashlib.sha1((hdrs["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                             b"Sec-WebSocket-Protocol: mqtt\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")
            self.ws = True
            first = self.read(1)
        try:
            while True:
                t = first[0]
                ln, mult = 0, 1
                while True:
                    b = self.read(1)[0]
                    ln += (b & 127) * mult
                    mult *= 128
                    if not b & 128:
                        break
                body = self.read(ln) if ln else b""
                kind = t >> 4
                if kind == 1:  # CONNECT
                    pl = struct.unpack(">H", body[:2])[0]
                    name = body[2:2 + pl].decode()
                    level, flags = body[2 + pl], body[3 + pl]
                    ka = struct.unpack(">H", body[4 + pl:6 + pl])[0]
                    rest, fields = body[6 + pl:], []
                    while rest:
                        n = struct.unpack(">H", rest[:2])[0]
                        fields.append(rest[2:2 + n].decode())
                        rest = rest[2 + n:]
                    log(conn, ["CONNECT", name, level, flags, ka, "(client id)" if fields else ""] + fields[1:])
                    self.write(b"\x20\x02\x00\x00")
                elif kind == 3:  # PUBLISH
                    qos = (t >> 1) & 3
                    tl = struct.unpack(">H", body[:2])[0]
                    topic = body[2:2 + tl].decode()
                    rest = body[2 + tl:]
                    pid = None
                    if qos:
                        pid, rest = struct.unpack(">H", rest[:2])[0], rest[2:]
                    log(conn, ["PUBLISH", qos, bool(t & 1), bool(t & 8), topic, pid, rest.decode()])
                    if qos == 1:
                        self.write(b"\x40\x02" + struct.pack(">H", pid))
                    elif qos == 2:
                        self.write(b"\x50\x02" + struct.pack(">H", pid))
                elif kind == 6:  # PUBREL
                    pid = struct.unpack(">H", body[:2])[0]
                    log(conn, ["PUBREL", t & 15, pid])
                    self.write(b"\x70\x02" + struct.pack(">H", pid))
                elif kind == 12:
                    log(conn, ["PINGREQ"])
                    self.write(b"\xd0\x00")
                elif kind == 14:
                    log(conn, ["DISCONNECT"])
                    return
                else:
                    log(conn, ["PACKET", t, body.hex()])
                first = self.read(1)
        except (EOFError, OSError, IndexError):
            return


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


S(("127.0.0.1", port), H).serve_forever()
