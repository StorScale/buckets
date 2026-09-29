# SPDX-License-Identifier: AGPL-3.0-or-later
"""An nsqd stand-in for target tests: accepts the V2 protocol's magic,
IDENTIFY (answered with nsqd's feature-negotiation JSON), NOP and PUB, and
logs every command, one JSON array per line: connection number, command,
arguments, body. With HEARTBEAT_MS set it sends heartbeats as nsqd does.

  python3 nsqmock.py PORT OUT"""
import json
import os
import socketserver
import struct
import sys
import threading
import time

port, out = int(sys.argv[1]), sys.argv[2]
heartbeat = int(os.environ.get("HEARTBEAT_MS", "0")) / 1000.0
lock = threading.Lock()
conns = [0]

IDENTIFY_RESPONSE = json.dumps({
    "max_rdy_count": 2500, "version": "1.3.0", "max_msg_timeout": 900000, "msg_timeout": 60000, "tls_v1": False,
    "deflate": False, "deflate_level": 6, "max_deflate_level": 6, "snappy": False, "sample_rate": 0,
    "auth_required": False, "output_buffer_size": 16384, "output_buffer_timeout": 250}).encode()


def log(conn, rec):
    with lock, open(out, "a") as f:
        f.write(json.dumps([conn] + rec) + "\n")


class H(socketserver.StreamRequestHandler):
    def frame(self, typ, data):
        with self.wlock:
            self.wfile.write(struct.pack(">ii", len(data) + 4, typ) + data)
            self.wfile.flush()

    def beat(self):
        while not self.done:
            time.sleep(heartbeat)
            if not self.done:
                try:
                    self.frame(0, b"_heartbeat_")
                except OSError:
                    return

    def handle(self):
        with lock:
            conns[0] += 1
            conn = conns[0]
        self.wlock = threading.Lock()
        self.done = False
        magic = self.rfile.read(4)
        log(conn, ["MAGIC", magic.decode()])
        if heartbeat:
            threading.Thread(target=self.beat, daemon=True).start()
        try:
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                parts = line.decode().rstrip("\n").split(" ")
                cmd = parts[0]
                if cmd in ("IDENTIFY", "PUB", "AUTH"):
                    (n,) = struct.unpack(">i", self.rfile.read(4))
                    body = self.rfile.read(n).decode()
                    if cmd == "IDENTIFY":
                        log(conn, [cmd, json.loads(body)])
                        self.frame(0, IDENTIFY_RESPONSE)
                    else:
                        log(conn, parts + [body])
                        self.frame(0, b"OK")
                else:
                    log(conn, parts)
        finally:
            self.done = True


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("127.0.0.1", port), H).serve_forever()
