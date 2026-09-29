# SPDX-License-Identifier: AGPL-3.0-or-later
"""A NATS server stand-in for target tests: sends INFO (headers on, a fixed
nonce so NKey signatures are reproducible), answers PING with PONG and
JetStream-style requests (a PUB with an _INBOX reply) with a PubAck, and
logs CONNECT, SUB and PUB, one JSON array per line.

  python3 natsmock.py PORT OUT"""
import json
import socketserver
import sys
import threading

port, out = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
conns = [0]
INFO = {"server_id": "MOCK", "server_name": "mock", "version": "2.11.1", "proto": 1, "go": "go1.24", "host": "127.0.0.1",
        "port": port, "headers": True, "max_payload": 1048576, "client_id": 1, "client_ip": "127.0.0.1",
        "nonce": "cGVyZmVjdGx5IGZpeGVkIG5vbmNl"}


def log(conn, rec):
    with lock, open(out, "a") as f:
        f.write(json.dumps([conn] + rec) + "\n")


class H(socketserver.StreamRequestHandler):
    def handle(self):
        with lock:
            conns[0] += 1
            conn = conns[0]
        self.wfile.write(b"INFO " + json.dumps(INFO).encode() + b"\r\n")
        subs, seq = {}, 0
        while True:
            line = self.rfile.readline()
            if not line:
                return
            parts = line.decode().rstrip("\r\n").split(" ")
            op = parts[0].upper()
            if op == "CONNECT":
                log(conn, ["CONNECT", json.loads(line.decode()[8:])])
            elif op == "PING":
                self.wfile.write(b"PONG\r\n")
            elif op == "PONG":
                pass
            elif op == "SUB":
                args = [p for p in parts[1:] if p]
                subs[args[0]] = args[-1]
                log(conn, ["SUB"] + args)
            elif op == "PUB":
                n = int(parts[-1])
                body = self.rfile.read(n + 2)[:-2].decode()
                log(conn, ["PUB"] + parts[1:-1] + [body])
                if len(parts) == 4 and parts[2].startswith("_INBOX."):
                    reply = parts[2]
                    sid = subs.get(reply.rsplit(".", 1)[0] + ".*", "1")
                    seq += 1
                    ack = json.dumps({"stream": "EVENTS", "seq": seq}).encode()
                    self.wfile.write(b"MSG %s %s %d\r\n%s\r\n" % (reply.encode(), sid.encode(), len(ack), ack))
            else:
                log(conn, parts)


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients hanging up mid-conversation are expected


S(("127.0.0.1", port), H).serve_forever()
