# SPDX-License-Identifier: AGPL-3.0-or-later
"""A Redis server stand-in for target tests: speaks RESP, remembers hashes
and lists well enough for TYPE, and appends every command it receives to
OUT, one JSON array per line (with the connection number), so two servers'
command streams can be diffed.

  python3 redismock.py PORT OUT [PASSWORD]"""
import json
import socketserver
import sys
import threading

port, out = int(sys.argv[1]), sys.argv[2]
password = sys.argv[3] if len(sys.argv) > 3 else None
lock = threading.Lock()
data = {}  # key -> ("hash", dict) | ("list", list)
conns = [0]


def log(conn, args):
    with lock, open(out, "a") as f:
        f.write(json.dumps([conn] + args) + "\n")


class H(socketserver.StreamRequestHandler):
    def read_cmd(self):
        line = self.rfile.readline()
        if not line:
            return None
        assert line[:1] == b"*", line
        args = []
        for _ in range(int(line[1:])):
            n = int(self.rfile.readline()[1:])
            args.append(self.rfile.read(n + 2)[:-2].decode())
        return args

    def handle(self):
        with lock:
            conns[0] += 1
            conn = conns[0]
        authed = password is None
        while True:
            args = self.read_cmd()
            if args is None:
                return
            log(conn, args)
            cmd = args[0].upper()
            w = self.wfile.write
            if cmd == "AUTH":
                authed = args[-1] == password
                w(b"+OK\r\n" if authed else b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
            elif not authed:
                w(b"-NOAUTH Authentication required.\r\n")
            elif cmd == "PING":
                w(b"+PONG\r\n")
            elif cmd == "CLIENT":
                w(b"+OK\r\n")
            elif cmd == "TYPE":
                w(("+%s\r\n" % data.get(args[1], ("none",))[0]).encode())
            elif cmd == "HSET":
                data.setdefault(args[1], ("hash", {}))[1][args[2]] = args[3]
                w(b":1\r\n")
            elif cmd == "HDEL":
                w(b":%d\r\n" % (1 if data.get(args[1], ("hash", {}))[1].pop(args[2], None) is not None else 0))
            elif cmd == "RPUSH":
                lst = data.setdefault(args[1], ("list", []))[1]
                lst.append(args[2])
                w(b":%d\r\n" % len(lst))
            else:
                w(("-ERR unknown command '%s'\r\n" % args[0]).encode())


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients hanging up mid-conversation are expected


S(("127.0.0.1", port), H).serve_forever()
