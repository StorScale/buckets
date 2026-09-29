# SPDX-License-Identifier: AGPL-3.0-or-later
"""An Elasticsearch 7.17 stand-in for target tests: answers the product
check and info request, index resolution and creation, pings, and document
HEAD/PUT/POST/DELETE, keeping documents in memory; logs every request (method,
path, content type, authorization, body), one JSON array per line.

  python3 esmock.py PORT OUT"""
import http.server
import json
import sys
import threading

port, out = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
indices, docs = set(), {}
INFO = {"name": "mock", "cluster_name": "mock", "version": {"number": "7.17.0", "build_flavor": "default"},
        "tagline": "You Know, for Search"}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        with lock, open(out, "a") as f:
            f.write(json.dumps([0, self.command, self.path, self.headers.get("Content-Type", ""),
                                self.headers.get("Authorization", ""), body]) + "\n")
        parts = [p for p in self.path.split("?")[0].split("/") if p]
        with lock:
            if not parts:
                return self.reply(200, INFO)
            if parts[0] == "_resolve":
                return self.reply(200, {"indices": [{"name": parts[2]}] if parts[2] in indices else [], "aliases": [],
                                        "data_streams": []})
            if len(parts) == 1 and self.command == "PUT":
                indices.add(parts[0])
                return self.reply(200, {"acknowledged": True, "index": parts[0]})
            if len(parts) >= 2 and parts[1] == "_doc":
                key = "/".join(parts)
                if self.command == "HEAD":
                    return self.reply(200 if key in docs else 404)
                if self.command == "DELETE":
                    return self.reply(200 if docs.pop(key, None) else 404, {"result": "deleted"})
                if len(parts) == 2:
                    key += "/%d" % (len(docs) + 1)
                docs[key] = body
                return self.reply(201, {"result": "created", "_id": key.rsplit("/", 1)[1]})
            return self.reply(404, {"error": "unknown"})

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = handle_any


class S(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("127.0.0.1", port), H).serve_forever()
