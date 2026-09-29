# SPDX-License-Identifier: AGPL-3.0-or-later
"""A webhook notification sink for tests: appends two lines per POST to
OUT -- "<path> <Authorization> <Content-Type>", then the body as sent -- and answers 200 (HEAD too: MinIO probes
the endpoint). FAIL_FILE, when it exists, makes every POST fail (503), to
exercise the queue store.

  python3 webhooksink.py PORT OUT [FAIL_FILE]
"""
import http.server
import os
import sys

port, out = int(sys.argv[1]), sys.argv[2]
fail_file = sys.argv[3] if len(sys.argv) > 3 else None


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if fail_file and os.path.exists(fail_file):
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with open(out, "a") as f:
            f.write("%s %s %s\n%s\n" % (self.path, self.headers.get("Authorization", ""),
                                         self.headers.get("Content-Type", ""), body.decode("utf-8", "replace")))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
