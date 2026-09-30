#!/usr/bin/env python3
"""FTP sessions against MinIO's FTP server and bucketsd's (see ftp.sh).

usage: ftp_cases.py BASE_PORT ACCESS SECRET WORK

MinIO serves S3 on BASE and FTP on BASE+2; bucketsd on BASE+1 and BASE+3.
Each case runs the same commands on both and compares the replies (and the
data read back), with what differs by nature (ports, times, the welcome
line) normalized.
"""
import json
import os
import re
import socket
import ssl
import subprocess
import sys

from adminlib import Score, admin, compare, curl, setup

BASE, AK, SK, WORK = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
setup(AK, SK)
S3 = (f"http://127.0.0.1:{BASE}", f"http://127.0.0.1:{BASE + 1}")
FTP = (BASE + 2, BASE + 3)
MC = os.environ.get("MC", "mc")
MC_CFG = os.path.join(WORK, "mc")


class Ftp:
    """A raw FTP client: every reply kept, as sent."""

    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.buf = b""
        self.data = None
        self.log = [self.reply()]

    def readline(self, timeout=20):
        self.s.settimeout(timeout)
        while b"\n" not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                line, self.buf = self.buf, b""
                return line.decode()
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        return (line + b"\n").decode()

    def reply(self):
        line = self.readline()
        out = line
        if len(line) > 3 and line[3] == "-":
            code = line[:3]
            while True:
                line = self.readline()
                out += line
                if not line or line.startswith(code + " "):
                    break
        return out

    def cmd(self, line, expect_reply=True, drain=True):
        self.s.sendall((line + "\r\n").encode())
        if not expect_reply:
            return None
        r = self.reply()
        if drain:  # some replies come in several lines (STAT)
            try:
                while True:
                    more = self.readline(0.3)
                    if not more:
                        break
                    r += more
            except (socket.timeout, OSError):
                pass
        self.log.append(r)
        return r

    def drop_data(self):
        """A client gives up the data connection of a refused transfer."""
        if self.data:
            self.data.close()
            self.data = None

    def auth_tls(self):
        r = self.cmd("AUTH TLS", drain=False)
        if r.startswith("234"):
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
            self.s = self.ctx.wrap_socket(self.s, server_hostname="127.0.0.1")
            self.buf = b""
        return r

    def wrap_data(self):
        ctx = getattr(self, "ctx", None)
        if self.data and ctx:
            self.data = ctx.wrap_socket(self.data, server_hostname="127.0.0.1")

    def pasv(self):
        r = self.cmd("PASV")
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", r)
        if m:
            port = int(m.group(5)) * 256 + int(m.group(6))
            self.data = socket.create_connection(("127.0.0.1", port), timeout=20)
        return r

    def epsv(self):
        r = self.cmd("EPSV")
        m = re.search(r"\(\|\|\|(\d+)\|\)", r)
        if m:
            self.data = socket.create_connection(("127.0.0.1", int(m.group(1))), timeout=20)
        return r

    def read_data(self, line):
        """A command that sends data: its replies and what came."""
        self.cmd(line, drain=False)
        body = b""
        if self.data and self.log[-1].startswith("150"):
            self.wrap_data()  # as ftplib does: after the command's reply
            while True:
                chunk = self.data.recv(65536)
                if not chunk:
                    break
                body += chunk
            self.data.close()
            self.data = None
            self.log.append(self.reply())
        self.drop_data()
        return body

    def write_data(self, line, payload):
        self.cmd(line, drain=False)
        if self.data and self.log[-1].startswith("150"):
            self.wrap_data()
            self.data.sendall(payload)
            self.data.close()
            self.data = None
            self.log.append(self.reply())
        self.drop_data()

    def login(self, user, password):
        self.cmd(f"USER {user}")
        self.cmd(f"PASS {password}")

    def close(self):
        try:
            self.cmd("QUIT")
        except OSError:
            pass
        self.s.close()


MONTHS = "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"


def norm(text):
    """Ports, times and the welcome line: what differs by nature."""
    if isinstance(text, bytes):
        text = text.decode("latin1")
    text = re.sub(r"^220 .*", "220 <welcome>", text, flags=re.M)
    text = re.sub(r"\(\d+,\d+,\d+,\d+,\d+,\d+\)", "(<pasv>)", text)
    text = re.sub(r"\(\|\|\|\d+\|\)", "(|||<port>|)", text)
    text = re.sub(r"Connection established \((?!1\))\d+\)", "Connection established (<port>)", text)
    text = re.sub(MONTHS + r" [ \d]\d (\d\d:\d\d| \d{4}) ", "<mtime> ", text)
    text = re.sub(r"Modify=(?!19800101)\d{14}", "Modify=<mtime>", text)
    text = re.sub(r"^213 (?!19800101)\d{14}", "213 <mtime>", text, flags=re.M)
    # goftp lists its extensions in Go's random map order
    text = re.sub(r"(Extensions supported:\n)((?: \S.*\n)+)",
                  lambda m: m.group(1) + "".join(sorted(m.group(2).splitlines(True))), text)
    return text


def run(name, steps, ports=FTP):
    """steps(ftp) -> extra value; compares the replies and the value."""
    res = []
    for i, port in enumerate(ports):
        f = Ftp(port)
        try:
            extra = steps(f, i)
        except Exception as e:  # noqa: BLE001
            extra = f"exception: {e!r}"
        f.close()
        res.append(([norm(x) for x in f.log], extra))
        if os.environ.get("SHOWLOG") == name: print(port, "".join(f.log))
    compare(name, *res)


def mc(*args):
    return subprocess.run([MC, "--config-dir", MC_CFG, *args], capture_output=True, text=True)


for i, base in enumerate(S3):
    mc("alias", "set", f"a{i}", base, AK, SK)
    mc("admin", "user", "add", f"a{i}", "ftpuser", "ftpsecret123")
    mc("admin", "policy", "attach", f"a{i}", "readwrite", "--user", "ftpuser")
    mc("admin", "user", "add", f"a{i}", "ftpreader", "readersecret123")
    mc("admin", "policy", "attach", f"a{i}", "readonly", "--user", "ftpreader")
    mc("admin", "user", "add", f"a{i}", "ftpnone", "nonesecret123")

# ---- before logging in ---------------------------------------------------------------------------------

run("commands before login", lambda f, i: [
    f.cmd("NOOP"), f.cmd("SYST"), f.cmd("FEAT"), f.cmd("OPTS UTF8 ON"), f.cmd("OPTS UTF8 OFF"),
    f.cmd("OPTS"), f.cmd("OPTS X Y"), f.cmd("TYPE I"), f.cmd("BOGUS"), f.cmd("USER"), f.cmd("PASS x"),
    f.cmd("PWD"), f.cmd("AUTH TLS"), f.cmd("PBSZ 0"), f.cmd("PROT P"), f.cmd("CLNT test"), f.cmd("ALLO 5"),
    f.cmd("noop")] and None)
run("wrong password", lambda f, i: f.login("ftpuser", "nope") or f.cmd("PWD") and None)
run("unknown user", lambda f, i: f.login("nosuchuser", "whatever") and None)
run("root login", lambda f, i: f.login(AK, SK) or f.cmd("PWD") and None)

# ---- directories and files -------------------------------------------------------------------------------

PAYLOAD = os.urandom(300000)


def tree(f, i):
    f.login("ftpuser", "ftpsecret123")
    for c in ("MKD ftpb", "MKD /ftpb/dir1", "MKD ftpb/dir1/sub", "MKD ftpb", "MKD x", "CWD ftpb", "PWD", "CWD dir1",
              "PWD", "CDUP", "PWD", "CWD /nosuchbucket", "CWD /", "XPWD", "TYPE I", "TYPE A", "TYPE X", "MODE S",
              "MODE B", "STRU F", "STRU R"):
        f.cmd(c)
    f.pasv()
    f.write_data("STOR /ftpb/dir1/file.txt", PAYLOAD)
    f.epsv()
    f.write_data("STOR /ftpb/top.json", b'{"a": 1}')
    f.pasv()
    f.write_data("STOR /ftpb/empty.bin", b"")
    out = {}
    for c in ("LIST /", "LIST /ftpb", "LIST -la /ftpb", "LIST /ftpb/dir1", "LIST /ftpb/dir1/file.txt",
              "LIST /nosuchbucket", "NLST /ftpb", "NLST /ftpb/top.json", "MLSD /ftpb", "MLSD /ftpb/dir1/file.txt"):
        f.pasv()
        out[c] = norm(f.read_data(c))
    f.cmd("CWD /ftpb")
    f.pasv()
    out["LIST (cwd)"] = norm(f.read_data("LIST"))
    for c in ("SIZE dir1/file.txt", "SIZE nothere", "SIZE /", "MDTM top.json", "MDTM nothere", "MDTM dir1",
              "STAT top.json", "STAT", "STAT nothere"):
        f.cmd(c)
    f.pasv()
    out["RETR"] = f.read_data("RETR dir1/file.txt") == PAYLOAD
    f.cmd("REST 1000")
    f.pasv()
    out["REST+RETR"] = f.read_data("RETR dir1/file.txt") == PAYLOAD[1000:]
    f.pasv()
    out["RETR missing"] = f.read_data("RETR nothere.txt")
    f.cmd("REST x")
    f.pasv()
    f.write_data("APPE /ftpb/appended.txt", b"appended")
    f.cmd("REST 5")
    f.pasv()
    f.write_data("APPE /ftpb/appended.txt", b"more")
    for c in ("RNFR top.json", "RNTO moved.json", "RNFR nothere/", "RNFR /nosuchbucket/x", "DELE nothere.txt",
              "DELE /ftpb", "RMD /", "RMD /nosuchbucket", "RMD /ftpb"):
        f.cmd(c)
    return out


run("a tree of directories and files", tree)


def objects(i):
    """What FTP stored, as S3 clients see it."""
    out = {}
    for key in ("dir1/file.txt", "top.json", "empty.bin", "appended.txt", "dir1/", "dir1/sub/"):
        c, h, b = curl(f"{S3[i]}/ftpb/{key}", "HEAD", headers=("x-amz-checksum-mode: ENABLED",))
        out[key] = (c, h.get("content-type"), h.get("content-length"), h.get("x-amz-checksum-crc32c"),
                    h.get("x-amz-checksum-type"), re.sub(r"[0-9a-f]{32}", "<md5>", h.get("etag", "")))
    return out


compare("objects written over FTP", objects(0), objects(1))


def removal(f, i):
    f.login("ftpuser", "ftpsecret123")
    for c in ("RMD /ftpb/dir1", "CWD /ftpb", "RMD dir1", "DELE top.json", "DELE empty.bin", "DELE appended.txt"):
        f.cmd(c)
    f.pasv()
    listing = norm(f.read_data("LIST /ftpb"))
    f.cmd("RMD /ftpb")
    f.pasv()
    return listing, norm(f.read_data("LIST /"))


run("removing directories and files", removal)

# ---- permissions -------------------------------------------------------------------------------------------

for i, base in enumerate(S3):
    curl(f"{base}/permb", "PUT")
    curl(f"{base}/permb/r.txt", "PUT", b"readable")


def reader(f, i):
    f.login("ftpreader", "readersecret123")
    f.pasv()
    got = f.read_data("RETR /permb/r.txt")
    f.pasv()
    f.write_data("STOR /permb/w.txt", b"nope")
    for c in ("MKD /permb/d", "DELE /permb/r.txt", "MKD /newbucketx", "RMD /permb"):
        f.cmd(c)
    f.pasv()
    return got, norm(f.read_data("LIST /permb"))


run("a read-only user", reader)


def nobody(f, i):
    f.login("ftpnone", "nonesecret123")
    f.pasv()
    ls = norm(f.read_data("LIST /"))
    f.cmd("CWD /permb")
    f.pasv()
    return ls, norm(f.read_data("LIST /permb"))


run("a user without policies", nobody)

# ---- data connections --------------------------------------------------------------------------------------


def data_conns(f, i):
    f.login("ftpuser", "ftpsecret123")
    out = [norm(f.read_data("LIST /permb"))]  # no data connection: 226 anyway
    f.cmd("PORT 127,0,0,1,0,1")  # nothing listens there
    f.cmd("EPRT |3|127.0.0.1|1|")
    f.cmd("EPRT |1|127.0.0.1|x|")
    f.cmd("LPRT 6,4,127,0,0,1,2,0,1")
    f.cmd("LPRT 4,16,1")
    # active mode: we listen, the server connects
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    p = ls.getsockname()[1]
    f.cmd(f"PORT 127,0,0,1,{p // 256},{p % 256}")
    conn, _ = ls.accept()
    f.data = conn
    out.append(norm(f.read_data("NLST /permb")))
    ls.close()
    return out


run("data connections", data_conns)

# ---- FTPS: AUTH TLS required, TLS data connections --------------------------------------------------------

TLS_FTP = (BASE + 12, BASE + 13)


def ftps(f, i):
    out = [f.cmd("FEAT"), f.cmd("USER x"), f.cmd("PBSZ 0"), f.cmd("AUTH SSL"), f.auth_tls(), f.cmd("PBSZ 0"),
           f.cmd("PROT C"), f.cmd("PROT P")]
    f.login(AK, SK)
    f.cmd("MKD tlsb")
    f.pasv()
    f.write_data("STOR /tlsb/secret.txt", b"over tls")
    f.pasv()
    got = f.read_data("RETR /tlsb/secret.txt")
    f.pasv()
    return got, norm(f.read_data("LIST /tlsb")), [norm(x) for x in out]


run("FTPS with force-tls", ftps, TLS_FTP)

print(f"ftp: {Score.passed} passed, {Score.failed} failed")
sys.exit(1 if Score.failed else 0)
